package server

import (
	"strings"
	"testing"

	"github.com/dariofad/river/my_types"
	"github.com/vmihailenco/msgpack/v5"
)

func TestDeserializeStateCatalogLookupAndValidation(t *testing.T) {
	config := &my_types.Configuration{
		NofCycles: "100",
		Catalog: map[string]my_types.Signal{
			"Simulink2Code.model_offset": {
				Name: "moffset",
				Type: "float64",
				Addr: "0x20018",
			},
			"AbstractFuelControl_M1.AbstractFuelControl_M1_P.Baseopeningangle_Value": {
				Name: "Baseopeningangle",
				Type: "float64",
				Addr: "0x30278",
			},
		},
	}

	// 1. Valid catalog lookup by full path (with explicit matching TYPE and VALUE_SIZE)
	raw, err := msgpack.Marshal([]map[string]any{
		{
			"TIME":       uint32(5),
			"NAME":       "Simulink2Code.model_offset",
			"VALUE_SIZE": uint32(8),
			"TYPE":       "float64",
			"VALUE":      50.0,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	records, err := deserializeState(raw, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 || records[0].Addr != 0x20018 || records[0].Type != "float64" || records[0].ValueSize != 8 {
		t.Fatalf("unexpected resolved record: %#v", records)
	}

	// 2. Valid catalog lookup when TYPE and VALUE_SIZE are omitted (inferred from catalog)
	rawInferred, err := msgpack.Marshal([]map[string]any{
		{
			"TIME":  uint32(50),
			"NAME":  "AbstractFuelControl_M1.AbstractFuelControl_M1_P.Baseopeningangle_Value",
			"VALUE": 16.0,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	records, err = deserializeState(rawInferred, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 || records[0].Addr != 0x30278 || records[0].Type != "float64" || records[0].ValueSize != 8 {
		t.Fatalf("unexpected inferred record: %#v", records)
	}

	// 3. Valid raw hex ADDR mode (backward compatible)
	rawHex, err := msgpack.Marshal([]map[string]any{
		{
			"TIME":       uint32(10),
			"ADDR":       uint64(0xdeadbeef),
			"VALUE_SIZE": uint32(4),
			"TYPE":       "int32",
			"VALUE":      int32(42),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	records, err = deserializeState(rawHex, config)
	if err != nil {
		t.Fatalf("unexpected error for raw ADDR: %v", err)
	}
	if len(records) != 1 || records[0].Addr != 0xdeadbeef || records[0].Type != "int32" || records[0].ValueSize != 4 {
		t.Fatalf("unexpected raw ADDR record: %#v", records)
	}

	// 4. Rejects type mismatch against catalog
	rawBadType, _ := msgpack.Marshal([]map[string]any{
		{
			"TIME":       uint32(5),
			"NAME":       "Simulink2Code.model_offset",
			"VALUE_SIZE": uint32(4),
			"TYPE":       "float32",
			"VALUE":      50.0,
		},
	})
	if _, err := deserializeState(rawBadType, config); err == nil || !strings.Contains(err.Error(), "catalog requires") {
		t.Fatalf("expected catalog type mismatch error, got %v", err)
	}

	// 5. Rejects unsanitized/malicious NAME characters
	rawBadChars, _ := msgpack.Marshal([]map[string]any{
		{
			"TIME":  uint32(5),
			"NAME":  "../etc/passwd; rm -rf",
			"VALUE": 1.0,
		},
	})
	if _, err := deserializeState(rawBadChars, config); err == nil || !strings.Contains(err.Error(), "invalid characters") {
		t.Fatalf("expected invalid characters error, got %v", err)
	}

	// 6. Rejects out-of-range TIME
	rawBadTime, _ := msgpack.Marshal([]map[string]any{
		{
			"TIME":  uint32(100),
			"NAME":  "Simulink2Code.model_offset",
			"VALUE": 1.0,
		},
	})
	if _, err := deserializeState(rawBadTime, config); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("expected out of range time error, got %v", err)
	}
}

func TestDeserializeSignalPerturbationPathAndNameLookup(t *testing.T) {
	config := &my_types.Configuration{
		Writes: []my_types.Group{
			{
				Symbol: "step",
				Offset: "0x0",
				Signals: []my_types.Signal{
					{
						Name: "x",
						Path: "Simulink2Code.Simulink2Code_U.x",
						Type: "float64",
						Addr: "0x20000",
					},
					{
						Name: "y",
						Path: "Simulink2Code.Simulink2Code_U.y",
						Type: "float64",
						Addr: "0x20008",
					},
				},
			},
		},
	}

	raw, err := msgpack.Marshal(map[string]any{
		"Simulink2Code.Simulink2Code_U.x": []any{1.5, 2.5},
		"time":                            []any{int32(0), int32(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := deserializeSignalPerturbation(raw, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := normalized["Simulink2Code.Simulink2Code_U.x"]; !ok {
		t.Fatalf("expected canonical path key in normalized perturbation, got %#v", normalized)
	}

	rawBad, _ := msgpack.Marshal(map[string]any{
		"Simulink2Code.unknown": []any{1.5},
		"time":                  []any{int32(0)},
	})
	if _, err := deserializeSignalPerturbation(rawBad, config); err == nil || !strings.Contains(err.Error(), "not a configured writable signal") {
		t.Fatalf("expected unknown writable signal error, got %v", err)
	}
}

func TestPrepareRequestErrorCategorization(t *testing.T) {
	// 1. Malformed msgpack -> request_error
	_, _, err := prepareRequest([]byte{0xff, 0x00})
	if cat, _ := my_types.CategorizeError(err, my_types.ErrCategoryNone); cat != my_types.ErrCategoryRequest {
		t.Fatalf("expected request_error, got %q (%v)", cat, err)
	}

	// 2. Invalid YAML manifest -> manifest_error
	rawBadYAML, _ := msgpack.Marshal(map[string]any{
		"manifest":   ":::not valid yaml:::",
		"trajectory": map[string]any{},
	})
	_, _, err = prepareRequest(rawBadYAML)
	if cat, _ := my_types.CategorizeError(err, my_types.ErrCategoryNone); cat != my_types.ErrCategoryManifest {
		t.Fatalf("expected manifest_error, got %q (%v)", cat, err)
	}
}

func TestSerializeAndDecodeServerResponse(t *testing.T) {
	expected := my_types.ServerResponse{
		Status:   my_types.StatusError,
		Category: my_types.ErrCategoryTrajectory,
		Message:  "trajectory for x has 10 values; expected 800",
	}
	buf, err := serializeResponse(expected)
	if err != nil {
		t.Fatalf("unexpected serialize error: %v", err)
	}
	var decoded my_types.ServerResponse
	if err := msgpack.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	if decoded.Status != expected.Status || decoded.Category != expected.Category || decoded.Message != expected.Message {
		t.Fatalf("decoded response mismatch: got %#v, want %#v", decoded, expected)
	}
}
