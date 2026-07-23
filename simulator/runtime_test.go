package simulator

import (
	"encoding/binary"
	"math"
	"path/filepath"
	"testing"

	"github.com/dariofad/river/manifest"
)

func TestParseRuntimeRecord(t *testing.T) {
	raw := make([]byte, 32)
	binary.LittleEndian.PutUint32(raw[0:4], 7)
	binary.LittleEndian.PutUint32(raw[4:8], 2)
	binary.LittleEndian.PutUint32(raw[8:12], 2)
	binary.LittleEndian.PutUint64(raw[16:24], math.Float64bits(1.25))
	binary.LittleEndian.PutUint64(raw[24:32], 42)
	record, err := parseRuntimeRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if record.Cycle != 7 || record.ModelID != 2 || len(record.Values) != 2 {
		t.Fatalf("unexpected record: %#v", record)
	}
}

func TestPrimitiveRoundTrip(t *testing.T) {
	tests := []struct {
		value float64
		type_ manifest.PrimitiveType
	}{
		{1.25, manifest.PrimitiveType{Name: "float64", Size: 8, Floating: true, Signed: true}},
		{-12, manifest.PrimitiveType{Name: "int16", Size: 2, Signed: true}},
		{250, manifest.PrimitiveType{Name: "uint8", Size: 1}},
	}
	for _, test := range tests {
		raw, err := encodePrimitive(test.value, test.type_)
		if err != nil {
			t.Fatal(err)
		}
		if got := decodePrimitive(raw, test.type_); got != test.value {
			t.Fatalf("%s round trip: got %v, want %v", test.type_.Name, got, test.value)
		}
	}
}

func TestParseRuntimeRecordRejectsTruncation(t *testing.T) {
	raw := make([]byte, 16)
	binary.LittleEndian.PutUint32(raw[8:12], 1)
	if _, err := parseRuntimeRecord(raw); err == nil {
		t.Fatal("expected truncated record error")
	}
}

func TestRuntimeNamesAcceptName(t *testing.T) {
	data := manifest.RuntimeData{
		ID:      4,
		ModelID: 0,
		Name:    "Pedal Angle",
		Path:    "AbstractFuelControl_M1.AbstractFuelControl_M1_U.PedalAngle",
	}
	names, ambiguous := runtimeNames(&manifest.RuntimePlan{
		Models: []manifest.RuntimeModel{{Name: "AbstractFuelControl_M1", Inputs: []manifest.RuntimeData{data}}},
	})
	if got, ok := names["Pedal Angle"]; !ok || got.ID != data.ID {
		t.Fatalf("name did not resolve: %#v", names)
	}
	if ambiguous["Pedal Angle"] {
		t.Fatal("single name must not be ambiguous")
	}
}

func TestRuntimeNamesRetainGeneratedAFCNames(t *testing.T) {
	for _, filename := range []string{"afc-with-descriptor.river.yaml", "afc.river.yaml"} {
		manifestPath, err := filepath.Abs(filepath.Join("..", filename))
		if err != nil {
			t.Fatal(err)
		}
		configured, err := manifest.Read(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := manifest.Compile(configured)
		if err != nil {
			t.Fatal(err)
		}
		names, ambiguous := runtimeNames(plan)
		for _, name := range []string{"PedalAngle", "EngineSpeed"} {
			data, ok, isAmbiguous := resolveRuntimeName(names, ambiguous, name)
			if !ok || isAmbiguous || data.ID > 1 {
				t.Fatalf("%s: generated input name %q is missing or ambiguous", filename, name)
			}
		}
	}
}
