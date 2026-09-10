package simulator

import (
	"debug/elf"
	"math"
	"os"
	"strings"
	"testing"
)

func TestHookAddress(t *testing.T) {
	image := &elfImage{
		loads: []elfLoadSegment{{start: 0x1000, end: 0x2000, flags: elf.PF_R | elf.PF_X}},
		symbols: map[string]uint64{
			"step": 0x1200,
		},
	}

	got, err := image.hookAddress("step", 0x34)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x1234 {
		t.Fatalf("hook address = %#x, want %#x", got, uint64(0x1234))
	}
}

func TestInspectELF(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := inspectELF(executable)
	if err != nil {
		t.Fatal(err)
	}
	if len(image.loads) == 0 {
		t.Fatal("ELF inspection returned no loadable segments")
	}
}

func TestLoadBiasFromProcessMappings(t *testing.T) {
	target := t.TempDir() + "/model"
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	mappings := parseProcessMappings("555555554000-555555556000 r-xp 00000000 00:00 0 " + target + "\n")
	image := &elfImage{loads: []elfLoadSegment{{start: 0, end: 0x2000, offset: 0}}}
	bias, err := image.loadBias(mappings, target, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if bias != 0x555555554000 {
		t.Fatalf("load bias = %#x, want %#x", bias, uint64(0x555555554000))
	}
}

func TestHookAddressRejectsInvalidLocations(t *testing.T) {
	image := &elfImage{
		loads:   []elfLoadSegment{{start: 0x1000, end: 0x2000, flags: elf.PF_R | elf.PF_X}},
		symbols: map[string]uint64{"overflow": math.MaxUint64, "data": 0x3000},
	}

	for _, test := range []struct {
		name   string
		symbol string
		offset uint64
	}{
		{name: "missing symbol", symbol: "missing"},
		{name: "overflow", symbol: "overflow", offset: 1},
		{name: "outside executable segment", symbol: "data"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := image.hookAddress(test.symbol, test.offset); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestValidateDataAddress(t *testing.T) {
	image := &elfImage{loads: []elfLoadSegment{
		{start: 0x1000, end: 0x2000, flags: elf.PF_R | elf.PF_X},
		{start: 0x3000, end: 0x4000, flags: elf.PF_R | elf.PF_W},
	}}

	if err := image.validateDataAddress(0x1800, false); err != nil {
		t.Fatalf("readable address rejected: %v", err)
	}
	if err := image.validateDataAddress(0x3800, true); err != nil {
		t.Fatalf("writable address rejected: %v", err)
	}
	if err := image.validateDataRange(0x3ff8, 8, true); err != nil {
		t.Fatalf("in-bounds range rejected: %v", err)
	}
	if err := image.validateDataRange(0x3ff9, 8, true); err == nil {
		t.Fatal("range crossing the end of a segment was accepted")
	}
	if err := image.validateDataAddress(0x1800, true); err == nil {
		t.Fatal("read-only address accepted for writing")
	}
	err := image.validateDataAddress(0x555555558000, false)
	if err == nil || !strings.Contains(err.Error(), "stale runtime address") {
		t.Fatalf("unexpected stale-address error: %v", err)
	}
}

func TestAddUint64(t *testing.T) {
	if got, ok := addUint64(4, 5); !ok || got != 9 {
		t.Fatalf("addUint64(4, 5) = (%d, %t)", got, ok)
	}
	if _, ok := addUint64(math.MaxUint64, 1); ok {
		t.Fatal("overflow was accepted")
	}
}
