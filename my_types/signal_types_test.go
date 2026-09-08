package my_types

import (
	"math"
	"testing"
)

func TestSignalValueRoundTripPreservesFixedWidthTypes(t *testing.T) {
	tests := []struct {
		typ  string
		in   any
		want any
	}{
		{"bool", true, true}, {"int8", -2.0, int8(-2)}, {"int16", -3.0, int16(-3)},
		{"int32", -4.0, int32(-4)}, {"int64", -5.0, int64(-5)}, {"uint8", 250.0, uint8(250)},
		{"uint16", 65000.0, uint16(65000)}, {"uint32", 4e9, uint32(4000000000)},
		{"uint64", uint64(18446744073709551615), uint64(18446744073709551615)},
		{"float32", 1.25, float32(1.25)}, {"float64", -2.5, float64(-2.5)},
	}
	for _, tt := range tests {
		bits, err := EncodeSignalValue(tt.in, tt.typ)
		if err != nil {
			t.Fatalf("EncodeSignalValue(%s): %v", tt.typ, err)
		}
		got, err := DecodeSignalValue(bits, tt.typ)
		if err != nil {
			t.Fatalf("DecodeSignalValue(%s): %v", tt.typ, err)
		}
		if got != tt.want {
			t.Errorf("%s round trip = %#v (%T), want %#v", tt.typ, got, got, tt.want)
		}
	}
}

func TestSignalValueFloatBitsUseNativeWidths(t *testing.T) {
	bits, err := EncodeSignalValue(1.5, "float32")
	if err != nil || uint32(bits) != math.Float32bits(1.5) {
		t.Fatalf("float32 bits = %#x, %v", bits, err)
	}
	bits, err = EncodeSignalValue(1.5, "float64")
	if err != nil || bits != math.Float64bits(1.5) {
		t.Fatalf("float64 bits = %#x, %v", bits, err)
	}
}
