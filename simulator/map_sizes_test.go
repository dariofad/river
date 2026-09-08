package simulator

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestConfigureSignalMapSizes(t *testing.T) {
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"trajectory_map":  {MaxEntries: 4096},
		"address_map":     {MaxEntries: 4096},
		"signal_type_map": {MaxEntries: 4096},
	}}

	if err := configureSignalMapSizes(spec, 4097); err != nil {
		t.Fatalf("configureSignalMapSizes() error = %v", err)
	}
	for _, name := range []string{"trajectory_map", "address_map", "signal_type_map"} {
		if got, want := spec.Maps[name].MaxEntries, uint32(8192); got != want {
			t.Errorf("%s MaxEntries = %d, want %d", name, got, want)
		}
	}
}

func TestConfigureSignalMapSizesRequiresBothMaps(t *testing.T) {
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"trajectory_map": {},
	}}

	if err := configureSignalMapSizes(spec, 1); err == nil {
		t.Fatal("configureSignalMapSizes() succeeded without address_map")
	}
}
