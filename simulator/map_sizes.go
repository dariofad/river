package simulator

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// paddedEntries rounds map capacity to the kernel's standard 4096-entry page.
func paddedEntries(entries uint32) uint32 {
	return ((entries + 4096 - 1) / 4096) * 4096
}

// configureSignalMapSizes sets capacities on the collection specification.
// It must be called before the collection is loaded, since MapSpec changes do
// not affect maps that already exist in the kernel.
func configureSignalMapSizes(spec *ebpf.CollectionSpec, signalCount uint32) error {
	entries := paddedEntries(signalCount)
	for _, name := range []string{"trajectory_map", "address_map"} {
		mapSpec := spec.Maps[name]
		if mapSpec == nil {
			return fmt.Errorf("missing %s map specification", name)
		}
		mapSpec.MaxEntries = entries
	}

	return nil
}
