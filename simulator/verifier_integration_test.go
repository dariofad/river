//go:build integration

package simulator

import (
	"testing"

	"github.com/cilium/ebpf"
)

// This test requires CAP_BPF/CAP_PERFMON (or root) and a Linux kernel matching
// River's documented prerequisites. It exercises the verifier without
// attaching to or launching a model.
func TestKernelAcceptsManifestRuntimePrograms(t *testing.T) {
	RemoveMemlock()
	spec, err := loadProbe()
	if err != nil {
		t.Fatal(err)
	}
	objects := probeObjects{}
	if err := spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: 1}}); err != nil {
		t.Fatal(err)
	}
	defer objects.Close()
}
