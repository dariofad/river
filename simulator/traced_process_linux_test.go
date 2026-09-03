//go:build linux

package simulator

import (
	"os/exec"
	"runtime"
	"testing"
)

func TestStartStoppedThenDetach(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command("/bin/true")
	if err := startStopped(cmd); err != nil {
		t.Skipf("ptrace post-exec synchronization unavailable: %v", err)
	}
	if err := detachStopped(cmd); err != nil {
		_ = abortStopped(cmd)
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}
