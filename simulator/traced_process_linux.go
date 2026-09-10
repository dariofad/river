//go:build linux

package simulator

import (
	"fmt"
	"os/exec"
	"syscall"
)

// startStopped starts cmd under ptrace and returns only after Linux has stopped
// the child following exec. No model instruction has run at that point.
func startStopped(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		return err
	}

	var status syscall.WaitStatus
	for {
		_, err := syscall.Wait4(cmd.Process.Pid, &status, syscall.WUNTRACED, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			_ = abortStopped(cmd)
			return fmt.Errorf("wait for target post-exec stop: %w", err)
		}
		break
	}
	if !status.Stopped() || status.StopSignal() != syscall.SIGTRAP {
		_ = abortStopped(cmd)
		return fmt.Errorf("target did not stop after exec (status: %#x)", uint32(status))
	}
	return nil
}

func detachStopped(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return fmt.Errorf("cannot detach an unstarted target")
	}
	return syscall.PtraceDetach(cmd.Process.Pid)
}

func abortStopped(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(cmd.Process.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return err
	}
	var status syscall.WaitStatus
	for {
		_, err := syscall.Wait4(cmd.Process.Pid, &status, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.ECHILD {
			return nil
		}
		return err
	}
}
