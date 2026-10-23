package sc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// waitid(WNOWAIT) reports child exit while leaving it waitable. No code in
// this helper reaps the group leader before signaling its process group:
// an unreaped leader pins its PID/PGID against numeric ID reuse on Linux.
// The kernel ABI's siginfo_t is 128 bytes; si_signo is the first int32.
func testLeaderExitedUnreaped(pid int) (bool, error) {
	const (
		waitIDPID  = 1
		waitExited = 0x4
		waitNoWait = 0x01000000
	)
	var info struct {
		signo int32
		_     [124]byte
	}
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID,
			waitIDPID, uintptr(pid), uintptr(unsafe.Pointer(&info)),
			waitExited|waitNoWait|syscall.WNOHANG, 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return false, fmt.Errorf("inspect unreaped test child: %w", errno)
		}
		return info.signo == int32(syscall.SIGCHLD), nil
	}
}

// terminateOwnedTestGroup only runs before Cmd.Wait, while the leader is
// known to be the still-unreaped process started by this helper. Do not call
// it after Wait: numeric PID lookup alone cannot authenticate a new generation.
func terminateOwnedTestGroup(pid int) error {
	if _, err := testLeaderExitedUnreaped(pid); err != nil {
		return fmt.Errorf("refuse signal without unreaped child ownership: %w", err)
	}
	err := syscall.Kill(-pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil // only the unreaped zombie remains; no live group members
	}
	if err != nil {
		return fmt.Errorf("terminate owned test process group: %w", err)
	}
	return nil
}

// runBoundedTestProcess owns Start, waitid observation, group termination and
// Wait in that order. No concurrent reaper or Cmd.Cancel callback can signal
// after PID/PGID reuse. The process is still waitable when group kill occurs,
// including when the leader exited early but descendants retained output pipes.
// WaitDelay provides an additional bound for pipes inherited outside the group.
// The only native mutating callers run fixed scripts behind unshare -Urn.
func runBoundedTestProcess(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(executable, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 500 * time.Millisecond
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return stdout.Bytes(), stderr.Bytes(), err
	}

	// Observe exit without reaping the direct child. A short interval avoids
	// another waiter goroutine while keeping normal successful exits prompt.
	pid := cmd.Process.Pid
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var observationErr error
	var canceled bool
observe:
	for {
		exited, err := testLeaderExitedUnreaped(pid)
		if err != nil {
			observationErr = err
			break
		}
		if exited {
			break
		}
		select {
		case <-ctx.Done():
			canceled = true
			break observe
		case <-ticker.C:
		}
	}

	// All negative-PGID signals happen before cmd.Wait reaps the leader.
	// If waitid cannot establish parent ownership, fail closed: only target
	// the direct os.Process (not a possibly recycled numeric process group).
	var cleanupErr error
	if observationErr != nil {
		cleanupErr = cmd.Process.Kill()
		if errors.Is(cleanupErr, os.ErrProcessDone) {
			cleanupErr = nil
		}
	} else {
		cleanupErr = terminateOwnedTestGroup(pid)
	}
	waitErr := cmd.Wait()
	if canceled {
		waitErr = errors.Join(waitErr, ctx.Err())
	}
	return stdout.Bytes(), stderr.Bytes(), errors.Join(observationErr, cleanupErr, waitErr)
}

// requireDisposableUserNetNamespace bounds even the non-mutating launcher
// capability probe. A blocked probe is a test failure, not an availability
// SKIP; permission-denied runners can still run the captured fixture tests.
func requireDisposableUserNetNamespace(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/unshare"); err != nil {
		t.Skip("unshare unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stdout, stderr, err := runBoundedTestProcess(ctx, "/usr/bin/unshare", "-Urn", "/usr/bin/true")
	if ctx.Err() != nil {
		t.Fatalf("private namespace capability probe exceeded deadline: %v stdout=%s stderr=%s", ctx.Err(), stdout, stderr)
	}
	if err != nil {
		t.Skipf("disposable user/network namespace unavailable: %v stdout=%s stderr=%s", err, stdout, stderr)
	}
}

// These fixtures deliberately do not use namespaces or change host networking.
func TestBoundedTestProcessDescendantCleanup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux process-group lifecycle regression")
	}
	for _, tc := range []struct {
		name, script string
		timeout      time.Duration
		parentExited bool
	}{
		{"canceled_running_tree", "/usr/bin/sleep 30 & echo $!; wait", 600 * time.Millisecond, false},
		{"successful_parent_retains_pipe", "/usr/bin/sleep 30 & echo $!; exit 0", 3 * time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			start := time.Now()
			stdout, stderr, err := runBoundedTestProcess(ctx, "/usr/bin/sh", "-c", tc.script)
			if elapsed := time.Since(start); elapsed >= 2*time.Second {
				t.Fatalf("subprocess tree or retained pipe exceeded bound: %v", elapsed)
			}
			if tc.parentExited {
				// The shell exited successfully; its retained-pipe child
				// was killed while the leader remained unreaped, so Wait
				// finishes normally without needing the WaitDelay fallback.
				if err != nil || ctx.Err() != nil {
					t.Fatalf("successful parent retained live child or pipe: err=%v ctx=%v stderr=%s", err, ctx.Err(), stderr)
				}
			} else if !errors.Is(ctx.Err(), context.DeadlineExceeded) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected deadline cancellation: err=%v ctx=%v stderr=%s", err, ctx.Err(), stderr)
			}
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(stdout)))
			if parseErr != nil || pid <= 1 {
				t.Fatalf("nested inert process did not start: stdout=%q stderr=%q err=%v", stdout, stderr, err)
			}
			// A missing or zombie child cannot run. Zombies may persist
			// briefly until the container's PID 1 reaps them.
			deadline := time.Now().Add(750 * time.Millisecond)
			for {
				stat, statErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				if errors.Is(statErr, os.ErrNotExist) || errors.Is(statErr, syscall.ESRCH) {
					// A quickly reaped /proc PID may report either ENOENT
					// or ESRCH depending on the procfs read phase.
					break
				}
				if statErr != nil {
					t.Fatalf("cannot inspect inert descendant %d: %v", pid, statErr)
				}
				idx := bytes.LastIndexByte(stat, ')')
				if idx < 0 {
					t.Fatalf("malformed descendant status: %q", stat)
				}
				fields := bytes.Fields(stat[idx+1:])
				if len(fields) > 0 && (bytes.Equal(fields[0], []byte("Z")) ||
					bytes.Equal(fields[0], []byte("X"))) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("descendant %d remains live after bounded cleanup: %s", pid, stat)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// A waitid(WNOWAIT) observation must preserve the leader's PID identity
// until Cmd.Wait. After Wait, inspect only: never attempt a stale group
// signal, because a numeric PID could already have been reused.
func TestBoundedTestProcessCannotSignalAfterReap(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux waitid ownership regression")
	}
	cmd := exec.Command("/usr/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	deadline := time.Now().Add(2 * time.Second)
	for {
		exited, err := testLeaderExitedUnreaped(pid)
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("waitid cannot preserve leader: %v", err)
		}
		if exited {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatal("short-lived fixture failed to exit")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i := 0; i < 2; i++ {
		exited, err := testLeaderExitedUnreaped(pid)
		if err != nil || !exited {
			_ = cmd.Wait()
			t.Fatalf("WNOWAIT consumed waitable leader: exited=%v err=%v", exited, err)
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := testLeaderExitedUnreaped(pid); !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("reaped fixture is unexpectedly still waitable: %v", err)
	}
}
