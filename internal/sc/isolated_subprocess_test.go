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
)

// runBoundedTestProcess contains the entire test subprocess tree in a
// dedicated Linux process group. On cancellation it signals the group;
// WaitDelay also bounds inherited stdout/stderr pipes. After Wait, a final
// group signal prevents a normally exited shell from leaving test children.
//
// Network-mutating tests pass only the fixed, safe unshare -Urn launchers.
// The lifecycle regression below uses inert shell/sleep fixtures only.
func runBoundedTestProcess(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 500 * time.Millisecond
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if cmd.Process != nil {
		// The group leader exiting does not imply all descendants exited.
		if cleanupErr := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); cleanupErr != nil &&
			!errors.Is(cleanupErr, syscall.ESRCH) {
			err = errors.Join(err, fmt.Errorf("terminate test subprocess group: %w", cleanupErr))
		}
	}
	return stdout.Bytes(), stderr.Bytes(), err
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
		waitDelay    bool
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
			if tc.waitDelay {
				if !errors.Is(err, exec.ErrWaitDelay) || ctx.Err() != nil {
					t.Fatalf("expected bounded pipe wait: err=%v ctx=%v stderr=%s", err, ctx.Err(), stderr)
				}
			} else if !errors.Is(ctx.Err(), context.DeadlineExceeded) || err == nil {
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
				if errors.Is(statErr, os.ErrNotExist) {
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
