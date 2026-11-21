//go:build linux

package sc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const nativeCoreCredential = "/run/credentials/server-connect-native-tun.service/native-config"

type nativeCoreIdentity struct {
	PID     int
	Started uint64 // Linux /proc starttime; PID alone is not a process identity.
}

func parseNativeChildStat(raw []byte, pid, parent int) (nativeCoreIdentity, error) {
	fail := func() (nativeCoreIdentity, error) {
		return nativeCoreIdentity{}, Fault("guard_unavailable", "managed Core identity is unavailable")
	}
	if len(raw) == 0 || len(raw) > 4096 || pid < 2 || parent < 2 {
		return fail()
	}
	value := string(raw)
	idx := strings.LastIndex(value, ") ")
	if idx < 0 || !strings.HasPrefix(value, strconv.Itoa(pid)+" (") {
		return fail()
	}
	parts := strings.Fields(value[idx+2:])
	if len(parts) < 20 {
		return fail()
	}
	ppid, err := strconv.Atoi(parts[1]) // field 4, after state
	if err != nil || ppid != parent || parts[0] == "Z" || parts[0] == "X" {
		return fail()
	}
	started, err := strconv.ParseUint(parts[19], 10, 64) // field 22
	if err != nil || started == 0 {
		return fail()
	}
	return nativeCoreIdentity{PID: pid, Started: started}, nil
}

// One exact systemd-owned parent and one direct Core child. This is a
// read-only independent identity witness, not a pgrep by process name.
func (m *Manager) nativeCoreChildIdentity() (nativeCoreIdentity, int, error) {
	if err := m.nativeUnitOwnership(); err != nil {
		return nativeCoreIdentity{}, 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	command, err := trustedSystemctlCommand(ctx, "show", nativeSmartUnit, "-p", "MainPID", "--value")
	if err != nil {
		return nativeCoreIdentity{}, 0, err
	}
	out, err := command.Output()
	if err != nil || ctx.Err() != nil {
		return nativeCoreIdentity{}, 0, Fault("service_state_unavailable", "native supervisor PID unavailable")
	}
	parent, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || parent <= 1 {
		return nativeCoreIdentity{}, 0, Fault("guard_unavailable", "native supervisor not active")
	}
	installed, err := os.Stat(filepath.Join(managedPrefix, "current", "bin", "server-connect"))
	if err != nil {
		return nativeCoreIdentity{}, 0, Fault("service_conflict", "installed native supervisor binary unavailable")
	}
	running, err := os.Stat(fmt.Sprintf("/proc/%d/exe", parent))
	if err != nil || !os.SameFile(installed, running) {
		return nativeCoreIdentity{}, 0, Fault("service_conflict", "native supervisor process is not installed manager")
	}
	// Go may fork from any runtime thread. The supervisor also invokes the
	// pinned systemctl during its own restart authorization, so a short-lived
	// trusted systemctl helper can legitimately coexist with the Core child.
	// Reject unknown/second Core children and never guess from process names.
	core, err := os.Stat(m.Core)
	if err != nil {
		return nativeCoreIdentity{}, parent, Fault("service_conflict", "installed selected Core missing")
	}
	control, err := os.Stat(nativeSystemctlPath)
	if err != nil {
		return nativeCoreIdentity{}, parent, Fault("service_conflict", "installed system controller unavailable")
	}
	for attempt := 0; attempt < 3; attempt++ {
		threads, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", parent))
		if err != nil || len(threads) == 0 || len(threads) > 512 {
			return nativeCoreIdentity{}, parent, Fault("guard_unavailable", "native supervisor threads unavailable")
		}
		children := make(map[string]bool)
		unstable := false
		for _, thread := range threads {
			if _, e := strconv.Atoi(thread.Name()); e != nil {
				return nativeCoreIdentity{}, parent, Fault("guard_unavailable", "native supervisor thread identity invalid")
			}
			data, e := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", parent, thread.Name()))
			if os.IsNotExist(e) {
				unstable = true // a Go runtime thread exited during observation
				break
			}
			if e != nil || len(data) > 256 {
				return nativeCoreIdentity{}, parent, Fault("guard_unavailable", "native supervisor children unavailable")
			}
			for _, child := range strings.Fields(string(data)) {
				children[child] = true
			}
		}
		if unstable {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		var found nativeCoreIdentity
		for child := range children {
			pid, e := strconv.Atoi(child)
			if e != nil || pid < 2 {
				return nativeCoreIdentity{}, parent, Fault("guard_unavailable", "native supervisor child PID invalid")
			}
			stat, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
			if os.IsNotExist(e) {
				unstable = true
				break
			}
			if e != nil {
				return nativeCoreIdentity{}, parent, Fault("guard_unavailable", "native supervisor child identity unreadable")
			}
			identity, e := parseNativeChildStat(stat, pid, parent)
			if e != nil {
				return nativeCoreIdentity{}, parent, e
			}
			executable, e := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
			if os.IsNotExist(e) {
				unstable = true
				break
			}
			if e != nil {
				return nativeCoreIdentity{}, parent, Fault("guard_unavailable", "native supervisor child executable unreadable")
			}
			switch {
			case os.SameFile(executable, core):
				if found.PID != 0 {
					return nativeCoreIdentity{}, parent, Fault("service_conflict", "native supervisor has multiple Core processes")
				}
				found = identity
			case os.SameFile(executable, control):
				// The only additional fork the manager's restart authorization
				// is permitted to perform is its pinned systemctl observer.
			default:
				return nativeCoreIdentity{}, parent, Fault("service_conflict", "native supervisor has foreign child process")
			}
		}
		if unstable {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if found.PID == 0 {
			return nativeCoreIdentity{}, parent, Fault("guard_unavailable", "native supervisor has no unique Core child")
		}
		return found, parent, nil
	}
	return nativeCoreIdentity{}, parent, Fault("guard_unavailable", "native Core process identity changed during observation")

}

func (m *Manager) nativeSupervisorRestartAuthorized(childPID int) error {
	return m.withLock(func() error {
		claim, err := m.readNativeSession()
		if err != nil {
			return err
		}
		h, err := m.readNativeHealth()
		if err != nil {
			return err
		}
		state, err := m.load()
		if err != nil {
			return err
		}
		if state.Desired != "smart" || h.Phase != "recovering" || !h.RestartInFlight ||
			h.RestartOriginalPID != childPID || h.OperationID != claim.HealthOperationID ||
			h.ConfigSHA256 != claim.ConfigSHA256 || !claim.CoreStartAttempted ||
			claim.StartupGuardPhase != "armed" {
			return Fault("guard_pending", "Core restart has no matching operation-bound barrier authority")
		}
		boot, err := trialBootIdentity()
		if err != nil || h.BootID != boot {
			return Fault("guard_pending", "Core restart belongs to another boot")
		}
		now, err := nativeUptimeMillis()
		if err != nil || now >= h.RestartIncidentMS+h.RestartDeadlineMS {
			return Fault("guard_pending", "Core restart incident deadline expired")
		}
		if err := m.validateNativeSessionConfig(claim); err != nil {
			return err
		}
		if err := nativeHealthGuardRoles(); err != nil {
			return err
		}
		plan, err := m.readNativeStartupPlan(claim)
		if err != nil {
			return err
		}
		return requireNativeStartupGuardClaim(context.Background(), nativeSystemRunner{}, plan, claim.StartupGuardHandle)
	})
}

func (m *Manager) requireNativeSupervisorMainPID() error {
	for attempt := 0; attempt < 8; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cmd, err := trustedSystemctlCommand(ctx, "show", nativeSmartUnit, "-p", "MainPID", "--value")
		if err != nil {
			cancel()
			return err
		}
		out, err := cmd.Output()
		cancel()
		if err != nil {
			return Fault("ownership_required", "native supervisor systemd MainPID unavailable")
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
		if err == nil && pid == os.Getpid() {
			return nil
		}
		if err != nil || pid > 1 {
			break
		} // wrong process, not a startup timing issue
		time.Sleep(40 * time.Millisecond)
	}
	return Fault("ownership_required", "native Core supervisor was not launched as signed systemd MainPID")
}

// The manager promotes desired=smart only AFTER committing the effective
// startup containment barrier and BEFORE starting the systemd unit.
// ExecStartPre then checks that smart-only claim and consumes it once;
// ExecStart is permitted only with the same committed, consumed identity.
func nativeSupervisorJustConsumedPrearm(s State, claim NativeSession, h NativeHealthState) error {
	if s.Desired != "smart" || s.Selected != claim.Selected ||
		!claim.CoreStartAttempted || claim.StartupGuardPhase != "armed" ||
		h.Phase != "starting" || h.OperationID != claim.HealthOperationID ||
		h.ConfigSHA256 != claim.ConfigSHA256 {
		return Fault("guard_pending", "native supervisor start has no consumed one-use prearm")
	}
	return nil
}

// This process is the systemd MainPID. ExecStopPost still runs on ANY exit
// of this parent, including unexpected child failure. A controlled child
// replacement is permitted only after the independent health role has staged
// and receipted an effective fail-closed OUTPUT barrier for this operation.
// A Core crash without that barrier is fatal: do not retry unguarded.
func (m *Manager) RunNativeCoreSupervisor() error {
	if err := m.nativeUnitOwnership(); err != nil {
		return err
	}
	// A manual root CLI invocation cannot become a parallel Core owner.
	// Only the *actual* PID systemd launched as this signed unit's MainPID
	// may supervise a child under the existing unit's resource controls.
	if err := m.requireNativeSupervisorMainPID(); err != nil {
		return err
	}
	if err := EnsureCore(m.Core); err != nil {
		return err
	}
	if err := m.withLock(func() error {
		claim, e := m.readNativeSession()
		if e != nil {
			return e
		}
		h, e := m.readNativeHealth()
		if e != nil {
			return e
		}
		s, e := m.load()
		if e != nil {
			return e
		}
		if err := nativeSupervisorJustConsumedPrearm(s, claim, h); err != nil {
			return err
		}
		plan, e := m.readNativeStartupPlan(claim)
		if e != nil {
			return e
		}
		return requireNativeStartupGuardClaim(context.Background(), nativeSystemRunner{}, plan, claim.StartupGuardHandle)
	}); err != nil {
		return err
	}
	return superviseNativeCore(m.Core, nativeCoreCredential, m.nativeSupervisorRestartAuthorized)
}

// The core subprocess runs under the original systemd service's capability,
// cgroup, filesystem and namespace controls. No second service/unit is added.
func superviseNativeCore(core, config string, authorized func(int) error) error {
	stopping := make(chan os.Signal, 2)
	restarting := make(chan os.Signal, 2)
	signal.Notify(stopping, syscall.SIGTERM, syscall.SIGINT)
	signal.Notify(restarting, syscall.SIGUSR1)
	defer signal.Stop(stopping)
	defer signal.Stop(restarting)
	return superviseNativeCoreWithSignals(core, config, authorized, stopping, restarting)
}

// Injectable signals let real-process restart tests check PID changes without
// delivering signals to the Go test runner or the developer's host.
func superviseNativeCoreWithSignals(core, config string, authorized func(int) error,
	stopping, restarting <-chan os.Signal) error {
	start := func() (*exec.Cmd, chan error, error) {
		cmd := exec.Command(core, "run", "-c", config)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			return nil, nil, Fault("service_state_unavailable", "managed native Core failed to start")
		}
		result := make(chan error, 1)
		go func() { result <- cmd.Wait() }()
		return cmd, result, nil
	}
	cmd, exited, err := start()
	if err != nil {
		return err
	}
	stopChild := func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	}
	for {
		select {
		case <-stopping:
			stopChild()
			return nil
		case e := <-exited:
			return fmt.Errorf("native Core exited without an armed replacement: %w", firstCoreExitError(e))
		case <-restarting:
			// A signal alone is NEVER restart authority.
			if err := authorized(cmd.Process.Pid); err != nil {
				// Do not kill an otherwise running Core on an untrusted or
				// stale signal; the independent guards handle real faults.
				continue
			}
			stopChild()
			// Losing containment after child exit is fatal; ExecStopPost
			// must take over instead of starting an unprotected new Core.
			if err := authorized(cmd.Process.Pid); err != nil {
				return fmt.Errorf("Core replacement barrier lost: %w", err)
			}
			select {
			case <-stopping:
				return nil
			default:
			}
			cmd, exited, err = start()
			if err != nil {
				return err
			}
		}
	}
}

func firstCoreExitError(err error) error {
	if err == nil {
		return errors.New("unrequested Core exit")
	}
	return err
}
