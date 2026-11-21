package sc

// An explicitly requested, VM-only repair for stale FAILED Health/Recovery
// oneshots. Never normalize a failed independent Guard as part of new Apply:
// failures remain safety signals until an operator proves exact idle ownership.
import (
	"context"
	"path/filepath"
	"strings"
	"time"
)

type NativeIdleGuardReconcileResult struct {
	Reconciled        bool `json:"reconciled"`
	HealthReconciled  bool `json:"health_reconciled"`
	GuardIdleVerified bool `json:"guard_idle_verified"`
	ActivationReady   bool `json:"activation_ready"`
}

// The accepted result is either a known, fully idle FAILED oneshot or an
// already idle SUCCESS oneshot. Never infer quiescence from ActiveState alone.
func parseNativeIdleManagedService(raw []byte, name string) (failed bool, err error) {
	invalid := func() (bool, error) {
		return false, Fault("guard_unavailable", "owned independent executor state is not safely idle")
	}
	if name != trialRecoveryUnit && name != smartTUNHealthUnit {
		return invalid()
	}
	if len(raw) == 0 || len(raw) > 16384 {
		return invalid()
	}
	fields := map[string]string{}
	allowed := map[string]bool{
		"Id": true, "LoadState": true, "FragmentPath": true, "DropInPaths": true,
		"Transient": true, "UnitFileState": true, "ActiveState": true,
		"SubState": true, "Result": true, "MainPID": true, "ControlPID": true,
		"Job": true, "ControlGroup": true,
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 || !allowed[pair[0]] {
			return invalid()
		}
		if _, seen := fields[pair[0]]; seen {
			return invalid()
		}
		fields[pair[0]] = pair[1]
	}
	if len(fields) != len(allowed) || fields["Id"] != name ||
		fields["LoadState"] != "loaded" ||
		fields["FragmentPath"] != filepath.Join(trialGuardUnitDir, name) ||
		fields["DropInPaths"] != "" || fields["Transient"] != "no" ||
		fields["UnitFileState"] != "static" ||
		fields["MainPID"] != "0" || fields["ControlPID"] != "0" ||
		fields["Job"] != "" || fields["ControlGroup"] != "" {
		return invalid()
	}
	if fields["ActiveState"] == "inactive" && fields["SubState"] == "dead" &&
		fields["Result"] == "success" {
		return false, nil
	}
	if fields["ActiveState"] == "failed" && fields["SubState"] == "failed" {
		switch fields["Result"] {
		case "exit-code", "timeout", "signal", "core-dump":
			return true, nil
		}
	}
	return invalid()
}

// Reobserve provenance before and after the detailed systemd process/job
// query. The first-party unit and manifest must match across observations.
func observeNativeIdleManagedService(name string) (nativeGuardUnitIdentity, bool, error) {
	var observe func(string) (nativeGuardUnitIdentity, map[string]string, error)
	switch name {
	case trialRecoveryUnit:
		observe = observeNativeRecoveryUnit
	case smartTUNHealthUnit:
		observe = observeNativeHealthUnit
	default:
		return nativeGuardUnitIdentity{}, false, Fault("guard_unavailable", "unknown idle executor role")
	}
	id, first, err := observe(name)
	if err != nil {
		return nativeGuardUnitIdentity{}, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, "show", name,
		"-p", "Id", "-p", "LoadState", "-p", "FragmentPath", "-p", "DropInPaths",
		"-p", "Transient", "-p", "UnitFileState", "-p", "ActiveState",
		"-p", "SubState", "-p", "Result", "-p", "MainPID", "-p", "ControlPID",
		"-p", "Job", "-p", "ControlGroup")
	if err != nil {
		return nativeGuardUnitIdentity{}, false, err
	}
	raw, err := cmd.Output()
	if err != nil || ctx.Err() != nil {
		return nativeGuardUnitIdentity{}, false, Fault("guard_unavailable", "owned independent executor cannot be inspected")
	}
	failed, err := parseNativeIdleManagedService(raw, name)
	if err != nil {
		return nativeGuardUnitIdentity{}, false, err
	}
	nextID, next, err := observe(name)
	if err != nil || nextID != id ||
		next["ActiveState"] != first["ActiveState"] ||
		next["Result"] != first["Result"] ||
		(failed && (first["ActiveState"] != "failed" || first["Result"] == "success")) ||
		(!failed && (first["ActiveState"] != "inactive" || first["Result"] != "success")) {
		return nativeGuardUnitIdentity{}, false, Fault("guard_unavailable", "owned independent executor changed during observation")
	}
	return id, failed, nil
}

func observeNativeIdleRecoveryService() (nativeGuardUnitIdentity, bool, error) {
	return observeNativeIdleManagedService(trialRecoveryUnit)
}

func observeNativeIdleHealthService() (nativeGuardUnitIdentity, bool, error) {
	return observeNativeIdleManagedService(smartTUNHealthUnit)
}

// These operations are injected only so fault-path tests can exercise the
// real ordered reconciliation without touching systemd or the guest network.
// The production caller supplies exact owned-service observers and executes
// this sequence while holding the journal lock, after all host/VM admission
// and idle journal, credential, core and timer checks have passed.
type nativeIdleReconcileOperations struct {
	observeHealth   func() (nativeGuardUnitIdentity, bool, error)
	observeRecovery func() (nativeGuardUnitIdentity, bool, error)
	inspectNative   func() error
	resetFailed     func(string) error
	verifyFinal     func() error
}

// A reset-failed command can fail after changing systemd state. Report only
// progress independently confirmed by the matching post-reset observation.
// In particular, a later failure must not turn an already verified Health
// reset back into false in the JSON error response.
func reconcileIdleNativeGuardServices(ops nativeIdleReconcileOperations) (NativeIdleGuardReconcileResult, error) {
	var result NativeIdleGuardReconcileResult
	healthID, healthFailed, err := ops.observeHealth()
	if err != nil {
		return result, err
	}
	recoveryID, recoveryFailed, err := ops.observeRecovery()
	if err != nil {
		return result, err
	}
	if err := ops.inspectNative(); err != nil {
		return result, err
	}
	if healthFailed {
		if err := ops.resetFailed(smartTUNHealthUnit); err != nil {
			return result, err
		}
	}
	afterHealth, stillHealthFailed, err := ops.observeHealth()
	if err != nil || stillHealthFailed || healthID != afterHealth {
		return result, Fault("guard_unavailable", "owned health executor failed-state reset is not independently verified")
	}
	result.HealthReconciled = healthFailed
	if recoveryFailed {
		if err := ops.resetFailed(trialRecoveryUnit); err != nil {
			return result, err
		}
	}
	afterRecovery, stillRecoveryFailed, err := ops.observeRecovery()
	if err != nil || stillRecoveryFailed || recoveryID != afterRecovery {
		return result, Fault("guard_unavailable", "owned recovery executor failed-state reset is not independently verified")
	}
	result.Reconciled = recoveryFailed
	if err := ops.verifyFinal(); err != nil {
		return result, err
	}
	result.GuardIdleVerified = true
	return result, nil
}
