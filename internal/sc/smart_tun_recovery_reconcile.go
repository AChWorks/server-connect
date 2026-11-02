package sc

// An explicitly requested, VM-only repair for stale FAILED Health/Recovery
// oneshots. Never normalize a failed independent Guard as part of new Apply:
// failures remain safety signals until an operator proves exact idle ownership.
import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type SmartTUNIdleGuardReconcileResult struct {
	Reconciled        bool `json:"reconciled"`
	HealthReconciled  bool `json:"health_reconciled"`
	GuardIdleVerified bool `json:"guard_idle_verified"`
	ActivationReady   bool `json:"activation_ready"`
}

// The accepted result is either a known, fully idle FAILED oneshot or an
// already idle SUCCESS oneshot. Never infer quiescence from ActiveState alone.
func parseSmartTUNIdleManagedService(raw []byte, name string) (failed bool, err error) {
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

func parseSmartTUNIdleRecoveryService(raw []byte) (bool, error) {
	return parseSmartTUNIdleManagedService(raw, trialRecoveryUnit)
}

// Reobserve provenance before and after the detailed systemd process/job
// query. The first-party unit and manifest must match across observations.
func observeSmartTUNIdleManagedService(name string) (smartTUNHealthUnitIdentity, bool, error) {
	var observe func(string) (smartTUNHealthUnitIdentity, map[string]string, error)
	switch name {
	case trialRecoveryUnit:
		observe = observeSmartTUNRecoveryUnit
	case smartTUNHealthUnit:
		observe = observeSmartTUNHealthUnit
	default:
		return smartTUNHealthUnitIdentity{}, false, Fault("guard_unavailable", "unknown idle executor role")
	}
	id, first, err := observe(name)
	if err != nil {
		return smartTUNHealthUnitIdentity{}, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, "show", name,
		"-p", "Id", "-p", "LoadState", "-p", "FragmentPath", "-p", "DropInPaths",
		"-p", "Transient", "-p", "UnitFileState", "-p", "ActiveState",
		"-p", "SubState", "-p", "Result", "-p", "MainPID", "-p", "ControlPID",
		"-p", "Job", "-p", "ControlGroup")
	if err != nil {
		return smartTUNHealthUnitIdentity{}, false, err
	}
	raw, err := cmd.Output()
	if err != nil || ctx.Err() != nil {
		return smartTUNHealthUnitIdentity{}, false, Fault("guard_unavailable", "owned independent executor cannot be inspected")
	}
	failed, err := parseSmartTUNIdleManagedService(raw, name)
	if err != nil {
		return smartTUNHealthUnitIdentity{}, false, err
	}
	nextID, next, err := observe(name)
	if err != nil || nextID != id ||
		next["ActiveState"] != first["ActiveState"] ||
		next["Result"] != first["Result"] ||
		(failed && (first["ActiveState"] != "failed" || first["Result"] == "success")) ||
		(!failed && (first["ActiveState"] != "inactive" || first["Result"] != "success")) {
		return smartTUNHealthUnitIdentity{}, false, Fault("guard_unavailable", "owned independent executor changed during observation")
	}
	return id, failed, nil
}

func observeSmartTUNIdleRecoveryService() (smartTUNHealthUnitIdentity, bool, error) {
	return observeSmartTUNIdleManagedService(trialRecoveryUnit)
}

func observeSmartTUNIdleHealthService() (smartTUNHealthUnitIdentity, bool, error) {
	return observeSmartTUNIdleManagedService(smartTUNHealthUnit)
}

// A lost journal must not hide an old operation-named product nft table,
// including an otherwise inert orphan that would not collide with the next
// random operation ID. Never adopt or delete an unreceipted object.
func rejectSmartTUNOrphanedTables(rows []map[string]any) error {
	for _, row := range rows {
		table, present := row["table"]
		if !present {
			continue
		}
		fields, ok := table.(map[string]any)
		if !ok {
			return Fault("trial_observation_uncertain", "nft table identity is malformed")
		}
		name, ok := fields["name"].(string)
		if !ok || name == "" {
			return Fault("trial_observation_uncertain", "nft table name is unavailable")
		}
		if strings.HasPrefix(name, "scnt_") {
			return Fault("trial_resource_conflict", "unreconciled native Smart TUN nft table remains")
		}
	}
	return nil
}

// This observes the same pre-Apply native collision boundary without
// creating any TUN, RPDB, route or nftables policy.
func smartTUNVMIdleNativePreflight() error {
	host, err := InspectHostRoutesAndFirewall(smartTUNVMEndpoint, smartTUNVMEndpoint)
	if err != nil {
		return err
	}
	if host.Firewall == nil || !host.Firewall.Observed {
		return Fault("trial_observation_uncertain", "complete nftables observation is required for idle guard reconciliation")
	}
	_, err = nativeTUNAdmission(SmartTUNCandidateOptions{
		TunnelInterface:   smartTUNVMInterface,
		UnderlayInterface: smartTUNVMUnderlay,
		TunnelIPv4:        "172.31.99.1/30",
	}, host)
	if err != nil {
		return err
	}
	before, err := nativeNFTGeneration()
	if err != nil || before == 0 {
		return Fault("trial_observation_uncertain", "native nftables generation is unavailable")
	}
	raw, err := nativeTUNRunNFT(nil, nil, "-n", "-j", "-a", "list", "ruleset")
	if err != nil {
		return err
	}
	rows, err := nativeTUNNftObjects(raw)
	if err != nil {
		return err
	}
	after, err := nativeNFTGeneration()
	if err != nil || before != after {
		return Fault("trial_observation_uncertain", "nftables generation changed during idle observation")
	}
	return rejectSmartTUNOrphanedTables(rows)
}

// ReconcileIdleSmartTUNRecoveryGuard is an explicit operator action, not a
// new-Apply fallback. It only clears systemd FAILED bookkeeping after an
// independent, complete OFF/ownership proof on the named disposable VM.
// The journal lock serializes all product Apply/Off/recovery transitions.
func (m *Manager) ReconcileIdleSmartTUNRecoveryGuard() (SmartTUNIdleGuardReconcileResult, error) {
	var result SmartTUNIdleGuardReconcileResult
	if m.Dir != DefaultDir || m.Core != DefaultCore {
		return result, Fault("trial_unsupported", "installed paths are required for VM guard reconciliation")
	}
	if err := nativeTrialApplyPlatform(); err != nil {
		return result, err
	}
	if err := smartTUNQAVMContext(); err != nil {
		return result, err
	}
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if _, _, err := store.readJournal(); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return Fault("guard_pending", "a pending or prepared journal blocks failed guard reconciliation")
			}
			return err
		}
		if _, _, err := store.readSmartTUNFile(smartTUNTrialConfigFile); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return Fault("trial_resource_conflict", "unreconciled private TUN credential remains")
			}
			return err
		}
		core, err := observeSmartTUNTrialUnit(context.Background())
		if err != nil || !core.stopped() {
			return Fault("guard_unavailable", "owned TUN core is not verifiably inactive")
		}
		_, healthTimer, err := observeSmartTUNHealthUnit(smartTUNHealthTimer)
		if err != nil || healthTimer["ActiveState"] != "inactive" ||
			healthTimer["UnitFileState"] != "disabled" ||
			healthTimer["Result"] != "success" || healthTimer["Unit"] != smartTUNHealthUnit {
			return Fault("guard_unavailable", "health timer must be inactive and disabled")
		}
		_, recoveryTimer, err := observeSmartTUNRecoveryUnit(trialRecoveryTimer)
		if err != nil || recoveryTimer["ActiveState"] != "inactive" ||
			recoveryTimer["UnitFileState"] != "disabled" ||
			recoveryTimer["Result"] != "success" || recoveryTimer["Unit"] != trialRecoveryUnit {
			return Fault("guard_unavailable", "independent recovery timer must be inactive and disabled")
		}
		// Both oneshots can time out under disposable QEMU TCG and become
		// mutually blocking: new Apply cannot normalize Health while Recovery
		// is failed, and the previous recovery-only repair refused failed
		// Health. Prove BOTH are genuinely quiescent before resetting either.
		healthID, healthFailed, err := observeSmartTUNIdleHealthService()
		if err != nil {
			return err
		}
		recoveryID, recoveryFailed, err := observeSmartTUNIdleRecoveryService()
		if err != nil {
			return err
		}
		if err := smartTUNVMIdleNativePreflight(); err != nil {
			return err
		}
		if healthFailed {
			if err := smartTUNTrialSystemctl("reset-failed", smartTUNHealthUnit); err != nil {
				return err
			}
		}
		afterHealth, stillHealthFailed, err := observeSmartTUNIdleHealthService()
		if err != nil || stillHealthFailed || healthID != afterHealth {
			return Fault("guard_unavailable", "owned health executor failed-state reset is not independently verified")
		}
		if recoveryFailed {
			if err := smartTUNTrialSystemctl("reset-failed", trialRecoveryUnit); err != nil {
				return err
			}
		}
		afterRecovery, stillRecoveryFailed, err := observeSmartTUNIdleRecoveryService()
		if err != nil || stillRecoveryFailed || recoveryID != afterRecovery {
			return Fault("guard_unavailable", "owned recovery executor failed-state reset is not independently verified")
		}
		if _, err := smartTUNHealthUnits(false, nil); err != nil {
			return err
		}
		if err := trialGuardUnits(false); err != nil {
			return err
		}
		// Check for journal/native drift after the only authorized bookkeeping changes.
		if err := store.checkTarget(nil); err != nil {
			return err
		}
		if err := smartTUNVMIdleNativePreflight(); err != nil {
			return err
		}
		result = SmartTUNIdleGuardReconcileResult{
			Reconciled: recoveryFailed, HealthReconciled: healthFailed,
			GuardIdleVerified: true, ActivationReady: false,
		}
		return nil
	})
	return result, err
}
