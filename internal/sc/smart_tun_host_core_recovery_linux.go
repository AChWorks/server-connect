//go:build linux

package sc

// Strict v8 core-first recovery. A durable systemd start intent and an exact
// private credential are the ONLY authority to stop the pinned native unit.
// The core is quiescent before any native link or host ingress rollback.
import (
	"context"
	"os"
	"syscall"
)

type hostCoreRecoveryServices struct {
	observe func() (smartTUNTrialUnitObservation, error)
	stop    func(smartTUNTrialUnitObservation, bool, bool) error
}

func defaultHostCoreRecoveryServices() hostCoreRecoveryServices {
	return hostCoreRecoveryServices{
		observe: func() (smartTUNTrialUnitObservation, error) { return observeSmartTUNTrialUnit(context.Background()) },
		stop:    stopSmartTUNTrialCore,
	}
}

func hostCoreStopLocked(store *activationJournalDir, r *hostCoreJournal, services hostCoreRecoveryServices) error {
	if r == nil {
		return Fault("guard_unavailable", "independent core parent missing")
	}
	if err := validateHostCoreJournal(*r); err != nil {
		return err
	}
	return hostCoreStopWith(store, &r.Core, func(stage string) error { return hostCoreAdvance(store, r, stage) }, services)
}

// Both v8 and v9 call this exact core-first, no-adoption recovery protocol.
// Its injected stage writer MUST fsync a full enclosing parent before any
// systemd action or credential unlink; the caller holds the journal lock.
func hostCoreStopWith(store *activationJournalDir, core *hostCoreLedger, advance func(string) error, services hostCoreRecoveryServices) error {
	if store == nil || core == nil || advance == nil || services.observe == nil || services.stop == nil {
		return Fault("guard_unavailable", "independent core recovery requires owned unit and parent writer")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	digest := core.ConfigSHA256
	if !journalHex64.MatchString(digest) {
		return Fault("trial_resource_conflict", "invalid owned core credential fingerprint")
	}

	observed, err := services.observe()
	if err != nil {
		return err
	}
	present, _, err := hostCoreCredentialMatch(store, digest)
	if err != nil {
		return err
	}
	if core.Stage == "stopped" {
		if !observed.stopped() || present {
			return Fault("trial_recovery_uncertain", "stopped core still active or credential retained")
		}
		return nil
	}
	if core.Stage == "planned" && present {
		return Fault("trial_resource_conflict", "core credential appeared before any write intent")
	}
	// A durable credential-remove intent can survive a SIGKILL between
	// unlink and terminal fsync. Such an operation must still independently
	// prove this very unit is stopped before treating absence as clean.
	if core.Stage == "credential_remove_requested" {
		if !observed.stopped() {
			return Fault("trial_recovery_uncertain", "credential retirement not yet quiescent")
		}
		if present {
			if err := hostCoreRemoveCredentialDigest(store, digest); err != nil {
				return err
			}
		}
		if still, _, err := hostCoreCredentialMatch(store, digest); err != nil || still {
			return Fault("trial_recovery_uncertain", "retired core credential reappeared or is ambiguous")
		}
		return advance("stopped")
	}
	if core.StartAttempted && !present {
		return Fault("trial_resource_conflict", "core was started without its recorded trusted credential")
	}
	if core.Stage == "credential_staged" && !present {
		return Fault("trial_resource_conflict", "durably staged core credential disappeared")
	}
	// A missing start intent forbids even an apparently safe systemctl stop:
	// external actors might own the active TUN service. No cleanup until idle.
	if !core.StartAttempted && !observed.stopped() {
		return Fault("trial_resource_conflict", "unowned core activity without a durable start intent")
	}
	if core.StartAttempted {
		if core.Stage != "stop_requested" {
			if err := advance("stop_requested"); err != nil {
				return err
			}
		}
		if err := services.stop(observed, true, present); err != nil {
			return err
		}
	}
	after, err := services.observe()
	if err != nil {
		return err
	}
	if !after.stopped() || after.identity != observed.identity {
		return Fault("trial_recovery_uncertain", "core identity changed or remained active after stop")
	}
	// A durable effect intent precedes unlink, so a SIGKILL after unlink
	// cannot manufacture an unowned missing-credential conflict.
	if err := advance("credential_remove_requested"); err != nil {
		return err
	}
	if err := hostCoreRemoveCredentialDigest(store, digest); err != nil {
		return err
	}
	if still, _, err := hostCoreCredentialMatch(store, digest); err != nil || still {
		return Fault("trial_recovery_uncertain", "core credential removal not independently observed")
	}
	return advance("stopped")
}

func recoverHostCoreJournalLocked(store *activationJournalDir, r *hostCoreJournal, services hostCoreRecoveryServices) (TrialReceipt, error) {
	if r == nil {
		return TrialReceipt{}, Fault("guard_unavailable", "missing v8 parent")
	}
	receipt := TrialReceipt{OperationID: r.Progress.Ingress.OperationID, Phase: "host_core_uncertain", ExperimentOnly: true}
	if err := validateHostCoreJournal(*r); err != nil {
		return receipt, err
	}
	if err := hostCoreStopLocked(store, r, services); err != nil {
		return receipt, err
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return receipt, err
	}
	base := r.nativeBase()
	if boot == r.Progress.Ingress.BootID {
		if err := hostNativeRemoveLinkWithPersist(store, &base, hostCoreNativePersist(store, r)); err != nil {
			return receipt, err
		}
	} else {
		if err := hostNativeOldBootLinkAbsent(base); err != nil {
			return receipt, err
		}
		next := *r
		next.Native.LinkStage = "removed"
		if err := persistHostCoreParent(store, r, next); err != nil {
			return receipt, err
		}
	}
	if err := hostNativeVerifyLinkAbsent(r.nativeBase(), boot); err != nil {
		return receipt, err
	}
	result, err := recoverHostCaptureGateLocked(store, &r.Progress, hostCoreCapturePersist(store, r))
	if err != nil {
		return receipt, err
	}
	if !result.RecoveryVerified {
		return receipt, Fault("trial_recovery_uncertain", "core parent ingress rollback unverified")
	}
	if err := hostNativeVerifyLinkAbsent(r.nativeBase(), boot); err != nil {
		return receipt, err
	}
	receipt.Phase, receipt.RecoveryVerified = "host_core_recovered", true
	return receipt, nil
}

// Only independently recovered v8 journals may be cleared. Installed
// systemd disarm is performed by the existing manager before this locked
// primitive runs, never inferred from an in-memory success flag.
func clearRecoveredHostCoreLocked(store *activationJournalDir, op string, services hostCoreRecoveryServices) error {
	if !journalHex32.MatchString(op) || store == nil || services.observe == nil {
		return Fault("invalid_arguments", "exact v8 operation and trusted idle observer required")
	}
	r, id, err := loadHostCoreJournal(store)
	if err != nil {
		return err
	}
	if r.Progress.Ingress.OperationID != op || r.Progress.Ingress.Phase != "recovered" ||
		r.Native.LinkStage != "removed" || r.Core.Stage != "stopped" {
		return Fault("activation_journal_conflict", "v8 operation not fully independently recovered")
	}
	unit, err := services.observe()
	if err != nil {
		return err
	}
	if !unit.stopped() {
		return Fault("trial_recovery_uncertain", "core is not quiescent at exact clear")
	}
	if exists, _, err := hostCoreCredentialState(store, r); err != nil || exists {
		return Fault("trial_resource_conflict", "core credential still exists or cannot be inspected")
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return err
	}
	if err := hostNativeVerifyLinkAbsent(r.nativeBase(), boot); err != nil {
		return err
	}
	if err := verifyHostNetworkBarrierReleased(r.Progress.Barrier); err != nil {
		return err
	}
	if err := verifyHostCapturePreparationOff(hostCaptureJournal{Version: hostCaptureJournalVersion, Intent: hostCaptureJournalIntent, Progress: r.Progress}); err != nil {
		return err
	}
	latest, current, err := loadHostCoreJournal(store)
	if err != nil {
		return err
	}
	if current != id || latest != r {
		return Fault("activation_journal_conflict", "v8 parent changed before terminal clear")
	}
	return store.removeJournal(current)
}

// Statically ensure exact absent credential on recovered journals. Missing
// credentials from another operation are never treated as ours to rewrite.

// Externally visible completion still requires the existing exact
// independently armed systemd Recovery timer, not a presumed successful
// process return or a sticky in-memory flag.
func (m *Manager) ClearRecoveredHostCorePreparation(op string) error {
	if m == nil || m.Dir != DefaultDir || m.Core != DefaultCore || os.Geteuid() != 0 || !journalHex32.MatchString(op) {
		return Fault("trial_unsupported", "installed root and exact recovered v8 operation required")
	}
	return m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		r, _, err := loadHostCoreJournal(store)
		if err != nil {
			return err
		}
		if r.Progress.Ingress.OperationID != op || r.Progress.Ingress.Phase != "recovered" ||
			r.Native.LinkStage != "removed" || r.Core.Stage != "stopped" {
			return Fault("activation_journal_conflict", "host core operation is not independently recovered")
		}
		if err := hostNativeCoreIdle(); err != nil {
			return err
		}
		if exists, _, err := hostCoreCredentialState(store, r); err != nil || exists {
			return Fault("trial_resource_conflict", "host core credential still exists or is ambiguous")
		}
		boot, err := trialBootIdentity()
		if err != nil {
			return err
		}
		if err := hostNativeVerifyLinkAbsent(r.nativeBase(), boot); err != nil {
			return err
		}
		if err := verifyHostNetworkBarrierReleased(r.Progress.Barrier); err != nil {
			return err
		}
		if err := verifyHostCapturePreparationOff(hostCaptureJournal{Version: hostCaptureJournalVersion, Intent: hostCaptureJournalIntent, Progress: r.Progress}); err != nil {
			return err
		}
		if _, err := smartTUNTrialTimerState(); err != nil {
			return err
		}
		if err := smartTUNTrialSystemctl("disable", "--now", trialRecoveryTimer); err != nil {
			return err
		}
		if armed, err := smartTUNTrialTimerState(); err != nil || armed {
			return Fault("guard_unavailable", "host core timer disarm unverified; parent retained")
		}
		return clearRecoveredHostCoreLocked(store, op, defaultHostCoreRecoveryServices())
	})
}
