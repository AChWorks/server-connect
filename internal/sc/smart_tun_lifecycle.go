package sc

import (
	"context"
	"crypto/subtle"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Revisions are operation-local, fixed, monotonic transitions. Historical
// v4 deadline recovery remains revision 2; operator-requested recovery uses
// revision 3 so the existing executor can finish that durable Off request.
func smartTUNTrialPhaseRevisionValid(phase string, revision uint64) bool {
	switch phase {
	case "trial_pending":
		return revision == 1
	case "trial_stop_requested":
		return revision == 2
	case "trial_recovered":
		return revision == 2 || revision == 3
	case "trial_cleanup_pending":
		return revision == 4
	}
	return false
}

func validateSmartTUNCleanupKillPoint(point string, disconnect bool) error {
	switch point {
	case "", "after-cleanup-intent", "after-credential-remove", "after-guard-disarm":
		return nil
	case "after-stop-request", "after-stop":
		if disconnect {
			return nil
		}
	}
	return Fault("invalid_arguments", "unsupported disposable TUN lifecycle SIGKILL boundary")
}

// Ownership is independent of readiness. A disabled but exact timer is a
// valid retry state after a cleanup interruption; a mask/drop-in/replacement
// is never authority to disable an arbitrary same-name unit.
func smartTUNTrialTimerState() (bool, error) {
	path := filepath.Join(trialGuardUnitDir, trialRecoveryTimer)
	body, err := readTrustedRootFile(path)
	if err != nil || len(body) == 0 {
		return false, Fault("guard_unavailable", "owned recovery timer is unavailable")
	}
	digest, err := readTrustedRootFile(filepath.Join(managedPrefix, trialRecoveryTimer+".sha256"))
	if err != nil || strings.TrimSpace(string(digest)) != sha256Hex(body) {
		return false, Fault("guard_unavailable", "recovery timer digest conflict")
	}
	if err := trialNoRuntimeUnitOverride(trialRuntimeUnitDir, trialRecoveryTimer); err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, "show", trialRecoveryTimer,
		"-p", "LoadState", "-p", "FragmentPath", "-p", "DropInPaths",
		"-p", "Transient", "-p", "UnitFileState", "-p", "ActiveState", "-p", "Unit")
	if err != nil {
		return false, err
	}
	output, err := cmd.Output()
	if err != nil || ctx.Err() != nil {
		return false, Fault("guard_unavailable", "recovery timer state cannot be observed")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) == 2 {
			fields[pair[0]] = pair[1]
		}
	}
	if fields["LoadState"] != "loaded" || fields["FragmentPath"] != path ||
		fields["DropInPaths"] != "" || fields["Transient"] != "no" ||
		fields["Unit"] != trialRecoveryUnit ||
		(fields["UnitFileState"] != "enabled" && fields["UnitFileState"] != "disabled") ||
		(fields["ActiveState"] != "active" && fields["ActiveState"] != "inactive") {
		return false, Fault("guard_unavailable", "recovery timer ownership or state conflicted")
	}
	return fields["ActiveState"] == "active" || fields["UnitFileState"] == "enabled", nil
}

// Only a durable cleanup intent permits an already absent start credential.
// Neither inactive service nor a matching baseline can substitute for this
// explicit authorization. Tampered present bytes remain a conflict always.
func smartTUNCredentialForCleanupLocked(store *activationJournalDir, record smartTUNTrialJournal) (*activationJournalFileIdentity, error) {
	data, identity, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
	if errors.Is(err, os.ErrNotExist) {
		if record.CoreStartAttempted && record.Phase != "trial_cleanup_pending" {
			return nil, Fault("trial_resource_conflict", "guarded TUN credential disappeared after core start intent")
		}
		return nil, nil
	}
	if err != nil || sha256Hex(data) != record.ConfigSHA256 {
		return nil, Fault("trial_resource_conflict", "guarded TUN credential was replaced or cannot be read")
	}
	return &identity, nil
}

func finalizeSmartTUNTrialLocked(store *activationJournalDir, identity activationJournalFileIdentity, record smartTUNTrialJournal, qaKillPoint string) (SmartTUNTrialReceipt, error) {
	if record.Phase != "trial_recovered" && record.Phase != "trial_cleanup_pending" {
		return SmartTUNTrialReceipt{}, Fault("activation_journal_conflict", "TUN operation has not recovered before cleanup")
	}
	// These phases never start/stop anything: independently verify native
	// Direct baseline again before disarming or discarding any evidence.
	if _, err := recoverSmartTUNTrialLocked(store, identity, record); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if _, err := smartTUNTrialTimerState(); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	credential, err := smartTUNCredentialForCleanupLocked(store, record)
	if err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if record.Phase != "trial_cleanup_pending" {
		// Intent is durable before deletion. After this transition a missing
		// credential is legitimate cleanup, never an unexplained lost secret.
		record.Phase, record.Revision = "trial_cleanup_pending", 4
		if err := writeSmartTUNTrialLocked(store, record, &identity); err != nil {
			return SmartTUNTrialReceipt{}, err
		}
		identity, err = reloadSmartTUNTrialLocked(store, record)
		if err != nil {
			return SmartTUNTrialReceipt{}, err
		}
	}
	if err := trialQAKillAt("after-cleanup-intent", qaKillPoint); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if credential != nil {
		if err := store.removeSmartTUNCredential(*credential, record.ConfigSHA256); err != nil {
			return SmartTUNTrialReceipt{}, err
		}
	} else if err := store.dir.Sync(); err != nil {
		// Retry an uncertain unlink fsync even when the file is absent now.
		return SmartTUNTrialReceipt{}, journalFSUnavailable("cannot persist absent TUN credential")
	}
	if err := trialQAKillAt("after-credential-remove", qaKillPoint); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	// Retain the already-running independent timer until the credential is
	// durably gone and the native baseline still matches. A death before
	// disarm is recoverable by that same executor, without a second service.
	if _, err := recoverSmartTUNTrialLocked(store, identity, record); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if _, err := smartTUNTrialTimerState(); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if err := smartTUNTrialSystemctl("disable", "--now", trialRecoveryTimer); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	armed, err := smartTUNTrialTimerState()
	if err != nil || armed {
		return SmartTUNTrialReceipt{}, Fault("guard_unavailable", "recovery timer disarm was not verified")
	}
	if err := trialQAKillAt("after-guard-disarm", qaKillPoint); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	// SIGKILL in this final interval may leave only a cleanup journal. It
	// requires an exact-operation retry unless an executor was already
	// queued. Networking and credentials are already safely deactivated;
	// do not advertise autonomous finalization after disarming the timer.
	if err := store.removeJournal(identity); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	record.Phase, record.Revision = "trial_cleared", 5
	return smartTUNReceipt(record, false, true), nil
}

func matchingSmartTUNOperation(record smartTUNTrialJournal, operationID string, revision uint64) bool {
	return record.Revision == revision &&
		subtle.ConstantTimeCompare([]byte(record.OperationID), []byte(operationID)) == 1
}

// Explicit Off is a complete operation: request stop durably, contain the
// trusted core, verify exact native restoration and finalize owned state.
// Wrong/replayed IDs and revisions are rejected before even stopping a unit.
func (m *Manager) DisconnectSmartTUNTrial(operationID string, revision uint64, qaKillPoint string) (SmartTUNTrialReceipt, error) {
	if m.Dir != DefaultDir || m.Core != DefaultCore || !journalHex32.MatchString(operationID) || revision < 1 || revision > 4 {
		return SmartTUNTrialReceipt{}, Fault("invalid_arguments", "exact installed TUN operation and current revision required")
	}
	if err := validateSmartTUNCleanupKillPoint(qaKillPoint, true); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if err := trialDisposableContext(); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	var receipt SmartTUNTrialReceipt
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record, identity, err := loadSmartTUNTrialLocked(store)
		if errors.Is(err, os.ErrNotExist) {
			return Fault("activation_journal_conflict", "requested TUN operation is absent or already finalized")
		}
		if err != nil {
			return err
		}
		if !matchingSmartTUNOperation(record, operationID, revision) {
			return Fault("activation_journal_conflict", "nonmatching TUN operation or stale revision")
		}
		if record.Phase == "trial_pending" {
			record.Phase, record.Revision = "trial_stop_requested", 2
			if err := writeSmartTUNTrialLocked(store, record, &identity); err != nil {
				return err
			}
			identity, err = reloadSmartTUNTrialLocked(store, record)
			if err != nil {
				return err
			}
		}
		if err := trialQAKillAt("after-stop-request", qaKillPoint); err != nil {
			return err
		}
		recovered, err := recoverSmartTUNTrialLocked(store, identity, record)
		if err != nil {
			return err
		}
		if err := trialQAKillAt("after-stop", qaKillPoint); err != nil {
			return err
		}
		record.Phase, record.Revision = recovered.Phase, recovered.Revision
		identity, err = reloadSmartTUNTrialLocked(store, record)
		if err != nil {
			return err
		}
		receipt, err = finalizeSmartTUNTrialLocked(store, identity, record, qaKillPoint)
		return err
	})
	return receipt, err
}

func (m *Manager) ClearSmartTUNTrial(operationID string, revision uint64) error {
	return m.ClearSmartTUNTrialWithQAKill(operationID, revision, "")
}

func (m *Manager) ClearSmartTUNTrialWithQAKill(operationID string, revision uint64, qaKillPoint string) error {
	if m.Dir != DefaultDir || m.Core != DefaultCore || !journalHex32.MatchString(operationID) || revision < 2 || revision > 4 {
		return Fault("invalid_arguments", "exact recovered TUN operation and current revision required")
	}
	if err := validateSmartTUNCleanupKillPoint(qaKillPoint, false); err != nil {
		return err
	}
	if err := trialDisposableContext(); err != nil {
		return err
	}
	return m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record, identity, err := loadSmartTUNTrialLocked(store)
		if errors.Is(err, os.ErrNotExist) {
			return Fault("activation_journal_conflict", "requested TUN operation is absent or already finalized")
		}
		if err != nil {
			return err
		}
		if !matchingSmartTUNOperation(record, operationID, revision) ||
			(record.Phase != "trial_recovered" && record.Phase != "trial_cleanup_pending") {
			return Fault("activation_journal_conflict", "cannot clear pending or nonmatching TUN operation")
		}
		_, err = finalizeSmartTUNTrialLocked(store, identity, record, qaKillPoint)
		return err
	})
}
