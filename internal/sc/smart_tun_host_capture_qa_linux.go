//go:build linux

package sc

// This is an explicit, installed, root-only host-capture PREPARATION QA
// transaction. It does not start a TUN or core, install host routing, configure
// DNS, or authorize general-host Smart Routing Apply. It exists to exercise the
// same independent v6 journal and systemd recovery used by the actual installed
// manager on an explicitly disposable host. A failed/aborted staging operation
// MUST retain the journal for the independent recovery executor.

import (
	"errors"
	"os"
	"syscall"
)

type HostCapturePreparationQAReceipt struct {
	OperationID         string `json:"operation_id,omitempty"`
	Phase               string `json:"phase"`
	ExperimentOnly      bool   `json:"experiment_only"`
	GuardScheduled      bool   `json:"guard_scheduled"`
	ActivationReady     bool   `json:"activation_ready"`
	KernelBarrierClosed bool   `json:"kernel_barrier_closed"`
	RecoveryVerified    bool   `json:"recovery_verified"`
}

func hostCaptureQAPrerequisiteResult(m *Manager, peer, underlay string, deadline int) (hostCaptureGateProgress, error) {
	if m == nil || m.Dir != DefaultDir || m.Core != DefaultCore || os.Geteuid() != 0 ||
		deadline < 30 || deadline > 300 {
		return hostCaptureGateProgress{}, Fault("trial_unsupported", "installed root QA and deadline 30-300 seconds required")
	}
	target, err := currentInstallerHostTarget()
	if err != nil || (target != "debian-12-amd64" && target != "debian-13-amd64") {
		return hostCaptureGateProgress{}, Fault("trial_unsupported", "host capture QA requires supported disposable Debian host")
	}
	if _, err := observeGeneralHostSSHPath(peer, underlay); err != nil {
		return hostCaptureGateProgress{}, err
	}
	state, err := m.load()
	if err != nil || state.Desired != "direct" {
		return hostCaptureGateProgress{}, Fault("service_conflict", "host capture QA requires Direct mode")
	}
	proxyState, err := m.unitActive()
	if err != nil || proxyState != "inactive" {
		return hostCaptureGateProgress{}, Fault("service_conflict", "host capture QA requires idle Proxy Only")
	}
	nativeState, err := smartTUNTrialUnitState()
	if err != nil || nativeState != "inactive" {
		return hostCaptureGateProgress{}, Fault("service_conflict", "host capture QA requires inactive native TUN core")
	}
	progress, err := newHostCaptureGateProgress(underlay, deadline)
	if err != nil {
		return hostCaptureGateProgress{}, err
	}
	if err := hostIngressMarkBoundary(progress.Ingress); err != nil {
		return hostCaptureGateProgress{}, err
	}
	if err := observeReservedHostSocketMarks(); err != nil {
		return hostCaptureGateProgress{}, err
	}
	return progress, nil
}

// runHostCaptureQAWithPrearm uses a deterministic external guard-prearm seam
// for negative testing, but all native effects are still behind the one
// strict installed journal lock, whole-record CAS and independent executor.
func (m *Manager) runHostCaptureQAWithPrearm(peer, underlay string, deadline int,
	prearm func() error) (HostCapturePreparationQAReceipt, error) {
	receipt := HostCapturePreparationQAReceipt{Phase: "not_started", ExperimentOnly: true}
	// Malformed or uninstalled invocation must never create even a private
	// journal lock, let alone arm independent systemd or touch the kernel.
	if m == nil || m.Dir != DefaultDir || m.Core != DefaultCore || os.Geteuid() != 0 ||
		deadline < 30 || deadline > 300 || !smartTUNDeviceName.MatchString(underlay) ||
		underlay == "lo" || peer == "" {
		return receipt, Fault("trial_unsupported", "host capture QA requires root installed paths, peer, underlay and bounded deadline")
	}
	if prearm == nil {
		return receipt, Fault("guard_unavailable", "independent prearm is required")
	}
	// All expensive host observations and the journal-absence check precede
	// *any* systemd action. A second admission after prearm catches drift.
	var expected hostCaptureGateProgress
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if _, _, e := store.readJournal(); e == nil {
			return Fault("activation_journal_conflict", "existing activation operation must recover first")
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		var e error
		expected, e = hostCaptureQAPrerequisiteResult(m, peer, underlay, deadline)
		return e
	})
	if err != nil {
		return receipt, err
	}
	if err := prearm(); err != nil {
		return receipt, err
	}
	journalPersisted := false
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if _, _, e := store.readJournal(); e == nil {
			return Fault("activation_journal_conflict", "another activation operation was published while prearming")
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if err := trialGuardScheduled(); err != nil {
			return err
		}
		fresh, err := hostCaptureQAPrerequisiteResult(m, peer, underlay, deadline)
		if err != nil {
			return err
		}
		// Deadline and random operation identity are intentionally fresh, but
		// preexisting foreign raw, boot, network namespace and underlay must
		// not change under the independently armed recovery timer.
		if fresh.Ingress.BootID != expected.Ingress.BootID ||
			fresh.Ingress.NamespaceDev != expected.Ingress.NamespaceDev ||
			fresh.Ingress.NamespaceIno != expected.Ingress.NamespaceIno ||
			fresh.Ingress.UnderlayIndex != expected.Ingress.UnderlayIndex ||
			fresh.Ingress.RawSHA256 != expected.Ingress.RawSHA256 ||
			fresh.Ingress.SysctlBefore != expected.Ingress.SysctlBefore {
			return Fault("trial_observation_uncertain", "host capture prerequisites changed while prearming")
		}
		record := hostCaptureJournal{Version: hostCaptureJournalVersion, Intent: hostCaptureJournalIntent, Progress: fresh}
		if err := writeHostCaptureJournal(store, record, nil); err != nil {
			return err
		}
		journalPersisted = true
		receipt.OperationID, receipt.Phase = fresh.Ingress.OperationID, "pending_recovery"
		receipt.GuardScheduled = true
		if err := runHostCaptureGateLocked(store, &record.Progress, trialGuardScheduled,
			hostCaptureJournalPersist(store, &record)); err != nil {
			return err
		}
		if record.Progress.Barrier.Stage != "closed" || record.Progress.Ingress.NFTStage != "observed" {
			return Fault("trial_observation_uncertain", "host capture preparation not completely observed")
		}
		receipt.Phase = "prepared_pending_independent_recovery"
		receipt.KernelBarrierClosed = true
		return nil
	})
	if !journalPersisted {
		// Safe only after rechecking exact journal absence and core quiescence;
		// never disarm the other operation's timer on an uncertain write.
		m.disarmUncommittedSmartTUNGuard()
	}
	return receipt, err
}

// BeginHostCapturePreparationQA is an intentionally narrow public QA entry.
// The caller's explicit disposable acknowledgement is validated by the CLI;
// authority must never be derived from an environment variable or a README.
func (m *Manager) BeginHostCapturePreparationQA(peer, underlay string, deadline int) (HostCapturePreparationQAReceipt, error) {
	return m.runHostCaptureQAWithPrearm(peer, underlay, deadline, func() error {
		if err := trialGuardUnits(false); err != nil {
			return err
		}
		if err := smartTUNTrialSystemctl("start", trialRecoveryUnit); err != nil {
			return err
		}
		if err := smartTUNTrialSystemctl("enable", "--now", trialRecoveryTimer); err != nil {
			m.disarmUncommittedSmartTUNGuard()
			return err
		}
		if err := trialGuardScheduled(); err != nil {
			m.disarmUncommittedSmartTUNGuard()
			return err
		}
		return nil
	})
}
