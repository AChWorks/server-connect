//go:build linux

package sc

// The installed independent executor can decode/recover v9 even though
// general-host routed Apply remains disabled. This is the same core-first
// exact-resource recovery graph as the native experiment, with one fsynced
// parent and with ingress/grace held until every routed object is gone.

import (
	"os"
	"syscall"
)

func recoverHostRouteJournalLocked(store *activationJournalDir, r *hostRouteJournal, services hostCoreRecoveryServices) (TrialReceipt, error) {
	if store == nil || r == nil {
		return TrialReceipt{}, Fault("guard_unavailable", "host routed parent missing")
	}
	receipt := TrialReceipt{OperationID: r.Progress.Ingress.OperationID, Phase: "host_route_uncertain", ExperimentOnly: true}
	if err := validateHostRouteJournal(*r); err != nil {
		return receipt, err
	}
	if r.Route.State == "removed" {
		if err := hostRouteVerifyOff(store, *r, services); err != nil {
			return receipt, err
		}
		receipt.Phase, receipt.RecoveryVerified = "host_route_recovered", true
		return receipt, nil
	}
	// Containment stays installed while the independently owned Core is
	// stopped and while each route/rule is removed. A durable off intent
	// excludes any competing Apply under the same journal flock.
	if r.Route.State != "off_pending" {
		if err := hostRoutePhasePersist(store, r, "off_pending"); err != nil {
			return receipt, err
		}
	}
	if err := hostCoreStopWith(store, &r.Core, func(stage string) error { return hostRouteCoreStagePersist(store, r, stage) }, services); err != nil {
		return receipt, err
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return receipt, err
	}
	if boot != r.Progress.Ingress.BootID {
		// Across a reboot no previous object handle/index is deletion authority.
		if err := hostNativeOldBootLinkAbsent(r.coreWithoutPolicy().nativeBase()); err != nil {
			return receipt, err
		}
		next := *r
		next.Native.LinkStage = "removed"
		next.Native.NFT.Stage = "removed"
		for _, f := range []*smartTUNNativeFamily{&next.Native.IPv4, &next.Native.IPv6} {
			if f.Address == "" {
				continue
			}
			f.Rule.Stage = "removed"
			f.Route.Stage = "removed"
			f.Fallback.Stage = "removed"
		}
		if err := persistHostRouteParent(store, r, next); err != nil {
			return receipt, err
		}
	} else {
		native := r.nativeView()
		if err := nativeTUNCheckRecoveryGraph(native); err != nil {
			return receipt, err
		}
		for _, family := range []int{4, 6} {
			if nativeFamily(native.Native, family).Address == "" {
				continue
			}
			for _, kind := range []string{"rule", "route", "fallback"} {
				if err := nativeTUNRemoveResourceWithPersist(store, &native, family, kind, "", hostRouteNativePersist(store, r)); err != nil {
					return receipt, err
				}
			}
		}
		if err := nativeTUNRemoveLinkWithPersist(store, &native, "", hostRouteNativePersist(store, r)); err != nil {
			return receipt, err
		}
		if err := nativeTUNRemoveNFTWithPersist(store, &native, "", hostRouteNativePersist(store, r)); err != nil {
			return receipt, err
		}
	}
	if err := hostRouteKernelPolicyAbsent(*r, boot); err != nil {
		return receipt, err
	}
	result, err := recoverHostCaptureGateLocked(store, &r.Progress, hostRouteCapturePersist(store, r))
	if err != nil {
		return receipt, err
	}
	if !result.RecoveryVerified {
		return receipt, Fault("trial_recovery_uncertain", "host routed ingress recovery not independently verified")
	}
	if err := hostRoutePhasePersist(store, r, "removed"); err != nil {
		return receipt, err
	}
	if err := hostRouteVerifyOff(store, *r, services); err != nil {
		return receipt, err
	}
	receipt.Phase, receipt.RecoveryVerified = "host_route_recovered", true
	return receipt, nil
}

func hostRouteKernelPolicyAbsent(r hostRouteJournal, boot string) error {
	// Do not accept an old-boot index as current authority. All objects must
	// be absent even for exact names before clearing persisted progress.
	if boot != r.Progress.Ingress.BootID {
		return hostNativeOldBootLinkAbsent(r.coreWithoutPolicy().nativeBase())
	}
	if !hostRouteOffEffects(r.Native) {
		return Fault("trial_recovery_uncertain", "host routed kernel stages not retired")
	}
	if err := hostNativeCheckNoPolicy(r.coreWithoutPolicy().nativeBase()); err != nil {
		return err
	}
	link, err := nativeTUNObserveLink(r.nativeView())
	if err != nil {
		return err
	}
	if link.Present {
		return Fault("trial_resource_conflict", "host routed TUN link remains")
	}
	return nil
}

func hostRouteVerifyOff(store *activationJournalDir, r hostRouteJournal, services hostCoreRecoveryServices) error {
	if r.Route.State != "removed" || r.Core.Stage != "stopped" || r.Progress.Ingress.Phase != "recovered" {
		return Fault("trial_recovery_uncertain", "host routed operation not terminal")
	}
	if services.observe == nil {
		return Fault("guard_unavailable", "host routed unit observer absent")
	}
	unit, err := services.observe()
	if err != nil {
		return err
	}
	if !unit.stopped() {
		return Fault("trial_recovery_uncertain", "host routed core remains active")
	}
	if present, _, err := hostCoreCredentialMatch(store, r.Core.ConfigSHA256); err != nil || present {
		return Fault("trial_resource_conflict", "host routed credential not verifiably absent")
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return err
	}
	if err := hostRouteKernelPolicyAbsent(r, boot); err != nil {
		return err
	}
	if err := verifyHostNetworkBarrierReleased(r.Progress.Barrier); err != nil {
		return err
	}
	return verifyHostCapturePreparationOff(hostCaptureJournal{Version: hostCaptureJournalVersion, Intent: hostCaptureJournalIntent, Progress: r.Progress})
}

func clearRecoveredHostRouteLocked(store *activationJournalDir, op string, services hostCoreRecoveryServices) error {
	if store == nil || !journalHex32.MatchString(op) {
		return Fault("invalid_arguments", "exact host route operation required")
	}
	r, id, err := loadHostRouteJournal(store)
	if err != nil {
		return err
	}
	if r.Progress.Ingress.OperationID != op {
		return Fault("activation_journal_conflict", "host route operation identity changed")
	}
	if err := hostRouteVerifyOff(store, r, services); err != nil {
		return err
	}
	latest, current, err := loadHostRouteJournal(store)
	if err != nil {
		return err
	}
	if current != id || latest != r {
		return Fault("activation_journal_conflict", "host routed parent changed before clear")
	}
	return store.removeJournal(current)
}

// No broad policy Apply CLI is exposed. An exact recovered operation must
// nevertheless be clearable after an interrupted isolated experiment.
func (m *Manager) ClearRecoveredHostRoutePreparation(op string) error {
	if m == nil || m.Dir != DefaultDir || m.Core != DefaultCore || os.Geteuid() != 0 || !journalHex32.MatchString(op) {
		return Fault("trial_unsupported", "installed root and exact recovered host route operation required")
	}
	return m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		r, _, err := loadHostRouteJournal(store)
		if err != nil {
			return err
		}
		if r.Progress.Ingress.OperationID != op {
			return Fault("activation_journal_conflict", "host routed operation mismatch")
		}
		if err := hostRouteVerifyOff(store, r, defaultHostCoreRecoveryServices()); err != nil {
			return err
		}
		if _, err := smartTUNTrialTimerState(); err != nil {
			return err
		}
		if err := smartTUNTrialSystemctl("disable", "--now", trialRecoveryTimer); err != nil {
			return err
		}
		armed, err := smartTUNTrialTimerState()
		if err != nil || armed {
			return Fault("guard_unavailable", "host routed timer disarm unverified")
		}
		return clearRecoveredHostRouteLocked(store, op, defaultHostCoreRecoveryServices())
	})
}
