//go:build linux

package sc

// Explicit root-only INSTALLED host native LINK preparation QA. The selected
// VPN/core is never started and NO host route/rule/nft egress capture or DNS
// is added. The independent systemd Recovery must be armed before the first
// ingress, kernel barrier or persistent TUN link effect is possible.

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"syscall"
)

func newHostNativeLinkPlan(progress hostCaptureGateProgress, tunnel string) (hostNativeJournal, error) {
	i := progress.Ingress
	if !smartTUNDeviceName.MatchString(tunnel) || tunnel == "lo" || tunnel == i.Underlay || tunnel == progress.Barrier.Name {
		return hostNativeJournal{}, Fault("invalid_arguments", "native link name conflicts with host ingress, underlay or loopback")
	}
	r := hostNativeJournal{Version: hostNativeJournalVersion, Intent: hostNativeJournalIntent,
		Progress: progress, TunnelInterface: tunnel,
		Native: smartTUNNativeLedger{
			Version: 1, NamespaceDev: i.NamespaceDev, NamespaceIno: i.NamespaceIno, UnderlayIndex: i.UnderlayIndex,
			LinkStage: "planned", NFTName: "scnt_" + i.OperationID, NFT: smartTUNNativeObject{Stage: "planned"},
			IPv4: nativeTUNPlannedFamily("172.31.99.1/30", nativeTUNTable4),
			IPv6: nativeTUNPlannedFamily("", nativeTUNTable6),
		},
	}
	return r, validateHostNativeJournal(r)
}

func hostNativeLinkPreflight(r hostNativeJournal) error {
	if err := validateHostNativeJournal(r); err != nil {
		return err
	}
	if r.Native.LinkStage != "planned" || r.Progress.Ingress.Phase != "pending" ||
		r.Progress.Barrier.Stage != "planned" || r.Progress.Ingress.NFTStage != "planned" {
		return Fault("trial_unsupported", "host native link QA requires an untouched plan")
	}
	if err := hostNativeCoreIdle(); err != nil {
		return err
	}
	if err := hostNativeCheckNoPolicy(r); err != nil {
		return err
	}
	native := r.nativeView()
	link, err := nativeTUNObserveLink(native)
	if err != nil {
		return err
	}
	if link.Present {
		return Fault("trial_resource_conflict", "native TUN name already occupied")
	}
	// The private fixed link address must not overlap an existing host-owned
	// local address before the exclusive TUN fd is opened.
	rows, err := nativeTUNRows("-j", "address", "show")
	if err != nil {
		return err
	}
	for _, row := range rows {
		var info []map[string]json.RawMessage
		if err := json.Unmarshal(row["addr_info"], &info); err != nil {
			return Fault("trial_observation_uncertain", "host address inventory unavailable")
		}
		for _, item := range info {
			if selectiveText(item["local"]) == "172.31.99.1" {
				return Fault("trial_resource_conflict", "native QA link address is already owned")
			}
		}
	}
	return nil
}

func sameHostNativePrerequisites(a, b hostNativeJournal) bool {
	x, y := a.Progress.Ingress, b.Progress.Ingress
	an, bn := a.Native, b.Native
	// The two admission passes have fresh random operation IDs and therefore
	// different operation-named nft reservations, never equal NFTName strings.
	an.NFTName, bn.NFTName = "", ""
	return a.TunnelInterface == b.TunnelInterface && x.BootID == y.BootID &&
		x.NamespaceDev == y.NamespaceDev && x.NamespaceIno == y.NamespaceIno &&
		x.Underlay == y.Underlay && x.UnderlayIndex == y.UnderlayIndex && x.RawSHA256 == y.RawSHA256 &&
		x.SysctlBefore == y.SysctlBefore && an == bn &&
		a.Progress.Barrier.NamespaceDev == b.Progress.Barrier.NamespaceDev &&
		a.Progress.Barrier.NamespaceIno == b.Progress.Barrier.NamespaceIno
}

func (m *Manager) hostNativeLinkPrerequisites(peer, underlay, tunnel string, deadline int) (hostNativeJournal, error) {
	progress, err := hostCaptureQAPrerequisiteResult(m, peer, underlay, deadline)
	if err != nil {
		return hostNativeJournal{}, err
	}
	r, err := newHostNativeLinkPlan(progress, tunnel)
	if err != nil {
		return hostNativeJournal{}, err
	}
	if err := hostNativeLinkPreflight(r); err != nil {
		return hostNativeJournal{}, err
	}
	return r, nil
}

func hostNativeQAKillAllowed(point string) bool {
	if hostCaptureQAKillValid(point) {
		return true
	}
	return point == "after-native-link-bind" || point == "after-native-persist"
}

func (m *Manager) runHostNativeLinkQAWithPrearm(peer, underlay, tunnel string, deadline int, point string,
	prearm func() error) (HostCapturePreparationQAReceipt, error) {
	receipt := HostCapturePreparationQAReceipt{Phase: "not_started", ExperimentOnly: true, NativeLinkOnly: true}
	if !hostNativeQAKillAllowed(point) {
		return receipt, Fault("invalid_arguments", "unsupported native link QA crash boundary")
	}
	if m == nil || m.Dir != DefaultDir || m.Core != DefaultCore || os.Geteuid() != 0 ||
		deadline < 30 || deadline > 300 || !smartTUNDeviceName.MatchString(underlay) || underlay == "lo" ||
		!smartTUNDeviceName.MatchString(tunnel) || tunnel == "lo" || tunnel == underlay ||
		peer == "" || prearm == nil {
		return receipt, Fault("trial_unsupported", "installed root and explicit disposable host native link parameters required")
	}
	var expected hostNativeJournal
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if _, _, e := store.readJournal(); e == nil {
			return Fault("activation_journal_conflict", "previous activation must be reconciled")
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		var e error
		expected, e = m.hostNativeLinkPrerequisites(peer, underlay, tunnel, deadline)
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
			return Fault("activation_journal_conflict", "another operation appeared while arming recovery")
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if err := trialGuardScheduled(); err != nil {
			return err
		}
		fresh, err := m.hostNativeLinkPrerequisites(peer, underlay, tunnel, deadline)
		if err != nil {
			return err
		}
		if !sameHostNativePrerequisites(expected, fresh) {
			return Fault("trial_observation_uncertain", "native link prerequisites drifted during independent guard prearm")
		}
		if err := writeHostNativeJournal(store, fresh, nil); err != nil {
			return err
		}
		journalPersisted = true
		receipt.OperationID, receipt.Phase = fresh.Progress.Ingress.OperationID, "pending_recovery"
		receipt.GuardScheduled = true
		if err := hostCaptureQAKillAt("after-journal", point); err != nil {
			return err
		}
		if err := runHostCaptureGateLockedWithHook(store, &fresh.Progress, trialGuardScheduled,
			hostNativeCapturePersist(store, &fresh), func(stage string) error { return hostCaptureQAKillAt(stage, point) }); err != nil {
			return err
		}
		if fresh.Progress.Barrier.Stage != "closed" || fresh.Progress.Ingress.NFTStage != "observed" {
			return Fault("trial_recovery_uncertain", "native link ingress/barrier stage incomplete")
		}
		native := fresh.nativeView()
		if err := nativeTUNPrepareLinkWithPersist(store, &native, point, hostNativeLinkPersist(store, &fresh)); err != nil {
			return err
		}
		if fresh.Native.LinkStage != "observed" || fresh.Native.LinkIndex < 2 {
			return Fault("trial_recovery_uncertain", "native TUN link is not durably observed")
		}
		receipt.Phase = "native_link_prepared_pending_independent_recovery"
		receipt.KernelBarrierClosed = true
		return nil
	})
	if err != nil && !journalPersisted {
		m.disarmUncommittedSmartTUNGuard()
	}
	return receipt, err
}

// This is a testable entry with an injected prearm ONLY for source-level
// negative tests; no optional bypass of the installed systemd guard exists.
func (m *Manager) BeginHostNativeLinkPreparationQAWithFault(peer, underlay, tunnel string, deadline int, point string) (HostCapturePreparationQAReceipt, error) {
	return m.runHostNativeLinkQAWithPrearm(peer, underlay, tunnel, deadline, point, func() error {
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

// Disarm only a fully recovered operation whose owner, foreign dependencies,
// core quiescence and exact absent network objects are independently verified.
// A failed verification leaves the recovery timer and parent intact.
func (m *Manager) ClearRecoveredHostNativePreparation(op string) error {
	if m == nil || m.Dir != DefaultDir || m.Core != DefaultCore || os.Geteuid() != 0 || !journalHex32.MatchString(op) {
		return Fault("trial_unsupported", "installed root and exact recovered native link operation required")
	}
	return m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		r, _, err := loadHostNativeJournal(store)
		if err != nil {
			return err
		}
		if r.Progress.Ingress.OperationID != op || r.Native.LinkStage != "removed" ||
			r.Progress.Ingress.Phase != "recovered" {
			return Fault("activation_journal_conflict", "native link operation is not fully recovered")
		}
		if err := hostNativeCoreIdle(); err != nil {
			return err
		}
		boot, err := trialBootIdentity()
		if err != nil {
			return err
		}
		if err := hostNativeVerifyLinkAbsent(r, boot); err != nil {
			return err
		}
		if err := verifyHostNetworkBarrierReleased(r.Progress.Barrier); err != nil {
			return err
		}
		v6 := hostCaptureJournal{Version: hostCaptureJournalVersion, Intent: hostCaptureJournalIntent, Progress: r.Progress}
		if err := verifyHostCapturePreparationOff(v6); err != nil {
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
			return Fault("guard_unavailable", "native link timer disarm unverified; recovered parent retained")
		}
		return clearRecoveredHostNativeLocked(store, op, hostNativeCoreIdle)
	})
}

// Keep one operator clearance command for v6 and v7. The read-only version
// selection is a locator only: each exact operation is reselected and checked
// inside its own uninterrupted write lock before disarming recovery.
func (m *Manager) ClearRecoveredHostPreparation(op string) error {
	status, err := m.InspectActivationJournal()
	if err != nil {
		return err
	}
	if !status.Present || status.OperationID != op || !journalHex32.MatchString(op) {
		return Fault("activation_journal_conflict", "host preparation operation does not match")
	}
	if strings.HasPrefix(status.Phase, "host_native_") {
		return m.ClearRecoveredHostNativePreparation(op)
	}
	if strings.HasPrefix(status.Phase, "host_core_") {
		return m.ClearRecoveredHostCorePreparation(op)
	}
	return m.ClearRecoveredHostCapturePreparation(op)
}
