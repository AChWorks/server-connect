//go:build linux

package sc

// Installed disposable-host core ATTACHMENT QA, not an Apply operation:
// ingress/grace, native persistent TUN and exact selected official sing-box
// core live in one fsynced v8 parent. There is deliberately NO FIB/RPDB/nft
// public capture, DNS rewrite, or independent Runtime Health claim. The
// prearmed independent 5s Recovery immediately stops and reconciles it.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"syscall"
)

type hostCoreQAAdmission struct {
	Native  hostNativeJournal
	Profile Profile
	Policy  []byte
}

func hostCoreQASelectedProfile(m *Manager, store *activationJournalDir, pinned, peer, underlay, tunnel, resolver string, deadline int) (hostCoreQAAdmission, error) {
	refuse := func() (hostCoreQAAdmission, error) {
		return hostCoreQAAdmission{}, Fault("trial_unsupported", "host core attachment QA preconditions not independently verified")
	}
	native, err := m.hostNativeLinkPrerequisites(peer, underlay, tunnel, deadline)
	if err != nil {
		return hostCoreQAAdmission{}, err
	}
	if _, _, err := store.readSmartTUNFile(smartTUNTrialConfigFile); err == nil {
		return hostCoreQAAdmission{}, Fault("activation_journal_conflict", "an unrelated TUN credential already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return hostCoreQAAdmission{}, err
	}
	state, err := m.load()
	if err != nil || state.Selected == "" || state.Desired != "direct" {
		return refuse()
	}
	profile, err := m.profile(state.Selected)
	if err != nil {
		return refuse()
	}
	policy, err := compileHostCoreAttachConfig(profile, pinned, underlay, tunnel)
	if err != nil {
		return hostCoreQAAdmission{}, err
	}
	if err := CheckConfig(m.Core, m.Dir, policy); err != nil {
		return hostCoreQAAdmission{}, err
	}
	report, err := m.InspectSelectedSmartTUNHost(pinned, peer, underlay, resolver, 53)
	if err != nil {
		return hostCoreQAAdmission{}, err
	}
	if !report.ReadOnly || report.ActivationReady || report.GeneralHostAdmitted ||
		report.SelectedTransport != "ws" || report.DNS != "pinned_resolver_observed" ||
		report.TCP != "bound_tcp_connected" || report.HostRoutes != "endpoint_and_management_on_expected_underlay" ||
		report.NativeNFT != "ruleset_observed" || report.ProxyOnly != "inactive_observed" ||
		len(report.Reasons) != 1 || report.Reasons[0] != "general_host_admission_not_implemented" {
		return refuse()
	}
	final, err := m.load()
	if err != nil || final != state {
		return refuse()
	}
	finalProfile, err := m.profile(final.Selected)
	if err != nil || !reflect.DeepEqual(profile, finalProfile) {
		return refuse()
	}
	return hostCoreQAAdmission{Native: native, Profile: profile, Policy: policy}, nil
}

func hostCoreQAKillAllowed(point string) bool {
	return hostNativeQAKillAllowed(point) || point == "after-core-credential" || point == "after-core-start" || point == "after-core-attached"
}

func (m *Manager) runHostCoreQAWithPrearm(peer, underlay, tunnel, pinned, resolver string, deadline int, point string, prearm func() error) (HostCapturePreparationQAReceipt, error) {
	receipt := HostCapturePreparationQAReceipt{Phase: "not_started", ExperimentOnly: true, NativeLinkOnly: true}
	if !hostCoreQAKillAllowed(point) {
		return receipt, Fault("invalid_arguments", "unsupported host core QA crash boundary")
	}
	if m == nil || m.Dir != DefaultDir || m.Core != DefaultCore || os.Geteuid() != 0 ||
		deadline < 30 || deadline > 300 || !smartTUNDeviceName.MatchString(underlay) ||
		!smartTUNDeviceName.MatchString(tunnel) || tunnel == underlay || tunnel == "lo" || underlay == "lo" ||
		peer == "" || resolver == "" || pinned == "" || prearm == nil {
		return receipt, Fault("trial_unsupported", "installed root, pinned endpoint, explicit source and disposable host required")
	}
	var expected hostCoreQAAdmission
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if _, _, err := store.readJournal(); err == nil {
			return Fault("activation_journal_conflict", "existing activation journal must be reconciled")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		var err error
		expected, err = hostCoreQASelectedProfile(m, store, pinned, peer, underlay, tunnel, resolver, deadline)
		return err
	})
	if err != nil {
		return receipt, err
	}
	if err := prearm(); err != nil {
		return receipt, err
	}
	journalPersisted := false
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if _, _, err := store.readJournal(); err == nil {
			return Fault("activation_journal_conflict", "another activation journal arrived during guard prearm")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := trialGuardScheduled(); err != nil {
			return err
		}
		actual, err := hostCoreQASelectedProfile(m, store, pinned, peer, underlay, tunnel, resolver, deadline)
		if err != nil {
			return err
		}
		if !sameHostNativePrerequisites(expected.Native, actual.Native) ||
			!reflect.DeepEqual(expected.Profile, actual.Profile) || !bytes.Equal(expected.Policy, actual.Policy) {
			return Fault("trial_observation_uncertain", "selected profile, routing controls or kernel baseline drifted during guard prearm")
		}
		native := actual.Native
		native.Version, native.Intent = hostCoreJournalVersion, hostCoreJournalIntent
		record := hostCoreJournal{hostNativeJournal: native, Core: hostCoreLedger{
			ProfileID: actual.Profile.ID, ConfigSHA256: sha256Hex(actual.Policy),
			PinnedEndpoint: pinned, Stage: "planned",
		}}
		if err := writeHostCoreJournal(store, record, nil); err != nil {
			return err
		}
		journalPersisted = true
		receipt.OperationID, receipt.Phase = record.Progress.Ingress.OperationID, "pending_recovery"
		receipt.GuardScheduled = true
		if err := hostCaptureQAKillAt("after-journal", point); err != nil {
			return err
		}
		if err := runHostCaptureGateLockedWithHook(store, &record.Progress, trialGuardScheduled,
			hostCoreCapturePersist(store, &record), func(stage string) error { return hostCaptureQAKillAt(stage, point) }); err != nil {
			return err
		}
		nativeView := record.nativeBase().nativeView()
		if err := nativeTUNPrepareLinkWithPersist(store, &nativeView, point, hostCoreNativePersist(store, &record)); err != nil {
			return err
		}
		if record.Native.LinkStage != "observed" || record.Native.LinkIndex < 2 {
			return Fault("trial_recovery_uncertain", "core preparation native link receipt absent")
		}
		if err := hostCoreAdvance(store, &record, "credential_possible"); err != nil {
			return err
		}
		if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, actual.Policy, nil); err != nil {
			return err
		}
		if err := hostCoreAdvance(store, &record, "credential_staged"); err != nil {
			return err
		}
		if err := hostCaptureQAKillAt("after-core-credential", point); err != nil {
			return err
		}
		watch, err := nativeTUNWatchStart(record.nativeBase().nativeView())
		if err != nil {
			return err
		}
		defer watch.close()
		if err := hostCoreAdvance(store, &record, "start_requested"); err != nil {
			return err
		}
		if err := smartTUNTrialSystemctl("start", smartTUNTrialUnit); err != nil {
			return Fault("trial_pending_recovery", "core start failed after durable v8 start authority; independent recovery owns Off")
		}
		if err := hostCaptureQAKillAt("after-core-start", point); err != nil {
			return err
		}
		if err := watch.verify(record.nativeBase().nativeView()); err != nil {
			return err
		}
		unit, err := observeSmartTUNTrialUnit(context.Background())
		if err != nil || unit.activeState != "active" || unit.mainPID == 0 || unit.subState != "running" {
			return Fault("trial_recovery_uncertain", "official core not independently observed attached and active")
		}
		if err := hostCoreAdvance(store, &record, "active_observed"); err != nil {
			return err
		}
		if err := hostCaptureQAKillAt("after-core-attached", point); err != nil {
			return err
		}
		receipt.Phase, receipt.CoreAttached, receipt.KernelBarrierClosed = "core_attached_pending_independent_recovery", true, true
		return nil
	})
	if err != nil && !journalPersisted {
		m.disarmUncommittedSmartTUNGuard()
	}
	return receipt, err
}

func (m *Manager) BeginHostCorePreparationQAWithFault(peer, underlay, tunnel, pinned, resolver string, deadline int, point string) (HostCapturePreparationQAReceipt, error) {
	return m.runHostCoreQAWithPrearm(peer, underlay, tunnel, pinned, resolver, deadline, point, func() error {
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
