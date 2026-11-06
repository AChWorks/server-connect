//go:build linux

package sc

// Root-only kernel acceptance in a disposable unshared network namespace.
// The core unit is simulated to isolate the policy ledger/rollback; this
// test cannot authorize general-host Apply or claim actual VPN delivery.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
)

func hostRouteKernelReady(t *testing.T, store *activationJournalDir, r *hostRouteJournal, guard func() error, secret []byte) error {
	t.Helper()
	if err := writeHostRouteJournal(store, *r, nil); err != nil {
		return err
	}
	if err := runHostCaptureGateLocked(store, &r.Progress, guard, hostRouteCapturePersist(store, r)); err != nil {
		return err
	}
	native := r.nativeView()
	if err := nativeTUNPrepareLinkWithPersist(store, &native, "", hostRouteNativePersist(store, r)); err != nil {
		return err
	}
	for _, stage := range []string{"credential_possible", "credential_staged", "start_requested", "active_observed"} {
		if stage == "credential_staged" {
			if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, secret, nil); err != nil {
				return err
			}
		}
		if err := hostRouteCoreStagePersist(store, r, stage); err != nil {
			return err
		}
	}
	return hostRoutePhasePersist(store, r, "effect_possible")
}

func hostRouteKernelExample(t *testing.T) hostRouteJournal {
	t.Helper()
	v7 := hostNativeExample()
	v7.Version, v7.Intent = hostRouteJournalVersion, hostRouteJournalIntent
	r := hostRouteJournal{hostCoreJournal: hostCoreJournal{hostNativeJournal: v7, Core: hostCoreLedger{
		ProfileID: "abcdef0123456789", ConfigSHA256: sha256Hex([]byte(`{"simulated":"host-route-v9"}`)),
		PinnedEndpoint: "8.8.8.8", Stage: "planned",
	}}, Route: hostRouteStage{State: "planned"}}
	raw, err := nativeNFTCreateJSON(r.nativeView())
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = sha256Hex(raw)
	return r
}

func TestHostRouteV9RealKernelOwnedPolicyAndCoreFirstOff(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_ROUTE_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: isolated root netns required")
	}
	guard, base := prepareHostNativeKernelFixture(t)
	before := hostNativeKernelSnapshot(t)
	r := hostRouteKernelExample(t)
	r.Progress = base.Progress
	r.Native = base.Native
	r.Native.NFTName = "scnt_" + r.Progress.Ingress.OperationID
	program, err := nativeNFTCreateJSON(r.nativeView())
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = sha256Hex(program)
	if err := validateHostRouteJournal(r); err != nil {
		t.Fatal(err)
	}
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	secret := []byte(`{"simulated":"host-route-v9"}`)
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := hostRouteKernelReady(t, store, &r, guard, secret); err != nil {
			return err
		}
		native := r.nativeView()
		if err := nativeTUNApplyPolicyWithPersist(store, &native, "", hostRouteNativePersist(store, &r)); err != nil {
			return err
		}
		if err := hostRoutePhasePersist(store, &r, "observed"); err != nil {
			return err
		}
		if r.Route.State != "observed" || r.Native.NFT.Stage != "observed" || r.Native.IPv4.Rule.Stage != "observed" {
			return errors.New("v9 kernel routing receipt was not durable in the same journal")
		}
		present, _, err := nativeTUNObserveResource(r.nativeView(), 4, "rule")
		if err != nil || !present {
			return errors.New("actual kernel RPDB mark not installed")
		}
		present, _, err = nativeTUNObserveResource(r.nativeView(), 4, "fallback")
		if err != nil || !present {
			return errors.New("native fail-closed unreachable route not installed")
		}
		obs, err := nativeTUNObserveNFT(r.nativeView())
		if err != nil || !obs.Present || !obs.Matches {
			return errors.New("native paired output/postrouting guard missing")
		}
		fmt.Println("HOST_ROUTE_V9_NATIVE_RPDB_FIB_NFT_CONTAINMENT_RECEIPTED=PASS")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	state := smartTUNCoreObservationExample("active")
	inactive := smartTUNCoreObservationExample("inactive")
	inactive.identity = state.identity
	stopped := false
	services := hostCoreRecoveryServices{
		observe: func() (smartTUNTrialUnitObservation, error) { return state, nil },
		stop: func(_ smartTUNTrialUnitObservation, started, valid bool) error {
			if !started || !valid {
				return errors.New("missing durable core start or credential")
			}
			hasRoute, _, err := nativeTUNObserveResource(r.nativeView(), 4, "route")
			if err != nil || !hasRoute {
				return errors.New("native policy removed before protected Core stop")
			}
			stopped = true
			state = inactive
			return nil
		},
	}
	receipt, err := m.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, s trialRecoverySelection) (TrialReceipt, error) {
		if s.version != hostRouteJournalVersion || s.hostRoute.Route.State != "observed" {
			return TrialReceipt{}, errors.New("independent guard did not choose exact v9 parent")
		}
		return recoverHostRouteJournalLocked(store, &s.hostRoute, services)
	})
	if err != nil || !receipt.RecoveryVerified || !stopped {
		t.Fatalf("v9 kernel route recovery failed: %+v %v", receipt, err)
	}
	fmt.Println("HOST_ROUTE_V9_CORE_FIRST_ROUTED_OFF=PASS")
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		return clearRecoveredHostRouteLocked(store, r.Progress.Ingress.OperationID, services)
	})
	if err != nil {
		t.Fatal(err)
	}
	if after := hostNativeKernelSnapshot(t); after != before {
		t.Fatal("v9 rollback did not restore native kernel and foreign Docker/NOTRACK state")
	}
	fmt.Println("HOST_ROUTE_V9_DOCKER_NAT_RAW_AND_IP_RULES_EXACTLY_PRESERVED=PASS")
}

func TestHostRouteV9ForeignOwnedKernelSlotCannotBeAdopted(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_ROUTE_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: isolated root netns required")
	}
	guard, base := prepareHostNativeKernelFixture(t)
	r := hostRouteKernelExample(t)
	r.Progress = base.Progress
	r.Native = base.Native
	r.Native.NFTName = "scnt_" + r.Progress.Ingress.OperationID
	program, err := nativeNFTCreateJSON(r.nativeView())
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = sha256Hex(program)
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	secret := []byte(`{"simulated":"host-route-v9"}`)
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := hostRouteKernelReady(t, store, &r, guard, secret); err != nil {
			return err
		}
		// A foreign owner of the fixed RPDB priority is a conflict, not a
		// reason to delete that resource or force-create our own capture rule.
		// An exact-looking foreign rule occupies the same RPDB selector,
		// but has no matching *journaled* creation intent or receipt.
		ingressNativeCommand(t, "/usr/sbin/ip", nativeRouteArgs(r.nativeView(), 4, "rule", "add")...)
		// Policy admission must reobserve exact absence, not trust a prior plan.
		native := r.nativeView()
		err := nativeTUNApplyPolicyWithPersist(store, &native, "", hostRouteNativePersist(store, &r))
		if err == nil {
			return errors.New("foreign owned RPDB priority was adopted")
		}
		if strings.Contains(err.Error(), "panic") {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("HOST_ROUTE_V9_FOREIGN_POLICY_PRIORITY_FAILS_CLOSED=PASS")
}
