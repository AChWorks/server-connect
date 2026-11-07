//go:build linux

package sc

// Root-only kernel acceptance in a disposable unshared network namespace.
// The core unit is simulated to isolate the policy ledger/rollback; this
// test cannot authorize general-host Apply or claim actual VPN delivery.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// All v9 positive/negative kernel tests use the same exact Docker NAT and
// paired ip/ip6 raw NOTRACK fixture as the host-ingress acceptance. The
// v4 disconnected policy classifier deliberately remains stricter.
func hostRouteKernelReady(t *testing.T, store *activationJournalDir, r *hostRouteJournal, guard func() error, secret []byte) error {
	t.Helper()
	if err := writeHostRouteJournal(store, *r, nil); err != nil {
		return fmt.Errorf("kernel-ready early: %w", err)
	}
	if err := runHostCaptureGateLocked(store, &r.Progress, guard, hostRouteCapturePersist(store, r)); err != nil {
		return fmt.Errorf("ingress: %w", err)
	}
	native := r.nativeView()
	if err := nativeTUNPrepareLinkWithPersist(store, &native, "", hostRouteNativePersist(store, r)); err != nil {
		return fmt.Errorf("link: %w", err)
	}
	for _, stage := range []string{"credential_possible", "credential_staged", "start_requested", "active_observed"} {
		if stage == "credential_staged" {
			if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, secret, nil); err != nil {
				return fmt.Errorf("credential: %w", err)
			}
		}
		if err := hostRouteCoreStagePersist(store, r, stage); err != nil {
			return fmt.Errorf("core %s: %w", stage, err)
		}
	}
	if err := hostRoutePhasePersist(store, r, "effect_possible"); err != nil {
		return fmt.Errorf("policy-intent: %w", err)
	}
	return nil
}

func hostRouteKernelExample(t *testing.T) hostRouteJournal {
	t.Helper()
	v7 := hostNativeExample()
	v7.Version, v7.Intent = hostRouteJournalVersion, hostRouteJournalIntent
	r := hostRouteJournal{hostCoreJournal: hostCoreJournal{hostNativeJournal: v7, Core: hostCoreLedger{
		ProfileID: "abcdef0123456789", ConfigSHA256: sha256Hex([]byte(`{"simulated":"host-route-v9"}`)),
		PinnedEndpoint: "8.8.8.8", Stage: "planned",
	}}, Route: hostRouteStage{State: "planned"}}
	digest, err := hostRoutePolicyPlanSHA256(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = digest
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
	digest, err := hostRoutePolicyPlanSHA256(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = digest
	if err := validateHostRouteJournal(r); err != nil {
		t.Fatal(err)
	}
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	secret := []byte(`{"simulated":"host-route-v9"}`)
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := hostRouteKernelReady(t, store, &r, guard, secret); err != nil {
			return fmt.Errorf("kernel-ready: %w", err)
		}
		native := r.nativeView()
		if err := nativeTUNApplyGuardFirstWithObserver(store, &native, "", hostRouteNativePersist(store, &r), hostRouteNFTObserver(&r)); err != nil {
			return fmt.Errorf("native-apply: %w", err)
		}
		if err := hostRoutePhasePersist(store, &r, "observed"); err != nil {
			return fmt.Errorf("observed-phase: %w", err)
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
		obs, err := hostRouteNFTObserver(&r)(r.nativeView())
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
		if err := hostTerminalClearReplacementRegression(t, store, m.Dir, func(change func() error) error {
			changed := services
			changed.observe = func() (smartTUNTrialUnitObservation, error) {
				if err := change(); err != nil {
					return smartTUNTrialUnitObservation{}, err
				}
				return services.observe()
			}
			return clearRecoveredHostRouteLocked(store, r.Progress.Ingress.OperationID, changed)
		}); err != nil {
			return err
		}
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
	before := hostNativeKernelSnapshot(t)
	r := hostRouteKernelExample(t)
	r.Progress = base.Progress
	r.Native = base.Native
	r.Native.NFTName = "scnt_" + r.Progress.Ingress.OperationID
	digest, err := hostRoutePolicyPlanSHA256(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = digest
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	secret := []byte(`{"simulated":"host-route-v9"}`)
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := hostRouteKernelReady(t, store, &r, guard, secret); err != nil {
			return err
		}
		// An exact-looking foreign RPDB selector is not a durable receipt.
		foreign := nativeRouteArgs(r.nativeView(), 4, "rule", "add")
		ingressNativeCommand(t, "/usr/sbin/ip", foreign...)
		native := r.nativeView()
		err := nativeTUNApplyGuardFirstWithObserver(store, &native, "", hostRouteNativePersist(store, &r), hostRouteNFTObserver(&r))
		if err == nil {
			return errors.New("foreign RPDB selector was silently adopted")
		}
		if !hostRouteNoKernelPolicyIntent(r.Native) {
			return errors.New("foreign RPDB drift left our own FIB/RPDB intent")
		}
		for _, kind := range []string{"route", "fallback"} {
			present, _, err := nativeTUNObserveResource(r.nativeView(), 4, kind)
			if err != nil || present {
				return errors.New("foreign RPDB drift caused partial FIB effects")
			}
		}
		// Undo only the isolated test's own deliberately created foreign rule.
		ingressNativeCommand(t, "/usr/sbin/ip", nativeRouteArgs(r.nativeView(), 4, "rule", "del")...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	state := smartTUNCoreObservationExample("active")
	inactive := smartTUNCoreObservationExample("inactive")
	inactive.identity = state.identity
	services := hostCoreRecoveryServices{
		observe: func() (smartTUNTrialUnitObservation, error) { return state, nil },
		stop: func(_ smartTUNTrialUnitObservation, started, valid bool) error {
			if !started || !valid {
				return errors.New("invalid core stop authority")
			}
			state = inactive
			return nil
		},
	}
	receipt, err := m.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, s trialRecoverySelection) (TrialReceipt, error) {
		return recoverHostRouteJournalLocked(store, &s.hostRoute, services)
	})
	if err != nil || !receipt.RecoveryVerified {
		t.Fatalf("exact pre-policy conflict Off failed: %+v %v", receipt, err)
	}
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		return clearRecoveredHostRouteLocked(store, r.Progress.Ingress.OperationID, services)
	}); err != nil {
		t.Fatal(err)
	}
	if after := hostNativeKernelSnapshot(t); after != before {
		t.Fatal("foreign RPDB rejection/Off changed host baseline")
	}
	fmt.Println("HOST_ROUTE_V9_FOREIGN_RPDB_CONFLICT_BEFORE_FIB_AND_EXACT_OFF=PASS")
}

// Foreign mutations discovered after initial ingress/Core admission must
// refuse BEFORE the first routing effect, preserving Docker/NOTRACK and
// allowing a same-parent exact Core-first Off after their owner restores the
// original prerequisite. No code here edits a non-disposable host.
func TestHostRouteV9ForeignFirewallDriftRefusesBeforeAnyRoutingEffect(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_ROUTE_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: isolated root netns required")
	}
	requested := os.Getenv("SC_TEST_HOST_ROUTE_FIREWALL_DRIFT")
	if requested != "added_raw_notrack" && requested != "published_docker_nat" {
		t.Skip("NOT_RUN: one drift case per fresh isolated namespace")
	}
	for _, tc := range []struct {
		name     string
		add, del []string
		program  string
	}{
		{name: "added_raw_notrack", add: []string{"-t", "raw", "-A", "OUTPUT", "-p", "tcp", "--sport", "28998", "-j", "NOTRACK"}, del: []string{"-t", "raw", "-D", "OUTPUT", "-p", "tcp", "--sport", "28998", "-j", "NOTRACK"}},
		{name: "published_docker_nat", add: []string{"-t", "nat", "-A", "DOCKER", "-p", "tcp", "--dport", "18080", "-j", "DNAT", "--to-destination", "172.17.0.2:80"}, del: []string{"-t", "nat", "-D", "DOCKER", "-p", "tcp", "--dport", "18080", "-j", "DNAT", "--to-destination", "172.17.0.2:80"}},
	} {
		if tc.name != requested {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			guard, base := prepareHostNativeKernelFixture(t)
			before := hostNativeKernelSnapshot(t)
			r := hostRouteKernelExample(t)
			r.Progress = base.Progress
			r.Native = base.Native
			r.Native.NFTName = "scnt_" + r.Progress.Ingress.OperationID
			digest, err := hostRoutePolicyPlanSHA256(r)
			if err != nil {
				t.Fatal(err)
			}
			r.Route.PolicySHA256 = digest
			secret := []byte(`{"simulated":"host-route-v9"}`)
			m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
			err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				if err := hostRouteKernelReady(t, store, &r, guard, secret); err != nil {
					return err
				}
				ingressNativeCommand(t, "/usr/sbin/iptables-nft", tc.add...)
				native := r.nativeView()
				err := nativeTUNApplyGuardFirstWithObserver(store, &native, "", hostRouteNativePersist(store, &r), hostRouteNFTObserver(&r))
				if err == nil {
					return errors.New("foreign firewall mutation was not refused")
				}
				if !hostRouteNoKernelPolicyIntent(r.Native) {
					return errors.New("preflight failure left native FIB/RPDB intent behind")
				}
				for _, kind := range []string{"fallback", "route", "rule"} {
					exists, _, err := nativeTUNObserveResource(r.nativeView(), 4, kind)
					if err != nil || exists {
						return errors.New("preflight refusal mutated native routing")
					}
				}
				ingressNativeCommand(t, "/usr/sbin/iptables-nft", tc.del...)
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
						return errors.New("no owned core stop authority")
					}
					stopped = true
					state = inactive
					return nil
				},
			}
			result, err := m.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, s trialRecoverySelection) (TrialReceipt, error) {
				return recoverHostRouteJournalLocked(store, &s.hostRoute, services)
			})
			if err != nil || !result.RecoveryVerified || !stopped {
				t.Fatalf("pre-policy rollback failed: %+v %v", result, err)
			}
			if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				return clearRecoveredHostRouteLocked(store, r.Progress.Ingress.OperationID, services)
			}); err != nil {
				t.Fatal(err)
			}
			if hostNativeKernelSnapshot(t) != before {
				t.Fatal("foreign firewall preflight rollback changed host baseline")
			}
			fmt.Println("HOST_ROUTE_V9_" + tc.name + "_BEFORE_FIB_AND_EXACT_OFF=PASS")
		})
	}
}

func TestHostRouteV9CrashHelper(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_ROUTE_CRASH_HELPER") != "isolated-netns" {
		t.Skip("NOT_RUN: isolated crash helper only")
	}
	requireNativeQANetworkNamespace(t)
	dir := os.Getenv("SC_TEST_HOST_ROUTE_CRASH_DIR")
	if dir == "" {
		t.Fatal("crash helper missing the previously staged journal")
	}
	m := New(dir, DefaultCore, DefaultPort)
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		r, _, err := loadHostRouteJournal(store)
		if err != nil {
			return err
		}
		if r.Route.State != "effect_possible" || r.Core.Stage != "active_observed" {
			return errors.New("crash helper was not given an exact routable parent")
		}
		native := r.nativeView()
		point := os.Getenv("SC_TEST_HOST_ROUTE_CRASH_POINT")
		if point != "" && point != "after-native-route-effect" && point != "after-native-nft-effect" && point != "after-native-rule-effect" {
			return errors.New("unsupported routed SIGKILL boundary")
		}
		if err := nativeTUNApplyGuardFirstWithObserver(store, &native, point, hostRouteNativePersist(store, &r), hostRouteNFTObserver(&r)); err != nil {
			return err
		}
		if err := hostRoutePhasePersist(store, &r, "observed"); err != nil {
			return err
		}
		if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
			return err
		}
		return errors.New("SIGKILL unexpectedly returned")
	})
	t.Fatalf("crash helper did not SIGKILL: %v", err)
}

func TestHostRouteV9RealSIGKILLAfterPolicyReceiptIndependentOff(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_ROUTE_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: isolated root netns required")
	}
	guard, base := prepareHostNativeKernelFixture(t)
	before := hostNativeKernelSnapshot(t)
	r := hostRouteKernelExample(t)
	r.Progress = base.Progress
	r.Native = base.Native
	r.Native.NFTName = "scnt_" + r.Progress.Ingress.OperationID
	digest, err := hostRoutePolicyPlanSHA256(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = digest
	dir := privateJournalTempDir(t)
	m := New(dir, DefaultCore, DefaultPort)
	secret := []byte(`{"simulated":"host-route-v9"}`)
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		return hostRouteKernelReady(t, store, &r, guard, secret)
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHostRouteV9CrashHelper$", "-test.v", "-test.timeout=30s")
	child.Env = append(os.Environ(), "SC_TEST_HOST_ROUTE_CRASH_HELPER=isolated-netns", "SC_TEST_HOST_ROUTE_CRASH_DIR="+dir)
	out, err := child.CombinedOutput()
	var killed *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &killed) || !killed.ProcessState.Sys().(syscall.WaitStatus).Signaled() ||
		killed.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("routed policy initiator did not SIGKILL after full receipt: %v %s", err, out)
	}
	fmt.Println("HOST_ROUTE_V9_REAL_SIGKILL_AFTER_ALL_KERNEL_POLICY_RECEIPTS=PASS")
	state := smartTUNCoreObservationExample("active")
	inactive := smartTUNCoreObservationExample("inactive")
	inactive.identity = state.identity
	stopCount := 0
	service := hostCoreRecoveryServices{
		observe: func() (smartTUNTrialUnitObservation, error) { return state, nil },
		stop: func(_ smartTUNTrialUnitObservation, started, valid bool) error {
			if !started || !valid {
				return errors.New("no core start/credential authority")
			}
			stopCount++
			state = inactive
			return nil
		},
	}
	result, err := m.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, s trialRecoverySelection) (TrialReceipt, error) {
		if s.version != hostRouteJournalVersion || s.hostRoute.Route.State != "observed" ||
			s.hostRoute.Native.NFT.Stage != "observed" || s.hostRoute.Native.IPv4.Rule.Stage != "observed" {
			return TrialReceipt{}, errors.New("independent process lost exact durable native routing receipt")
		}
		return recoverHostRouteJournalLocked(store, &s.hostRoute, service)
	})
	if err != nil || !result.RecoveryVerified || stopCount != 1 {
		t.Fatalf("v9 genuine SIGKILL independent Off failed: %+v %v", result, err)
	}
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		return clearRecoveredHostRouteLocked(store, r.Progress.Ingress.OperationID, service)
	}); err != nil {
		t.Fatal(err)
	}
	if after := hostNativeKernelSnapshot(t); after != before {
		t.Fatal("post-SIGKILL policy cleanup altered Docker/NAT/foreign kernel baseline")
	}
	fmt.Println("HOST_ROUTE_V9_POST_SIGKILL_CORE_FIRST_OFF_BASELINE_IDENTICAL=PASS")
}

// A kernel route, nft graph or RPDB selector might be committed immediately before the
// initiator dies and before its exact receipt is fsynced. A later matching
// object is NOT historical proof of ownership. In this case the independent
// executor must retain journal and conflict evidence, never manufacture
// a successful Direct/off or broad-delete an unreceipted host resource.
func TestHostRouteV9UnreceiptedSIGKILLEffectFailsClosed(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_ROUTE_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: isolated root netns required")
	}
	point := os.Getenv("SC_TEST_HOST_ROUTE_UNRECEIPTED")
	if point != "after-native-route-effect" && point != "after-native-nft-effect" && point != "after-native-rule-effect" {
		t.Skip("NOT_RUN: exact one effect boundary per isolated namespace")
	}
	guard, base := prepareHostNativeKernelFixture(t)
	r := hostRouteKernelExample(t)
	r.Progress = base.Progress
	r.Native = base.Native
	r.Native.NFTName = "scnt_" + r.Progress.Ingress.OperationID
	digest, err := hostRoutePolicyPlanSHA256(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = digest
	dir := privateJournalTempDir(t)
	m := New(dir, DefaultCore, DefaultPort)
	secret := []byte(`{"simulated":"host-route-v9"}`)
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		return hostRouteKernelReady(t, store, &r, guard, secret)
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHostRouteV9CrashHelper$", "-test.v", "-test.timeout=30s")
	child.Env = append(os.Environ(), "SC_TEST_HOST_ROUTE_CRASH_HELPER=isolated-netns", "SC_TEST_HOST_ROUTE_CRASH_DIR="+dir, "SC_TEST_HOST_ROUTE_CRASH_POINT="+point)
	out, err := child.CombinedOutput()
	var killed *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &killed) || !killed.ProcessState.Sys().(syscall.WaitStatus).Signaled() ||
		killed.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("native effect boundary did not SIGKILL: %v %s", err, out)
	}
	present := false
	var effectSHA string
	var effectNFT nativeTUNNFTObservation
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		actual, _, err := loadHostRouteJournal(store)
		if err != nil {
			return err
		}
		if actual.Route.State != "effect_possible" {
			return errors.New("native crash lost incomplete durable parent")
		}
		if point == "after-native-route-effect" {
			if actual.Native.IPv4.Route.Stage != "effect_possible" {
				return errors.New("route intent was not persisted before SIGKILL")
			}
			present, effectSHA, err = nativeTUNObserveResource(actual.nativeView(), 4, "route")
		} else if point == "after-native-rule-effect" {
			if actual.Native.IPv4.Rule.Stage != "effect_possible" || actual.Native.NFT.Stage != "observed" {
				return errors.New("RPDB effect occurred without the earlier durable nft guard")
			}
			present, effectSHA, err = nativeTUNObserveResource(actual.nativeView(), 4, "rule")
			if err != nil || !present {
				return errors.New("unreceipted RPDB rule did not survive SIGKILL")
			}
			guard, guardErr := hostRouteNFTObserver(&actual)(actual.nativeView())
			if guardErr != nil || !guard.Matches ||
				!nativeTUNNFTReceiptCovers(actual.nativeView(), guard, true) {
				return errors.New("RPDB crash did not retain the fully receipted independent leak guard")
			}
		} else {
			if actual.Native.NFT.Stage != "effect_possible" || actual.Native.IPv4.Rule.Stage != "planned" {
				return errors.New("nft effect occurred after an unguarded RPDB selector")
			}
			var observed nativeTUNNFTObservation
			observed, err = hostRouteNFTObserver(&actual)(actual.nativeView())
			present = observed.Present && observed.Matches
			effectNFT = observed
		}
		return err
	})
	if err != nil || !present {
		t.Fatalf("unreceipted native effect was not observed: %v", err)
	}
	state := smartTUNCoreObservationExample("active")
	inactive := smartTUNCoreObservationExample("inactive")
	inactive.identity = state.identity
	service := hostCoreRecoveryServices{observe: func() (smartTUNTrialUnitObservation, error) { return state, nil },
		stop: func(_ smartTUNTrialUnitObservation, attempted, valid bool) error {
			if !attempted || !valid {
				return errors.New("no legal core stop authority")
			}
			state = inactive
			return nil
		},
	}
	result, err := m.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, s trialRecoverySelection) (TrialReceipt, error) {
		return recoverHostRouteJournalLocked(store, &s.hostRoute, service)
	})
	if err == nil || result.RecoveryVerified {
		t.Fatal("unreceipted native resource was mistakenly claimed recovered")
	}
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		actual, _, err := loadHostRouteJournal(store)
		if err != nil {
			return err
		}
		// Refusal must preserve the actual ambiguous effect, not only a
		// truthful journal. Reobserve its identity after independent Off.
		if point == "after-native-nft-effect" {
			current, observeErr := hostRouteNFTObserver(&actual)(actual.nativeView())
			if observeErr != nil || !current.Present || !current.Matches || current != effectNFT {
				return errors.New("failed recovery removed or changed unreceipted nft evidence")
			}
		} else {
			kind := "route"
			if point == "after-native-rule-effect" {
				kind = "rule"
			}
			exists, digest, observeErr := nativeTUNObserveResource(actual.nativeView(), 4, kind)
			if observeErr != nil || !exists || digest == "" || digest != effectSHA {
				return errors.New("failed recovery removed or changed unreceipted FIB/RPDB evidence")
			}
		}
		if actual.Route.State != "off_pending" || actual.Core.Stage != "stopped" || actual.Progress.Ingress.Phase != "pending" {
			return errors.New("failed recovery destroyed parent, guard or truthful pending state")
		}
		if point == "after-native-rule-effect" {
			guard, guardErr := hostRouteNFTObserver(&actual)(actual.nativeView())
			if guardErr != nil || !guard.Matches || !nativeTUNNFTReceiptCovers(actual.nativeView(), guard, true) {
				return errors.New("failed RPDB recovery lost the independently receipted leak guard")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("HOST_ROUTE_V9_" + strings.ToUpper(strings.ReplaceAll(point, "-", "_")) + "_UNRECEIPTED_NO_FALSE_OFF=PASS")
	// Kernel state only exists in this fresh unshared namespace. It is discarded
	// on process exit, not by guessing ownership over foreign live host state.
}

// A foreign nft writer can change the already-receipted guard between the
// nft addition and first RPDB selector. The v9 sequencer must reobserve the
// exact guard before installing any rule; independent recovery must not
// delete the altered table or claim Direct/off.
func TestHostRouteV9GuardDriftAfterReceiptRefusesBeforeRPDB(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_ROUTE_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: isolated root netns required")
	}
	guard, base := prepareHostNativeKernelFixture(t)
	r := hostRouteKernelExample(t)
	r.Progress, r.Native = base.Progress, base.Native
	r.Native.NFTName = "scnt_" + r.Progress.Ingress.OperationID
	digest, err := hostRoutePolicyPlanSHA256(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = digest
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	secret := []byte(`{"simulated":"host-route-v9"}`)
	tampered := false
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := hostRouteKernelReady(t, store, &r, guard, secret); err != nil {
			return err
		}
		observer := func(view smartTUNTrialJournal) (nativeTUNNFTObservation, error) {
			if !tampered && view.Native.NFT.Stage == "observed" &&
				view.Native.IPv4.Rule.Stage == "planned" {
				// The injection takes place only AFTER the first durable
				// guard receipt and BEFORE even an IPv4 RPDB add intent.
				ingressNativeCommand(t, "/usr/sbin/nft", "add", "rule", "inet", r.Native.NFTName, "guard", "counter")
				tampered = true
			}
			return hostRouteNFTObserver(&r)(view)
		}
		native := r.nativeView()
		if err := nativeTUNApplyGuardFirstWithObserver(store, &native, "", hostRouteNativePersist(store, &r), observer); err == nil {
			return errors.New("foreign guard change was silently admitted")
		}
		if !tampered || r.Native.NFT.Stage != "observed" || r.Native.IPv4.Rule.Stage != "planned" {
			return errors.New("foreign guard drift was not refused before RPDB")
		}
		for _, family := range []int{4, 6} {
			present, _, err := nativeTUNObserveResource(r.nativeView(), family, "rule")
			if err != nil || present {
				return errors.New("RPDB selector was installed after foreign guard mutation")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	beforeRecovery := hostNativeKernelSnapshot(t)
	state := smartTUNCoreObservationExample("active")
	inactive := smartTUNCoreObservationExample("inactive")
	inactive.identity = state.identity
	services := hostCoreRecoveryServices{
		observe: func() (smartTUNTrialUnitObservation, error) { return state, nil },
		stop: func(_ smartTUNTrialUnitObservation, started, valid bool) error {
			if !started || !valid {
				return errors.New("missing native Core recovery authority")
			}
			state = inactive
			return nil
		},
	}
	result, err := m.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, selection trialRecoverySelection) (TrialReceipt, error) {
		return recoverHostRouteJournalLocked(store, &selection.hostRoute, services)
	})
	if err == nil || result.RecoveryVerified {
		t.Fatal("foreign-modified nft guard was adopted or falsely cleaned")
	}
	if afterRecovery := hostNativeKernelSnapshot(t); afterRecovery != beforeRecovery {
		t.Fatal("independent recovery changed foreign-modified kernel state")
	}
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		current, _, err := loadHostRouteJournal(store)
		if err != nil {
			return err
		}
		if current.Route.State != "off_pending" || current.Core.Stage != "stopped" ||
			current.Native.NFT.Stage != "observed" || current.Progress.Ingress.Phase != "pending" {
			return errors.New("foreign guard refusal discarded durable uncertainty")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fmt.Println("HOST_ROUTE_V9_FOREIGN_GUARD_DRIFT_BEFORE_RPDB_FAIL_CLOSED=PASS")
}
