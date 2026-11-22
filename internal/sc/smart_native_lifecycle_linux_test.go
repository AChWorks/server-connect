//go:build linux

package sc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A real Core SIGKILL leaves an inert private config after autonomous
// restoration, but removes the one-use recovery claim. Explicit Disconnect
// must still route to the native cleanup, never report a Proxy Only no-op.
func TestExplicitDisconnectSelectsNativeAfterRecoveredCrash(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "state"), "", 0)
	if err := m.withLock(func() error {
		return m.save(State{Version: 1, Desired: "direct", Selected: "0123456789abcdef", Port: m.Port})
	}); err != nil {
		t.Fatal(err)
	}
	check := func(want bool) {
		t.Helper()
		plan, err := m.planDisconnect()
		if err != nil || plan.native != want {
			t.Fatalf("native Disconnect decision: got=%+v want=%v err=%v", plan, want, err)
		}
	}
	check(false) // ordinary Direct
	config := filepath.Join(m.Dir, nativeConfigFile)
	if err := put(config, []byte("inert-private-core-config")); err != nil {
		t.Fatal(err)
	}
	check(true) // Direct restored, claim retired, inert config remains
	if err := m.withLock(func() error {
		return m.save(State{Version: 1, Desired: "proxy", Selected: "0123456789abcdef", Port: m.Port})
	}); err != nil {
		t.Fatal(err)
	}
	check(true) // a legacy Proxy Only activation cannot hide native residue
	if err := m.withLock(func() error {
		return m.save(State{Version: 1, Desired: "direct", Selected: "0123456789abcdef", Port: m.Port})
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.planDisconnect(); err == nil {
		t.Fatal("insecure private config silently bypassed native cleanup")
	}
	if err := os.Chmod(config, 0600); err != nil {
		t.Fatal(err)
	}
	check(true)
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	check(false) // native cleanup already completed
	if err := os.Symlink("foreign", config); err != nil {
		t.Fatal(err)
	}
	if _, err := m.planDisconnect(); err == nil {
		t.Fatal("symlinked native config silently bypassed native cleanup")
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	receipt, err := json.Marshal(NativeSession{Version: 1, Selected: "0123456789abcdef",
		InterfaceName: "sctun0", UnderlayIF: "eth0", ConfigSHA256: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if err := put(filepath.Join(m.Dir, nativeSessionFile), receipt); err != nil {
		t.Fatal(err)
	}
	check(true) // retained claim still takes native path
	if err := put(filepath.Join(m.Dir, nativeSessionFile), []byte("invalid-claim")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.planDisconnect(); err == nil {
		t.Fatal("malformed native claim silently bypassed recovery")
	}
}

// The outer transition and existing owned cleanups comprise one operator
// action. A Proxy Only service may be active even when state persistence failed
// before its Desired=proxy write, or under a legacy Proxy+native-residue state.
func TestDisconnectReconcilesBothOwnedServicesAndRetry(t *testing.T) {
	for _, desired := range []string{"direct", "proxy"} {
		t.Run(desired, func(t *testing.T) {
			m := New(filepath.Join(t.TempDir(), "state"), "", 0)
			if err := m.withLock(func() error {
				return m.save(State{Version: 1, Desired: desired, Port: m.Port})
			}); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(m.Dir, nativeConfigFile)
			if err := put(config, []byte("inert-private-config")); err != nil {
				t.Fatal(err)
			}
			profile := filepath.Join(m.Dir, "profiles", "0123456789abcdef.json")
			if err := put(profile, []byte("preserve-this-profile")); err != nil {
				t.Fatal(err)
			}
			runtime := filepath.Join(m.Dir, "runtime.json")
			if err := put(runtime, []byte("owned-proxy-runtime")); err != nil {
				t.Fatal(err)
			}
			proxyActive, nativeFailed := true, true
			var actions []string
			proxyCleanup := func() error {
				actions = append(actions, "proxy")
				proxyActive = false
				return m.withLock(func() error {
					state, err := m.load()
					if err != nil {
						return err
					}
					state.Desired = "direct"
					if err := m.save(state); err != nil {
						return err
					}
					if err := os.Remove(runtime); err != nil && !os.IsNotExist(err) {
						return err
					}
					return nil
				})
			}
			failNative := true
			nativeCleanup := func() error {
				actions = append(actions, "native")
				if failNative {
					return Fault("service_state_unavailable", "injected native failure")
				}
				if proxyActive {
					t.Fatal("native cleanup ran before stopping unexpected Proxy Only")
				}
				nativeFailed = false
				return os.Remove(config)
			}
			// Partial failure: Proxy stops successfully, but native still has
			// its inert config/failed bookkeeping. Never report completion.
			if err := m.disconnectWith(proxyCleanup, nativeCleanup); ErrorCode(err) != "service_state_unavailable" {
				t.Fatalf("partial native failure hidden: %v", err)
			}
			if proxyActive || !nativeFailed {
				t.Fatalf("partial effects misreported: proxy=%v nativeFailed=%v", proxyActive, nativeFailed)
			}
			if _, err := readRegular(config); err != nil {
				t.Fatalf("failed native cleanup lost retryable config: %v", err)
			}
			if _, err := os.Stat(runtime); !os.IsNotExist(err) {
				t.Fatalf("proxy runtime retained after owned proxy stop: %v", err)
			}
			failNative = false
			if err := m.disconnectWith(proxyCleanup, nativeCleanup); err != nil {
				t.Fatalf("retry did not complete both lifecycles: %v", err)
			}
			if proxyActive || nativeFailed || strings.Join(actions[:2], ",") != "proxy,native" {
				t.Fatalf("wrong lifecycle result/order: %v proxy=%v native=%v", actions, proxyActive, nativeFailed)
			}
			if _, err := os.Stat(config); !os.IsNotExist(err) {
				t.Fatalf("retired native config retained: %v", err)
			}
			if b, err := readRegular(profile); err != nil || string(b) != "preserve-this-profile" {
				t.Fatalf("saved profile changed: %v", err)
			}
			state, err := m.load()
			if err != nil || state.Desired != "direct" {
				t.Fatalf("final mode not Direct: %+v %v", state, err)
			}
		})
	}
}

func TestDisconnectNativeClaimPrecedesProxyAndFailureIsReported(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "state"), "", 0)
	if err := m.withLock(func() error {
		if err := m.save(State{Version: 1, Desired: "smart", Port: m.Port}); err != nil {
			return err
		}
		return put(filepath.Join(m.Dir, nativeSessionFile), []byte("claim-placeholder"))
	}); err != nil {
		t.Fatal(err)
	}
	// A valid-shaped claim is required: a corrupt receipt cannot authorize
	// either cleanup. The serialized transition refuses before any actions.
	visited := false
	if err := m.disconnectWith(func() error { visited = true; return nil }, func() error { visited = true; return nil }); err == nil || visited {
		t.Fatalf("invalid native claim allowed effects: %v", err)
	}
	claim := NativeSession{Version: 1, Selected: "0123456789abcdef",
		InterfaceName: "sctun0", UnderlayIF: "eth0", ConfigSHA256: strings.Repeat("a", 64)}
	b, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	if err := put(filepath.Join(m.Dir, nativeSessionFile), b); err != nil {
		t.Fatal(err)
	}
	var calls []string
	nativeCleanup := func() error {
		calls = append(calls, "native")
		return m.withLock(func() error {
			if err := os.Remove(filepath.Join(m.Dir, nativeSessionFile)); err != nil {
				return err
			}
			return m.save(State{Version: 1, Desired: "direct", Port: m.Port})
		})
	}
	proxyFails := true
	proxyCleanup := func() error {
		calls = append(calls, "proxy")
		if proxyFails {
			return Fault("service_conflict", "proxy service cannot be stopped")
		}
		return nil
	}
	// The second cleanup failure after verified native rollback must be a
	// non-success; a new Disconnect can finish Proxy Only without replaying
	// the retired native claim.
	if err := m.disconnectWith(proxyCleanup, nativeCleanup); ErrorCode(err) != "service_conflict" {
		t.Fatalf("second cleanup failure hidden: %v", err)
	}
	if strings.Join(calls, ",") != "native,proxy" {
		t.Fatalf("native claim must be retired before Proxy Only: %v", calls)
	}
	proxyFails = false
	if err := m.disconnectWith(proxyCleanup, nativeCleanup); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, ",") != "native,proxy,proxy" {
		t.Fatalf("retry replayed native claim or omitted proxy stop: %v", calls)
	}
}

// Real Connect and Native Connect must both acquire the same outer lock as
// generic Disconnect. Neither may select/stage another mode between a
// native-residue decision and the corresponding two-service cleanup.
func TestDisconnectTransitionBlocksBothConnectCommands(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "state"), "", 0)
	if err := m.withLock(func() error { return m.save(State{Version: 1, Desired: "direct", Port: m.Port}) }); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(m.Dir, nativeConfigFile)
	if err := put(config, []byte("inert-private-config")); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- m.disconnectWith(func() error {
			close(entered)
			<-release
			return nil
		}, func() error { return os.Remove(config) })
	}()
	<-entered
	proxyDone := make(chan error, 1)
	nativeDone := make(chan error, 1)
	proxyStarted, nativeStarted := make(chan struct{}), make(chan struct{})
	go func() { close(proxyStarted); proxyDone <- m.Connect() }()
	go func() {
		close(nativeStarted)
		_, err := m.ConnectNativeSmartRouting(NativePolicyOptions{InterfaceName: "sctun0", UnderlayInterface: "eth0"})
		nativeDone <- err
	}()
	<-proxyStarted
	<-nativeStarted
	// The real entry points must not reach their ownership checks while
	// the old Disconnect transaction is between selection and cleanup.
	for _, tc := range []struct {
		name string
		done <-chan error
	}{
		{"proxy", proxyDone}, {"native", nativeDone},
	} {
		select {
		case err := <-tc.done:
			t.Fatalf("%s Connect crossed active Disconnect transition: %v", tc.name, err)
		case <-time.After(80 * time.Millisecond):
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		done <-chan error
	}{
		{"proxy", proxyDone}, {"native", nativeDone},
	} {
		select {
		case err := <-tc.done:
			if err == nil {
				t.Fatalf("%s Connect unexpectedly succeeded on a fixture without installed units", tc.name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s Connect did not exit transition", tc.name)
		}
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatalf("residual config persisted: %v", err)
	}
}

func TestDisconnectWaitsForNativeClaimStagingBeforePlanning(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "state"), "", 0)
	if err := m.withLock(func() error { return m.save(State{Version: 1, Desired: "direct", Port: m.Port}) }); err != nil {
		t.Fatal(err)
	}
	staged, release := make(chan struct{}), make(chan struct{})
	connectDone := make(chan error, 1)
	go func() {
		connectDone <- m.withNativeTransition(func() error {
			if err := m.withLock(func() error {
				if err := m.save(State{Version: 1, Desired: "smart", Port: m.Port}); err != nil {
					return err
				}
				claim := NativeSession{Version: 1, Selected: "0123456789abcdef", InterfaceName: "sctun0",
					UnderlayIF: "eth0", ConfigSHA256: strings.Repeat("a", 64)}
				b, err := json.Marshal(claim)
				if err != nil {
					return err
				}
				return put(filepath.Join(m.Dir, nativeSessionFile), b)
			}); err != nil {
				return err
			}
			close(staged)
			<-release
			return nil
		})
	}()
	<-staged
	var calls []string
	disconnectDone := make(chan error, 1)
	disconnectStarted := make(chan struct{})
	go func() {
		close(disconnectStarted)
		disconnectDone <- m.disconnectWith(func() error {
			calls = append(calls, "proxy")
			return nil
		}, func() error {
			calls = append(calls, "native")
			return m.withLock(func() error {
				if err := os.Remove(filepath.Join(m.Dir, nativeSessionFile)); err != nil {
					return err
				}
				return m.save(State{Version: 1, Desired: "direct", Port: m.Port})
			})
		})
	}()
	<-disconnectStarted
	select {
	case err := <-disconnectDone:
		t.Fatalf("Disconnect crossed unfinished native claim staging: %v", err)
	case <-time.After(80 * time.Millisecond):
	}
	close(release)
	if err := <-connectDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-disconnectDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Disconnect did not complete after native staging")
	}
	if strings.Join(calls, ",") != "native,proxy" {
		t.Fatalf("Disconnect observed stale Direct rather than staged native claim: %v", calls)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, nativeSessionFile)); !os.IsNotExist(err) {
		t.Fatalf("native claim was not retired: %v", err)
	}
}
func TestNativeSessionClaimStrictAndConfigBound(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "state"), "", 0)
	if err := m.prepare(); err != nil {
		t.Fatal(err)
	}
	config := []byte("{\"inbounds\":[{\"type\":\"tun\",\"interface_name\":\"sctun0\"}]}")
	sum := sha256.Sum256(config)
	base := NativeSession{Version: 1, Selected: "0123456789abcdef",
		InterfaceName: "sctun0", UnderlayIF: "eth0", ConfigSHA256: hex.EncodeToString(sum[:])}
	b, _ := json.Marshal(base)
	if err := put(filepath.Join(m.Dir, nativeSessionFile), b); err != nil {
		t.Fatal(err)
	}
	if err := put(filepath.Join(m.Dir, nativeConfigFile), config); err != nil {
		t.Fatal(err)
	}
	found, err := m.readNativeSession()
	if err != nil || found != base {
		t.Fatalf("claim roundtrip: %+v %v", found, err)
	}
	if err := m.validateNativeSessionConfig(found); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"duplicate-key", []byte("{\"version\":2," + string(b[1:]))},
		{"unknown-field", []byte(string(b[:len(b)-1]) + ",\"extra\":\"foreign\"}")},
		{"trailing-object", []byte(string(b) + "{}")},
		{"missing-claim", []byte("{\"version\":1}")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := put(filepath.Join(m.Dir, nativeSessionFile), tc.raw); err != nil {
				t.Fatal(err)
			}
			if _, err := m.readNativeSession(); err == nil {
				t.Fatal("untrusted native claim accepted")
			}
		})
	}
	if err := put(filepath.Join(m.Dir, nativeSessionFile), b); err != nil {
		t.Fatal(err)
	}
	if err := put(filepath.Join(m.Dir, nativeConfigFile), []byte("{\"inbounds\":[]}")); err != nil {
		t.Fatal(err)
	}
	if err := m.validateNativeSessionConfig(base); err == nil {
		t.Fatal("modified native config accepted")
	}
	if err := os.Remove(filepath.Join(m.Dir, nativeSessionFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readNativeSession(); !os.IsNotExist(err) {
		t.Fatalf("claim removal not observable: %v", err)
	}
}

type fakeNativeAdmission struct {
	outputs map[string]string
	called  []string
}

func (f *fakeNativeAdmission) output(_ context.Context, binary string, args ...string) (string, error) {
	key := binary + " " + strings.Join(args, " ")
	f.called = append(f.called, key)
	return f.outputs[key], nil
}
func (f *fakeNativeAdmission) run(_ context.Context, binary string, args ...string) error {
	f.called = append(f.called, "MUTATION:"+binary+" "+strings.Join(args, " "))
	return nil
}
func nativeAdmissionFixture() *fakeNativeAdmission {
	return &fakeNativeAdmission{outputs: map[string]string{
		"ip -N -4 rule show":           "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n",
		"ip -N -6 rule show":           "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n",
		"ip -4 route show table 27432": "",
		"ip -6 route show table 27432": "",
		"nft list tables":              "table inet other-service\n",
		"ip -o link show":              "1: lo: <LOOPBACK>\n2: eth0@if12: <UP>\n",
		"ip -o link show dev eth0":     "2: eth0@if12: <UP>\n",
	}}
}

func TestNativeAdmissionRejectsOccupiedResources(t *testing.T) {
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "eth0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	clean := nativeAdmissionFixture()
	if err := inspectNativeAdmission(context.Background(), clean, scope); err != nil {
		t.Fatalf("clean native slots incorrectly blocked: %v", err)
	}
	for _, tc := range []struct {
		name, key, value string
	}{
		{"priority-one", "ip -N -4 rule show", "0: from all lookup local\n1: from all lookup 12345\n"},
		{"managed-slot", "ip -N -4 rule show", "0: from all lookup local\n14200: from all lookup 123\n"},
		{"policy-route", "ip -4 route show table 27432", "default via 1.2.3.4 dev eth0\n"},
		{"nft-foreign", "nft list tables", "table inet sing-box\n"},
		{"reply-guard-foreign", "nft list tables", "table inet sc_reply_guard\n"},
		{"existing-tun", "ip -o link show", "1: lo: <LOOPBACK>\n5: sctun0: <UP>\n"},
		{"underlay-missing", "ip -o link show dev eth0", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := nativeAdmissionFixture()
			runner.outputs[tc.key] = tc.value
			if err := inspectNativeAdmission(context.Background(), runner, scope); err == nil {
				t.Fatalf("occupied or unsupported native resources accepted: %s", tc.name)
			}
			for _, call := range runner.called {
				if strings.HasPrefix(call, "MUTATION:") {
					t.Fatalf("preflight modified host: %s", call)
				}
			}
		})
	}
}

func TestNativePreflightRequiresSavedDesiredProfile(t *testing.T) {
	s := NativeSession{Selected: "0123456789abcdef"}
	if err := nativeDesiredMatchesClaim(State{
		Desired: "smart", Selected: s.Selected,
	}, s); err != nil {
		t.Fatalf("accepted matching Smart Routing profile refused: %v", err)
	}
	for _, state := range []State{
		{Desired: "direct", Selected: s.Selected},
		{Desired: "proxy", Selected: s.Selected},
		{Desired: "smart", Selected: "1111111111111111"},
	} {
		if err := nativeDesiredMatchesClaim(state, s); err == nil {
			t.Fatalf("manual/reboot native restart ignored saved intent: %+v", state)
		}
	}
}

// A retired journal must keep its private bytes and block Native admission,
// never become a second simultaneously active network-policy owner.
func TestRetiredV4JournalBlocksNativeAdmission(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "state"), "", 0)
	if err := m.prepare(); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"version":4,"intent_type":"smart_tun_pending_trial_v4"}`)
	if err := put(filepath.Join(m.Dir, activationJournalFilename), raw); err != nil {
		t.Fatal(err)
	}
	phase, err := m.pendingLegacyActivationJournal()
	if err != nil || phase == "" {
		t.Fatalf("retired operation not blocked: %q %v", phase, err)
	}
	again, err := os.ReadFile(filepath.Join(m.Dir, activationJournalFilename))
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatalf("retired operation mutated by admission: %v", err)
	}
}

// A verified native stop hook must leave Direct without requiring a CLI
// Disconnect after a reboot. The packet-filter and routing proof itself is
// tested separately; this verifies the crash-consistent persistence boundary.
func TestNativeRecoveryFinalizesOnlyValidatedDirectSession(t *testing.T) {
	for _, initial := range []string{"smart", "direct"} {
		t.Run(initial, func(t *testing.T) {
			m := New(filepath.Join(t.TempDir(), "state"), "", 0)
			if err := m.prepare(); err != nil {
				t.Fatal(err)
			}
			state := State{Version: 1, Selected: "0123456789abcdef", Desired: initial, Port: m.Port}
			if err := m.save(state); err != nil {
				t.Fatal(err)
			}
			receipt := []byte(`{"version":1,"selected":"0123456789abcdef"}`)
			if err := put(filepath.Join(m.Dir, nativeSessionFile), receipt); err != nil {
				t.Fatal(err)
			}
			if err := put(filepath.Join(m.Dir, nativeConfigFile), []byte("private-config")); err != nil {
				t.Fatal(err)
			}
			// A direct-only helper cannot retire the receipt before the
			// separately verified kernel/OUTPUT barrier transition.
			if initial == "smart" {
				if err := m.finalizeNativeRecoveryLocked(); ErrorCode(err) != "guard_pending" {
					t.Fatalf("retired Smart claim before Direct and barrier cleanup: %v", err)
				}
			}
			if err := m.commitNativeDirectAfterKernelRestoreLocked(); err != nil {
				t.Fatal(err)
			}
			if err := m.finalizeNativeRecoveryLocked(); err != nil {
				t.Fatal(err)
			}
			got, err := m.load()
			if err != nil || got.Desired != "direct" || got.Selected != state.Selected {
				t.Fatalf("native recovery changed saved policy or did not reach Direct: %+v %v", got, err)
			}
			if _, err := os.Stat(filepath.Join(m.Dir, nativeSessionFile)); !os.IsNotExist(err) {
				t.Fatalf("recovered receipt not retired: %v", err)
			}
			if b, err := readRegular(filepath.Join(m.Dir, nativeConfigFile)); err != nil || string(b) != "private-config" {
				t.Fatalf("recovery mutated private config before explicit disconnect: %s %v", b, err)
			}
		})
	}
}

func TestNativeRecoveryRefusesUnrelatedDesiredModeWithoutRetiringClaim(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "state"), "", 0)
	if err := m.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := m.save(State{Version: 1, Desired: "proxy", Selected: "0123456789abcdef", Port: m.Port}); err != nil {
		t.Fatal(err)
	}
	receipt := []byte(`{"version":1,"selected":"0123456789abcdef"}`)
	if err := put(filepath.Join(m.Dir, nativeSessionFile), receipt); err != nil {
		t.Fatal(err)
	}
	if err := m.finalizeNativeRecoveryLocked(); ErrorCode(err) != "guard_pending" {
		t.Fatalf("unrelated mode finalized: %v", err)
	}
	if raw, err := readRegular(filepath.Join(m.Dir, nativeSessionFile)); err != nil || !bytes.Equal(raw, receipt) {
		t.Fatalf("unrelated claim was consumed: %s %v", raw, err)
	}
}

// A persisted crash-recovery claim is never a boot or manual restart grant.
// The existing health receipt must belong to this boot, this config and the
// just-staged Connect operation; failure leaves the receipt for owned cleanup.
func TestNativeFreshPrearmRejectsRetainedBootAndStaleGuard(t *testing.T) {
	health := nativeHealthTestState()
	claim := NativeSession{Selected: "0123456789abcdef", ConfigSHA256: strings.Repeat("b", 64),
		HealthOperationID: health.OperationID}
	boot := health.BootID
	for _, tc := range []struct {
		name    string
		mutate  func(*NativeSession, *NativeHealthState)
		boot    string
		now     int64
		allowed bool
	}{
		{"fresh-just-armed", nil, boot, 1000, true},
		{"fresh-grace-boundary", nil, boot, 1000 + nativeHealthGraceMS, true},
		{"stale-previous-boot", nil, "22222222-2222-4222-8222-222222222222", 1000, false},
		{"uptime-rewound-after-boot", nil, boot, 999, false},
		{"prearm-expired", nil, boot, 1000 + nativeHealthGraceMS + 1, false},
		{"reused-healthy-state", func(_ *NativeSession, h *NativeHealthState) { h.Phase = "healthy" }, boot, 1100, false},
		{"reused-degraded-state", func(_ *NativeSession, h *NativeHealthState) { h.Phase = "degraded" }, boot, 1100, false},
		{"off-claim", func(_ *NativeSession, h *NativeHealthState) { h.Phase = "off" }, boot, 1100, false},
		{"unrelated-config", func(s *NativeSession, _ *NativeHealthState) { s.ConfigSHA256 = strings.Repeat("c", 64) }, boot, 1100, false},
		{"unrelated-health-operation", func(s *NativeSession, _ *NativeHealthState) { s.HealthOperationID = strings.Repeat("c", 32) }, boot, 1100, false},
		{"heartbeat-future", func(_ *NativeSession, h *NativeHealthState) { h.HeartbeatMS = 1101 }, boot, 1100, false},
		{"heartbeat-before-start", func(_ *NativeSession, h *NativeHealthState) { h.HeartbeatMS = 999 }, boot, 1100, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, h := claim, health
			if tc.mutate != nil {
				tc.mutate(&s, &h)
			}
			err := nativeFreshPrearm(s, h, tc.boot, tc.now)
			if (err == nil) != tc.allowed {
				t.Fatalf("fresh authorization mismatch: allowed=%t err=%v", tc.allowed, err)
			}
			if !tc.allowed && ErrorCode(err) != "guard_pending" {
				t.Fatalf("stale prearm was not refused with retained-claim class: %v", err)
			}
		})
	}
}

func TestNativeAdmissionRechecksCommittedEarlyReplyGuard(t *testing.T) {
	ctx := context.Background()
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "eth0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	newFixture := func() *fakeNativeAdmission {
		r := nativeAdmissionFixture()
		r.outputs["nft list tables"] = "table inet foreign\n" + "table inet sc_reply_guard\n"
		r.outputs["nft -j list table inet sc_reply_guard"] = nativeReplyGuardFixtureJSON
		return r
	}
	if err := inspectNativeAdmissionWithReplyGuard(ctx, newFixture(), scope, 10, nativeAcceptedTCPFingerprint(nil)); err != nil {
		t.Fatalf("previously committed reply guard refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*fakeNativeAdmission)
		handle uint64
	}{
		{"uncommitted", func(_ *fakeNativeAdmission) {}, 0},
		{"foreign-handle", func(_ *fakeNativeAdmission) {}, 17},
		{"tampered-expression", func(r *fakeNativeAdmission) {
			r.outputs["nft -j list table inet sc_reply_guard"] =
				strings.Replace(nativeReplyGuardFixtureJSON, `"value":8228`, `"value":8227`, 1)
		}, 10},
		{"missing-owned-table", func(r *fakeNativeAdmission) { r.outputs["nft list tables"] = "table inet foreign\n" }, 10},
		{"occupied-core-table", func(r *fakeNativeAdmission) { r.outputs["nft list tables"] += "table inet sing-box\n" }, 10},
		{"occupied-managed-rule", func(r *fakeNativeAdmission) { r.outputs["ip -N -4 rule show"] = "14200: from all lookup 254\n" }, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newFixture()
			tc.mutate(r)
			if err := inspectNativeAdmissionWithReplyGuard(ctx, r, scope, tc.handle, nativeAcceptedTCPFingerprint(nil)); err == nil {
				t.Fatalf("stale/foreign preflight unexpectedly passed: %s", tc.name)
			}
			for _, call := range r.called {
				if strings.HasPrefix(call, "MUTATION:") {
					t.Fatalf("read-only preflight mutated kernel: %s", call)
				}
			}
		})
	}
}

// Systemd does not report ExecStopPost as a fully idle unit: its ControlPID
// is the *current* recovery process and the stop Job may still be pending.
// This exact stopped-Core exception must not admit ExecStartPre or a separate
// control process just because MainPID has not appeared yet.
func TestNativeCoreRecoveryQuiescenceRejectsStartingAndForeignControl(t *testing.T) {
	self := 4321
	idle := "Id=server-connect-native-tun.service\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\nControlGroup=\n"
	stopPost := "Id=server-connect-native-tun.service\nActiveState=deactivating\nSubState=stop-post\nMainPID=0\nControlPID=4321\nJob=67\nControlGroup=/system.slice/server-connect-native-tun.service\n"
	for _, tc := range []struct {
		name string
		raw  string
		ok   bool
	}{
		{"idle", idle, true},
		{"failed-idle", strings.Replace(strings.Replace(idle, "inactive", "failed", 1), "SubState=dead", "SubState=failed", 1), true},
		{"real-exec-stop-post-self", stopPost, true},
		{"pending-start-pre", strings.Replace(strings.Replace(stopPost, "deactivating", "activating", 1), "stop-post", "start-pre", 1), false},
		{"not-this-control-pid", strings.Replace(stopPost, "ControlPID=4321", "ControlPID=9999", 1), false},
		{"wrong-stop-substate", strings.Replace(stopPost, "stop-post", "stop-sigterm", 1), false},
		{"active-core", strings.Replace(idle, "inactive", "active", 1), false},
		{"main-pid-present", strings.Replace(idle, "MainPID=0", "MainPID=9999", 1), false},
		{"idle-pending-job", strings.Replace(idle, "Job=\n", "Job=72\n", 1), false},
		{"idle-control-pid", strings.Replace(idle, "ControlPID=0", "ControlPID=9999", 1), false},
		{"idle-cgroup-occupied", strings.Replace(idle, "ControlGroup=\n", "ControlGroup=/system.slice/server-connect-native-tun.service\n", 1), false},
		{"foreign-service", strings.Replace(idle, "Id=server-connect-native-tun.service", "Id=foreign.service", 1), false},
		{"duplicate-control-key", idle + "ControlPID=0\n", false},
		{"missing-job", strings.Replace(idle, "Job=\n", "", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := parseNativeCoreRecoveryQuiescence([]byte(tc.raw), self)
			if (err == nil) != tc.ok {
				t.Fatalf("recovery quiescence mismatch: ok=%t err=%v", tc.ok, err)
			}
		})
	}
}

func TestNativeOrphanRecoveryAttestsBootOperationAndReplyGuardBeforeRPDB(t *testing.T) {
	health := nativeHealthTestState()
	digest := nativeAcceptedTCPFingerprint(nil)
	session := NativeSession{
		Version: 1, Selected: "0123456789abcdef", InterfaceName: "sctun0",
		UnderlayIF: "scouter0", ConfigSHA256: health.ConfigSHA256,
		HealthOperationID: health.OperationID, ReplyGuardHandle: 10,
		ReplyGuardFingerprint: digest, CoreStartAttempted: true,
	}
	boot := health.BootID
	for _, tc := range []struct {
		name   string
		change func(*NativeSession, *NativeHealthState, *fakeReplyGuardRunner, *string)
	}{
		{"stale-boot", func(_ *NativeSession, _ *NativeHealthState, _ *fakeReplyGuardRunner, boot *string) {
			*boot = "22222222-2222-4222-8222-222222222222"
		}},
		{"wrong-operation", func(s *NativeSession, _ *NativeHealthState, _ *fakeReplyGuardRunner, _ *string) {
			s.HealthOperationID = strings.Repeat("c", 32)
		}},
		{"wrong-config", func(s *NativeSession, _ *NativeHealthState, _ *fakeReplyGuardRunner, _ *string) {
			s.ConfigSHA256 = strings.Repeat("c", 64)
		}},
		{"missing-health", func(_ *NativeSession, h *NativeHealthState, _ *fakeReplyGuardRunner, _ *string) {
			*h = NativeHealthState{}
		}},
		{"changed-guard-handle", func(s *NativeSession, _ *NativeHealthState, _ *fakeReplyGuardRunner, _ *string) {
			s.ReplyGuardHandle = 11
		}},
		{"changed-accepted-tuple-fingerprint", func(s *NativeSession, _ *NativeHealthState, _ *fakeReplyGuardRunner, _ *string) {
			s.ReplyGuardFingerprint = strings.Repeat("e", 64)
		}},
		{"changed-guard-rules", func(_ *NativeSession, _ *NativeHealthState, g *fakeReplyGuardRunner, _ *string) {
			g.foreign = strings.Replace(nativeReplyGuardFixtureJSON, `"value":8228`, `"value":8227`, 1)
		}},
		{"missing-guard-outstanding-rpdb", func(_ *NativeSession, _ *NativeHealthState, g *fakeReplyGuardRunner, _ *string) {
			g.has = false
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, h, b := session, health, boot
			g := &fakeReplyGuardRunner{has: true}
			r := newNativeCoreSIGKILLOrphanFixture()
			tc.change(&s, &h, g, &b)
			err := recoverNativeNetworkWithReceipt(context.Background(), &nativeDockerAdmissionRunner{r}, g, s, h, b)
			if err == nil || len(r.mutations) != 0 || len(g.mutations) != 0 {
				t.Fatalf("unattested orphan mutated kernel: err=%v rpdb=%v nft=%v", err, r.mutations, g.mutations)
			}
			if !strings.Contains(strings.Join(r.rules["-4"], "\n"), "14200:") {
				t.Fatal("unauthorized RPDB rule disappeared")
			}
		})
	}
	t.Run("exact-valid-core-crash", func(t *testing.T) {
		r := newNativeCoreSIGKILLOrphanFixture()
		g := &fakeReplyGuardRunner{has: true}
		if err := recoverNativeNetworkWithReceipt(context.Background(), &nativeDockerAdmissionRunner{r}, g, session, health, boot); err != nil {
			t.Fatalf("verified consumed orphan claim refused: %v", err)
		}
		if g.has || !g.deleted || len(r.mutations) != 8 {
			t.Fatalf("verified Core cleanup did not retire exactly owned effects: rpdb=%v nft=%v", r.mutations, g.mutations)
		}
		for _, family := range []string{"-4", "-6"} {
			text := strings.Join(r.rules[family], "\n")
			if strings.Contains(text, "1420") || strings.Contains(text, "32768:") ||
				!strings.Contains(text, "40960: from all lookup 123") {
				t.Fatalf("valid cleanup altered foreign RPDB: %s", text)
			}
		}
	})
	t.Run("interrupted-owned-deletion-retry", func(t *testing.T) {
		r := newNativeCoreSIGKILLOrphanFixture()
		g := &fakeReplyGuardRunner{has: true}
		r.failOnce = "ip -4 rule del pref 14201"
		kernel := &nativeDockerAdmissionRunner{r}
		if err := recoverNativeNetworkWithReceipt(context.Background(), kernel, g, session, health, boot); err == nil || !g.has {
			t.Fatalf("first interrupted recovery must retain guard: %v", err)
		}
		if err := recoverNativeNetworkWithReceipt(context.Background(), kernel, g, session, health, boot); err != nil || g.has {
			t.Fatalf("exact interrupted recovery must retry: %v", err)
		}
	})
	t.Run("already-clean-kernel-missing-guard", func(t *testing.T) {
		r := newNativeCoreSIGKILLOrphanFixture()
		for _, family := range []string{"-4", "-6"} {
			var remain []string
			for _, rule := range r.rules[family] {
				if strings.HasPrefix(rule, "1420") || strings.HasPrefix(rule, "32768:") {
					continue
				}
				remain = append(remain, rule)
			}
			r.rules[family] = remain
		}
		g := &fakeReplyGuardRunner{}
		if err := recoverNativeNetworkWithReceipt(context.Background(), &nativeDockerAdmissionRunner{r}, g, session, health, boot); err != nil {
			t.Fatalf("already-clean Direct refused without recreated reply table: %v", err)
		}
		if len(r.mutations) != 0 || len(g.mutations) != 0 {
			t.Fatalf("idempotent Direct mutated foreign resources: rpdb=%v nft=%v", r.mutations, g.mutations)
		}
	})
	t.Run("unconsumed-preflight-guard-cleanup", func(t *testing.T) {
		s := session
		s.CoreStartAttempted = false
		r := newNativeCoreSIGKILLOrphanFixture()
		for _, family := range []string{"-4", "-6"} {
			keep := r.rules[family][:0]
			for _, rule := range r.rules[family] {
				if !strings.HasPrefix(rule, "1420") && !strings.HasPrefix(rule, "32768:") {
					keep = append(keep, rule)
				}
			}
			r.rules[family] = keep
		}
		g := &fakeReplyGuardRunner{has: true}
		if err := recoverNativeNetworkWithReceipt(context.Background(), &nativeDockerAdmissionRunner{r}, g, s, health, boot); err != nil {
			t.Fatalf("unconsumed preflight-only table cannot be recovered: %v", err)
		}
		if !g.deleted || len(r.mutations) != 0 {
			t.Fatalf("preflight-only recovery touched unexpected kernel resources: %v / %v", r.mutations, g.mutations)
		}
	})
}
