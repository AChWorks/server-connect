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
	"syscall"
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
		"ip -4 rule show":              "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n",
		"ip -6 rule show":              "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n",
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
		{"priority-one", "ip -4 rule show", "0: from all lookup local\n1: from all lookup 12345\n"},
		{"managed-slot", "ip -4 rule show", "0: from all lookup local\n14200: from all lookup 123\n"},
		{"policy-route", "ip -4 route show table 27432", "default via 1.2.3.4 dev eth0\n"},
		{"nft-foreign", "nft list tables", "table inet sing-box\n"},
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

// Both data planes touch the same host networking. A leftover native
// session must block even the disposable legacy trial before any guard
// arming or kernel admission is attempted.
func TestLegacySmartTUNAdmissionRejectsNativeReceipt(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "state"), "", 0)
	if err := m.prepare(); err != nil {
		t.Fatal(err)
	}
	session := NativeSession{
		Version: 1, Selected: "0123456789abcdef",
		InterfaceName: "sctun0", UnderlayIF: "eth0",
		ConfigSHA256: strings.Repeat("a", 64),
	}
	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := put(filepath.Join(m.Dir, nativeSessionFile), raw); err != nil {
		t.Fatal(err)
	}
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		_, e := m.admitSmartTUNTrialLocked(store, SmartTUNCandidateOptions{}, "")
		return e
	})
	if ErrorCode(err) != "guard_pending" {
		t.Fatalf("unfinalized native session must block legacy unit: %v", err)
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
	claim := NativeSession{Selected: "0123456789abcdef", ConfigSHA256: strings.Repeat("b", 64)}
	health := nativeHealthTestState()
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
