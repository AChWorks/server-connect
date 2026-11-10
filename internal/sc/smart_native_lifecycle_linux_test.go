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
)

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
