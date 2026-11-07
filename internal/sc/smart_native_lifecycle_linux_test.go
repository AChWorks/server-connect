//go:build linux

package sc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
