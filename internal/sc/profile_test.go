package sc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testUUID = "c2902f3a-1c25-41ef-a8dc-760b483aa247"

func TestVLESSParsingAndLocalProxyAuth(t *testing.T) {
	tests := []struct {
		name, source string
		valid        bool
	}{
		{"tcp", "vless://" + testUUID + "@127.0.0.1:30303?security=none&type=tcp#Test%20connection", true},
		{"tls", "vless://" + testUUID + "@edge.example.org:443?type=ws&security=tls&sni=edge.example.org&path=%2Fws&host=edge.example.org", true},
		{"reality", "vless://" + testUUID + "@edge.example.org:443?type=tcp&security=reality&sni=example.org&pbk=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA&sid=1234&fp=chrome", true},
		{"bad port", "vless://" + testUUID + "@example.org:99999?security=none", false},
		{"bad secret", "vless://abc@example.org:443?type=tcp", false},
		{"unknown transport", "vless://" + testUUID + "@example.org:443?type=grpc", false},
		{"unsupported security", "vless://" + testUUID + "@example.org:443?security=xtls", false},
		{"no reality key", "vless://" + testUUID + "@example.org:443?security=reality&sni=example.org", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, e := ValidateSource([]byte(tt.source), "")
			if (e == nil) != tt.valid {
				t.Fatalf("unexpected acceptance: %v", e)
			}
			if e != nil {
				return
			}
			b, e := CoreConfig(p, 20807, "secret-local-pass")
			if e != nil {
				t.Fatal(e)
			}
			var obj map[string]any
			if e = json.Unmarshal(b, &obj); e != nil {
				t.Fatal(e)
			}
			if strings.Contains(string(b), "127.0.0.1:30303?") {
				t.Fatal("raw VLESS link leaked")
			}
			in := obj["inbounds"].([]any)[0].(map[string]any)
			if in["listen"] != "127.0.0.1" {
				t.Fatal("not loopback-only")
			}
			if in["users"] == nil {
				t.Fatal("unauthenticated listener")
			}
		})
	}
}
func TestNativeConfigExtraction(t *testing.T) {
	b := []byte(`{"inbounds":[{"type":"tun","auto_route":true}],"route":{"final":"direct"},"outbounds":[{"type":"direct","tag":"direct"},{"type":"vless","tag":"proxy","server":"127.0.0.1","server_port":30303,"uuid":"` + testUUID + `"}]}`)
	p, e := ValidateSource(b, "")
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := CoreConfig(p, 20807, "secret-local-pass")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(cfg), "tun") || strings.Contains(string(cfg), "auto_route") {
		t.Fatal("host routing imported")
	}
	if strings.Contains(string(cfg), `"final": "direct"`) {
		t.Fatal("foreign route imported")
	}
	bad := []byte(`{"outbounds":[{"type":"vless","tag":"a"},{"type":"vless","tag":"b"}]}`)
	if _, e = ValidateSource(bad, ""); e == nil {
		t.Fatal("ambiguous selection allowed")
	}
	if _, e = ValidateSource(bad, "a"); e != nil {
		t.Fatal(e)
	}
}
func TestPrivateStateAndNoProfileSecretsInListing(t *testing.T) {
	dir := t.TempDir()
	m := New(filepath.Join(dir, "state"), "/does/not/exist", DefaultPort)
	if e := m.withLock(func() error { return m.save(State{Version: 1, Desired: "direct", Port: DefaultPort}) }); e != nil {
		t.Fatal(e)
	}
	if s, e := os.Stat(m.Dir); e != nil || s.Mode().Perm() != 0700 {
		t.Fatalf("unsafe state permissions: %v %v", s, e)
	}
	p, e := ValidateSource([]byte("vless://"+testUUID+"@example.org:443?security=none"), "")
	if e != nil {
		t.Fatal(e)
	}
	if e = m.withLock(func() error { b, _ := json.Marshal(p); return put(filepath.Join(m.Dir, "profiles", p.ID+".json"), b) }); e != nil {
		t.Fatal(e)
	}
	if e = m.Select(p.ID); e != nil {
		t.Fatal(e)
	}
	list, e := m.List()
	if e != nil || len(list) != 1 || !list[0].Selected {
		t.Fatalf("bad list: %v %v", list, e)
	}
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), testUUID) || strings.Contains(string(b), "example.org") {
		t.Fatal("profile secret or remote leaked in list")
	}
	if e = m.Remove(p.ID); e != nil {
		t.Fatal(e)
	}
	list, _ = m.List()
	if len(list) != 0 {
		t.Fatal("profile not removed")
	}
}
func TestRejectSymlinkedPrivateState(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "foreign")
	if e := os.Mkdir(secret, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(secret, filepath.Join(dir, "state")); e != nil {
		t.Fatal(e)
	}
	m := New(filepath.Join(dir, "state"), "", 0)
	if _, e := m.List(); e == nil {
		t.Fatal("symlinked state accepted")
	}
}

// HTTP errors must never become CLI/JSON success. This is particularly important
// because sing-box may return HTTP 502 when a VLESS upstream disappears.
func TestDirectProbeHTTPFailureIsFailure(t *testing.T) {
	failed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer failed.Close()
	m := New(t.TempDir(), "", 0)
	result, e := m.Probe("direct", failed.URL)
	if e == nil || result.Code != 502 || result.Result != "http_error" {
		t.Fatalf("HTTP 502 must be reported as failure: result=%+v err=%v", result, e)
	}
	passed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer passed.Close()
	success, e := m.Probe("direct", passed.URL)
	if e != nil || success.Code != 200 || success.Result != "reachable" {
		t.Fatalf("unexpected healthy path result=%+v err=%v", success, e)
	}
}

func TestUnsupportedVLESSQueryCannotBeSilentlyIgnored(t *testing.T) {
	base := "vless://" + testUUID + "@example.org:443?type=tcp&security=none"
	invalid := []string{
		base + "&headerType=http",
		base + "&serviceName=grpc",
		base + "&type=ws",
		base + "&path=%2Fws",
		base + "&fp=chrome",
		base + "&sni=secret.example",
		base + "&flow=xtls-rprx-vision",
		base + "&unsupported_token=never-log-this",
	}
	for _, src := range invalid {
		_, err := ValidateSource([]byte(src), "")
		if err == nil {
			t.Fatalf("unsupported VLESS query was silently accepted")
		}
		if strings.Contains(err.Error(), "never-log-this") {
			t.Fatalf("secret value leaked: %v", err)
		}
	}
}

func TestLifecycleRefusesUnmanagedTestState(t *testing.T) {
	manager := New(t.TempDir(), DefaultCore, DefaultPort)
	if err := manager.verifyUnitOwnership(); err == nil {
		t.Fatal("arbitrary/test state cannot authorize installed systemd service mutations")
	}
}

func TestSharedLifecycleFlockSerializesIndependentOperations(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "state"), DefaultCore, DefaultPort)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- m.withLock(func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	second := make(chan error, 1)
	go func() { second <- m.withLock(func() error { return nil }) }()
	select {
	case err := <-second:
		t.Fatalf("second state operation escaped the shared lifecycle lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("lock not released to waiting operation")
	}
}
