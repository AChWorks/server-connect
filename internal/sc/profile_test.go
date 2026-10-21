package sc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testUUID = "c2902f3a-1c25-41ef-a8dc-760b483aa247"

func TestVLESSParsingAndLocalProxyAuth(t *testing.T) {
	tests := []struct {
		name, source string
		valid        bool
	}{
		{"tcp", "vless://" + testUUID + "@127.0.0.1:30303?security=none&type=tcp#Test%20connection", true},
		{"tls", "vless://" + testUUID + "@edge.example.org:443?type=ws&security=tls&sni=edge.example.org&path=%2Fws&host=edge.example.org", true},
		{"reality", "vless://" + testUUID + "@edge.example.org:443?type=tcp&security=reality&sni=example.org&pbk=AbCdEf1234&sid=1234", true},
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
	m := New(filepath.Join(dir, "state"), "/does/not/exist", DefaultUnit, DefaultPort)
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
	m := New(filepath.Join(dir, "state"), "", "", 0)
	if _, e := m.List(); e == nil {
		t.Fatal("symlinked state accepted")
	}
}
