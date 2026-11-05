package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

// Exercise the actual CLI argument routing with a saved but entirely synthetic
// selected profile; no external sing-box process, tunnel or kernel mutation.
func TestRoutingRulesCLIBundledIRSourcePreviewAndMixedInputRefusal(t *testing.T) {
	m := rulesCLIManager(t)
	profile, err := sc.ValidateSource([]byte("vless://c2902f3a-1c25-41ef-a8dc-760b483aa247@node.example.org:443?type=tcp&security=tls#Native"), "")
	if err != nil {
		t.Fatal(err)
	}
	rawProfile, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.Dir, "profiles", profile.ID+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, rawProfile, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Select(profile.ID); err != nil {
		t.Fatal(err)
	}
	savedState, err := os.ReadFile(filepath.Join(m.Dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"smart-routing-rules", "preview",
		"--tunnel-if", "sctunqa0", "--underlay-if", "qaedge0",
		"--tunnel-ipv4", "172.31.99.1/30", "--domestic-source", "bundled-ir-estimate",
		"--endpoint-pin-ipv4", "8.8.8.8"}
	for _, extra := range [][]string{nil, {"--tunnel-ipv6", "fd73:98::1/64"}} {
		flags := append(append([]string(nil), args...), extra...)
		code, out, stderr := captureRulesCommand(t, m, flags...)
		if len(extra) != 0 {
			if code == 0 || out["ok"] != false {
				t.Fatalf("unsupported broad IPv6 estimate accepted: %+v", out)
			}
			continue
		}
		if code != 0 || stderr != "" || out["ok"] != true {
			t.Fatalf("source preview failed: %d %+v %s", code, out, stderr)
		}
		data := ruleResult(t, out)
		estimate, ok := data["domestic_estimate"].(map[string]any)
		if !ok || estimate["ipv4_count"] != float64(2024) ||
			estimate["ipv6_count"] != float64(1014) ||
			estimate["publisher_signature_verified"] != false ||
			estimate["safe_for_geographic_routing"] != false ||
			estimate["activation_ready"] != false ||
			data["activation_ready"] != false || data["applied"] != false ||
			data["validation_level"] != "native_policy_compile_only" ||
			len(data["native_config_sha256"].(string)) != 64 {
			t.Fatalf("unsigned IR estimate preview claimed readiness: %+v", data)
		}
	}
	for _, extra := range [][]string{
		{"--domestic-cidr", "5.22.0.0/17"},
		{"--domestic-ipv6-cidr", "2a01:1::/32"},
		{"--domestic-source", "untrusted-list"},
	} {
		flags := append(append([]string(nil), args...), extra...)
		code, out, _ := captureRulesCommand(t, m, flags...)
		if code == 0 || out["ok"] != false {
			t.Fatalf("conflicting source flags accepted: %+v -> %+v", flags, out)
		}
	}
	afterProfile, err := os.ReadFile(path)
	if err != nil || string(afterProfile) != string(rawProfile) {
		t.Fatal("CLI preview modified the private profile")
	}
	afterState, err := os.ReadFile(filepath.Join(m.Dir, "state.json"))
	if err != nil || string(afterState) != string(savedState) {
		t.Fatal("CLI preview changed saved mode/selection")
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "smart-routing-rules.json")); !os.IsNotExist(err) {
		t.Fatal("CLI preview saved the unsigned dataset as rules")
	}
}
