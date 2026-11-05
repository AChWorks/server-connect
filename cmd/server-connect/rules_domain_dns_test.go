package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

func TestRoutingRulesCLIDirectDomainsUseExplicitDNSCorrelatedPreview(t *testing.T) {
	m := rulesCLIManager(t)
	rc, out, stderr := captureRulesCommand(t, m, "smart-routing-rules", "add", "--domain", "direct.example.org", "--via", "direct")
	if rc != 0 || out["ok"] != true {
		t.Fatalf("save Direct domain: %d %+v %s", rc, out, stderr)
	}
	profile, err := sc.ValidateSource([]byte("vless://c2902f3a-1c25-41ef-a8dc-760b483aa247@8.8.8.8:443?type=tcp&security=none#QA"), "")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(profile)
	if err := os.Mkdir(filepath.Join(m.Dir, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.Dir, "profiles", profile.ID+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Select(profile.ID); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(m.Dir, "smart-routing-rules.json"))
	args := []string{"smart-routing-rules", "preview", "--tunnel-if", "sctunqa0", "--underlay-if", "qaedge0", "--tunnel-ipv4", "172.31.99.1/30", "--domestic-cidr", "5.22.0.0/17"}
	rc, out, _ = captureRulesCommand(t, m, args...)
	if rc == 0 || out["ok"] != false {
		t.Fatal("plain preview admitted Direct domain")
	}
	args = append(args, "--domain-dns-ipv4", "1.1.1.1", "--domain-dns-name", "cloudflare-dns.com")
	rc, out, stderr = captureRulesCommand(t, m, args...)
	if rc != 0 || out["ok"] != true {
		t.Fatalf("correlated CLI: %d %+v %s", rc, out, stderr)
	}
	result := ruleResult(t, out)
	capture, ok := result["dns_capture"].(map[string]any)
	if !ok || capture["ipv4_pool"] != sc.SmartTUNDomainFakeIPv4 || capture["real_ip_reverse_mapping"] != false || result["activation_ready"] != false || result["validation_level"] != "native_dns_correlated_policy_compile_only" {
		t.Fatalf("incorrect CLI scope: %+v", result)
	}
	for _, tail := range [][]string{
		{"--domain-dns-ipv4", "1.1.1.1"},
		{"--domain-dns-name", "cloudflare-dns.com"},
		{"--domain-dns-port", "443"},
		{"--domain-dns-ipv4", "", "--domain-dns-name", "cloudflare-dns.com"},
		{"--domain-dns-ipv4", "1.1.1.1", "--domain-dns-name", "cloudflare-dns.com", "--domain-dns-port", "0"},
	} {
		invalid := append(append([]string{}, args[:len(args)-4]...), tail...)
		rc, out, _ = captureRulesCommand(t, m, invalid...)
		if rc == 0 || out["ok"] != false {
			t.Fatalf("incomplete DNS controls accepted: %v", tail)
		}
	}
	after, _ := os.ReadFile(filepath.Join(m.Dir, "smart-routing-rules.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("preview altered saved rules")
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "route-activation-journal.json")); !os.IsNotExist(err) {
		t.Fatal("preview created activation journal")
	}
}
