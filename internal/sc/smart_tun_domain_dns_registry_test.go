package sc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRoutingRulesDirectDomainsRequireExplicitCorrelatedCompilation(t *testing.T) {
	m := rulesManager(t)
	profile, opts := smartTUNFixture()
	profile.ID = "0123456789abcdef"
	opts.Exceptions = nil
	if err := m.withLock(func() error {
		raw, _ := json.Marshal(profile)
		if err := put(filepath.Join(m.Dir, "profiles", profile.ID+".json"), raw); err != nil {
			return err
		}
		return m.save(State{Version: 1, Selected: profile.ID, Desired: "direct", Port: m.Port})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddSmartRoutingRule(SmartRoutingRule{Type: "domain", Value: "direct.example.org", Via: "direct"}); err != nil {
		t.Fatal(err)
	}
	list := []byte("suffix direct example.net\ndomain vpn vpn.example.net\n")
	sum := sha256.Sum256(list)
	if _, err := m.ImportSmartRoutingRules("local", "2026-10-01", hex.EncodeToString(sum[:]), "", list); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(m.Dir, smartRoutingRulesFilename))
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, _ := os.ReadFile(filepath.Join(m.Dir, "state.json"))
	if _, err := m.PreviewSmartRoutingRulesPinned(opts, ""); ErrorCode(err) != "routing_rules_invalid" {
		t.Fatalf("sniff-only preview admitted Direct domains: %v", err)
	}
	preview, err := m.PreviewSmartRoutingRulesDNSCorrelatedPinned(opts, "", domainDNSFixture())
	if err != nil {
		t.Fatal(err)
	}
	if preview.ActivationReady || preview.Applied || preview.HostNetworkInspected || preview.CoreExecutionTested || preview.RuleCount != 3 || preview.ValidationLevel != "native_dns_correlated_policy_compile_only" || preview.DNSCapture == nil {
		t.Fatalf("false correlated preview evidence: %+v", preview)
	}
	capture := preview.DNSCapture
	if capture.NameSource != "operation_owned_core_fakeip_map" || capture.IPv4Pool != SmartTUNDomainFakeIPv4 || capture.IPv6Pool != "" ||
		!capture.HijackBeforeProtected || capture.RealIPReverseMapping || capture.DNSPort != 53 || len(capture.DNSNetworks) != 2 || capture.ActivationReady {
		t.Fatalf("capture metadata: %+v", capture)
	}
	second, err := m.PreviewSmartRoutingRulesDNSCorrelatedPinned(opts, "", domainDNSFixture())
	if err != nil || second.NativeConfigSHA256 != preview.NativeConfigSHA256 {
		t.Fatal("non-deterministic correlated preview", err)
	}
	after, _ := os.ReadFile(filepath.Join(m.Dir, smartRoutingRulesFilename))
	stateAfter, _ := os.ReadFile(filepath.Join(m.Dir, "state.json"))
	if !bytes.Equal(before, after) || !bytes.Equal(stateBefore, stateAfter) {
		t.Fatal("preview changed saved policy/state")
	}
	if _, err := os.Stat(filepath.Join(m.Dir, activationJournalFilename)); !os.IsNotExist(err) {
		t.Fatal("preview created an activation operation")
	}
	opts.DomesticCIDRs = nil
	opts.TunnelIPv6 = "fd73:98::1/64"
	bundled, err := m.PreviewSmartRoutingRulesBundledEstimateDNSCorrelatedPinned(opts, "", domainDNSFixture())
	if err != nil {
		t.Fatal(err)
	}
	if bundled.DomesticEstimate == nil || bundled.DomesticEstimate.IPv6Count != 1014 || bundled.DomesticEstimate.PublisherSignatureVerified || bundled.DomesticEstimate.SafeForGeographicRouting || bundled.DNSCapture.IPv6Pool != SmartTUNDomainFakeIPv6 {
		t.Fatalf("bundled correlated preview: %+v", bundled)
	}
}
