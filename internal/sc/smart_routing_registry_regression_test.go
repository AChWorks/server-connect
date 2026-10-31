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

func routingRegistryFixture(t *testing.T) (*Manager, []byte) {
	t.Helper()
	m := rulesManager(t)
	if _, err := m.AddSmartRoutingRule(SmartRoutingRule{Type: "cidr", Value: "8.8.8.8/32", Via: "vpn"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(m.Dir, smartRoutingRulesFilename))
	if err != nil {
		t.Fatal(err)
	}
	return m, raw
}

func assertRoutingRegistryUnchanged(t *testing.T, m *Manager, original []byte) {
	t.Helper()
	current, err := os.ReadFile(filepath.Join(m.Dir, smartRoutingRulesFilename))
	if err != nil || !bytes.Equal(original, current) {
		t.Fatalf("rejected policy changed saved file bytes: err=%v", err)
	}
	view, err := m.InspectSmartRoutingRules()
	if err != nil || view.Revision != 1 || len(view.Rules) != 1 || view.ActivationReady {
		t.Fatalf("rejected policy changed revision or activation state: %+v %v", view, err)
	}
}

func TestRoutingRegistryR1IPv6SpecialPurposeRejectsAllEntryPaths(t *testing.T) {
	invalid := []string{
		"100::/64",          // discard-only
		"100:0:0:1::/64",    // dummy prefix
		"2001::/64",         // Teredo/IETF protocol
		"2001:2::/64",       // benchmarking
		"2001:db8::/64",     // documentation
		"2002::/64",         // 6to4
		"3fff::/64",         // documentation
		"5f00::/64",         // SRv6
		"64:ff9b::/96",      // translation
		"2620:4f:8000::/64", // special AS112 anycast
	}
	for _, cidr := range invalid {
		t.Run(cidr, func(t *testing.T) {
			m, original := routingRegistryFixture(t)
			for _, via := range []string{"direct", "vpn"} {
				rule := SmartRoutingRule{Type: "cidr", Value: cidr, Via: via}
				if _, err := m.AddSmartRoutingRule(rule); err == nil {
					t.Fatalf("manual accepted special-purpose IPv6 %s via %s", cidr, via)
				}
				assertRoutingRegistryUnchanged(t, m, original)
				raw := []byte("cidr " + via + " " + cidr + "\n")
				digest := sha256.Sum256(raw)
				if _, err := m.ImportSmartRoutingRules("untrusted", "2026-10-01", hex.EncodeToString(digest[:]), "", raw); err == nil {
					t.Fatalf("import accepted special-purpose IPv6 %s via %s", cidr, via)
				}
				assertRoutingRegistryUnchanged(t, m, original)
				p, o := smartTUNFixture()
				o.TunnelIPv6 = "fd73:99::1/64"
				o.DomesticIPv6CIDRs = []string{"2001:4860::/32"}
				o.IPv6Exceptions = []SmartTUNCIDRException{{CIDR: cidr, Via: via}}
				if _, err := SmartTUNCandidateConfig(p, o); err == nil {
					t.Fatalf("native candidate accepted IPv6 special purpose %s via %s", cidr, via)
				}
				// Synthetic domestic source is separately supplied to the
				// preview compiler and must not evade the same IANA admission.
				o.IPv6Exceptions = nil
				o.DomesticIPv6CIDRs = []string{cidr}
				if _, err := SmartTUNCandidateConfig(p, o); err == nil {
					t.Fatalf("native domestic policy accepted special IPv6 %s", cidr)
				}
			}
		})
	}
}

func TestRoutingRegistryR1AllowOrdinaryPublicIPv6(t *testing.T) {
	for _, cidr := range []string{"2001:4860::/64", "2606:4700::/64", "2a00:1450::/64"} {
		t.Run(cidr, func(t *testing.T) {
			m := rulesManager(t)
			if _, err := m.AddSmartRoutingRule(SmartRoutingRule{Type: "cidr", Value: cidr, Via: "direct"}); err != nil {
				t.Fatal(err)
			}
			p, o := smartTUNFixture()
			o.TunnelIPv6 = "fd73:99::1/64"
			o.DomesticIPv6CIDRs = []string{"2001:4860::/32"}
			o.IPv6Exceptions = []SmartTUNCIDRException{{CIDR: cidr, Via: "direct"}}
			if _, err := SmartTUNCandidateConfig(p, o); err != nil {
				t.Fatalf("native compiler rejected accepted IPv6: %v", err)
			}
		})
	}
}

func TestRoutingRegistryR2PSLRejectsWholePublicSuffixes(t *testing.T) {
	invalid := []string{"co.uk", "com.au", "github.io", "blogspot.com", "com", "unknown-root.unrecognizedtld"}
	for _, root := range invalid {
		t.Run(root, func(t *testing.T) {
			m, original := routingRegistryFixture(t)
			r := SmartRoutingRule{Type: "suffix", Value: root, Via: "vpn"}
			if _, err := m.AddSmartRoutingRule(r); err == nil {
				t.Fatalf("manual accepted whole PSL suffix %s", root)
			}
			assertRoutingRegistryUnchanged(t, m, original)
			raw := []byte("suffix vpn " + root + "\n")
			h := sha256.Sum256(raw)
			if _, err := m.ImportSmartRoutingRules("source", "2026-10-01", hex.EncodeToString(h[:]), "", raw); err == nil {
				t.Fatalf("import accepted whole PSL suffix %s", root)
			}
			assertRoutingRegistryUnchanged(t, m, original)
			p, o := smartTUNFixture()
			o.DomainExceptions = []SmartTUNDomainException{{Domain: root, Suffix: true, Via: "vpn"}}
			if _, err := SmartTUNCandidateConfig(p, o); err == nil {
				t.Fatalf("native compiler accepted whole suffix %s", root)
			}
		})
	}
}
func TestRoutingRegistryR2PSLAcceptsRegistrantDomains(t *testing.T) {
	good := []string{"example.co.uk", "test.example.co.uk", "example.com.au", "user.github.io", "test.user.github.io", "foo.example.org"}
	for _, name := range good {
		t.Run(name, func(t *testing.T) {
			m := rulesManager(t)
			if _, err := m.AddSmartRoutingRule(SmartRoutingRule{Type: "suffix", Value: name, Via: "vpn"}); err != nil {
				t.Fatalf("manual rejected registrable suffix: %v", err)
			}
			p, o := smartTUNFixture()
			o.DomainExceptions = []SmartTUNDomainException{{Domain: name, Suffix: true, Via: "vpn"}}
			if _, err := SmartTUNCandidateConfig(p, o); err != nil {
				t.Fatalf("native rejected registrable suffix: %v", err)
			}
			// Imported path must use same policy, with a different valid source/rule.
			raw := []byte("suffix vpn " + name + "\n")
			h := sha256.Sum256(raw)
			imported := rulesManager(t)
			if _, err := imported.ImportSmartRoutingRules("source", "2026-10-01", hex.EncodeToString(h[:]), "", raw); err != nil {
				t.Fatalf("import rejected registrable suffix: %v", err)
			}
		})
	}
}
func TestRoutingRegistryR1R2CorruptedSavedStateFailsClosed(t *testing.T) {
	cases := []SmartRoutingRule{
		{Type: "cidr", Value: "100::/64", Via: "direct"},
		{Type: "suffix", Value: "co.uk", Via: "vpn"},
	}
	for _, r := range cases {
		t.Run(r.Value, func(t *testing.T) {
			m, _ := routingRegistryFixture(t)
			file := filepath.Join(m.Dir, smartRoutingRulesFilename)
			tampered := smartRoutingRulesDocument{
				Version: 1, Revision: 2, Manual: []SmartRoutingRule{r},
				Imports: []smartRoutingRuleSource{},
			}
			b, err := json.Marshal(tampered)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := m.InspectSmartRoutingRules(); err == nil {
				t.Fatal("untrusted saved rule accepted")
			}
			_, candidate := smartTUNFixture()
			if _, err := m.PreviewSmartRoutingRules(candidate); err == nil {
				t.Fatal("preview accepted invalid saved rule before profile checks")
			}
			if _, err := m.AddSmartRoutingRule(SmartRoutingRule{Type: "cidr", Value: "9.9.9.9/32", Via: "vpn"}); err == nil {
				t.Fatal("invalid existing state overwritten")
			}
			after, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(b, after) {
				t.Fatalf("tampered saved bytes modified: %v", err)
			}
		})
	}
}
