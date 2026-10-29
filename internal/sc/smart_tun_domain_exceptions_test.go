package sc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestSmartTUNDomainExceptionOrdering(t *testing.T) {
	p, o := smartTUNFixture()
	o.DomainExceptions = []SmartTUNDomainException{
		{Domain: "example.test", Suffix: true, Via: "vpn"},
		{Domain: "sub.example.test", Via: "vpn"},
		{Domain: "EXAMPLE.TEST", Via: "vpn"},
	}
	raw, err := SmartTUNCandidateConfig(p, o)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Route struct {
			Rules []struct {
				Action       string   `json:"action"`
				Outbound     string   `json:"outbound"`
				Domain       []string `json:"domain"`
				DomainSuffix []string `json:"domain_suffix"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	r := cfg.Route.Rules
	if len(r) != 7 || r[0].Action != "bypass" || r[2].Action != "sniff" ||
		r[3].Domain[0] != "sub.example.test" || r[3].Outbound != "upstream" ||
		r[4].Domain[0] != "example.test" || r[4].Outbound != "upstream" ||
		r[5].DomainSuffix[0] != ".example.test" || r[5].Outbound != "upstream" {
		t.Fatalf("unexpected rule ordering: %+v", r)
	}
	o.DomainExceptions[0], o.DomainExceptions[2] = o.DomainExceptions[2], o.DomainExceptions[0]
	shuffled, err := SmartTUNCandidateConfig(p, o)
	if err != nil || !bytes.Equal(raw, shuffled) {
		t.Fatal("config depends on policy order", err)
	}
	if core := os.Getenv("SC_TEST_SINGBOX"); core != "" {
		if err := CheckConfig(core, t.TempDir(), raw); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSmartTUNDomainExceptionAdmission(t *testing.T) {
	// Each rejected name must be tested with an otherwise VALID VPN route.
	// A Direct route would be rejected regardless of the name, masking a
	// regression in the domain validator.
	invalid := []struct {
		name, domain, expectedError string
	}{
		{"empty", "", "invalid operator domain"},
		{"whitespace", "bad name.test", "invalid operator domain"},
		{"wildcard", "*.example.test", "invalid operator domain"},
		{"trailing-dot", "example.test.", "invalid operator domain label"},
		{"literal-ip", "8.8.8.8", "IP address cannot be a domain exception"},
		{"empty-label", "bad..test", "invalid operator domain label"},
		{"hyphen-edge", "-bad.test", "invalid operator domain label"},
		{"long-label", strings.Repeat("z", 64) + ".test", "invalid operator domain label"},
		{"single-label-exact", "localhost", "exact domain exception requires a fully qualified name"},
		{"url", "https://example.test", "invalid operator domain"},
		{"non-ascii", "مثال.test", "invalid operator domain label"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			// Inspect the specific rejection, independent of the generic
			// config-compiler admission message.
			_, err := canonicalSmartTUNDomain(tc.domain, false)
			if err == nil || !strings.Contains(err.Error(), tc.expectedError) {
				t.Fatalf("domain %q: validator returned %v; want %q", tc.domain, err, tc.expectedError)
			}
			p, o := smartTUNFixture()
			o.DomainExceptions = []SmartTUNDomainException{{Domain: tc.domain, Via: "vpn"}}
			if _, err := SmartTUNCandidateConfig(p, o); err == nil {
				t.Fatalf("compiler accepted malformed VPN-only domain %q", tc.domain)
			}
		})
	}
	p, o := smartTUNFixture()
	o.DomainExceptions = []SmartTUNDomainException{{Domain: "example.test", Via: "vpn"}, {Domain: "EXAMPLE.TEST", Via: "vpn"}}
	if _, err := SmartTUNCandidateConfig(p, o); err == nil {
		t.Fatal("accepted duplicate canonical exception")
	}
	o.DomainExceptions = []SmartTUNDomainException{{Domain: "example.test", Via: "direct"}}
	if _, err := SmartTUNCandidateConfig(p, o); err == nil {
		t.Fatal("accepted spoofable Direct policy based only on Host/SNI")
	}
	o.DomainExceptions = []SmartTUNDomainException{{Domain: "example.test", Via: "auto"}}
	if _, err := SmartTUNCandidateConfig(p, o); err == nil {
		t.Fatal("accepted invalid outbound")
	}
	// Both sides of the limit use valid, unique names AND valid VPN routes.
	// Empty entries or disallowed Direct dispositions would make the 129-case
	// pass even if the resource limit were accidentally removed.
	valid := make([]SmartTUNDomainException, 129)
	for i := range valid {
		valid[i] = SmartTUNDomainException{
			Domain: fmt.Sprintf("route-%03d.example.test", i),
			Via:    "vpn",
		}
	}
	o.DomainExceptions = valid[:128]
	if _, err := SmartTUNCandidateConfig(p, o); err != nil {
		t.Fatalf("rejected 128 valid VPN-only domain exceptions: %v", err)
	}
	o.DomainExceptions = valid
	if _, err := SmartTUNCandidateConfig(p, o); err == nil || !strings.Contains(err.Error(), "too many operator domain exceptions") {
		t.Fatalf("129 valid VPN-only exceptions must fail the resource bound: %v", err)
	}
}
