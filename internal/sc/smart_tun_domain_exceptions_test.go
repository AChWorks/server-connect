package sc

import (
	"bytes"
	"encoding/json"
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
	invalid := []string{"", "bad name.test", "*.example.test", "example.test.", "8.8.8.8", "bad..test", "-bad.test", strings.Repeat("z", 64) + ".test"}
	for _, domain := range invalid {
		p, o := smartTUNFixture()
		o.DomainExceptions = []SmartTUNDomainException{{Domain: domain, Via: "direct"}}
		if _, err := SmartTUNCandidateConfig(p, o); err == nil {
			t.Errorf("accepted invalid domain %q", domain)
		}
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
	o.DomainExceptions = make([]SmartTUNDomainException, 129)
	if _, err := SmartTUNCandidateConfig(p, o); err == nil {
		t.Fatal("accepted unbounded operator policy")
	}
}
