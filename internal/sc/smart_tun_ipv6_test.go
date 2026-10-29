package sc

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// The explicitly opted-in candidate is development-only: these documentation
// addresses are synthetic and are not Iranian prefix / field evidence.
func dualStackTUNFixture() (Profile, SmartTUNCandidateOptions) {
	p, o := smartTUNFixture()
	o.TunnelIPv6 = "fd73:99::1/64"
	o.ProtectedIPv6CIDRs = []string{"2001:db8:ffff::42/128"}
	o.DomesticIPv6CIDRs = []string{"2001:db8:5::/64"}
	o.IPv6Exceptions = []SmartTUNCIDRException{
		{CIDR: "2001:db8:5::10/128", Via: "vpn"},
		{CIDR: "2001:db8:8::9/128", Via: "direct"},
	}
	return p, o
}

func TestSmartTUNOptionalDualStackPrecedenceAndCore(t *testing.T) {
	profile, o := dualStackTUNFixture()
	raw, err := SmartTUNCandidateConfig(profile, o)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Address  []string `json:"address"`
			Excluded []string `json:"route_exclude_address"`
			Strict   bool     `json:"strict_route"`
		} `json:"inbounds"`
		Route struct {
			Final string `json:"final"`
			Rules []struct {
				CIDRs    []string `json:"ip_cidr"`
				Action   string   `json:"action"`
				Outbound string   `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 || !config.Inbounds[0].Strict ||
		!slices.Equal(config.Inbounds[0].Address, []string{"172.31.99.1/30", "fd73:99::1/64"}) ||
		config.Route.Final != "upstream" {
		t.Fatalf("unexpected opt-in dual-stack TUN: %+v", config)
	}
	for _, need := range []string{"::1/128", "fc00::/7", "fe80::/10", "2001:db8:ffff::42/128"} {
		if !slices.Contains(config.Inbounds[0].Excluded, need) {
			t.Fatalf("essential IPv6 protection missing: %s", need)
		}
	}
	var order []string
	for _, rule := range config.Route.Rules {
		if len(rule.CIDRs) > 0 {
			order = append(order, rule.CIDRs[0]+"="+rule.Action+"/"+rule.Outbound)
		}
	}
	expected := []string{
		"127.0.0.0/8=bypass/direct",
		"1.1.1.0/24=route/direct",
		"2001:db8:5::10/128=route/upstream",
		"2001:db8:8::9/128=route/direct",
		"5.22.0.0/17=route/direct",
		"2001:db8:5::/64=route/direct",
	}
	if !slices.Equal(order, expected) {
		t.Fatalf("IPv4/IPv6 protected, operator and domestic precedence incorrect: %v", order)
	}
	if core := os.Getenv("SC_TEST_SINGBOX"); core != "" {
		if err := CheckConfig(core, t.TempDir(), raw); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSmartTUNOptionalDualStackFailClosedInvalidConfigurations(t *testing.T) {
	cases := []struct {
		name string
		edit func(*SmartTUNCandidateOptions)
	}{
		{"unarmed-domestic-v6", func(o *SmartTUNCandidateOptions) { o.TunnelIPv6 = "" }},
		{"invalid-address", func(o *SmartTUNCandidateOptions) { o.TunnelIPv6 = "2001:db8::1/64" }},
		{"ipv4-address", func(o *SmartTUNCandidateOptions) { o.TunnelIPv6 = "10.1.1.2/30" }},
		{"noncanonical-tun", func(o *SmartTUNCandidateOptions) { o.TunnelIPv6 = "fd73:99::1/63" }},
		{"missing-domestic", func(o *SmartTUNCandidateOptions) { o.DomesticIPv6CIDRs = nil }},
		{"ipv4-domestic", func(o *SmartTUNCandidateOptions) { o.DomesticIPv6CIDRs = []string{"5.22.0.0/17"} }},
		{"noncanonical-domestic", func(o *SmartTUNCandidateOptions) { o.DomesticIPv6CIDRs = []string{"2001:db8:5::1/64"} }},
		{"broad-domestic", func(o *SmartTUNCandidateOptions) { o.DomesticIPv6CIDRs = []string{"2000::/3"} }},
		{"duplicate-domestic", func(o *SmartTUNCandidateOptions) {
			o.DomesticIPv6CIDRs = []string{"2001:db8:5::/64", "2001:db8:5::/64"}
		}},
		{"private-domestic", func(o *SmartTUNCandidateOptions) { o.DomesticIPv6CIDRs = []string{"fd73:99::/64"} }},
		{"broad-protection", func(o *SmartTUNCandidateOptions) { o.ProtectedIPv6CIDRs = []string{"2001:db8:ffff::/48"} }},
		{"operator-protected-overlap", func(o *SmartTUNCandidateOptions) {
			o.IPv6Exceptions = []SmartTUNCIDRException{{CIDR: "fc00::/8", Via: "vpn"}}
		}},
		{"operator-duplicate", func(o *SmartTUNCandidateOptions) {
			o.IPv6Exceptions = []SmartTUNCIDRException{{CIDR: "2001:db8:5::10/128", Via: "vpn"}, {CIDR: "2001:db8:5::10/128", Via: "direct"}}
		}},
		{"operator-overlap", func(o *SmartTUNCandidateOptions) {
			o.IPv6Exceptions = []SmartTUNCIDRException{{CIDR: "2001:db8:8::/64", Via: "vpn"}, {CIDR: "2001:db8:8::10/128", Via: "direct"}}
		}},
		{"operator-invalid-action", func(o *SmartTUNCandidateOptions) {
			o.IPv6Exceptions = []SmartTUNCIDRException{{CIDR: "2001:db8:8::9/128", Via: "auto"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, o := dualStackTUNFixture()
			tc.edit(&o)
			if _, err := SmartTUNCandidateConfig(p, o); err == nil {
				t.Fatal("unsafe optional IPv6 candidate was accepted")
			}
		})
	}
}

func TestSmartTUNDoesNotAccidentallyEnableIPv6FromUntrustedList(t *testing.T) {
	p, o := smartTUNFixture()
	for _, mutate := range []func(*SmartTUNCandidateOptions){
		func(o *SmartTUNCandidateOptions) { o.DomesticIPv6CIDRs = []string{"2001:db8:5::/64"} },
		func(o *SmartTUNCandidateOptions) {
			o.IPv6Exceptions = []SmartTUNCIDRException{{CIDR: "2001:db8:8::9/128", Via: "direct"}}
		},
		func(o *SmartTUNCandidateOptions) { o.ProtectedIPv6CIDRs = []string{"2001:db8:ffff::42/128"} },
	} {
		mutate(&o)
		if _, err := SmartTUNCandidateConfig(p, o); err == nil || !strings.Contains(err.Error(), "IPv6") {
			t.Fatalf("IPv6 without explicit TUN address was accepted: %v", err)
		}
		o = SmartTUNCandidateOptions{}
		_, o = smartTUNFixture()
	}
}
