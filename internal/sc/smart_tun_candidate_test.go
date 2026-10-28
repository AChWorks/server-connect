package sc

import (
	"encoding/json"
	"os"
	"testing"
)

func smartTUNFixture() (Profile, SmartTUNCandidateOptions) {
	return Profile{Outbound: json.RawMessage(`{"type":"vless","tag":"upstream","server":"8.8.8.8","server_port":443,"uuid":"c2902f3a-1c25-41ef-a8dc-760b483aa247"}`)},
		SmartTUNCandidateOptions{
			TunnelInterface: "sctunqa0", UnderlayInterface: "qaedge0", TunnelIPv4: "172.31.99.1/30",
			ProtectedCIDRs: []string{"203.0.113.42/32"},
			DomesticCIDRs:  []string{"5.22.0.0/17"},
			Exceptions:     []SmartTUNCIDRException{{CIDR: "1.1.1.0/24", Via: "direct"}},
		}
}

func TestSmartTUNCandidateRouteHierarchy(t *testing.T) {
	profile, o := smartTUNFixture()
	config, err := SmartTUNCandidateConfig(profile, o)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Inbounds []struct {
			Type         string   `json:"type"`
			AutoRoute    bool     `json:"auto_route"`
			AutoRedirect bool     `json:"auto_redirect"`
			StrictRoute  bool     `json:"strict_route"`
			Excluded     []string `json:"route_exclude_address"`
		} `json:"inbounds"`
		Route struct {
			Final            string `json:"final"`
			DefaultInterface string `json:"default_interface"`
			Rules            []struct {
				CIDRs    []string `json:"ip_cidr"`
				Action   string   `json:"action"`
				Outbound string   `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(config, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Inbounds) != 1 || v.Inbounds[0].Type != "tun" ||
		!v.Inbounds[0].AutoRoute || !v.Inbounds[0].AutoRedirect || !v.Inbounds[0].StrictRoute ||
		len(v.Inbounds[0].Excluded) < 6 {
		t.Fatal("not a real strict TUN with host underlay exceptions")
	}
	if v.Route.Final != "upstream" || v.Route.DefaultInterface != "qaedge0" || len(v.Route.Rules) != 3 {
		t.Fatalf("incorrect final/priority: %+v", v.Route)
	}
	if v.Route.Rules[0].Action != "bypass" || v.Route.Rules[0].Outbound != "direct" ||
		v.Route.Rules[1].Outbound != "direct" || v.Route.Rules[2].Outbound != "direct" {
		t.Fatal("incorrect route rule precedence")
	}
	if core := os.Getenv("SC_TEST_SINGBOX"); core != "" {
		if err := CheckConfig(core, t.TempDir(), config); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSmartTUNCandidateRejectsUnsafeConfigurations(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Profile, *SmartTUNCandidateOptions)
	}{
		{"same-interface", func(_ *Profile, o *SmartTUNCandidateOptions) { o.UnderlayInterface = o.TunnelInterface }},
		{"invalid-interface", func(_ *Profile, o *SmartTUNCandidateOptions) { o.UnderlayInterface = "bad;name" }},
		{"invalid-tun", func(_ *Profile, o *SmartTUNCandidateOptions) { o.TunnelIPv4 = "8.8.8.1/30" }},
		{"missing-domestic", func(_ *Profile, o *SmartTUNCandidateOptions) { o.DomesticCIDRs = nil }},
		{"ipv6-domestic", func(_ *Profile, o *SmartTUNCandidateOptions) { o.DomesticCIDRs = []string{"2001:db8::/32"} }},
		{"ipv6-operator", func(_ *Profile, o *SmartTUNCandidateOptions) {
			o.Exceptions = []SmartTUNCIDRException{{CIDR: "2001:db8::/32", Via: "vpn"}}
		}},
		{"ipv6-protected", func(_ *Profile, o *SmartTUNCandidateOptions) { o.ProtectedCIDRs = []string{"2001:db8::/32"} }},
		{"invalid-domestic", func(_ *Profile, o *SmartTUNCandidateOptions) { o.DomesticCIDRs = []string{"no-ip"} }},
		{"noncanonical-domestic", func(_ *Profile, o *SmartTUNCandidateOptions) { o.DomesticCIDRs = []string{"5.22.0.1/17"} }},
		{"global-bypass", func(_ *Profile, o *SmartTUNCandidateOptions) { o.ProtectedCIDRs = []string{"0.0.0.0/0"} }},
		{"protected-overlap", func(_ *Profile, o *SmartTUNCandidateOptions) {
			o.Exceptions = []SmartTUNCIDRException{{CIDR: "203.0.113.0/24", Via: "vpn"}}
		}},
		{"operator-overlap", func(_ *Profile, o *SmartTUNCandidateOptions) {
			o.Exceptions = []SmartTUNCIDRException{{CIDR: "1.1.1.0/24", Via: "vpn"}, {CIDR: "1.1.1.1/32", Via: "direct"}}
		}},
		{"bad-action", func(_ *Profile, o *SmartTUNCandidateOptions) {
			o.Exceptions = []SmartTUNCIDRException{{CIDR: "1.1.1.0/24", Via: "auto"}}
		}},
		{"hostname-upstream", func(p *Profile, _ *SmartTUNCandidateOptions) {
			p.Outbound = json.RawMessage(`{"type":"vless","tag":"upstream","server":"example.org"}`)
		}},
		{"no-real-upstream", func(p *Profile, _ *SmartTUNCandidateOptions) {
			p.Outbound = json.RawMessage(`{"type":"direct","tag":"upstream","server":"8.8.8.8"}`)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile, o := smartTUNFixture()
			tc.change(&profile, &o)
			if _, err := SmartTUNCandidateConfig(profile, o); err == nil {
				t.Fatal("unsafe config unexpectedly accepted")
			}
		})
	}
}
