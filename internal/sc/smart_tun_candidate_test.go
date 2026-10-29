package sc

import (
	"encoding/json"
	"fmt"
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
			DNSMode      string   `json:"dns_mode"`
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
		v.Inbounds[0].DNSMode != "disabled" ||
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
		{"single-public-broad-protection", func(_ *Profile, o *SmartTUNCandidateOptions) {
			o.ProtectedCIDRs = []string{"8.0.0.0/8"}
		}},
		{"two-complementary-half-space-protections", func(_ *Profile, o *SmartTUNCandidateOptions) {
			o.ProtectedCIDRs = []string{"0.0.0.0/1", "128.0.0.0/1"}
		}},
		{"overlapping-protected-controls", func(_ *Profile, o *SmartTUNCandidateOptions) {
			o.ProtectedCIDRs = []string{"203.0.113.40/29", "203.0.113.44/30"}
		}},
		{"aggregate-narrow-protected-controls", func(_ *Profile, o *SmartTUNCandidateOptions) {
			o.ProtectedCIDRs = nil
			for i := 0; i < 9; i++ {
				o.ProtectedCIDRs = append(o.ProtectedCIDRs, fmt.Sprintf("203.0.113.%d/29", i*8))
			}
		}},
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

func TestSmartTUNCandidateAllowsNarrowManagementAndUnderlay(t *testing.T) {
	profile, o := smartTUNFixture()
	// The private underlay is already protected by the built-in private block;
	// a narrow public management subnet and host require explicit admission.
	o.ProtectedCIDRs = []string{"10.254.72.0/30", "198.51.100.40/29", "203.0.113.42/32"}
	config, err := SmartTUNCandidateConfig(profile, o)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Inbounds []struct {
			Excluded []string `json:"route_exclude_address"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Inbounds) != 1 {
		t.Fatal("missing TUN inbound")
	}
	has := make(map[string]bool)
	for _, prefix := range v.Inbounds[0].Excluded {
		has[prefix] = true
	}
	if !has["10.0.0.0/8"] || !has["198.51.100.40/29"] || !has["203.0.113.42/32"] {
		t.Fatalf("narrow control or private underlay not protected: %v", v.Inbounds[0].Excluded)
	}
}

func TestSmartTUNCandidateAllowsBoundedAggregate(t *testing.T) {
	profile, o := smartTUNFixture()
	o.ProtectedCIDRs = nil
	for i := 0; i < 8; i++ {
		o.ProtectedCIDRs = append(o.ProtectedCIDRs, fmt.Sprintf("203.0.113.%d/29", i*8))
	}
	if _, err := SmartTUNCandidateConfig(profile, o); err != nil {
		t.Fatalf("64 narrowly identified protected addresses should be allowed: %v", err)
	}
}
