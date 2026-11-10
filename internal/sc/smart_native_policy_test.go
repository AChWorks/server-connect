package sc

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func nativePolicyFixture() (Profile, NativePolicyOptions) {
	return Profile{
		ID: "1234567890abcdef", Kind: "vless-link",
		Outbound: json.RawMessage("{\"type\":\"vless\",\"tag\":\"upstream\",\"server\":\"8.8.8.8\",\"server_port\":443,\"uuid\":\"c2902f3a-1c25-41ef-a8dc-760b483aa247\"}"),
	}, NativePolicyOptions{
		InterfaceName: "sctun0", UnderlayInterface: "ens3",
		IPv4Address: "172.31.99.1/30", IPv6Address: "fd73:99::1/64",
		Mode: "bypass_iran",
	}
}

func nativePolicyJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestNativeSmartPolicyUsesOfficialSingBox(t *testing.T) {
	profile, o := nativePolicyFixture()
	before := append([]byte(nil), profile.Outbound...)
	rules := []SmartRoutingRule{
		{Type: "cidr", Value: "9.9.9.9/32", Via: "vpn"},
		{Type: "cidr", Value: "1.1.1.0/24", Via: "direct"},
		{Type: "domain", Value: "example.org", Via: "vpn"},
	}
	raw, err := NativeSmartRoutingConfig(profile, o, rules)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, profile.Outbound) {
		t.Fatal("selected profile mutated")
	}
	root := nativePolicyJSON(t, raw)
	inbound := root["inbounds"].([]any)[0].(map[string]any)
	if inbound["stack"] != "gvisor" {
		t.Fatal("selected native stack must reassemble fragmented IPv6 UDP rather than write packets back")
	}
	for _, key := range []string{"auto_route", "auto_redirect", "strict_route"} {
		if inbound[key] != true {
			t.Fatalf("%s not enabled", key)
		}
	}
	if inbound["dns_mode"] != "disabled" {
		t.Fatal("platform DNS must remain unmodified; TUN route rule handles nonlocal DNS")
	}
	if inbound["iproute2_table_index"] != float64(NativePolicyTableIndex) ||
		inbound["iproute2_rule_index"] != float64(NativePolicyRuleIndex) {
		t.Fatal("native recovery cannot identify policy-owned RPDB slots")
	}
	if _, ok := inbound["route_exclude_address_set"]; ok {
		t.Fatal("kernel IR bypass overrides manual VPN")
	}
	route := root["route"].(map[string]any)
	if route["final"] != "upstream" || route["default_interface"] != "ens3" || route["default_domain_resolver"] != "bootstrap" {
		t.Fatal("wrong selected VPN default or safe endpoint binding")
	}
	routeRules := route["rules"].([]any)
	if len(routeRules) < 2 {
		t.Fatal("native DNS interception and ordinary traffic routing are missing")
	}
	if routeRules[0].(map[string]any)["ip_is_private"] != true {
		t.Fatal("private destinations must be matched before DNS hijack")
	}
	// See TestNativeSmartPolicyDNSAddressPrecedence for explicit IP/geo
	// ordering and the unmatched-DNS resolver fallback.
	sets := route["rule_set"].([]any)
	if len(sets) != 1 {
		t.Fatal("expected one inline native IR rule-set")
	}
	geo := sets[0].(map[string]any)
	if geo["type"] != "inline" || geo["tag"] != "iran-public" {
		t.Fatal("invalid native rule-set")
	}
	countries := geo["rules"].([]any)[0].(map[string]any)["ip_cidr"].([]any)
	if len(countries) != 3038 {
		t.Fatalf("unexpected verified IR prefix count %d", len(countries))
	}
	joined, _ := json.Marshal(route["rules"])
	idxOverride := strings.Index(string(joined), "9.9.9.9/32")
	idxIran := strings.Index(string(joined), "iran-public")
	if idxOverride < 0 || idxIran < 0 || idxOverride >= idxIran {
		t.Fatal("operator VPN override must precede Iran Direct")
	}
	dns := root["dns"].(map[string]any)
	if dns["reverse_mapping"] != false || strings.Contains(string(raw), "fakeip") {
		t.Fatal("unproven FakeIP or reverse-map route introduced")
	}
	servers := dns["servers"].([]any)
	if dns["final"] != "vpn-dns" || servers[1].(map[string]any)["detour"] != "upstream" {
		t.Fatal("default application DNS not tunnel-detoured")
	}
	if core := os.Getenv("SC_TEST_SINGBOX"); core != "" {
		if err := EnsureCore(core); err != nil {
			t.Fatalf("official pinned Core identity: %v", err)
		}
		if err := CheckConfig(core, t.TempDir(), raw); err != nil {
			t.Fatalf("real official Core rejected generated config: %v", err)
		}
	}
}

func TestNativeSmartPolicyDefaultModeAndDeterminism(t *testing.T) {
	p, o := nativePolicyFixture()
	o.Mode = "default"
	o.IPv6Address = ""
	a := []SmartRoutingRule{{Type: "cidr", Value: "1.1.1.0/24", Via: "direct"}, {Type: "cidr", Value: "9.9.9.9/32", Via: "vpn"}}
	b := []SmartRoutingRule{a[1], a[0]}
	configA, err := NativeSmartRoutingConfig(p, o, a)
	if err != nil {
		t.Fatal(err)
	}
	configB, err := NativeSmartRoutingConfig(p, o, b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(configA, configB) {
		t.Fatal("rule ordering should be deterministic")
	}
	root := nativePolicyJSON(t, configA)
	if len(root["route"].(map[string]any)["rule_set"].([]any)) != 0 {
		t.Fatal("default mode may not exempt Iran")
	}
	if core := os.Getenv("SC_TEST_SINGBOX"); core != "" {
		if err := CheckConfig(core, t.TempDir(), configA); err != nil {
			t.Fatalf("core rejected default native mode: %v", err)
		}
	}
}

func TestNativeSmartPolicyUnsafeInputsRejected(t *testing.T) {
	p, o := nativePolicyFixture()
	baseline := []SmartRoutingRule{{Type: "cidr", Value: "1.1.1.0/24", Via: "direct"}}
	cases := []struct {
		name   string
		modify func(*Profile, *NativePolicyOptions, *[]SmartRoutingRule)
	}{
		{"interface loopback", func(_ *Profile, x *NativePolicyOptions, _ *[]SmartRoutingRule) { x.InterfaceName = "lo" }},
		{"underlay equal tun", func(_ *Profile, x *NativePolicyOptions, _ *[]SmartRoutingRule) { x.UnderlayInterface = x.InterfaceName }},
		{"unknown mode", func(_ *Profile, x *NativePolicyOptions, _ *[]SmartRoutingRule) { x.Mode = "other" }},
		{"invalid IPv4", func(_ *Profile, x *NativePolicyOptions, _ *[]SmartRoutingRule) { x.IPv4Address = "172.31.0.1/8" }},
		{"missing IPv6 bypass", func(_ *Profile, x *NativePolicyOptions, _ *[]SmartRoutingRule) { x.IPv6Address = "" }},
		{"global IPv6", func(_ *Profile, x *NativePolicyOptions, _ *[]SmartRoutingRule) { x.IPv6Address = "2001:db8::1/64" }},
		{"duplicate operator", func(_ *Profile, _ *NativePolicyOptions, r *[]SmartRoutingRule) { *r = append(*r, baseline[0]) }},
		{"Direct domain not verified", func(_ *Profile, _ *NativePolicyOptions, r *[]SmartRoutingRule) {
			*r = append(*r, SmartRoutingRule{Type: "domain", Value: "example.org", Via: "direct"})
		}},
		{"foreign selector", func(p *Profile, _ *NativePolicyOptions, _ *[]SmartRoutingRule) {
			p.Outbound = json.RawMessage("{\"tag\":\"upstream\",\"type\":\"vless\",\"server\":\"8.8.8.8\",\"detour\":\"other\"}")
		}},
		{"nonremote outbound", func(p *Profile, _ *NativePolicyOptions, _ *[]SmartRoutingRule) {
			p.Outbound = json.RawMessage("{\"tag\":\"upstream\",\"type\":\"direct\"}")
		}},
		{"duplicate outbound keys", func(p *Profile, _ *NativePolicyOptions, _ *[]SmartRoutingRule) {
			p.Outbound = json.RawMessage("{\"tag\":\"upstream\",\"tag\":\"other\",\"type\":\"vless\"}")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := o
			q := p
			rules := append([]SmartRoutingRule(nil), baseline...)
			tc.modify(&q, &x, &rules)
			if _, err := NativeSmartRoutingConfig(q, x, rules); err == nil {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
}

func TestNativeSmartPolicyForeignDefaultIsVPN(t *testing.T) {
	p, o := nativePolicyFixture()
	raw, err := NativeSmartRoutingConfig(p, o, nil)
	if err != nil {
		t.Fatal(err)
	}
	route := nativePolicyJSON(t, raw)["route"].(map[string]any)
	if route["final"] != "upstream" {
		t.Fatal("foreign default lost VPN")
	}
	rules := route["rules"].([]any)
	last := rules[len(rules)-1].(map[string]any)
	if last["outbound"] != "direct" || last["action"] != "route" {
		t.Fatal("IR exception must remain last")
	}
	if _, ok := last["rule_set"]; !ok {
		t.Fatal("final Direct rule lacks IR selector")
	}
}

// The official Core evaluates route rules in order. In particular, a
// port-53 hijack must not preempt explicit Direct/VPN CIDRs, local DNS, or
// the domestic Direct rule while leaving unmatched DNS on the selected VPN.
func TestNativeSmartPolicyDNSAddressPrecedence(t *testing.T) {
	p, base := nativePolicyFixture()
	operator := []SmartRoutingRule{
		{Type: "cidr", Value: "8.8.8.8/32", Via: "direct"},
		{Type: "cidr", Value: "9.9.9.9/32", Via: "vpn"},
		{Type: "cidr", Value: "2001:4860:4860::8888/128", Via: "direct"},
		{Type: "domain", Value: "example.org", Via: "vpn"},
	}
	for _, mode := range []string{"default", "bypass_iran"} {
		t.Run(mode, func(t *testing.T) {
			o := base
			o.Mode = mode
			config, err := NativeSmartRoutingConfig(p, o, operator)
			if err != nil {
				t.Fatal(err)
			}
			rules := nativePolicyJSON(t, config)["route"].(map[string]any)["rules"].([]any)
			index := func(match func(map[string]any) bool) int {
				t.Helper()
				found := -1
				for n, raw := range rules {
					if match(raw.(map[string]any)) {
						if found != -1 {
							t.Fatal("ambiguous native rule selector")
						}
						found = n
					}
				}
				return found
			}
			isCIDR := func(cidr, outbound string) func(map[string]any) bool {
				return func(rule map[string]any) bool {
					values, ok := rule["ip_cidr"].([]any)
					return ok && len(values) == 1 && values[0] == cidr && rule["outbound"] == outbound
				}
			}
			hijack := index(func(r map[string]any) bool { return r["action"] == "hijack-dns" && r["port"] == float64(53) })
			private := index(func(r map[string]any) bool { return r["ip_is_private"] == true && r["action"] == "bypass" })
			if hijack < 0 || private < 0 || private >= hijack {
				t.Fatal("local or private DNS could be intercepted by selected VPN DNS")
			}
			for _, tc := range []struct{ cidr, outbound string }{
				{"8.8.8.8/32", "direct"}, {"9.9.9.9/32", "upstream"}, {"2001:4860:4860::8888/128", "direct"},
			} {
				i := index(isCIDR(tc.cidr, tc.outbound))
				if i < 0 || i >= hijack {
					t.Fatalf("DNS to operator %s %s preempted by hijack-dns", tc.outbound, tc.cidr)
				}
			}
			countryDNS := index(func(r map[string]any) bool {
				_, ok := r["rule_set"]
				return ok && r["port"] == float64(53) && r["outbound"] == "direct"
			})
			countryOther := index(func(r map[string]any) bool {
				_, ok := r["rule_set"]
				return ok && r["port"] == nil && r["outbound"] == "direct"
			})
			if mode == "bypass_iran" {
				if countryDNS <= private || countryDNS >= hijack || countryOther <= hijack {
					t.Fatal("domestic DNS Direct must precede hijack, other domestic Direct must follow VPN-domain policy")
				}
			} else if countryDNS != -1 || countryOther != -1 {
				t.Fatal("default mode must not silently bypass Iranian public DNS")
			}
			if index(func(r map[string]any) bool { return r["action"] == "sniff" }) <= hijack {
				t.Fatal("unmatched DNS should not pay the TCP TLS/HTTP sniff timeout")
			}
			if core := os.Getenv("SC_TEST_SINGBOX"); core != "" {
				if err := CheckConfig(core, t.TempDir(), config); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
