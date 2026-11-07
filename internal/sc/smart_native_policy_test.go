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
	intercept := routeRules[0].(map[string]any)
	if intercept["port"] != float64(53) || intercept["action"] != "hijack-dns" {
		t.Fatal("DNS must be intercepted before ordinary IP/geo routing")
	}
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
