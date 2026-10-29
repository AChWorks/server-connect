package sc

import (
	"encoding/json"
	"fmt"
	"net/netip"
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
		{"near-global-operator-direct", func(o *SmartTUNCandidateOptions) {
			o.IPv6Exceptions = []SmartTUNCIDRException{{CIDR: "2000::/3", Via: "direct"}}
		}},
		{"too-broad-operator-direct-63", func(o *SmartTUNCandidateOptions) {
			o.IPv6Exceptions = []SmartTUNCIDRException{{CIDR: "2001:db8:9::/63", Via: "direct"}}
		}},
		{"too-broad-domestic-31", func(o *SmartTUNCandidateOptions) {
			o.DomesticIPv6CIDRs = []string{"2001:db8::/31"}
		}},
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

func testCandidateIPv6Policy(t *testing.T, o SmartTUNCandidateOptions, accepted bool) {
	t.Helper()
	profile, _ := dualStackTUNFixture()
	config, err := SmartTUNCandidateConfig(profile, o)
	if accepted && (err != nil || len(config) == 0) {
		t.Fatalf("bounded IPv6 Direct candidate unexpectedly rejected: %v", err)
	}
	if !accepted && (err == nil || len(config) != 0) {
		t.Fatalf("unsafe IPv6 Direct candidate generated runnable config: %v", err)
	}
}

func TestSmartTUNIPv6DirectBreadthAndAggregateLimits(t *testing.T) {
	_, base := dualStackTUNFixture()
	// The existing narrow foreign Direct /128 and domestic VPN /128 remain valid.
	testCandidateIPv6Policy(t, base, true)
	_, boundary64 := dualStackTUNFixture()
	boundary64.IPv6Exceptions = []SmartTUNCIDRException{
		{CIDR: "2001:db8:9::/64", Via: "direct"},
		{CIDR: "2001:db8:5::10/128", Via: "vpn"},
	}
	testCandidateIPv6Policy(t, boundary64, true)
	_, invalid63 := dualStackTUNFixture()
	invalid63.IPv6Exceptions = []SmartTUNCIDRException{
		{CIDR: "2001:db8:9::/63", Via: "direct"},
	}
	testCandidateIPv6Policy(t, invalid63, false)
	_, global := dualStackTUNFixture()
	global.IPv6Exceptions = []SmartTUNCIDRException{{CIDR: "2000::/3", Via: "direct"}}
	testCandidateIPv6Policy(t, global, false)

	// A collection of individually allowed disjoint /64 Direct rules cannot
	// silently compose more than the accepted IPv6 operator Direct budget.
	for _, count := range []int{64, 65} {
		_, options := dualStackTUNFixture()
		options.IPv6Exceptions = nil
		for i := 0; i < count; i++ {
			addr := netip.MustParseAddr(fmt.Sprintf("2001:db8:9:%x::", i))
			optionsPrefix := netip.PrefixFrom(addr, 64).Masked().String()
			options.IPv6Exceptions = append(options.IPv6Exceptions,
				SmartTUNCIDRException{CIDR: optionsPrefix, Via: "direct"})
		}
		t.Run(fmt.Sprintf("operator-distinct-64s-%d", count), func(t *testing.T) {
			testCandidateIPv6Policy(t, options, count == 64)
		})
	}
	// Narrow exceptions inside the same /64 count once, not 64 times.
	_, narrow := dualStackTUNFixture()
	narrow.IPv6Exceptions = nil
	for i := 0; i < 65; i++ {
		narrow.IPv6Exceptions = append(narrow.IPv6Exceptions,
			SmartTUNCIDRException{CIDR: fmt.Sprintf("2001:db8:9::%x/128", i+1), Via: "direct"})
	}
	testCandidateIPv6Policy(t, narrow, true)
}

func TestSmartTUNIPv6SyntheticDomesticBreadthAndAggregate(t *testing.T) {
	_, narrow := dualStackTUNFixture()
	narrow.DomesticIPv6CIDRs = []string{"2001:db8::/32"}
	testCandidateIPv6Policy(t, narrow, true)
	_, tooBroad := dualStackTUNFixture()
	tooBroad.DomesticIPv6CIDRs = []string{"2001:db8::/31"}
	testCandidateIPv6Policy(t, tooBroad, false)
	for _, count := range []int{1024, 1025} {
		_, options := dualStackTUNFixture()
		options.DomesticIPv6CIDRs = nil
		for i := 0; i < count; i++ {
			addr := netip.MustParseAddr(fmt.Sprintf("2004:%x::", i))
			options.DomesticIPv6CIDRs = append(options.DomesticIPv6CIDRs,
				netip.PrefixFrom(addr, 32).Masked().String())
		}
		t.Run(fmt.Sprintf("domestic-distinct-32s-%d", count), func(t *testing.T) {
			testCandidateIPv6Policy(t, options, count == 1024)
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
