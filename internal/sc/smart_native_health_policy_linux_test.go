//go:build linux

package sc

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeNativeHealthPolicy struct{ values map[string]string }

func (f fakeNativeHealthPolicy) output(_ context.Context, bin string, args ...string) (string, error) {
	key := bin + " " + strings.Join(args, " ")
	value, ok := f.values[key]
	if !ok {
		return "", errors.New("missing expected read-only kernel witness: " + key)
	}
	return value, nil
}
func nativeHealthPolicyFixture() fakeNativeHealthPolicy {
	ipv4 := "0: from all lookup local\n1: from all lookup 3362254344\n14200: from all fwmark 0x2024 goto 14202\n14201: from all fwmark 0x2023 lookup 27432\n14202: from all nop\n32766: from all lookup main\n32767: from all lookup default\n32768: not from all fwmark 0x2024 lookup 27432\n"
	ipv6 := strings.Replace(ipv4, "32767: from all lookup default\n", "", 1)
	return fakeNativeHealthPolicy{values: map[string]string{
		"ip -N -4 rule show":                           ipv4,
		"ip -N -6 rule show":                           ipv6,
		"ip -4 route show table 27432":                 "default via 172.31.99.2 dev sctun0\n",
		"ip -N -4 route get 8.8.8.8 mark 0x2023":       "8.8.8.8 via 172.31.99.2 dev sctun0 table 27432 src 172.31.99.1 mark 0x2023 uid 0\n",
		"ip -N -4 route get 198.51.100.42 mark 0x2023": "198.51.100.42 via 172.31.99.2 dev sctun0 table 27432 src 172.31.99.1 mark 0x2023 uid 0\n",
		"nft list tables":                              "table inet sc_reply_guard\ntable inet sing-box\n",
		"nft -j list table inet sc_reply_guard":        nativeReplyGuardFixtureJSON,
		"nft list table inet sing-box": `table inet sing-box {
    chain prerouting_prematch {
      type filter hook prerouting priority dstnat - 1; policy accept;
      iifname "sctun0" return
    }
    chain output_prematch {
      type route hook output priority mangle + 1; policy accept;
      meta l4proto tcp counter packets 2 bytes 80 queue flags bypass to 100
    }
    chain output {
      type nat hook output priority mangle + 2; policy accept;
      meta l4proto tcp counter packets 2 bytes 80 redirect to :35785 return
    }
    chain prerouting {
      type nat hook prerouting priority dstnat + 2; policy accept;
      iifname "sctun0" return
    }
}`,
	}}
}

// Health proof must never accept an unrelated priority-30000 clone of the
// fixed fallback, nor report healthy while the actual fallback is missing.
func TestNativeHealthRefusesMissingAndForeignFallbackPriority(t *testing.T) {
	p := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "enp5s0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	targets := []nativeProbeTarget{{IP: "8.8.8.8", Name: smartTUNHealthHTTPSName, Port: 19224}}
	for _, tc := range []struct{ name, old, replace string }{
		{"missing-32768", "32768: not from all fwmark 0x2024 lookup 27432\n", ""},
		{"foreign-lookalike-30000", "32768: not from all fwmark 0x2024 lookup 27432",
			"30000: not from all fwmark 0x2024 lookup 27432\n32768: not from all fwmark 0x2024 lookup 27432"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := nativeHealthPolicyFixture()
			r.values["ip -N -4 rule show"] = strings.Replace(r.values["ip -N -4 rule show"], tc.old, tc.replace, 1)
			if err := inspectNativeHealthPolicy(context.Background(), r, p, targets); err == nil {
				t.Fatal("missing or foreign fixed fallback accepted as healthy")
			}
		})
	}
}

func TestNativeHealthMarkedRoutingAttestation(t *testing.T) {
	p := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "enp5s0", Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	targets := []nativeProbeTarget{{IP: "8.8.8.8", Name: smartTUNHealthHTTPSName, Port: 19224}, {IP: "198.51.100.42", Name: smartTUNHealthHTTPSName, Port: 19224}}
	fixture := nativeHealthPolicyFixture()
	if err := inspectNativeHealthPolicy(context.Background(), fixture, p, targets); err != nil {
		t.Fatalf("expected active marked native capture: %v", err)
	}
	// The actual Debian 12 guest emits numeric IPPROTO_TCP 6, not the
	// human-readable tcp alias. Keep the explicit TCP counter check while
	// refusing a UDP-only, mark-only or uncounted replacement.
	debian12 := nativeHealthPolicyFixture()
	debian12.values["nft list table inet sing-box"] = strings.ReplaceAll(
		debian12.values["nft list table inet sing-box"],
		"meta l4proto tcp counter", "meta l4proto 6 counter")
	if err := inspectNativeHealthPolicy(context.Background(), debian12, p, targets); err != nil {
		t.Fatalf("Debian 12 nft numeric TCP capture refused: %v", err)
	}
	for _, variant := range []struct{ name, from, to string }{
		{"udp-only", "meta l4proto 6 counter", "meta l4proto 17 counter"},
		{"missing-counter", "meta l4proto 6 counter", "meta l4proto 6"},
		{"wrong-proto", "meta l4proto 6 counter", "meta l4proto 7 counter"},
	} {
		t.Run("debian12-"+variant.name, func(t *testing.T) {
			bad := nativeHealthPolicyFixture()
			bad.values["nft list table inet sing-box"] = strings.ReplaceAll(
				debian12.values["nft list table inet sing-box"], variant.from, variant.to)
			if err := inspectNativeHealthPolicy(context.Background(), bad, p, targets); err == nil {
				t.Fatal("missing or non-TCP counter falsely accepted as healthy")
			}
		})
	}
	for _, tc := range []struct{ name, key, old, replace string }{
		{"missing-v4-fwmark", "ip -N -4 rule show", "14201: from all fwmark 0x2023 lookup 27432\n", ""},
		{"foreign-v6-fwmark", "ip -N -6 rule show", "14201: from all fwmark 0x2023 lookup 27432", "14201: from all fwmark 0x2023 lookup 254"},
		{"wrong-mark-route", "ip -N -4 route get 8.8.8.8 mark 0x2023", "dev sctun0 table 27432", "dev enp5s0 table main"},
		{"partial-tun-policy", "ip -4 route show table 27432", "dev sctun0", "dev enp5s0"},
		{"removed-nft-output", "nft list table inet sing-box", "chain output {", "chain wrong_output {"},
		{"foreign-nft-chain", "nft list table inet sing-box", "chain prerouting {", "chain injected {"},
		{"disabled-output-capture", "nft list table inet sing-box", "redirect to :35785", "accept"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := nativeHealthPolicyFixture()
			f.values[tc.key] = strings.Replace(f.values[tc.key], tc.old, tc.replace, 1)
			if e := inspectNativeHealthPolicy(context.Background(), f, p, targets); e == nil {
				t.Fatal("changed kernel routing accepted as selected VPN proof")
			}
		})
	}
}
