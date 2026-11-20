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

// The output_prematch chain has its own TCP counter. It must not make an
// unrelated or incomplete redirect in the actual output chain look healthy.
// This was missed by replacing both fixtures' counters at the same time.
func TestNativeHealthRejectsOutputRedirectPartialDrift(t *testing.T) {
	p := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "enp5s0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	targets := []nativeProbeTarget{{IP: "8.8.8.8", Name: smartTUNHealthHTTPSName, Port: 19224}}
	key := "nft list table inet sing-box"
	for _, tc := range []struct {
		name, tcp string
	}{
		{"debian13-symbolic", "tcp"},
		{"debian12-numeric", "6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := nativeHealthPolicyFixture()
			body := base.values[key]
			if tc.tcp == "6" {
				body = strings.ReplaceAll(body, "meta l4proto tcp counter", "meta l4proto 6 counter")
			}
			if e := inspectNativeHealthPolicy(context.Background(), fakeNativeHealthPolicy{values: withNftHealthBody(base, body)}, p, targets); e != nil {
				t.Fatalf("intact TCP output rule refused: %v", e)
			}
			valid := "meta l4proto " + tc.tcp + " counter packets 2 bytes 80 redirect to :35785 return"
			for _, drift := range []struct {
				name, replacement string
			}{
				{"output-only-udp", "meta l4proto 17 counter packets 2 bytes 80 redirect to :35785 return"},
				{"output-only-uncounted", "meta l4proto " + tc.tcp + " redirect to :35785 return"},
				{"counter-and-redirect-separated", "meta l4proto " + tc.tcp + " counter packets 2 bytes 80 return\n      redirect to :35785 return"},
				{"tcp-counter-on-different-rule", "meta l4proto " + tc.tcp + " counter packets 2 bytes 80 return\n      meta l4proto 17 redirect to :35785 return"},
				{"redirect-before-tcp-match", "redirect to :35785 meta l4proto " + tc.tcp + " counter packets 2 bytes 80 return"},
				{"wrong-output-hook", "meta l4proto " + tc.tcp + " counter packets 2 bytes 80 redirect to :35785 return"},
			} {
				t.Run(drift.name, func(t *testing.T) {
					badBody := body
					if drift.name == "wrong-output-hook" {
						badBody = strings.Replace(badBody,
							"type nat hook output priority mangle + 2;",
							"type nat hook input priority mangle + 2;", 1)
						// A decoy in a different chain must not supply the hook.
						badBody = strings.Replace(badBody,
							"chain prerouting_prematch {",
							"chain prerouting_prematch {\n      type nat hook output priority mangle + 2;", 1)
					} else {
						badBody = strings.Replace(badBody, valid, drift.replacement, 1)
					}
					if badBody == body {
						t.Fatal("expected precise output-only fixture mutation")
					}
					bad := fakeNativeHealthPolicy{values: withNftHealthBody(base, badBody)}
					if e := inspectNativeHealthPolicy(context.Background(), bad, p, targets); e == nil {
						t.Fatalf("%s output-only drift falsely accepted as healthy", drift.name)
					}
				})
			}
		})
	}
}

// Earlier NAT output verdicts can bypass a valid later redirect. A marked
// route-get does not attest ordinary unmarked TCP capture. Recognize only the
// Core's legitimate narrowly scoped exclusions before the redirect.
func TestNativeHealthOutputPreRedirectVerdicts(t *testing.T) {
	p := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "enp5s0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	targets := []nativeProbeTarget{{IP: "8.8.8.8", Name: smartTUNHealthHTTPSName, Port: 19224}}
	key := "nft list table inet sing-box"
	for _, proto := range []string{"tcp", "6"} {
		t.Run(proto, func(t *testing.T) {
			fixture := nativeHealthPolicyFixture()
			base := fixture.values[key]
			if proto == "6" {
				base = strings.ReplaceAll(base, "meta l4proto tcp counter", "meta l4proto 6 counter")
			}
			redirect := "      meta l4proto " + proto + " counter packets 2 bytes 80 redirect to :35785 return"
			if !strings.Contains(base, redirect) {
				t.Fatal("missing actual output redirect in test witness")
			}
			coreRules := []string{
				"meta mark 0x00002024 counter packets 1 bytes 70 return",
				"ct mark 0x00002024 counter packets 1 bytes 70 return",
				"ct mark 0x00002023 counter packets 1 bytes 70 return",
				"ip daddr @inet4_local_address_set counter packets 1 bytes 70 return",
				"ip6 daddr @inet6_local_address_set counter packets 1 bytes 70 return",
				"meta nfproto ipv4 ip daddr @inet4_local_address_set counter packets 1 bytes 70 return",
				"meta nfproto ipv6 ip6 daddr @inet6_local_address_set counter packets 1 bytes 70 return",
				"meta nfproto ipv6 counter packets 1 bytes 70 reject",
				"meta l4proto " + proto + " tcp option 30 exists counter packets 1 bytes 70 drop",
				"meta l4proto " + proto + " tcp option mptcp present counter packets 1 bytes 70 drop",
				// Exact Debian12 nft 1.0.6 installed-Core rendering from
				// 44733846527: the TCP dependency is implicit in the option.
				"tcp option mptcp exists counter packets 0 bytes 0 drop",
			}
			// These originate from sing-tun's native mark/conntrack, own-host
			// address, unsupported family and MPTCP exception paths. No fixed
			// number of such rules is assumed by the reader.
			safeBody := strings.Replace(base, redirect, "      "+strings.Join(coreRules, "\n      ")+"\n"+redirect, 1)
			if err := inspectNativeHealthPolicy(context.Background(), fakeNativeHealthPolicy{values: withNftHealthBody(fixture, safeBody)}, p, targets); err != nil {
				t.Fatalf("legitimate Core output exemptions refused: %v", err)
			}
			for _, tc := range []struct{ name, rule string }{
				{"earlier-tcp-return", "meta l4proto " + proto + " return"},
				{"earlier-tcp-accept", "meta l4proto " + proto + " accept"},
				{"unconditional-return", "return"},
				{"unconditional-accept", "accept"},
				{"early-public-destination-return", "ip daddr 8.8.8.8 return"},
				{"early-unknown-mark-return", "ct mark 0x00002022 return"},
				{"early-udp-tcp-accept", "meta l4proto { tcp, udp } accept"},
				{"early-tcp-jump", "meta l4proto " + proto + " jump foreign"},
				{"early-tcp-goto", "meta l4proto " + proto + " goto foreign"},
				{"early-tcp-queue", "meta l4proto " + proto + " queue to 100"},
				{"early-tcp-dnat", "meta l4proto " + proto + " dnat ip to 10.10.10.1"},
				{"early-unrelated-tcp-option-drop", "tcp option maxseg exists counter packets 0 bytes 0 drop"},
				{"early-mptcp-without-option-test", "tcp option mptcp counter packets 0 bytes 0 drop"},
				{"early-tcp-misdirected-redirect", "meta l4proto " + proto + " redirect to :12345"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					bad := strings.Replace(safeBody, redirect, "      "+tc.rule+"\n"+redirect, 1)
					if bad == safeBody {
						t.Fatal("test did not insert a preceding verdict")
					}
					if err := inspectNativeHealthPolicy(context.Background(), fakeNativeHealthPolicy{values: withNftHealthBody(fixture, bad)}, p, targets); err == nil {
						t.Fatalf("early output rule %q bypassed a later healthy-looking TCP redirect", tc.rule)
					}
				})
			}
		})
	}
}

func withNftHealthBody(f fakeNativeHealthPolicy, body string) map[string]string {
	values := make(map[string]string, len(f.values))
	for k, v := range f.values {
		values[k] = v
	}
	values["nft list table inet sing-box"] = body
	return values
}
