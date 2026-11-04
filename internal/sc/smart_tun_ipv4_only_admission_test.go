package sc

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

func ipv4OnlyIPv6Host(routes, rules string) HostPreflight {
	return HostPreflight{IPv6Routes: json.RawMessage(routes), IPv6Rules: json.RawMessage(rules)}
}

const ipv6DefaultRules = `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`

func TestIPv4OnlyNativeAdmissionRejectsUnprotectedIPv6(t *testing.T) {
	// IPv4-only TUN does not provide working public IPv6-over-VPN; refuse
	// potential public IPv6 paths before guard prearm rather than relying on
	// the active inet guard to drop those paths.
	for _, tc := range []struct{ name, routes, rules string }{
		{"global_default", `[{"dst":"default","gateway":"fe80::1","dev":"ens3","protocol":"ra","metric":1024,"flags":[],"pref":"medium"}]`, ipv6DefaultRules},
		{"global_connected", `[{"dst":"2001:4860:4860::/64","dev":"ens3","protocol":"kernel","metric":256,"flags":[],"pref":"medium"}]`, ipv6DefaultRules},
		{"global_local_address", `[{"type":"local","dst":"2001:4860:4860::15","dev":"ens3","table":"local","protocol":"kernel","metric":0,"flags":[],"pref":"medium"}]`, ipv6DefaultRules},
		{"public_documentation_route", `[{"dst":"2001:db8::/32","dev":"ens3"}]`, ipv6DefaultRules},
		{"indirect_linklocal_nhid", `[{"dst":"fe80::/64","dev":"ens3","nhid":18}]`, ipv6DefaultRules},
		{"indirect_linklocal_via", `[{"dst":"fe80::/64","dev":"ens3","via":{"family":"inet6","addr":"fe80::1"}}]`, ipv6DefaultRules},
		{"foreign_table", `[{"dst":"fe80::/64","dev":"ens3","table":"83"}]`, ipv6DefaultRules},
		{"nonlocal_blackhole", `[{"type":"blackhole","dst":"2001:4860::/32","table":"main"}]`, ipv6DefaultRules},
		{"empty_explicit_type", `[{"dst":"fe80::/64","dev":"ens3","type":""}]`, ipv6DefaultRules},
		{"empty_explicit_table", `[{"dst":"fe80::/64","dev":"ens3","table":""}]`, ipv6DefaultRules},
		{"bad_metric", `[{"dst":"fe80::/64","dev":"ens3","metric":-1}]`, ipv6DefaultRules},
		{"nonempty_flags", `[{"dst":"fe80::/64","dev":"ens3","flags":["onlink"]}]`, ipv6DefaultRules},
		{"linkdown_plus_foreign_flag", `[{"dst":"fe80::/64","dev":"ens3","flags":["linkdown","onlink"]}]`, ipv6DefaultRules},
		{"duplicate_linkdown", `[{"dst":"fe80::/64","dev":"ens3","flags":["linkdown","linkdown"]}]`, ipv6DefaultRules},
		{"public_route_still_rejected_when_linkdown", `[{"dst":"2001:4860::/64","dev":"ens3","flags":["linkdown"]}]`, ipv6DefaultRules},
		{"forged_prefsrc", `[{"dst":"fe80::/64","dev":"ens3","prefsrc":"2001:4860::1"}]`, ipv6DefaultRules},
		{"extra_selector", `[{"dst":"fe80::/64","dev":"ens3","from":"2001:4860::/32"}]`, ipv6DefaultRules},
		{"broad_linklocal_mask", `[{"dst":"fe80::/8","dev":"ens3"}]`, ipv6DefaultRules},
		{"forged_unicast_multicast", `[{"dst":"ff00::/8","dev":"ens3"}]`, ipv6DefaultRules},
		{"duplicate_native_member", `[{"dst":"fe80::/64","dev":"ens3","dev":"lo"}]`, ipv6DefaultRules},
		{"case_ambiguous_native_member", `[{"dst":"fe80::/64","dev":"ens3","Dev":"lo"}]`, ipv6DefaultRules},
		{"null_route", `[null]`, ipv6DefaultRules},
		{"missing_routes", `null`, ipv6DefaultRules},
		{"missing_rules", `[]`, `null`},
		{"foreign_rpdb", `[]`, `[{"priority":0,"src":"all","table":"local"},{"priority":100,"src":"all","table":"83"},{"priority":32766,"src":"all","table":"main"}]`},
		{"goto_rpdb", `[]`, `[{"priority":0,"src":"all","table":"local"},{"priority":100,"src":"all","goto":32766},{"priority":32766,"src":"all","table":"main"}]`},
		{"missing_local_rpdb", `[]`, `[{"priority":32766,"src":"all","table":"main"}]`},
		{"duplicate_rpdb", `[]`, `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32766,"src":"all","table":"main"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := nativeIPv4OnlyIPv6Admission(ipv4OnlyIPv6Host(tc.routes, tc.rules))
			if ErrorCode(err) != "trial_resource_conflict" || !strings.Contains(err.Error(), "IPv6") {
				t.Fatalf("unsafe IPv6 path not refused by native admission: %v", err)
			}
		})
	}
}

func TestIPv4OnlyNativeAdmissionPreservesLocalIPv6(t *testing.T) {
	const observedKernel = `[
      {"dst":"fe80::/64","dev":"ens3","protocol":"kernel","metric":256,"flags":[],"pref":"medium"},
      {"type":"local","dst":"::1","dev":"lo","table":"local","protocol":"kernel","metric":0,"flags":[],"pref":"medium"},
      {"type":"local","dst":"fe80::216:3eff:fe92:6a83","dev":"ens3","table":"local","protocol":"kernel","metric":0,"flags":[],"pref":"medium"},
      {"type":"multicast","dst":"ff00::/8","dev":"ens3","table":"local","protocol":"kernel","metric":256,"flags":[],"pref":"medium"}
    ]`
	const safeULA = `[{"dst":"fd00:1234::/64","dev":"ens3","protocol":"kernel","metric":256,"flags":[],"pref":"medium"}]`
	for _, tc := range []struct{ name, routes, rules string }{
		{"ipv6_disabled", `[]`, ipv6DefaultRules},
		{"real_linux_linklocal_only", observedKernel, ipv6DefaultRules},
		{"private_ula", safeULA, ipv6DefaultRules},
		{"linklocal_during_reconnect", `[{"dst":"fe80::/64","dev":"scqavm0","flags":["linkdown"]}]`, ipv6DefaultRules},
		{"private_ula_during_reconnect", `[{"dst":"fd00:1234::/64","dev":"scqavm0","flags":["linkdown"]}]`, ipv6DefaultRules},
		{"local_multicast_during_reconnect", `[{"type":"multicast","dst":"ff00::/8","dev":"scqavm0","table":"local","flags":["linkdown"]}]`, ipv6DefaultRules},
		{"optional_native_default_rpdb", `[]`, `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := nativeIPv4OnlyIPv6Admission(ipv4OnlyIPv6Host(tc.routes, tc.rules)); err != nil {
				t.Fatalf("private/local IPv6 native state incorrectly refused: %v", err)
			}
		})
	}
}

func TestIPv4OnlyNativeAdmissionRechecksLiveIPv6(t *testing.T) {
	// A newly learned public IPv6 route while the IPv4-only TUN is live
	// cannot reuse an earlier successful pre-admission observation.
	tests := []struct {
		name, routes, rules string
		failStep            int
		refuse              bool
	}{
		{"unchanged_loopback_and_linklocal", `[{"dst":"fe80::/64","dev":"ens3"}]`, ipv6DefaultRules, 0, false},
		{"disconnected_tun_linklocal_during_reconnect", `[{"dst":"fe80::/64","dev":"scqavm0","flags":["linkdown"]}]`, ipv6DefaultRules, 0, false},
		{"new_global_ra", `[{"dst":"default","dev":"ens3","gateway":"fe80::1"}]`, ipv6DefaultRules, 0, true},
		{"new_foreign_ipv6_rule", `[]`, `[{"priority":0,"src":"all","table":"local"},{"priority":100,"src":"all","table":"99"},{"priority":32766,"src":"all","table":"main"}]`, 0, true},
		{"route_read_failed", `[]`, ipv6DefaultRules, 1, true},
		{"rule_read_failed", `[]`, ipv6DefaultRules, 2, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			count := 0
			read := func(args ...string) (json.RawMessage, error) {
				count++
				if count == 1 {
					if !slices.Equal(args, []string{"-j", "-6", "route", "show", "table", "all"}) {
						t.Fatalf("wrong route observation: %v", args)
					}
					if tc.failStep == 1 {
						return nil, errors.New("iproute2 unavailable")
					}
					return json.RawMessage(tc.routes), nil
				}
				if !slices.Equal(args, []string{"-j", "-6", "rule", "show"}) {
					t.Fatalf("wrong RPDB observation: %v", args)
				}
				if tc.failStep == 2 {
					return nil, errors.New("iproute2 unavailable")
				}
				return json.RawMessage(tc.rules), nil
			}
			err := nativeIPv4OnlyIPv6Current(read)
			if (err != nil) != tc.refuse {
				t.Fatalf("IPv6 recheck error=%v, refusal expected=%v", err, tc.refuse)
			}
			if tc.refuse && ErrorCode(err) != "trial_resource_conflict" {
				t.Fatalf("unexpected refusal taxonomy: %v", err)
			}
			wantCalls := 2
			if tc.failStep == 1 {
				wantCalls = 1
			}
			if count != wantCalls {
				t.Fatalf("read count=%d want %d", count, wantCalls)
			}
		})
	}
}

func TestNativeTUNAdmissionRefusesPublicIPv6BeforeHostResourceChecks(t *testing.T) {
	_, opts := smartTUNFixture()
	opts.TunnelIPv6 = ""
	// Host Links, native nftables and namespace identity are intentionally
	// not provided: the early admission must reject IPv6 BEFORE probing any
	// of those later resources or arming a recovery service.
	host := ipv4OnlyIPv6Host(`[{"dst":"default","dev":"ens3","gateway":"fe80::1"}]`, ipv6DefaultRules)
	if _, err := nativeTUNAdmission(opts, host); ErrorCode(err) != "trial_resource_conflict" ||
		!strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("public IPv6 was not refused at the earliest admission boundary: %v", err)
	}
}
