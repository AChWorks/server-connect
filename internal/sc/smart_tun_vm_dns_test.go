package sc

import (
	"encoding/json"
	"strings"
	"testing"
)

// All these lexical IPv4 addresses must remain outside the tiny experimental
// public DNS allowlist, including addresses assigned to the exact QEMU ingress.
var smartTUNVMReservedDNSCases = []struct{ name, addr string }{
	{"test-net-1", "192.0.2.53"},
	{"test-net-2", "198.51.100.53"},
	{"test-net-3", "203.0.113.53"},
	{"qa-ingress", smartTUNVMIngressIP},
	{"qa-ingress-peer", smartTUNVMIngressPeerIP},
	{"shared-space-low", "100.64.0.1"},
	{"shared-space-high", "100.127.255.254"},
	{"benchmark-low", "198.18.0.1"},
	{"benchmark-high", "198.19.255.254"},
	{"reserved-240", "240.0.0.1"},
	{"rfc1918", "172.16.0.1"},
	{"guest-tun-address", "172.31.99.1"},
	{"nonallowlisted-public", "8.8.8.8"},
}

func TestSmartTUNVMOwnedLinkDNSQACrashGate(t *testing.T) {
	if !nativeTUNQAKillValid("after-native-dns-effect", true) ||
		nativeTUNQAKillValid("after-native-dns-effect", false) {
		t.Fatal("partial DNS fault injection has incorrect apply/recover scope")
	}
	// This must be rejected before even installed-path or privileged
	// platform inspection; a QA crash flag cannot silently do nothing.
	m := New(t.TempDir(), DefaultCore, DefaultPort)
	_, err := m.BeginSmartTUNTrial(qaVMPolicyFixture(), smartTUNVMEndpoint, 180, "after-native-dns-effect")
	if ErrorCode(err) != "invalid_arguments" {
		t.Fatalf("missing DNS policy accepted privileged crash point: %v", err)
	}
}

func TestSmartTUNVMOwnedLinkDNSPolicyFailClosed(t *testing.T) {
	o := qaVMPolicyFixture()
	o.Exceptions = nil
	for _, test := range []struct {
		name, resolver string
		allowed        bool
	}{
		{"empty-unchanged", "", true},
		{"public-resolver", "1.1.1.1", true},
		{"second-public-resolver", "9.9.9.9", true},
		{"protected-underlay", "10.0.2.2", false},
		{"localhost", "127.0.0.1", false},
		{"link-local", "169.254.1.1", false},
		{"domestic-direct", "5.22.0.10", false},
		{"health-witness", "1.0.0.1", false},
		{"ipv6", "2606:4700:4700::1111", false},
		{"ipv4-in-ipv6", "::ffff:1.1.1.1", false},
		{"invalid", "not-an-ip", false},
		{"unspecified", "0.0.0.0", false},
		{"broadcast", "255.255.255.255", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := o
			candidate.DNSResolverIPv4 = test.resolver
			if got := smartTUNVMPolicySupported(candidate); got != test.allowed {
				t.Fatalf("unexpected DNS admission %q: %v", test.resolver, got)
			}
			if test.resolver != "" && smartTUNTrialFixturePolicySupported(candidate) {
				t.Fatal("a QEMU-only DNS resolver entered the legacy Docker trial")
			}
		})
	}
	for _, test := range smartTUNVMReservedDNSCases {
		t.Run("special-"+test.name, func(t *testing.T) {
			candidate := o
			candidate.DNSResolverIPv4 = test.addr
			if smartTUNVMPolicySupported(candidate) {
				t.Fatalf("reserved/fixture resolver admitted: %s", test.addr)
			}
		})
	}
	o.DNSResolverIPv4 = "1.1.1.1"
	o.Exceptions = []SmartTUNCIDRException{{CIDR: "1.1.1.0/24", Via: "direct"}}
	if smartTUNVMPolicySupported(o) {
		t.Fatal("Direct CIDR was allowed to intercept a configured VPN-only DNS resolver")
	}
	if smartTUNVMPolicySupported(func() SmartTUNCandidateOptions {
		s := savedSmartTUNFixture()
		s.DNSResolverIPv4 = "1.1.1.1"
		return s
	}()) {
		t.Fatal("non-VM route policy accepted VM link DNS")
	}
}

func TestSmartTUNVMResolverEffectPossibleFiniteStates(t *testing.T) {
	const expected = "1.1.1.1"
	cases := []struct {
		name, stage, dns, domain string
		owned                    bool
	}{
		{"planned-clean", "planned", "", "", true},
		{"planned-first-setter", "planned", expected, "", false},
		{"planned-complete", "planned", expected, "~.", false},
		{"planned-domain-only", "planned", "", "~.", false},
		{"effect-not-started", "effect_possible", "", "", true},
		{"effect-first-setter", "effect_possible", expected, "", true},
		{"effect-both-setters", "effect_possible", expected, "~.", true},
		{"effect-domain-only-foreign", "effect_possible", "", "~.", false},
		{"effect-foreign-resolver", "effect_possible", "8.8.8.8", "", false},
		{"effect-foreign-both", "effect_possible", "8.8.8.8", "~.", false},
		{"effect-foreign-domain", "effect_possible", expected, "~local", false},
		{"effect-extra-domain", "effect_possible", expected, "~. ~other", false},
		{"effect-unrelated-resolver", "effect_possible", "9.9.9.9", "~.", false},
		{"observed-exact", "observed", expected, "~.", true},
		{"observed-incomplete", "observed", expected, "", false},
		{"observed-domain-only", "observed", "", "~.", false},
		{"observed-empty", "observed", "", "", false},
		{"observed-foreign", "observed", "8.8.8.8", "~.", false},
		{"removed-link-present-empty", "removed", "", "", false},
		{"removed-link-present-full", "removed", expected, "~.", false},
		{"removed-link-present-domain-only", "removed", "", "~.", false},
		{"unknown-stage", "unknown", expected, "~.", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeTUNVMResolverStateOwned(tc.stage, expected, tc.dns, tc.domain); got != tc.owned {
				t.Fatalf("stage=%s dns=%q domain=%q accepted=%t expected=%t", tc.stage, tc.dns, tc.domain, got, tc.owned)
			}
		})
	}
	if !nativeTUNVMResolverStateOwned("effect_possible", "9.9.9.9", "9.9.9.9", "") ||
		nativeTUNVMResolverStateOwned("effect_possible", "9.9.9.9", "1.1.1.1", "") {
		t.Fatal("partial DNS state did not bind to the chosen approved resolver")
	}
}

func TestSmartTUNVMResolverStrictLinkObservation(t *testing.T) {
	for _, test := range []struct {
		name, value, wanted string
		valid               bool
	}{
		{"single-IP", "Link 3 (scqavm0): 1.1.1.1\n", "1.1.1.1", true},
		{"single-domain", "Link 3 (scqavm0): ~.\n", "~.", true},
		{"empty", "Link 3 (scqavm0):\n", "", true},
		{"wrong-interface", "Link 3 (tun-other): 1.1.1.1\n", "", false},
		{"wrong-index", "Link 4 (scqavm0): 1.1.1.1\n", "", false},
		{"multi-DNS", "Link 3 (scqavm0): 1.1.1.1 8.8.8.8\n", "", false},
		{"multi-domain", "Link 3 (scqavm0): ~. ~private\n", "", false},
		{"multi-line", "Link 3 (scqavm0): 1.1.1.1\nLink 2 (ens3): 10.0.2.3\n", "", false},
		{"untrusted-extra", "Link 3 (scqavm0): 1.1.1.1 (foreign)\n", "", false},
		{"control", "Link 3 (scqavm0): ~.\rNOTE\n", "", false},
		{"unknown", "Global: 1.1.1.1\n", "", false},
		{"blank", "", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := nativeTUNVMParseLinkResolver([]byte(test.value), 3, smartTUNVMInterface)
			if test.valid != (err == nil) || (err == nil && value != test.wanted) {
				t.Fatalf("strict read parse mismatch %q value=%q err=%v", test.value, value, err)
			}
		})
	}
	if _, err := nativeTUNVMParseLinkResolver([]byte("Link 3 (scqavm0):"), 1, smartTUNVMInterface); err == nil {
		t.Fatal("loopback/control index was accepted")
	}
}

func TestSmartTUNVMOwnedLinkDNSLegacySavedPolicyAndSchema(t *testing.T) {
	baseline := smartTUNSavedPolicy{Version: 1, ManagementPeerIP: smartTUNVMEndpoint, Options: qaVMPolicyFixture()}
	baseline.Options.Exceptions = nil
	old, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeSavedSmartTUNPolicy(old); err != nil {
		t.Fatalf("prior VM policy was invalidated by the new optional field: %v", err)
	}
	baseline.Options.DNSResolverIPv4 = "1.1.1.1"
	newData, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSavedSmartTUNPolicy(newData)
	if err != nil || decoded.Options.DNSResolverIPv4 != "1.1.1.1" {
		t.Fatalf("explicit DNS policy was not preserved: %+v %v", decoded, err)
	}
	for _, candidate := range smartTUNVMReservedDNSCases {
		t.Run("saved-special-"+candidate.name, func(t *testing.T) {
			p := baseline
			p.Options.DNSResolverIPv4 = candidate.addr
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeSavedSmartTUNPolicy(raw); err == nil {
				t.Fatalf("saved policy accepted reserved resolver %q", candidate.addr)
			}
		})
	}
	baseline.Options.DNSResolverIPv4 = "9.9.9.9"
	alternate, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSavedSmartTUNPolicy(alternate); err != nil {
		t.Fatalf("second approved resolver rejected in saved policy: %v", err)
	}
	for _, variant := range []string{
		strings.Replace(string(newData), "\"dns_resolver_ipv4\"", "\"DNS_RESOLVER_IPv4\"", 1),
		strings.Replace(string(newData), "\"dns_resolver_ipv4\":\"1.1.1.1\"", "\"dns_resolver_ipv4\":null", 1),
		strings.Replace(string(newData), "\"dns_resolver_ipv4\":\"1.1.1.1\"", "\"dns_resolver_ipv4\":\"10.0.2.2\"", 1),
		strings.Replace(string(newData), "\"dns_resolver_ipv4\":\"1.1.1.1\"", "\"dns_resolver_ipv4\":\"1.1.1.1\",\"extra\":true", 1),
	} {
		if _, err := decodeSavedSmartTUNPolicy([]byte(variant)); err == nil {
			t.Fatalf("unsafe optional DNS policy field accepted")
		}
	}
}

func TestSmartTUNVMNativeJournalDNSAllowlist(t *testing.T) {
	// This is a complete strict v4 native-journal record with a zero-effect
	// DNS intent. There is no privileged host or network operation here.
	base := nativeTrialExample(false)
	base.EndpointIP, base.ManagementPeerIP = smartTUNVMEndpoint, smartTUNVMEndpoint
	base.TunnelInterface, base.UnderlayInterface = smartTUNVMInterface, smartTUNVMUnderlay
	base.Native.IPv6 = nativeTUNPlannedFamily("", nativeTUNTable6)
	base.Native.DNSStage = "planned"
	for _, tc := range []struct {
		resolver string
		allowed  bool
	}{
		{"1.1.1.1", true},
		{"9.9.9.9", true},
	} {
		record := cloneSmartTUNTrial(base)
		record.Native.DNSResolverIPv4 = tc.resolver
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeSmartTUNTrial(raw); (err == nil) != tc.allowed {
			t.Fatalf("native journal approval unexpected for %q: %v", tc.resolver, err)
		}
	}
	for _, test := range smartTUNVMReservedDNSCases {
		t.Run("native-special-"+test.name, func(t *testing.T) {
			record := cloneSmartTUNTrial(base)
			record.Native.DNSResolverIPv4 = test.addr
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeSmartTUNTrial(raw); err == nil {
				t.Fatalf("native journal granted recovery authority to %q", test.addr)
			}
		})
	}
}

func TestSmartTUNVMOwnedLinkDNSDoesNotRewriteCoreDNS(t *testing.T) {
	opts := qaVMPolicyFixture()
	opts.Exceptions = nil
	opts.DNSResolverIPv4 = "1.1.1.1"
	profile := Profile{Outbound: json.RawMessage(`{"type":"vless","tag":"upstream","server":"10.0.2.2","server_port":19182,"uuid":"c2902f3a-1c25-41ef-a8dc-760b483aa247"}`)}
	core, err := smartTUNNativeConfig(profile, opts)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []struct {
			DNSMode      string `json:"dns_mode"`
			AutoRoute    bool   `json:"auto_route"`
			AutoRedirect bool   `json:"auto_redirect"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(core, &cfg) != nil || len(cfg.Inbounds) != 1 ||
		cfg.Inbounds[0].DNSMode != "disabled" || cfg.Inbounds[0].AutoRoute || cfg.Inbounds[0].AutoRedirect {
		t.Fatal("external resolver link operation rewrote sing-box core DNS or routing ownership")
	}
}
