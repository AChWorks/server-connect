package sc

import (
	"encoding/json"
	"strings"
	"testing"
)

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
