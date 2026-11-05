package sc

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func domainDNSFixture() SmartTUNDomainDNS {
	return SmartTUNDomainDNS{ServerIPv4: "1.1.1.1", ServerName: "cloudflare-dns.com", ServerPort: 443}
}
func TestSmartTUNDNSCorrelatedConfigUsesFakeIPWithoutSniffOrRealIPReverseMapping(t *testing.T) {
	for _, dual := range []bool{false, true} {
		profile, o := smartTUNFixture()
		if dual {
			profile, o = dualStackTUNFixture()
		}
		o.DomainExceptions = []SmartTUNDomainException{
			{Domain: "example.org", Suffix: true, Via: "vpn"},
			{Domain: "direct.example.org", Via: "direct"},
		}
		original, _ := json.Marshal(o)
		for _, native := range []bool{false, true} {
			var data []byte
			var err error
			if native {
				data, err = smartTUNDNSCorrelatedNativeConfig(profile, o, domainDNSFixture())
			} else {
				data, err = SmartTUNDNSCorrelatedConfig(profile, o, domainDNSFixture())
			}
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if json.Unmarshal(data, &cfg) != nil {
				t.Fatal("invalid JSON")
			}
			dns := cfg["dns"].(map[string]any)
			if dns["reverse_mapping"] != false || dns["final"] != "sc-domain-doh" {
				t.Fatal("raw-IP reverse mapping or DNS fallback enabled")
			}
			servers := dns["servers"].([]any)
			doh := servers[0].(map[string]any)
			fake := servers[1].(map[string]any)
			if doh["type"] != "https" || doh["server"] != "1.1.1.1" || doh["detour"] != "upstream" || doh["path"] != "/dns-query" {
				t.Fatalf("DNS bootstrap/detour: %+v", doh)
			}
			tls := doh["tls"].(map[string]any)
			if tls["enabled"] != true || tls["server_name"] != "cloudflare-dns.com" || tls["insecure"] != nil {
				t.Fatal("DNS TLS not authenticated")
			}
			if fake["inet4_range"] != SmartTUNDomainFakeIPv4 || (dual && fake["inet6_range"] != SmartTUNDomainFakeIPv6) || (!dual && fake["inet6_range"] != nil) {
				t.Fatalf("wrong fake-IP family: %+v", fake)
			}
			rules := cfg["route"].(map[string]any)["rules"].([]any)
			if rules[0].(map[string]any)["action"] != "hijack-dns" || rules[1].(map[string]any)["action"] != "resolve" || rules[2].(map[string]any)["action"] != "bypass" {
				t.Fatalf("DNS/protected precedence: %+v", rules[:3])
			}
			directFound := false
			for _, value := range rules {
				r := value.(map[string]any)
				if r["action"] == "sniff" {
					t.Fatal("sniff can override trusted DNS identity")
				}
				if domains, ok := r["domain"].([]any); ok && len(domains) == 1 && domains[0] == "direct.example.org" {
					directFound = r["outbound"] == "direct" && r["network"] == nil
				}
			}
			if !directFound {
				t.Fatal("DNS-correlated Direct domain rule missing")
			}
			if native {
				inbound := cfg["inbounds"].([]any)[0].(map[string]any)
				if inbound["auto_route"] != false || inbound["auto_redirect"] != false {
					t.Fatal("native DNS compiler acquired host policy")
				}
			}
			if core := os.Getenv("SC_TEST_SINGBOX"); core != "" {
				if err := CheckConfig(core, t.TempDir(), data); err != nil {
					t.Fatalf("pinned core dual=%v native=%v: %v", dual, native, err)
				}
			}
		}
		after, _ := json.Marshal(o)
		if !bytes.Equal(original, after) {
			t.Fatal("compiler mutated caller domain policy")
		}
		if _, err := SmartTUNCandidateConfig(profile, o); err == nil {
			t.Fatal("non-correlated compiler admitted sniffed Direct domain")
		}
	}
}
func TestSmartTUNDNSCorrelatedEndpointRejectsAmbiguousOrUnauthenticatedDialPaths(t *testing.T) {
	for _, change := range []func(*SmartTUNDomainDNS){
		func(x *SmartTUNDomainDNS) { x.ServerIPv4 = "127.0.0.1" },
		func(x *SmartTUNDomainDNS) { x.ServerIPv4 = "10.0.0.1" },
		func(x *SmartTUNDomainDNS) { x.ServerIPv4 = "198.18.0.1" },
		func(x *SmartTUNDomainDNS) { x.ServerIPv4 = "2001:4860:4860::8888" },
		func(x *SmartTUNDomainDNS) { x.ServerIPv4 = "resolver.example.org" },
		func(x *SmartTUNDomainDNS) { x.ServerName = "" },
		func(x *SmartTUNDomainDNS) { x.ServerName = "1.1.1.1" },
		func(x *SmartTUNDomainDNS) { x.ServerName = "DNS.example.org" },
		func(x *SmartTUNDomainDNS) { x.ServerName = " dns.example.org" },
		func(x *SmartTUNDomainDNS) { x.ServerName = "https://dns.example.org" },
		func(x *SmartTUNDomainDNS) { x.ServerPort = 0 },
		func(x *SmartTUNDomainDNS) { x.ServerPort = 65536 },
	} {
		dns := domainDNSFixture()
		change(&dns)
		profile, o := smartTUNFixture()
		o.DomainExceptions = []SmartTUNDomainException{{Domain: "example.org", Via: "direct"}}
		if _, err := SmartTUNDNSCorrelatedConfig(profile, o, dns); err == nil {
			t.Fatalf("invalid DNS admitted: %+v", dns)
		}
		if _, err := smartTUNDNSCorrelatedNativeConfig(profile, o, dns); err == nil {
			t.Fatalf("invalid native DNS admitted: %+v", dns)
		}
	}
	profile, o := smartTUNFixture()
	o.DNSResolverIPv4 = "10.0.2.3"
	if _, err := SmartTUNDNSCorrelatedConfig(profile, o, domainDNSFixture()); err == nil || !strings.Contains(err.Error(), "fixture DNS") {
		t.Fatal("fixture DNS silently replaced", err)
	}
}
func TestSmartTUNSourcePinnedBroadIPv6DoesNotWidenManualPolicy(t *testing.T) {
	profile, o := dualStackTUNFixture()
	raw, err := iranGeoSnapshotFiles.ReadFile("data/iran-dbip-lite-2026-10.json")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := decodeIranGeoSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	o.DomesticCIDRs = append([]string{}, snapshot.IPv4...)
	o.DomesticIPv6CIDRs = append([]string{}, snapshot.IPv6...)
	if !sourcePinnedBundledDualStackEstimate(o) {
		t.Fatal("exact source not recognized")
	}
	if _, err := SmartTUNCandidateConfig(profile, o); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*SmartTUNCandidateOptions){
		func(x *SmartTUNCandidateOptions) { x.DomesticCIDRs = x.DomesticCIDRs[:len(x.DomesticCIDRs)-1] },
		func(x *SmartTUNCandidateOptions) {
			x.DomesticIPv6CIDRs = x.DomesticIPv6CIDRs[:len(x.DomesticIPv6CIDRs)-1]
		},
		func(x *SmartTUNCandidateOptions) {
			x.DomesticIPv6CIDRs = append(append([]string{}, x.DomesticIPv6CIDRs...), "2606:4700::/31")
		},
		func(x *SmartTUNCandidateOptions) { x.DomesticIPv6CIDRs = []string{"2606:4700::/31"} },
	} {
		altered := o
		change(&altered)
		if sourcePinnedBundledDualStackEstimate(altered) {
			t.Fatal("altered source retained pinned classification")
		}
		if _, err := SmartTUNCandidateConfig(profile, altered); err == nil {
			t.Fatal("altered broad source bypassed manual limits")
		}
	}
}
