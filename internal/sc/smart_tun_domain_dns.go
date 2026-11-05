package sc

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
)

// FakeIP pools belong exclusively to the correlated core operation. A native
// activation must independently reserve/capture these ranges and reject host
// route conflicts before starting this configuration.
const SmartTUNDomainFakeIPv4 = "198.18.0.0/15"
const SmartTUNDomainFakeIPv6 = "2001:2::/48"

// SmartTUNDomainDNS is an explicit authenticated DNS endpoint. Its literal
// dial address avoids recursive resolver bootstrap. TLS verifies ServerName
// normally; the selected upstream carries all DoH transport. No ambient
// resolver, plaintext fallback, custom CA, insecure TLS or sniff-to-Direct.
type SmartTUNDomainDNS struct {
	ServerIPv4 string `json:"server_ipv4"`
	ServerName string `json:"server_name"`
	ServerPort int    `json:"server_port"`
}

func validateSmartTUNDomainDNS(d SmartTUNDomainDNS) error {
	ip, err := netip.ParseAddr(d.ServerIPv4)
	name, nameErr := validateEndpointHostname(d.ServerName)
	if err != nil || !ip.Is4() || ip.String() != d.ServerIPv4 ||
		!ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || overlapsSpecialPurpose(netip.PrefixFrom(ip, 32)) ||
		nameErr != nil || name != d.ServerName || strings.ToLower(d.ServerName) != d.ServerName ||
		d.ServerPort < 1 || d.ServerPort > 65535 {
		return Fault("routing_rules_invalid", "correlated DNS requires a public IPv4 dial address, canonical TLS hostname and port 1-65535")
	}
	return nil
}

// Prepare the existing IP/protected/domain validation path without granting
// a Direct decision to its sniffed names. Only the separate FakeIP compiler
// below can restore an explicit Direct disposition.
func smartTUNDomainDNSBaseOptions(o SmartTUNCandidateOptions) SmartTUNCandidateOptions {
	copyOptions := o
	copyOptions.DomainExceptions = append([]SmartTUNDomainException(nil), o.DomainExceptions...)
	for i := range copyOptions.DomainExceptions {
		if copyOptions.DomainExceptions[i].Via == "direct" {
			copyOptions.DomainExceptions[i].Via = "vpn"
		}
	}
	return copyOptions
}

// SmartTUNDNSCorrelatedConfig compiles DNS-name policy for a TUN candidate.
// A literal real IP is never reverse mapped to a previous DNS query. TUN
// packets carry numeric destinations; only this core's FakeIP map supplies a
// destination domain. A missing/stale mapping fails in the core. There is no
// HTTP/TLS sniff action capable of changing a Direct decision.
func SmartTUNDNSCorrelatedConfig(profile Profile, o SmartTUNCandidateOptions, dns SmartTUNDomainDNS) ([]byte, error) {
	if err := validateSmartTUNDomainDNS(dns); err != nil {
		return nil, err
	}
	if o.DNSResolverIPv4 != "" {
		return nil, Fault("routing_rules_invalid", "owned-link fixture DNS cannot be combined with correlated DNS")
	}
	base, err := SmartTUNCandidateConfig(profile, smartTUNDomainDNSBaseOptions(o))
	if err != nil {
		return nil, err
	}
	return applySmartTUNDomainDNS(base, o, dns)
}

// This companion uses exactly the existing VLESS native validation/projection,
// including its independently controlled TUN and protected egress marks.
func smartTUNDNSCorrelatedNativeConfig(profile Profile, o SmartTUNCandidateOptions, dns SmartTUNDomainDNS) ([]byte, error) {
	if err := validateSmartTUNDomainDNS(dns); err != nil {
		return nil, err
	}
	if o.DNSResolverIPv4 != "" {
		return nil, Fault("routing_rules_invalid", "owned-link fixture DNS cannot be combined with correlated DNS")
	}
	base, err := smartTUNNativeConfig(profile, smartTUNDomainDNSBaseOptions(o))
	if err != nil {
		return nil, err
	}
	return applySmartTUNDomainDNS(base, o, dns)
}

func applySmartTUNDomainDNS(base []byte, o SmartTUNCandidateOptions, dns SmartTUNDomainDNS) ([]byte, error) {
	var cfg map[string]any
	decoder := json.NewDecoder(bytes.NewReader(base))
	decoder.UseNumber()
	if decoder.Decode(&cfg) != nil {
		return nil, Fault("routing_rules_invalid", "validated native DNS policy cannot be decoded")
	}
	route := cfg["route"].(map[string]any)
	strategy := "ipv4_only"
	if o.TunnelIPv6 != "" {
		strategy = "prefer_ipv4"
	}
	rules := []any{
		map[string]any{"network": []string{"tcp", "udp"}, "port": 53, "action": "hijack-dns"},
		map[string]any{"action": "resolve", "server": "sc-domain-doh", "strategy": strategy},
	}
	dispositions := map[string]string{}
	for _, domain := range o.DomainExceptions {
		name, err := canonicalSmartTUNDomain(domain.Domain, domain.Suffix)
		if err != nil || (domain.Via != "direct" && domain.Via != "vpn") {
			return nil, Fault("routing_rules_invalid", "invalid correlated domain exception")
		}
		if domain.Suffix {
			name = "." + name
		}
		dispositions[name] = domain.Via
	}
	for _, rawRule := range route["rules"].([]any) {
		rule := rawRule.(map[string]any)
		if rule["action"] == "sniff" {
			continue
		}
		if names, ok := rule["domain"].([]any); ok && len(names) == 1 {
			key, _ := names[0].(string)
			if suffixes, ok := rule["domain_suffix"].([]any); ok && len(suffixes) == 1 {
				key, _ = suffixes[0].(string)
			}
			via := dispositions[key]
			if via == "" {
				return nil, Fault("routing_rules_invalid", "validated domain disposition missing")
			}
			delete(rule, "network") // DNS correlation applies equally to TCP and UDP.
			if via == "direct" {
				rule["outbound"] = "direct"
			}
		}
		rules = append(rules, rule)
	}
	route["rules"] = rules
	route["default_domain_resolver"] = map[string]any{"server": "sc-domain-doh", "strategy": strategy}
	fakeServer := map[string]any{"type": "fakeip", "tag": "sc-domain-fakeip", "inet4_range": SmartTUNDomainFakeIPv4}
	queryTypes := []string{"A"}
	if o.TunnelIPv6 != "" {
		fakeServer["inet6_range"] = SmartTUNDomainFakeIPv6
		queryTypes = append(queryTypes, "AAAA")
	}
	cfg["dns"] = map[string]any{
		"servers": []any{
			map[string]any{"type": "https", "tag": "sc-domain-doh", "server": dns.ServerIPv4, "server_port": dns.ServerPort,
				"path": "/dns-query", "detour": "upstream", "tls": map[string]any{"enabled": true, "server_name": dns.ServerName}},
			fakeServer,
		},
		"rules": []any{map[string]any{"query_type": queryTypes, "action": "route", "server": "sc-domain-fakeip"}},
		"final": "sc-domain-doh", "reverse_mapping": false, "cache_capacity": 4096,
	}
	if o.TunnelIPv6 == "" {
		// Never return an uncaptured real AAAA path on an IPv4-only correlated
		// operation. This is an explicit empty successful answer, not DNS outage.
		cfg["dns"].(map[string]any)["rules"] = append(cfg["dns"].(map[string]any)["rules"].([]any),
			map[string]any{"query_type": []string{"AAAA"}, "action": "predefined", "rcode": "NOERROR"})
	}
	return json.MarshalIndent(cfg, "", "  ")
}
