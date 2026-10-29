package sc

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// SmartTUNCandidateOptions only compiles configuration. It never authorizes
// or applies privileged Linux routing changes.
type SmartTUNCandidateOptions struct {
	TunnelInterface   string
	UnderlayInterface string
	TunnelIPv4        string
	ProtectedCIDRs    []string
	DomesticCIDRs     []string
	Exceptions        []SmartTUNCIDRException
	DomainExceptions  []SmartTUNDomainException
}

type SmartTUNCIDRException struct {
	CIDR string
	Via  string // "direct" or "vpn"
}

// SmartTUNDomainException is an explicit VPN-only developer policy, NOT
// inferred geolocation. Suffix covers its apex and subdomains. The sniffed
// HTTP Host / TLS SNI is untrusted client-supplied text, so it can only send
// traffic into the VPN, never exempt it into Direct. Direct-domain decisions
// require trusted DNS/IP correlation and are deliberately not implemented.
type SmartTUNDomainException struct {
	Domain string
	Suffix bool
	Via    string // "vpn"; direct requires trusted DNS/IP correlation
}

var smartTUNDeviceName = regexp.MustCompile("^[a-zA-Z0-9_.-]{1,15}$")
var smartTUNDomainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func canonicalSmartTUNDomain(raw string, suffix bool) (string, error) {
	name := strings.ToLower(raw)
	if name == "" || len(name) > 253 || strings.ContainsAny(name, "/:*\\ ") {
		return "", errors.New("invalid operator domain")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", errors.New("IP address cannot be a domain exception")
	}
	labels := strings.Split(name, ".")
	if !suffix && len(labels) < 2 {
		return "", errors.New("exact domain exception requires a fully qualified name")
	}
	for _, label := range labels {
		if !smartTUNDomainLabel.MatchString(label) {
			return "", errors.New("invalid operator domain label")
		}
	}
	return name, nil
}

func canonicalRoutePrefix(raw string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(raw)
	if err != nil || !p.IsValid() || !p.Addr().Is4() || p.Bits() == 0 || p.Masked().String() != raw {
		return netip.Prefix{}, errors.New("invalid or noncanonical CIDR")
	}
	return p, nil
}

func routePrefixesOverlap(a, b netip.Prefix) bool {
	return a.Addr().Is4() == b.Addr().Is4() && (a.Contains(b.Addr()) || b.Contains(a.Addr()))
}

// SmartTUNCandidateConfig compiles a real Linux sing-box TUN configuration.
// No production Apply path exists. IPv6, trustworthy DNS/domain correlation,
// imported rule-list validation, protected foreign-client replies, resource
// ownership, guards and verified rollback remain
// unimplemented and must block production activation.
func SmartTUNCandidateConfig(profile Profile, o SmartTUNCandidateOptions) ([]byte, error) {
	if !smartTUNDeviceName.MatchString(o.TunnelInterface) ||
		!smartTUNDeviceName.MatchString(o.UnderlayInterface) ||
		o.TunnelInterface == o.UnderlayInterface ||
		o.TunnelInterface == "lo" || o.UnderlayInterface == "lo" {
		return nil, errors.New("invalid or colliding TUN/underlay interfaces")
	}
	tun, err := netip.ParsePrefix(o.TunnelIPv4)
	if err != nil || !tun.IsValid() || !tun.Addr().Is4() || !tun.Addr().IsPrivate() || tun.Bits() < 16 || tun.Bits() > 30 {
		return nil, errors.New("TUN requires a private IPv4 interface address/prefix")
	}
	var outbound map[string]json.RawMessage
	if json.Unmarshal(profile.Outbound, &outbound) != nil {
		return nil, errors.New("invalid selected outbound")
	}
	var typ, tag, server string
	if json.Unmarshal(outbound["type"], &typ) != nil ||
		json.Unmarshal(outbound["tag"], &tag) != nil ||
		json.Unmarshal(outbound["server"], &server) != nil ||
		typ == "" || typ == "direct" || tag != "upstream" {
		return nil, errors.New("selected profile must be a tagged remote outbound")
	}
	endpoint, err := netip.ParseAddr(server)
	if err != nil || !endpoint.Is4() || !endpoint.IsGlobalUnicast() {
		return nil, errors.New("first TUN candidate requires a literal IPv4 VPN endpoint")
	}
	if len(o.DomesticCIDRs) == 0 {
		return nil, errors.New("missing domestic prefix source")
	}
	// Kernel bypass for essential Direct paths. Inbound website/SSH foreign
	// reply preservation is NOT inferred from this insufficient list.
	protected := []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", server + "/32"}
	baseProtectedCount := len(protected)
	protected = append(protected, o.ProtectedCIDRs...)
	seen := map[string]bool{}
	exclusions := []string{}
	protections := []netip.Prefix{}
	// Extra kernel exclusions are only for narrow, identified host/control paths.
	// Deliberately broad Direct policy belongs in explicit operator exceptions.
	// Bounding the total also prevents many small prefixes from composing a
	// near-global exclusion. This is admission control, not proof of path ownership.
	const maxExtraProtectedAddresses = 64
	extraProtectedAddresses := 0
	for i, raw := range protected {
		prefix, err := canonicalRoutePrefix(raw)
		if err != nil {
			return nil, errors.New("invalid protected CIDR")
		}
		if seen[raw] {
			continue
		}
		if i >= baseProtectedCount {
			if prefix.Bits() < 29 {
				return nil, errors.New("protected control path exceeds a narrow IPv4 /29")
			}
			// A caller may redundantly identify a private/on-link or endpoint
			// host already excluded by the essential built-in protections.
			alreadyProtected := false
			for _, base := range protections[:baseProtectedCount] {
				if base.Contains(prefix.Addr()) && prefix.Bits() >= base.Bits() {
					alreadyProtected = true
					break
				}
			}
			if alreadyProtected {
				seen[raw] = true
				continue
			}
			for _, existing := range protections {
				if routePrefixesOverlap(prefix, existing) {
					return nil, errors.New("overlapping protected control paths")
				}
			}
			extraProtectedAddresses += 1 << (32 - prefix.Bits())
			if extraProtectedAddresses > maxExtraProtectedAddresses {
				return nil, errors.New("aggregate protected control paths exceed bounded IPv4 admission")
			}
		}
		seen[raw] = true
		exclusions = append(exclusions, raw)
		protections = append(protections, prefix)
	}
	rules := []any{map[string]any{"ip_cidr": exclusions, "action": "bypass", "outbound": "direct"}}
	operator := []netip.Prefix{}
	for _, r := range o.Exceptions {
		prefix, err := canonicalRoutePrefix(r.CIDR)
		if err != nil || (r.Via != "direct" && r.Via != "vpn") {
			return nil, errors.New("invalid CIDR exception")
		}
		for _, p := range protections {
			if routePrefixesOverlap(prefix, p) {
				return nil, errors.New("exception overlaps protected host/underlay path")
			}
		}
		for _, p := range operator {
			if routePrefixesOverlap(prefix, p) {
				return nil, errors.New("overlapping operator exceptions")
			}
		}
		operator = append(operator, prefix)
		out := "upstream"
		if r.Via == "direct" {
			out = "direct"
		}
		rules = append(rules, map[string]any{"ip_cidr": []string{r.CIDR}, "action": "route", "outbound": out})
	}
	for _, raw := range o.DomesticCIDRs {
		if _, err := canonicalRoutePrefix(raw); err != nil {
			return nil, errors.New("invalid domestic CIDR")
		}
	}
	// Only explicit VPN-only operator domain exceptions are admitted. Sniffed
	// names cannot permit Direct, since an application can forge Host/SNI.
	// More specific exact names precede longer suffixes; IP exceptions have
	// higher precedence. No destination or system DNS is rewritten.
	if len(o.DomainExceptions) > 128 {
		return nil, errors.New("too many operator domain exceptions")
	}
	type domainRule struct {
		name   string
		suffix bool
	}
	domainRules := make([]domainRule, 0, len(o.DomainExceptions))
	seenDomains := make(map[string]bool, len(o.DomainExceptions))
	for _, candidate := range o.DomainExceptions {
		name, err := canonicalSmartTUNDomain(candidate.Domain, candidate.Suffix)
		if err != nil || candidate.Via != "vpn" {
			return nil, errors.New("domain Direct is unsafe without authenticated DNS/IP correlation; only VPN is supported")
		}
		key := name
		if candidate.Suffix {
			key = "." + name
		}
		if seenDomains[key] {
			return nil, errors.New("duplicate operator domain exception")
		}
		seenDomains[key] = true
		domainRules = append(domainRules, domainRule{name: name, suffix: candidate.Suffix})
	}
	if len(domainRules) != 0 {
		sort.Slice(domainRules, func(i, j int) bool {
			a, b := domainRules[i], domainRules[j]
			if a.suffix != b.suffix {
				return !a.suffix
			}
			if len(a.name) != len(b.name) {
				return len(a.name) > len(b.name)
			}
			return a.name < b.name
		})
		rules = append(rules, map[string]any{
			"network": []string{"tcp"}, "action": "sniff",
			"sniffer": []string{"http", "tls"}, "timeout": "200ms",
		})
		for _, candidate := range domainRules {
			rule := map[string]any{"network": []string{"tcp"}, "domain": []string{candidate.name}, "action": "route", "outbound": "upstream"}
			if candidate.suffix {
				rule["domain_suffix"] = []string{"." + candidate.name}
			}
			rules = append(rules, rule)
		}
	}
	rules = append(rules, map[string]any{"ip_cidr": o.DomesticCIDRs, "action": "route", "outbound": "direct"})
	return json.MarshalIndent(map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "tun", "tag": "tun-in", "interface_name": o.TunnelInterface,
			"address": []string{o.TunnelIPv4}, "mtu": 1400,
			"auto_route": true, "auto_redirect": true, "strict_route": true,
			// The 1.14.x default DNS hijack rewrites port 53 and would
			// silently override this candidate's explicit Direct/VPN IP rules.
			// Full resolver/domain-policy integration is not implemented yet.
			"dns_mode": "disabled", "route_exclude_address": exclusions,
		}},
		"outbounds": []any{json.RawMessage(profile.Outbound), map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"default_interface": o.UnderlayInterface, "rules": rules, "final": "upstream"},
	}, "", "  ")
}
