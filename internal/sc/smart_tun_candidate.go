package sc

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// SmartTUNCandidateOptions only compiles configuration. It never authorizes
// or applies privileged Linux routing changes.
type SmartTUNCandidateOptions struct {
	TunnelInterface   string `json:"tunnel_interface"`
	UnderlayInterface string `json:"underlay_interface"`
	TunnelIPv4        string `json:"tunnel_ipv4"`
	// Optional, explicitly selected dual-stack development candidate.
	// This does not authorize privileged routing or production activation.
	TunnelIPv6         string                    `json:"tunnel_ipv6"`
	ProtectedCIDRs     []string                  `json:"protected_cidrs"`
	ProtectedIPv6CIDRs []string                  `json:"protected_ipv6_cidrs"`
	DomesticCIDRs      []string                  `json:"domestic_cidrs"`
	DomesticIPv6CIDRs  []string                  `json:"domestic_ipv6_cidrs"`
	Exceptions         []SmartTUNCIDRException   `json:"exceptions"`
	IPv6Exceptions     []SmartTUNCIDRException   `json:"ipv6_exceptions"`
	DomainExceptions   []SmartTUNDomainException `json:"domain_exceptions"`
}

type SmartTUNCIDRException struct {
	CIDR string `json:"cidr"`
	Via  string `json:"via"` // "direct" or "vpn"
}

// SmartTUNDomainException is an explicit VPN-only developer policy, NOT
// inferred geolocation. Suffix covers its apex and subdomains. The sniffed
// HTTP Host / TLS SNI is untrusted client-supplied text, so it can only send
// traffic into the VPN, never exempt it into Direct. Direct-domain decisions
// require trusted DNS/IP correlation and are deliberately not implemented.
type SmartTUNDomainException struct {
	Domain string `json:"domain"`
	Suffix bool   `json:"suffix"`
	Via    string `json:"via"` // "vpn"; direct requires trusted DNS/IP correlation
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
	if suffix {
		// Offline PSL from the pinned Go module includes ICANN and PRIVATE
		// boundaries (e.g. co.uk, com.au, github.io, blogspot.com),
		// with wildcard/exception semantics. A dot is not proof of
		// registrability. Unknown/unmanaged TLDs fail closed until the
		// pinned PSL snapshot is updated, without relying on DNS.
		root, icann := publicsuffix.PublicSuffix(name)
		if root == name {
			return "", errors.New("whole public suffix is not an operator domain exception")
		}
		if !icann && !strings.Contains(root, ".") {
			return "", errors.New("unrecognized top-level public suffix")
		}
		if _, err := publicsuffix.EffectiveTLDPlusOne(name); err != nil {
			return "", errors.New("domain suffix has no registrable parent")
		}
	}
	return name, nil
}

func canonicalRoutePrefixFamily(raw string, ipv6 bool) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(raw)
	if err != nil || !p.IsValid() || p.Addr().Is6() != ipv6 ||
		p.Bits() == 0 || p.Masked().String() != raw {
		return netip.Prefix{}, errors.New("invalid or noncanonical CIDR")
	}
	return p, nil
}

func canonicalRoutePrefix(raw string) (netip.Prefix, error) {
	return canonicalRoutePrefixFamily(raw, false)
}

func routePrefixesOverlap(a, b netip.Prefix) bool {
	return a.Addr().Is4() == b.Addr().Is4() && (a.Contains(b.Addr()) || b.Contains(a.Addr()))
}

// smartTUNIPv6Policy is opt-in, development-only, and does not infer
// geographic correctness. It preserves essential IPv6 underlay/local paths
// ahead of any operator override, with no catch-all public Direct bypass.
func smartTUNIPv6Policy(o SmartTUNCandidateOptions) ([]string, []any, error) {
	if o.TunnelIPv6 == "" {
		if len(o.DomesticIPv6CIDRs) != 0 || len(o.ProtectedIPv6CIDRs) != 0 || len(o.IPv6Exceptions) != 0 {
			return nil, nil, errors.New("IPv6 rules require an explicit private IPv6 TUN address")
		}
		return nil, nil, nil
	}
	tun, err := netip.ParsePrefix(o.TunnelIPv6)
	if err != nil || !tun.IsValid() || !tun.Addr().Is6() || !tun.Addr().IsPrivate() ||
		tun.Bits() < 64 || tun.Bits() > 126 || len(o.DomesticIPv6CIDRs) == 0 {
		return nil, nil, errors.New("IPv6 TUN requires a private IPv6 address and domestic prefixes")
	}
	if len(o.ProtectedIPv6CIDRs) > 64 || len(o.IPv6Exceptions) > 128 ||
		len(o.DomesticIPv6CIDRs) > 10000 {
		return nil, nil, errors.New("IPv6 rule set exceeds candidate limits")
	}
	base := []string{"::1/128", "fc00::/7", "fe80::/10"}
	exclusions := append([]string(nil), base...)
	protections := make([]netip.Prefix, 0, len(base)+len(o.ProtectedIPv6CIDRs))
	for _, text := range base {
		protections = append(protections, netip.MustParsePrefix(text))
	}
	for _, text := range o.ProtectedIPv6CIDRs {
		prefix, err := canonicalRoutePrefixFamily(text, true)
		if err != nil || prefix.Bits() != 128 {
			return nil, nil, errors.New("IPv6 extra control path must be a canonical single host")
		}
		covered := false
		for _, previous := range protections {
			if previous.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		protections = append(protections, prefix)
		exclusions = append(exclusions, text)
	}
	// This development-only IPv6 admission policy is deliberately narrower
	// than an arbitrary public country allocation: explicit operator Direct
	// covers at most 64 distinct /64s (each exception /64 or narrower).
	// The synthetic domestic list may include /32s, but at most 1024
	// distinct /32 blocks. Neither bound authenticates real Iranian prefixes.
	const minOperatorDirectBits = 64
	const maxOperatorDirect64s = 64
	const minDomesticDirectBits = 32
	const maxDomesticDirect32s = 1024
	operatorDirect64s := make(map[netip.Prefix]bool)
	rules := []any{}
	operator := []netip.Prefix{}
	for _, exception := range o.IPv6Exceptions {
		prefix, err := canonicalRoutePrefixFamily(exception.CIDR, true)
		if err != nil || (exception.Via != "direct" && exception.Via != "vpn") ||
			!conservativelyPublicIPv6Prefix(prefix) {
			return nil, nil, errors.New("invalid or special-purpose IPv6 operator exception")
		}
		for _, p := range protections {
			if routePrefixesOverlap(prefix, p) {
				return nil, nil, errors.New("IPv6 operator exception overlaps protected path")
			}
		}
		for _, p := range operator {
			if routePrefixesOverlap(prefix, p) {
				return nil, nil, errors.New("overlapping IPv6 operator exceptions")
			}
		}
		operator = append(operator, prefix)
		out := "upstream"
		if exception.Via == "direct" {
			if prefix.Bits() < minOperatorDirectBits {
				return nil, nil, errors.New("IPv6 operator Direct exception exceeds /64 breadth")
			}
			operatorDirect64s[netip.PrefixFrom(prefix.Addr(), 64).Masked()] = true
			if len(operatorDirect64s) > maxOperatorDirect64s {
				return nil, nil, errors.New("aggregate IPv6 operator Direct exceptions exceed 64 distinct /64s")
			}
			out = "direct"
		}
		rules = append(rules, map[string]any{"ip_cidr": []string{exception.CIDR}, "action": "route", "outbound": out})
	}
	seen := map[string]bool{}
	domesticDirect32s := make(map[netip.Prefix]bool)
	for _, raw := range o.DomesticIPv6CIDRs {
		prefix, err := canonicalRoutePrefixFamily(raw, true)
		if err != nil || prefix.Bits() < minDomesticDirectBits ||
			!conservativelyPublicIPv6Prefix(prefix) || seen[raw] {
			return nil, nil, errors.New("invalid, broad or duplicate IPv6 domestic Direct prefix")
		}
		seen[raw] = true
		domesticDirect32s[netip.PrefixFrom(prefix.Addr(), 32).Masked()] = true
		if len(domesticDirect32s) > maxDomesticDirect32s {
			return nil, nil, errors.New("aggregate IPv6 domestic Direct prefixes exceed 1024 distinct /32s")
		}
	}
	return exclusions, rules, nil
}

// SmartTUNCandidateConfig compiles a real Linux sing-box TUN configuration.
// No production Apply path exists. Optional IPv6 candidate compilation is
// development-only; trustworthy DNS/domain correlation, imported rule lists,
// independently protected foreign-client replies, production IPv6/IPv4 Apply,
// resource ownership, guards and verified rollback remain unimplemented and
// must block production activation.
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
	// Bound caller-controlled collections before any O(n^2) exception overlap
	// checks or network configuration generation (mirrors IPv6 candidate caps).
	if len(o.ProtectedCIDRs) > 64 || len(o.Exceptions) > 128 {
		return nil, errors.New("IPv4 protected or operator exception count exceeds candidate limits")
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
	// Development-only IPv4 admission: untrusted inputs must not turn a
	// near-global collection into Direct while the default remains VPN.
	// These budgets do NOT authenticate geography or operator intent.
	const minOperatorDirectBits = 24
	const maxOperatorDirect24s = 64
	operatorDirect24s := make(map[netip.Prefix]bool)
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
			if prefix.Bits() < minOperatorDirectBits {
				return nil, errors.New("IPv4 operator Direct exception exceeds /24 breadth")
			}
			operatorDirect24s[netip.PrefixFrom(prefix.Addr(), 24).Masked()] = true
			if len(operatorDirect24s) > maxOperatorDirect24s {
				return nil, errors.New("aggregate IPv4 operator Direct exceptions exceed 64 distinct /24s")
			}
			out = "direct"
		}
		rules = append(rules, map[string]any{"ip_cidr": []string{r.CIDR}, "action": "route", "outbound": out})
	}
	// Synthetic domestic Direct candidates are bounded in BOTH number and
	// effective address coverage. A pile of individually narrow prefixes
	// must not silently route almost all public IPv4 traffic outside VPN.
	const minDomesticDirectBits = 8
	const maxDomesticDirectPrefixes = 10000
	const maxDomesticDirectAddresses uint64 = 1 << 25
	if len(o.DomesticCIDRs) > maxDomesticDirectPrefixes {
		return nil, errors.New("IPv4 domestic Direct prefix count exceeds candidate limit")
	}
	domestic := make([]netip.Prefix, 0, len(o.DomesticCIDRs))
	var domesticAddresses uint64
	for _, raw := range o.DomesticCIDRs {
		prefix, err := canonicalRoutePrefix(raw)
		if err != nil || prefix.Bits() < minDomesticDirectBits {
			return nil, errors.New("invalid, nonpublic or broad IPv4 domestic Direct prefix")
		}
		if !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() ||
			prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() ||
			overlapsSpecialPurpose(prefix) {
			return nil, errors.New("IPv4 domestic Direct prefix intersects special-purpose or nonpublic space")
		}
		domestic = append(domestic, prefix)
		domesticAddresses += uint64(1) << (32 - prefix.Bits())
		if domesticAddresses > maxDomesticDirectAddresses {
			return nil, errors.New("aggregate IPv4 domestic Direct address coverage exceeds candidate limit")
		}
	}
	// Sorting only the parsed copy leaves the emitted policy in the explicit
	// caller-provided order; reject overlaps/duplicates regardless of order.
	sort.Slice(domestic, func(i, j int) bool {
		a, b := domestic[i], domestic[j]
		if cmp := a.Addr().Compare(b.Addr()); cmp != 0 {
			return cmp < 0
		}
		return a.Bits() < b.Bits()
	})
	for i := 1; i < len(domestic); i++ {
		if routePrefixesOverlap(domestic[i-1], domestic[i]) {
			return nil, errors.New("overlapping or duplicate IPv4 domestic Direct prefixes")
		}
	}
	v6Exclusions, v6Rules, err := smartTUNIPv6Policy(o)
	if err != nil {
		return nil, err
	}
	if len(v6Exclusions) > 0 {
		exclusions = append(exclusions, v6Exclusions...)
		rules = append(rules, v6Rules...)
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
	addresses := []string{o.TunnelIPv4}
	if len(v6Exclusions) != 0 {
		rules = append(rules, map[string]any{"ip_cidr": o.DomesticIPv6CIDRs, "action": "route", "outbound": "direct"})
		addresses = append(addresses, o.TunnelIPv6)
	}
	return json.MarshalIndent(map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "tun", "tag": "tun-in", "interface_name": o.TunnelInterface,
			"address": addresses, "mtu": 1400,
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
