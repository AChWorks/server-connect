package sc

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
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
}

type SmartTUNCIDRException struct {
	CIDR string
	Via  string // "direct" or "vpn"
}

var smartTUNDeviceName = regexp.MustCompile("^[a-zA-Z0-9_.-]{1,15}$")

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
// No production Apply path exists. IPv6, DNS/domain rules, protected foreign
// client replies, resource ownership, guards and verified rollback remain
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
	rules = append(rules, map[string]any{"ip_cidr": o.DomesticCIDRs, "action": "route", "outbound": "direct"})
	return json.MarshalIndent(map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "tun", "tag": "tun-in", "interface_name": o.TunnelInterface,
			"address": []string{o.TunnelIPv4}, "mtu": 1400,
			"auto_route": true, "auto_redirect": true, "strict_route": true,
			"route_exclude_address": exclusions,
		}},
		"outbounds": []any{json.RawMessage(profile.Outbound), map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"default_interface": o.UnderlayInterface, "rules": rules, "final": "upstream"},
	}, "", "  ")
}
