package sc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// NativePolicyOptions describes a proposed sing-box-owned Linux TUN policy.
// Compiling it changes no host resources and does not authorize activation.
type NativePolicyOptions struct {
	InterfaceName          string
	UnderlayInterface      string
	IPv4Address            string
	IPv6Address            string
	Mode                   string // "default" or "bypass_iran"
	HealthFailureThreshold int    // 0 selects conservative default 3 consecutive rounds
	HealthSyntheticQA      bool   // explicit synthetic HTTPS QA scope, not field acceptance
}

// NativePolicyTableIndex and NativePolicyRuleIndex reserve predictable native
// RPDB slots for Server Connect. Admission must verify they are free before
// the Core starts; sing-tun's auto_redirect also uses a separate random table
// at priority 1 and requires its own crash-recovery cleanup.
const NativePolicyTableIndex = 27432
const NativePolicyRuleIndex = 14200

// NativePolicyTunMTU is a virtual TUN MTU, not an underlay-path MTU.
// Official sing-box tunnels datagrams over the selected transport; limiting
// the TUN to 1400 forced local IPv6 UDP fragmentation at 1353 payload bytes,
// which the pinned gVisor receive path did not deliver to the selected peer.
// 9000 is the official Core's normal virtual-TUN default. An underlay below
// this MTU must still pass independent selected-path and no-leak tests.
const NativePolicyTunMTU = 9000

// NativePolicyLegacyTunMTU remains recognized ONLY for journal-bound cleanup
// of installations created before the virtual-MTU change.
const NativePolicyLegacyTunMTU = 1400

// NativeSmartRoutingConfig deliberately delegates TUN, routing and nftables to
// official sing-box. The separate activation/runtime guards and host admission
// are not implemented by this compiler; callers MUST NOT treat a successful
// compile or sing-box check as permission to activate on a hosting server.
func NativeSmartRoutingConfig(profile Profile, opts NativePolicyOptions, operator []SmartRoutingRule) ([]byte, error) {
	if !smartTUNDeviceName.MatchString(opts.InterfaceName) ||
		!smartTUNDeviceName.MatchString(opts.UnderlayInterface) ||
		opts.InterfaceName == opts.UnderlayInterface ||
		opts.InterfaceName == "lo" || opts.UnderlayInterface == "lo" {
		return nil, errors.New("invalid native TUN or underlay interface")
	}
	if opts.Mode != "default" && opts.Mode != "bypass_iran" {
		return nil, errors.New("unsupported native policy mode")
	}
	v4, err := netip.ParsePrefix(opts.IPv4Address)
	if err != nil || !v4.IsValid() || !v4.Addr().Is4() ||
		!v4.Addr().IsPrivate() || v4.Masked().Bits() < 16 || v4.Bits() > 30 {
		return nil, errors.New("invalid private native TUN IPv4 address")
	}
	address := []string{opts.IPv4Address}
	if opts.IPv6Address != "" {
		v6, err := netip.ParsePrefix(opts.IPv6Address)
		if err != nil || !v6.IsValid() || !v6.Addr().Is6() ||
			!v6.Addr().IsPrivate() || v6.Bits() < 64 || v6.Bits() > 126 {
			return nil, errors.New("invalid private native TUN IPv6 address")
		}
		address = append(address, opts.IPv6Address)
	}

	// Imported outbounds are treated as one selected transport, never as
	// authority to install imported routes/DNS/inbounds or other outbounds.
	if rejectAmbiguousJournalJSON(profile.Outbound) != nil {
		return nil, errors.New("ambiguous selected outbound")
	}
	var selected map[string]json.RawMessage
	if json.Unmarshal(profile.Outbound, &selected) != nil || selected == nil {
		return nil, errors.New("invalid selected outbound")
	}
	var tag, kind string
	if json.Unmarshal(selected["tag"], &tag) != nil || tag != "upstream" ||
		json.Unmarshal(selected["type"], &kind) != nil {
		return nil, errors.New("selected outbound must have the reserved upstream tag")
	}
	switch kind {
	case "vless", "vmess", "trojan", "shadowsocks", "hysteria2":
	default:
		return nil, errors.New("selected outbound is not a supported remote VPN")
	}
	for _, key := range []string{"bind_interface", "routing_mark", "detour", "inet4_bind_address", "inet6_bind_address"} {
		if _, exists := selected[key]; exists {
			return nil, fmt.Errorf("selected outbound has an unsupported network selector: %s", key)
		}
	}
	if err := validateSmartRoutingDocument(smartRoutingRulesDocument{
		Version: 1, Revision: 1, Manual: operator, Imports: []smartRoutingRuleSource{},
	}, time.Now().UTC()); err != nil {
		return nil, err
	}

	// Keep platform DNS untouched (dns_mode=disabled), and prioritize
	// directly attached/private destinations before any port-53 hijack.
	// The route rule sees only DNS that actually entered the native TUN.
	rules := []any{map[string]any{"ip_is_private": true, "action": "bypass", "outbound": "direct"}}

	// Explicit VPN CIDR rules precede country Direct; no kernel-level country
	// exclusion is installed, so an operator VPN exception is not overridden.
	// Only VPN domain matches are accepted until safe DNS correlation is proved.
	cidrs := make([]SmartRoutingRule, 0, len(operator))
	domains := make([]SmartRoutingRule, 0, len(operator))
	for _, rule := range operator {
		switch rule.Type {
		case "cidr":
			cidrs = append(cidrs, rule)
		case "domain", "suffix":
			if rule.Via != "vpn" {
				return nil, errors.New("Direct domain policy requires independently verified DNS association")
			}
			domains = append(domains, rule)
		}
	}
	sortSmartRoutingRules(cidrs)
	sortSmartRoutingRules(domains)
	for _, rule := range cidrs {
		out := "upstream"
		if rule.Via == "direct" {
			out = "direct"
		}
		rules = append(rules, map[string]any{"ip_cidr": []string{rule.Value}, "action": "route", "outbound": out})
	}
	sets := []any{}
	if opts.Mode == "bypass_iran" {
		if opts.IPv6Address == "" {
			return nil, errors.New("bypass Iran requires explicit IPv6 handling; IPv4-only is not presumed safe")
		}
		raw, err := iranGeoSnapshotFiles.ReadFile("data/iran-dbip-lite-2026-10.json")
		if err != nil {
			return nil, errors.New("bundled Iran prefix estimate unavailable")
		}
		geo, err := decodeIranGeoSnapshot(raw)
		if err != nil || len(geo.IPv4) == 0 || len(geo.IPv6) == 0 {
			return nil, errors.New("bundled Iran prefix estimate failed integrity validation")
		}
		// Inline rule-set is a property of the selected Core, not thousands
		// of app-owned kernel routes. This source is an estimate, not verified
		// evidence that any individual network is reachable from Iran.
		sets = append(sets, map[string]any{
			"type": "inline", "tag": "iran-public",
			"rules": []any{map[string]any{"ip_cidr": append(append([]string{}, geo.IPv4...), geo.IPv6...)}},
		})
		// A pinned domestic DNS destination remains Direct. Operator VPN
		// CIDRs above it still win, even when the resolver uses port 53.
		rules = append(rules, map[string]any{
			"rule_set": []string{"iran-public"}, "port": 53, "action": "route", "outbound": "direct",
		})
	}

	// Unmatched DNS continues to use the selected VPN-detoured resolver;
	// this rule must not preempt operator or domestic IP policy. Keeping it
	// before TCP sniffing avoids unnecessary TLS/HTTP inspection of DNS.
	rules = append(rules, map[string]any{"port": 53, "action": "hijack-dns"})
	if len(domains) != 0 {
		rules = append(rules, map[string]any{"action": "sniff", "sniffer": []string{"tls", "http"}, "timeout": "200ms"})
		for _, rule := range domains {
			match := map[string]any{"action": "route", "outbound": "upstream"}
			if rule.Type == "domain" {
				match["domain"] = []string{rule.Value}
			} else {
				match["domain_suffix"] = []string{"." + rule.Value}
			}
			rules = append(rules, match)
		}
	}
	if opts.Mode == "bypass_iran" {
		rules = append(rules, map[string]any{"rule_set": []string{"iran-public"}, "action": "route", "outbound": "direct"})
	}

	// No FakeIP: stale synthetic addresses must not be reclassified Direct.
	// DNS is tunnel-detoured by default; only selected-outbound bootstrap uses
	// the explicitly separate local resolver. Native DNS correlation for
	// Direct domain rules is NOT claimed by this preview.
	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "tun", "tag": "smart-tun",
			"interface_name": opts.InterfaceName, "address": address,
			"mtu": NativePolicyTunMTU, "stack": "gvisor", "auto_route": true, "auto_redirect": true,
			"iproute2_table_index": NativePolicyTableIndex, "iproute2_rule_index": NativePolicyRuleIndex,
			"strict_route": true, "dns_mode": "disabled",
		}},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"type": "local", "tag": "bootstrap"},
				map[string]any{"type": "udp", "tag": "vpn-dns", "server": "1.1.1.1", "server_port": 53, "detour": "upstream"},
			},
			"final": "vpn-dns", "reverse_mapping": false,
		},
		"outbounds": []any{json.RawMessage(profile.Outbound), map[string]any{"type": "direct", "tag": "direct"}},
		"route": map[string]any{
			"default_interface":       opts.UnderlayInterface,
			"default_domain_resolver": "bootstrap",
			"rule_set":                sets, "rules": rules, "final": "upstream",
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}
