package sc

import (
	"bytes"
	"encoding/json"
	"net/netip"
)

// The IPv4-only native TUN cannot *carry* public IPv6 through the selected
// VPN. Its independent inet POSTROUTING guard currently drops unsupported
// host-origin public IPv6, but that must not be mistaken for working IPv6
// routing. Refuse any public IPv6 path before Apply and upon subsequent
// supervision instead of silently blackholing otherwise viable host IPv6.
// This restrictive QA-only gate is NOT general-host admission.
func nativeIPv4OnlyIPv6Admission(host HostPreflight) error {
	unsafe := func() error {
		return nativeTUNConflict("IPv4-only Smart TUN cannot protect a public, indirect or unverified IPv6 route/policy")
	}
	if rejectAmbiguousJournalJSON(host.IPv6Routes) != nil ||
		rejectAmbiguousJournalJSON(host.IPv6Rules) != nil {
		return unsafe()
	}
	var rules []map[string]json.RawMessage
	if json.Unmarshal(host.IPv6Rules, &rules) != nil || rules == nil ||
		(len(rules) != 2 && len(rules) != 3) {
		return unsafe()
	}
	expected := map[int]string{0: "local", 32766: "main"}
	if len(rules) == 3 {
		expected[32767] = "default"
	}
	for _, row := range rules {
		if row == nil || len(row) != 3 {
			return unsafe()
		}
		priority, ok := selectiveInt(row["priority"])
		if !ok || selectiveText(row["src"]) != "all" ||
			selectiveText(row["table"]) != expected[priority] {
			return unsafe()
		}
		delete(expected, priority)
	}
	if len(expected) != 0 {
		return unsafe()
	}

	var routes []map[string]json.RawMessage
	if json.Unmarshal(host.IPv6Routes, &routes) != nil || routes == nil {
		return unsafe()
	}
	for _, row := range routes {
		if row == nil || len(row) == 0 {
			return unsafe()
		}
		// A future/foreign path selector cannot inherit a local-only proof.
		// Unknown native keys are deliberately unsupported in this bounded
		// QA admission until their semantics are independently reviewed.
		allowed := map[string]bool{
			"dst": true, "dev": true, "type": true, "table": true,
			"protocol": true, "scope": true, "prefsrc": true,
			"metric": true, "flags": true, "pref": true,
		}
		for key, raw := range row {
			if !allowed[key] || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return unsafe()
			}
			switch key {
			case "protocol", "scope", "pref":
				if selectiveText(raw) == "" {
					return unsafe()
				}
			case "metric":
				if _, ok := selectiveInt(raw); !ok {
					return unsafe()
				}
			}
		}
		if raw, ok := row["flags"]; ok {
			var flags []string
			if json.Unmarshal(raw, &flags) != nil || flags == nil ||
				(len(flags) != 0 && (len(flags) != 1 || flags[0] != "linkdown")) {
				return unsafe()
			}
			// A disconnected (but still owned) persistent TUN may leave
			// otherwise local IPv6 routes flagged linkdown during a
			// bounded reconnect. This is not a public Direct bypass.
		}
		for _, key := range []string{"type", "table"} {
			if raw, present := row[key]; present && selectiveText(raw) == "" {
				return unsafe()
			}
		}
		dst := selectiveText(row["dst"])
		dev := selectiveText(row["dev"])
		if dst == "" || dev == "" || dst == "default" {
			return unsafe()
		}
		var prefix netip.Prefix
		if p, err := netip.ParsePrefix(dst); err == nil {
			if p.Masked() != p || p.String() != dst {
				return unsafe()
			}
			prefix = p
		} else if ip, err := netip.ParseAddr(dst); err == nil && ip.Is6() && ip.Zone() == "" {
			prefix = netip.PrefixFrom(ip, 128)
		} else {
			return unsafe()
		}
		if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Zone() != "" {
			return unsafe()
		}
		localOnly := func(root string) bool {
			r := netip.MustParsePrefix(root)
			return prefix.Bits() >= r.Bits() && r.Contains(prefix.Addr())
		}
		if src, ok := row["prefsrc"]; ok {
			ip, err := netip.ParseAddr(selectiveText(src))
			if err != nil || !ip.Is6() || ip.Zone() != "" ||
				!(ip.IsLinkLocalUnicast() || ip.IsPrivate() || ip.IsLoopback()) {
				return unsafe()
			}
		}
		table := selectiveText(row["table"])
		if table == "" {
			table = "main"
		}
		switch selectiveText(row["type"]) {
		case "multicast":
			if table != "local" || dev == "lo" || !localOnly("ff00::/8") {
				return unsafe()
			}
		case "local":
			if table != "local" {
				return unsafe()
			}
			if localOnly("::1/128") {
				if dev != "lo" {
					return unsafe()
				}
			} else if dev == "lo" || !(localOnly("fe80::/10") || localOnly("fc00::/7")) {
				return unsafe()
			}
		case "", "unicast":
			if table != "main" || dev == "lo" ||
				!(localOnly("fe80::/10") || localOnly("fc00::/7")) {
				return unsafe()
			}
		default:
			return unsafe()
		}
	}
	return nil
}

// Subsequent health/confirmation checks must not reuse an IPv6 snapshot
// obtained before a router advertisement, host policy edit or new address.
// The test seam is read-only; production always uses trusted native iproute2.
func nativeIPv4OnlyIPv6Current(read func(...string) (json.RawMessage, error)) error {
	routes, err := read("-j", "-6", "route", "show", "table", "all")
	if err != nil {
		return nativeTUNConflict("IPv4-only Smart TUN cannot verify current IPv6 routes")
	}
	rules, err := read("-j", "-6", "rule", "show")
	if err != nil {
		return nativeTUNConflict("IPv4-only Smart TUN cannot verify current IPv6 policy")
	}
	return nativeIPv4OnlyIPv6Admission(HostPreflight{IPv6Routes: routes, IPv6Rules: rules})
}
