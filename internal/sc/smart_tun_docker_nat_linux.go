//go:build linux

package sc

// Exact, read-only recognition of the smallest currently observed Docker
// IPv4 iptables-nft NAT topology. This is neither an owner grant, a route
// exception nor permission to activate host Smart Routing. A future host
// transaction must independently prove capture/guard ordering, dynamic
// firewall changes and precisely owned rollback; no foreign chain is edited.

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
)

const dockerNATObservedShape = "docker_bridge_nat_shape_observed_only"
const dockerNATUnverified = "foreign_or_unverified"
const dockerNATAbsent = "not_observed"

func dockerNATInvalid() error {
	return Fault("foreign_nat_unverified", "Docker NAT owner or IPv4 bridge grammar cannot be verified")
}

func dockerNATNumber(v any, want int) bool {
	switch n := v.(type) {
	case json.Number:
		return n.String() == strconv.Itoa(want)
	case int:
		return n == want
	}
	return false
}

func dockerNATOne(raw any, key string) (map[string]any, bool) {
	obj, ok := raw.(map[string]any)
	if !ok || len(obj) != 1 {
		return nil, false
	}
	child, ok := obj[key].(map[string]any)
	return child, ok
}

func dockerNATExactMatch(expr any, side string, right any, op string) bool {
	match, ok := dockerNATOne(expr, "match")
	if !ok || len(match) != 3 || match["op"] != op {
		return false
	}
	left, ok := match["left"].(map[string]any)
	if !ok || len(left) != 1 {
		return false
	}
	var field map[string]any
	switch side {
	case "oifname", "iifname":
		field, ok = left["meta"].(map[string]any)
		if !ok || len(field) != 1 || field["key"] != side {
			return false
		}
	case "saddr", "daddr":
		field, ok = left["payload"].(map[string]any)
		if !ok || len(field) != 2 || field["field"] != side || field["protocol"] != "ip" {
			return false
		}
	default:
		return false
	}
	switch r := right.(type) {
	case string:
		return match["right"] == r
	case netip.Prefix:
		prefix, ok := dockerNATOne(match["right"], "prefix")
		if !ok || len(prefix) != 2 || prefix["addr"] != r.Addr().String() {
			return false
		}
		return dockerNATNumber(prefix["len"], r.Bits())
	default:
		return false
	}
}

func dockerNATExpr(expr any, kind string, expect any) bool {
	fields, ok := expr.(map[string]any)
	if !ok || len(fields) != 1 {
		return false
	}
	v, has := fields[kind]
	if !has {
		return false
	}
	switch kind {
	case "counter":
		m, ok := v.(map[string]any)
		return ok && len(m) == 2 && dockerNATNonnegative(m["bytes"]) && dockerNATNonnegative(m["packets"])
	case "xt":
		m, ok := v.(map[string]any)
		kind := "target"
		if expect == "addrtype" {
			kind = "match"
		}
		return ok && len(m) == 2 && m["name"] == expect && m["type"] == kind
	case "jump":
		m, ok := v.(map[string]any)
		return ok && len(m) == 1 && m["target"] == expect
	case "return":
		return v == nil
	}
	return false
}

func dockerNATNonnegative(v any) bool {
	var value string
	switch n := v.(type) {
	case json.Number:
		value = n.String()
	case int:
		if n < 0 {
			return false
		}
		return true
	default:
		return false
	}
	parsed, e := strconv.ParseUint(value, 10, 64)
	return e == nil && strconv.FormatUint(parsed, 10) == value
}

func dockerNATRulesMatch(chain string, expr []any, bridge string, subnet netip.Prefix) bool {
	switch chain {
	case "PREROUTING":
		return len(expr) == 3 && dockerNATExpr(expr[0], "xt", "addrtype") && dockerNATExpr(expr[1], "counter", nil) && dockerNATExpr(expr[2], "jump", "DOCKER")
	case "OUTPUT":
		return len(expr) == 4 && dockerNATExactMatch(expr[0], "daddr", netip.MustParsePrefix("127.0.0.0/8"), "!=") && dockerNATExpr(expr[1], "xt", "addrtype") && dockerNATExpr(expr[2], "counter", nil) && dockerNATExpr(expr[3], "jump", "DOCKER")
	case "POSTROUTING":
		if len(expr) != 4 || !dockerNATExpr(expr[2], "counter", nil) || !dockerNATExpr(expr[3], "xt", "MASQUERADE") {
			return false
		}
		// iptables-nft 1.0.6 and 1.1.3 emit the same two pure, side-effect-free
		// matches in different orders. Match AND is commutative only BEFORE
		// the separately required counter and exact MASQUERADE target.
		iface := func(x any) bool { return dockerNATExactMatch(x, "oifname", bridge, "!=") }
		source := func(x any) bool { return dockerNATExactMatch(x, "saddr", subnet, "==") }
		return (iface(expr[0]) && source(expr[1])) || (source(expr[0]) && iface(expr[1]))
	case "DOCKER":
		return len(expr) == 3 && dockerNATExactMatch(expr[0], "iifname", bridge, "==") && dockerNATExpr(expr[1], "counter", nil) && dockerNATExpr(expr[2], "return", nil)
	}
	return false
}

// Canonical iptables-nft -S text verifies the otherwise opaque addrtype and
// MASQUERADE extensions; nft JSON independently binds the chain hooks,
// expression order and bridge subnet. A partial or different graph refuses.
func strictDockerNATText(nftPolicy, legacyPolicy []byte, bridge string, subnet netip.Prefix) bool {
	if len(nftPolicy) == 0 || len(nftPolicy) > 16384 || bytes.IndexByte(nftPolicy, 0) >= 0 || !strictEmptyLegacyNAT(legacyPolicy) {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(string(nftPolicy), "\n"), "\n")
	want := []string{
		"-P PREROUTING ACCEPT", "-P INPUT ACCEPT", "-P OUTPUT ACCEPT", "-P POSTROUTING ACCEPT", "-N DOCKER",
		"-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER",
		"-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER",
		"-A POSTROUTING -s " + subnet.String() + " ! -o " + bridge + " -j MASQUERADE",
		"-A DOCKER -i " + bridge + " -j RETURN",
	}
	if len(lines) != len(want) {
		return false
	}
	for i := range lines {
		if lines[i] != want[i] {
			return false
		}
	}
	return true
}

func strictEmptyLegacyNAT(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 2048 {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	want := []string{"-P PREROUTING ACCEPT", "-P INPUT ACCEPT", "-P OUTPUT ACCEPT", "-P POSTROUTING ACCEPT"}
	if len(lines) != len(want) {
		return false
	}
	for i := range want {
		if lines[i] != want[i] {
			return false
		}
	}
	return true
}

// Bind Docker's translated packets to the actual non-underlay Linux bridge,
// its one private IPv4 CIDR and its one kernel-connected route. This does not
// assume an installation always uses 172.17/16 or a bridge always is docker0.
func strictDockerNATBridge(link, address, route json.RawMessage, bridge, underlay string) (netip.Prefix, error) {
	bad := func() (netip.Prefix, error) { return netip.Prefix{}, dockerNATInvalid() }
	if bridge == underlay || bridge == "lo" || !smartTUNDeviceName.MatchString(bridge) {
		return bad()
	}
	var l []map[string]json.RawMessage
	if rejectAmbiguousJournalJSON(link) != nil || json.Unmarshal(link, &l) != nil || len(l) != 1 || selectiveText(l[0]["ifname"]) != bridge {
		return bad()
	}
	index, ok := selectiveInt(l[0]["ifindex"])
	if !ok || index < 2 || selectiveText(l[0]["master"]) != "" {
		return bad()
	}
	promisc, ok := selectiveInt(l[0]["promiscuity"])
	if !ok || promisc != 0 {
		return bad()
	}
	var info struct {
		Kind string `json:"info_kind"`
	}
	if e := json.Unmarshal(l[0]["linkinfo"], &info); e != nil || info.Kind != "bridge" {
		return bad()
	}
	var a []struct {
		Ifname string `json:"ifname"`
		Info   []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			Prefixlen int    `json:"prefixlen"`
			Scope     string `json:"scope"`
		} `json:"addr_info"`
	}
	if rejectAmbiguousJournalJSON(address) != nil || json.Unmarshal(address, &a) != nil || len(a) != 1 || a[0].Ifname != bridge || len(a[0].Info) != 1 {
		return bad()
	}
	record := a[0].Info[0]
	ip, e := netip.ParseAddr(record.Local)
	if e != nil || !ip.Is4() || !ip.IsPrivate() || record.Family != "inet" || record.Scope != "global" || record.Prefixlen < 8 || record.Prefixlen > 30 {
		return bad()
	}
	subnet := netip.PrefixFrom(ip, record.Prefixlen).Masked()
	privateBlocks := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	contained := false
	for _, block := range privateBlocks {
		if block.Bits() <= subnet.Bits() && block.Contains(subnet.Addr()) {
			contained = true
		}
	}
	if !contained || !subnet.Contains(ip) {
		return bad()
	}
	var routes []map[string]json.RawMessage
	if rejectAmbiguousJournalJSON(route) != nil || json.Unmarshal(route, &routes) != nil || len(routes) != 1 {
		return bad()
	}
	row := routes[0]
	if selectiveText(row["dst"]) != subnet.String() || selectiveText(row["protocol"]) != "kernel" || selectiveText(row["scope"]) != "link" || selectiveText(row["prefsrc"]) != ip.String() {
		return bad()
	}
	for _, k := range []string{"via", "gateway", "nhid", "nexthops", "multipath", "encap", "newdst", "src", "dev"} {
		if _, has := row[k]; has {
			return bad()
		}
	}
	if flags, exists := row["flags"]; exists {
		var names []string
		if json.Unmarshal(flags, &names) != nil || (len(names) != 0 && !(len(names) == 1 && names[0] == "linkdown")) {
			return bad()
		}
	}
	return subnet, nil
}

// Inspects ONLY the ip/nat table. NAT in any other family or table makes the
// overall foreign-NAT proof incomplete, even if Docker's own table matches.
func strictDockerNATGraph(objects []map[string]any, bridge string, subnet netip.Prefix) bool {
	chains := map[string]bool{}
	rules := map[string]bool{}
	tableSeen := false
	for _, item := range objects {
		if len(item) != 1 {
			return false
		}
		for kind, raw := range item {
			fields, ok := raw.(map[string]any)
			if !ok {
				return false
			}
			family, _ := fields["family"].(string)
			table, _ := fields["table"].(string)
			if kind == "table" {
				table, _ = fields["name"].(string)
			}
			if family != "ip" || table != "nat" {
				if kind == "rule" {
					for _, raw := range dockerNATExprList(fields) {
						if dockerNATForeignEffect(raw) {
							return false
						}
					}
				}
				if kind == "chain" && fields["type"] == "nat" {
					return false
				}
				continue
			}
			switch kind {
			case "table":
				if tableSeen {
					return false
				}
				tableSeen = true
			case "chain":
				name, _ := fields["name"].(string)
				if chains[name] {
					return false
				}
				switch name {
				case "PREROUTING", "OUTPUT", "POSTROUTING", "INPUT":
					if fields["type"] != "nat" || fields["hook"] != strings.ToLower(name) || fields["policy"] != "accept" {
						return false
					}
					prio := 100
					if name == "PREROUTING" || name == "OUTPUT" {
						prio = -100
					}
					if !dockerNATNumber(fields["prio"], prio) {
						return false
					}
				case "DOCKER":
					for _, key := range []string{"hook", "type", "prio", "policy"} {
						if _, found := fields[key]; found {
							return false
						}
					}
				default:
					return false
				}
				chains[name] = true
			case "rule":
				name, _ := fields["chain"].(string)
				if rules[name] || !dockerNATRulesMatch(name, dockerNATExprList(fields), bridge, subnet) {
					return false
				}
				rules[name] = true
			default:
				return false
			}
		}
	}
	// On Debian 13 iptables-nft reports an implicit empty INPUT ACCEPT
	// policy without materializing a chain in nft JSON. All four actual
	// Docker rules, including their targets, remain mandatory. Any present
	// INPUT chain must have the exact verified hook/policy from above.
	return tableSeen && (len(chains) == 4 || (len(chains) == 5 && chains["INPUT"])) &&
		chains["PREROUTING"] && chains["OUTPUT"] && chains["POSTROUTING"] && chains["DOCKER"] &&
		len(rules) == 4 && rules["PREROUTING"] && rules["OUTPUT"] && rules["POSTROUTING"] && rules["DOCKER"]
}

func dockerNATExprList(fields map[string]any) []any { x, _ := fields["expr"].([]any); return x }
func dockerNATForeignEffect(raw any) bool {
	expr, ok := raw.(map[string]any)
	if !ok || len(expr) != 1 {
		return true
	}
	for kind, v := range expr {
		switch kind {
		case "snat", "dnat", "masquerade", "redirect":
			return true
		case "xt":
			m, ok := v.(map[string]any)
			if !ok {
				return true
			}
			if m["type"] == "target" {
				switch m["name"] {
				case "SNAT", "DNAT", "MASQUERADE", "REDIRECT":
					return true
				}
			}
		}
	}
	return false
}

// Returns only a bounded static shape, not support for active routing. No
// implicit backend switch, global flush, or mutation can originate here.
func strictDockerNATSnapshot(link, address, route json.RawMessage, objects []map[string]any, nftText, legacyText []byte, bridge, underlay string) bool {
	subnet, e := strictDockerNATBridge(link, address, route, bridge, underlay)
	return e == nil && strictDockerNATText(nftText, legacyText, bridge, subnet) && strictDockerNATGraph(objects, bridge, subnet)
}

func dockerNATBridgeFromPolicy(policy []byte) string {
	if len(policy) == 0 || len(policy) > 16384 || bytes.IndexByte(policy, 0) >= 0 {
		return ""
	}
	lines := strings.Split(strings.TrimSuffix(string(policy), "\n"), "\n")
	if len(lines) != 9 {
		return ""
	}
	const before, after = "-A DOCKER -i ", " -j RETURN"
	last := lines[8]
	if !strings.HasPrefix(last, before) || !strings.HasSuffix(last, after) {
		return ""
	}
	bridge := strings.TrimSuffix(strings.TrimPrefix(last, before), after)
	if !smartTUNDeviceName.MatchString(bridge) || bridge == "lo" {
		return ""
	}
	return bridge
}

func observeDockerNATShape(objects []map[string]any, underlay string) bool {
	nftText, e := runReadOnlyHostNetfilter("/usr/sbin/iptables-nft", "-t", "nat", "-S")
	if e != nil {
		return false
	}
	bridge := dockerNATBridgeFromPolicy(nftText)
	if bridge == "" || bridge == underlay {
		return false
	}
	link, e := nativeIPJSON("-d", "-j", "link", "show", "dev", bridge)
	if e != nil {
		return false
	}
	addr, e := nativeIPJSON("-j", "-4", "address", "show", "dev", bridge)
	if e != nil {
		return false
	}
	routes, e := nativeIPJSON("-j", "-4", "route", "show", "table", "main", "dev", bridge)
	if e != nil {
		return false
	}
	legacyText, e := runReadOnlyHostNetfilter("/usr/sbin/iptables-legacy", "-t", "nat", "-S")
	if e != nil {
		return false
	}
	// A second real backend inventory catches ordinary drift while the
	// bridge and legacy backend are observed. It is still NOT a reservation.
	after, e := runReadOnlyHostNetfilter("/usr/sbin/iptables-nft", "-t", "nat", "-S")
	if e != nil || !bytes.Equal(nftText, after) {
		return false
	}
	return strictDockerNATSnapshot(link, addr, routes, objects, nftText, legacyText, bridge, underlay)
}
