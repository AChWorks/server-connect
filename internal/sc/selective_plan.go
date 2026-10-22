package sc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SelectivePlanRequest describes intent only. It never claims that an
// interface is owned, a core is ready, or a route can safely be installed.
type SelectivePlanRequest struct {
	EndpointIP       string
	ManagementPeerIP string
	TunnelInterface  string
	Destinations     []string
}

type PlannedRoute struct {
	Family      string `json:"family"`
	Destination string `json:"destination"`
	Table       int    `json:"table"`
	Device      string `json:"device"`
}

type PlannedRule struct {
	Family      string `json:"family"`
	Destination string `json:"destination"`
	Priority    int    `json:"priority"`
	Table       int    `json:"table"`
}

// SelectiveRoutePlan is an advisory preview, not a command list, journal,
// activation permission, or host-side reservation. A later guarded applier
// must re-observe all host state under its own exclusive transaction lock.
type SelectiveRoutePlan struct {
	Mode              string         `json:"mode"`
	ReadOnly          bool           `json:"read_only"`
	SnapshotAtomic    bool           `json:"snapshot_atomic"`
	ActivationReady   bool           `json:"activation_ready"`
	GuardArmed        bool           `json:"guard_armed"`
	OwnershipVerified bool           `json:"ownership_verified"`
	Endpoint          string         `json:"endpoint"`
	ManagementPeer    string         `json:"management_peer"`
	TunnelInterface   string         `json:"tunnel_interface"`
	RouteTable        int            `json:"route_table"`
	Routes            []PlannedRoute `json:"routes"`
	Rules             []PlannedRule  `json:"rules"`
	ObservationSHA256 string         `json:"observation_sha256"`
	PlanSHA256        string         `json:"plan_sha256"`
	Limitations       []string       `json:"limitations"`
}

const (
	selectiveMaxDestinations = 32
	selectiveFirstTable      = 20000
	selectiveLastTable       = 20127
	selectiveFirstPriority   = 30000
	selectiveLastPriority    = 30999
)

// IsGlobalUnicast deliberately includes several non-public special-purpose
// ranges. Refuse commonly routed private, carrier, documentation and
// transition space rather than offering a misleading "foreign route" preview.
// This is a conservative candidate filter, NOT a geo-IP classifier or
// proof of public reachability.
var selectiveExcludedRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func selectiveOverlapsExcluded(prefix netip.Prefix) bool {
	for _, excluded := range selectiveExcludedRanges {
		if prefix.Overlaps(excluded) {
			return true
		}
	}
	return false
}

var selectiveInterfacePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$`)

type validatedSelective struct {
	endpoint, peer netip.Addr
	device         string
	prefixes       []netip.Prefix
}

func validateSelectiveRequest(req SelectivePlanRequest) (validatedSelective, error) {
	bad := func(msg string) (validatedSelective, error) {
		return validatedSelective{}, Fault("invalid_arguments", msg)
	}
	if !selectiveInterfacePattern.MatchString(req.TunnelInterface) ||
		strings.HasPrefix(req.TunnelInterface, ".") {
		return bad("a new Linux tunnel interface name (1-15 ASCII characters) is required")
	}
	if req.EndpointIP == "" || req.ManagementPeerIP == "" {
		return bad("both literal endpoint and management peer addresses are mandatory")
	}
	endpoint, err := parsePreflightAddress(req.EndpointIP, "endpoint")
	if err != nil || !endpoint.IsValid() || endpoint.IsLoopback() {
		return bad("endpoint must be a literal non-loopback unicast IP")
	}
	peer, err := parsePreflightAddress(req.ManagementPeerIP, "management peer")
	if err != nil || !peer.IsValid() || peer.IsLoopback() {
		return bad("management peer must be a literal non-loopback unicast IP")
	}
	if len(req.Destinations) == 0 || len(req.Destinations) > selectiveMaxDestinations {
		return bad("selective mode requires 1-32 explicit destination prefixes")
	}
	prefixes := make([]netip.Prefix, 0, len(req.Destinations))
	for _, raw := range req.Destinations {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.IsValid() || prefix.Addr().Zone() != "" ||
			prefix.Addr().Is4In6() || prefix.Masked() != prefix ||
			!prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() ||
			prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() ||
			selectiveOverlapsExcluded(prefix) {
			return bad("each destination must be a canonical public unicast CIDR prefix")
		}
		// Broad/catch-all selection is a separate mode with a different
		// ingress-reply and fail-closed safety contract.
		if (prefix.Addr().Is4() && prefix.Bits() < 8) ||
			(prefix.Addr().Is6() && prefix.Bits() < 32) {
			return bad("destination scope is too wide for selective preview")
		}
		if (prefix.Addr().Is4() == endpoint.Is4() && prefix.Contains(endpoint)) ||
			(prefix.Addr().Is4() == peer.Is4() && prefix.Contains(peer)) {
			return bad("destination would redirect the protected endpoint or management peer")
		}
		for _, prev := range prefixes {
			if prefix.Overlaps(prev) {
				return bad("duplicate or overlapping destination prefixes")
			}
		}
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return prefixes[i].String() < prefixes[j].String()
	})
	return validatedSelective{endpoint: endpoint, peer: peer, device: req.TunnelInterface, prefixes: prefixes}, nil
}

// PreviewSelectiveRoutes is read-only and never persists network/manager state.
// Invalid inputs are rejected before any kernel inspection.
func PreviewSelectiveRoutes(req SelectivePlanRequest) (SelectiveRoutePlan, error) {
	intent, err := validateSelectiveRequest(req)
	if err != nil {
		return SelectiveRoutePlan{}, err
	}
	host, err := InspectHostRoutes(intent.endpoint.String(), intent.peer.String())
	if err != nil {
		return SelectiveRoutePlan{}, err
	}
	return buildSelectivePlan(intent, host)
}

func selectiveRows(raw json.RawMessage) ([]map[string]json.RawMessage, error) {
	var rows []map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &rows) != nil || rows == nil {
		return nil, Fault("route_plan_uncertain", "kernel route/rule inventory is incomplete")
	}
	for _, row := range rows {
		if len(row) == 0 {
			return nil, Fault("route_plan_uncertain", "kernel route/rule entry is unsupported")
		}
	}
	return rows, nil
}

func selectiveText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func selectiveInt(raw json.RawMessage) (int, bool) {
	var value int
	if json.Unmarshal(raw, &value) == nil {
		return value, value >= 0
	}
	s := selectiveText(raw)
	if s == "" {
		return 0, false
	}
	v, err := strconv.Atoi(s)
	return v, err == nil && v >= 0
}

// Unknown iproute2 table names are intentionally unsupported: custom
// rt_tables aliases may name a table in our candidate range.
func selectiveTable(raw json.RawMessage, absentMeansMain bool) (int, error) {
	if len(raw) == 0 {
		if absentMeansMain {
			return 254, nil
		}
		return 0, Fault("route_plan_uncertain", "policy rule has no identifiable lookup table")
	}
	switch selectiveText(raw) {
	case "main":
		return 254, nil
	case "local":
		return 255, nil
	case "default":
		return 253, nil
	case "unspec":
		return 0, nil
	}
	if v, ok := selectiveInt(raw); ok && v <= 0x7fffffff {
		return v, nil
	}
	return 0, Fault("route_plan_uncertain", "kernel table identity uses an unsupported alias")
}

func selectiveRoutePrefix(dst json.RawMessage, isIPv6 bool) (netip.Prefix, bool, error) {
	s := selectiveText(dst)
	if s == "default" {
		return netip.Prefix{}, true, nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		addr, e := netip.ParseAddr(s)
		if e != nil || !addr.IsValid() {
			return netip.Prefix{}, false, Fault("route_plan_uncertain", "kernel route destination is unsupported")
		}
		p = netip.PrefixFrom(addr, addr.BitLen())
	}
	if !p.IsValid() || p.Addr().Is6() != isIPv6 || p.Addr().Is4In6() {
		return netip.Prefix{}, false, Fault("route_plan_uncertain", "kernel route family is inconsistent")
	}
	if p.Bits() == 0 {
		return netip.Prefix{}, true, nil
	}
	return p.Masked(), false, nil
}

// An existing RPDB rule may terminate lookup before a proposed rule.
// Since a selective preview has no source, mark or interface constraint,
// those selectors cannot prove that a foreign rule is disjoint.
type selectiveObservedRule struct {
	priority int
	table    int
	row      map[string]json.RawMessage
}

func selectiveEarlierRuleMayPreempt(rule selectiveObservedRule, destination netip.Prefix, defaults map[int]bool) (bool, error) {
	uncertain := func() (bool, error) {
		return false, Fault("route_plan_uncertain", "higher-precedence policy rule cannot be proven to fall through for the selected destination")
	}
	// The inverse of a disjoint 'to' selector DOES match. Unknown rule
	// flags and negation cannot be used to prove safe non-interference.
	if len(rule.row["not"]) != 0 || len(rule.row["invert"]) != 0 || len(rule.row["flags"]) != 0 {
		return uncertain()
	}
	if raw := rule.row["dst"]; len(raw) != 0 {
		text := selectiveText(raw)
		if text == "" {
			return uncertain()
		}
		if text != "all" && text != "default" {
			selected, err := netip.ParsePrefix(text)
			if err != nil {
				address, parseErr := netip.ParseAddr(text)
				if parseErr != nil {
					return uncertain()
				}
				selected = netip.PrefixFrom(address, address.BitLen())
			}
			if !selected.IsValid() || selected.Addr().Zone() != "" ||
				selected.Addr().Is4In6() || selected.Addr().Is6() != destination.Addr().Is6() {
				return uncertain()
			}
			if !selected.Overlaps(destination) {
				return false, nil
			}
		}
	}
	// Unsupported actions, dynamic tables, suppressors, and jumps can
	// terminate routing evaluation without any table route.
	if rule.table == 0 || len(rule.row["l3mdev"]) != 0 ||
		len(rule.row["goto"]) != 0 || len(rule.row["suppress_prefixlength"]) != 0 ||
		len(rule.row["suppress_ifgroup"]) != 0 || len(rule.row["nat"]) != 0 {
		return uncertain()
	}
	if action := selectiveText(rule.row["action"]); len(rule.row["action"]) != 0 &&
		action != "to_tbl" && action != "lookup" {
		return uncertain()
	}
	if kind := selectiveText(rule.row["type"]); len(rule.row["type"]) != 0 &&
		kind != "unicast" {
		return uncertain()
	}
	for key := range rule.row {
		switch key {
		case "priority", "table", "src", "dst", "fwmark", "fwmask", "iif",
			"oif", "tos", "uidrange", "ipproto", "sport", "dport", "tun_id",
			"protocol", "realms", "action", "type":
		default:
			return uncertain()
		}
	}
	// All non-default routes are checked globally for overlapping
	// destinations. A plain lookup with no matching route falls through,
	// but a table default can shadow the proposed destination-specific
	// policy even when no non-default route overlaps.
	return defaults[rule.table], nil
}

// Fingerprints cover the complete protected-path observation, not merely
// inventory. Canonical JSON removes object key ordering and whitespace
// differences while retaining numeric precision through json.Number.
func selectiveCanonicalArray(raw json.RawMessage, requireEntry bool) (json.RawMessage, error) {
	rows, err := selectiveRows(raw)
	if err != nil || (requireEntry && len(rows) == 0) {
		return nil, Fault("route_plan_uncertain", "kernel observation evidence is absent or unsupported")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var data any
	if err := decoder.Decode(&data); err != nil {
		return nil, Fault("route_plan_uncertain", "protected route lookup evidence cannot be normalized")
	}
	canonical, err := json.Marshal(data)
	if err != nil {
		return nil, Fault("route_plan_uncertain", "protected route lookup evidence cannot be fingerprinted")
	}
	return canonical, nil
}

func selectiveCanonicalLookup(lookup *HostRouteLookup, target netip.Addr) (HostRouteLookup, error) {
	family := "ipv4"
	if target.Is6() {
		family = "ipv6"
	}
	if lookup == nil || lookup.Target != target.String() || lookup.Family != family {
		return HostRouteLookup{}, Fault("route_plan_uncertain", "protected route lookup identity does not match the request")
	}
	rows, err := selectiveRows(lookup.KernelRoute)
	if err != nil || len(rows) == 0 {
		return HostRouteLookup{}, Fault("route_plan_uncertain", "protected route lookup has no kernel evidence")
	}
	for _, row := range rows {
		if selectiveText(row["dst"]) != target.String() {
			return HostRouteLookup{}, Fault("route_plan_uncertain", "protected route lookup target is missing or inconsistent")
		}
	}
	canonical, err := selectiveCanonicalArray(lookup.KernelRoute, true)
	if err != nil {
		return HostRouteLookup{}, err
	}
	return HostRouteLookup{Target: target.String(), Family: family, KernelRoute: canonical}, nil
}

func buildSelectivePlan(intent validatedSelective, host HostPreflight) (SelectiveRoutePlan, error) {
	uncertain := func(message string) (SelectiveRoutePlan, error) {
		return SelectiveRoutePlan{}, Fault("route_plan_uncertain", message)
	}
	if host.Mode != "observation_only" || !host.ReadOnly || host.SnapshotAtomic ||
		host.ActivationReady || host.Endpoint == nil || host.ManagementPeer == nil ||
		host.Endpoint.Target != intent.endpoint.String() ||
		host.ManagementPeer.Target != intent.peer.String() {
		return uncertain("host preflight does not match the requested protected paths")
	}
	linkRows, err := selectiveRows(host.Links)
	if err != nil || len(linkRows) == 0 {
		return uncertain("kernel link inventory is unavailable")
	}
	seenLinks := map[string]bool{}
	for _, link := range linkRows {
		name := selectiveText(link["ifname"])
		if name == "" || seenLinks[name] {
			return uncertain("kernel link identity is incomplete")
		}
		seenLinks[name] = true
		// Linux alternate interface names also occupy the device name
		// namespace; do not accidentally propose adopting an existing one.
		if len(link["altnames"]) != 0 {
			var aliases []string
			if json.Unmarshal(link["altnames"], &aliases) != nil || aliases == nil {
				return uncertain("kernel alternate link identity is unsupported")
			}
			for _, alias := range aliases {
				if alias == "" || seenLinks[alias] {
					return uncertain("kernel alternate link identity is incomplete")
				}
				seenLinks[alias] = true
			}
		}
	}
	if seenLinks[intent.device] {
		return uncertain("requested tunnel interface is already present and not proven owned")
	}
	endpointLookup, err := selectiveCanonicalLookup(host.Endpoint, intent.endpoint)
	if err != nil {
		return SelectiveRoutePlan{}, err
	}
	managementLookup, err := selectiveCanonicalLookup(host.ManagementPeer, intent.peer)
	if err != nil {
		return SelectiveRoutePlan{}, err
	}
	usedTables := make(map[int]bool)
	usedPriorities := make(map[int]bool)
	defaultTables := map[bool]map[int]bool{false: {}, true: {}}
	rulesByFamily := map[bool][]selectiveObservedRule{false: {}, true: {}}
	for _, family := range []struct {
		raw  json.RawMessage
		ipv6 bool
	}{
		{host.IPv4Routes, false}, {host.IPv6Routes, true},
	} {
		rows, err := selectiveRows(family.raw)
		if err != nil {
			return SelectiveRoutePlan{}, err
		}
		for _, route := range rows {
			table, err := selectiveTable(route["table"], true)
			if err != nil {
				return SelectiveRoutePlan{}, err
			}
			usedTables[table] = true
			known, isDefault, err := selectiveRoutePrefix(route["dst"], family.ipv6)
			if err != nil {
				return SelectiveRoutePlan{}, err
			}
			if isDefault {
				defaultTables[family.ipv6][table] = true
				continue
			}
			for _, dst := range intent.prefixes {
				if dst.Addr().Is6() == family.ipv6 && known.Overlaps(dst) {
					return uncertain("requested destinations overlap existing host-owned routes")
				}
			}
		}
	}
	for _, family := range []struct {
		raw  json.RawMessage
		ipv6 bool
	}{
		{host.IPv4Rules, false}, {host.IPv6Rules, true},
	} {
		rows, err := selectiveRows(family.raw)
		if err != nil {
			return SelectiveRoutePlan{}, err
		}
		for _, rule := range rows {
			priority, ok := selectiveInt(rule["priority"])
			if !ok {
				return uncertain("kernel rule priority is missing or unsupported")
			}
			usedPriorities[priority] = true
			// A non-lookup rule or l3mdev/VRF dynamic selection must be
			// reviewed by a future guarded planner; no table is owned.
			table, err := selectiveTable(rule["table"], false)
			if err != nil {
				return SelectiveRoutePlan{}, err
			}
			usedTables[table] = true
			rulesByFamily[family.ipv6] = append(rulesByFamily[family.ipv6], selectiveObservedRule{
				priority: priority, table: table, row: rule,
			})
		}
	}
	table := 0
	for n := selectiveFirstTable; n <= selectiveLastTable; n++ {
		if !usedTables[n] {
			table = n
			break
		}
	}
	if table == 0 {
		return uncertain("no unoccupied preview routing table in the bounded candidate range")
	}
	plan := SelectiveRoutePlan{
		Mode: "selective_preview", ReadOnly: true, SnapshotAtomic: false,
		ActivationReady: false, GuardArmed: false, OwnershipVerified: false,
		Endpoint: intent.endpoint.String(), ManagementPeer: intent.peer.String(),
		TunnelInterface: intent.device, RouteTable: table,
		Routes: []PlannedRoute{}, Rules: []PlannedRule{},
		Limitations: []string{
			"This is a non-atomic read-only preview: no routes, rules, interfaces, services or manager state were changed or reserved.",
			"An unused table/priority is NOT proof of ownership; any future apply must re-observe atomically and journal exact owned deltas.",
			"No independent activation/runtime guard, fresh SSH confirmation, firewall/conntrack, existing ingress replies, domestic reachability, DNS, or VPN-bound probe is verified.",
			"Do not apply these advisory rules manually; they cannot establish safe host-wide activation.",
		},
	}
	priority := selectiveFirstPriority
	for _, prefix := range intent.prefixes {
		for priority <= selectiveLastPriority && usedPriorities[priority] {
			priority++
		}
		if priority > selectiveLastPriority {
			return uncertain("no unoccupied preview rule priority in the bounded candidate range")
		}
		// Evaluate every proposed priority. A rule between planned priorities
		// may shadow a later destination even when the first is unaffected.
		ipv6 := prefix.Addr().Is6()
		for _, earlier := range rulesByFamily[ipv6] {
			if earlier.priority >= priority {
				continue
			}
			preempts, err := selectiveEarlierRuleMayPreempt(earlier, prefix, defaultTables[ipv6])
			if err != nil {
				return SelectiveRoutePlan{}, err
			}
			if preempts {
				return uncertain("higher-precedence lookup can shadow the selected route through an existing default route")
			}
		}
		family := "ipv4"
		if prefix.Addr().Is6() {
			family = "ipv6"
		}
		plan.Routes = append(plan.Routes, PlannedRoute{
			Family: family, Destination: prefix.String(), Table: table, Device: intent.device,
		})
		plan.Rules = append(plan.Rules, PlannedRule{
			Family: family, Destination: prefix.String(), Table: table, Priority: priority,
		})
		priority++
	}
	// Never interpret a preview digest as an activation precondition.
	observations := [5]json.RawMessage{
		host.Links, host.IPv4Routes, host.IPv6Routes, host.IPv4Rules, host.IPv6Rules,
	}
	for i, raw := range observations {
		var err error
		observations[i], err = selectiveCanonicalArray(raw, false)
		if err != nil {
			return uncertain("cannot canonicalize kernel observation")
		}
	}
	observed, err := json.Marshal(struct {
		Links, V4Routes, V6Routes, V4Rules, V6Rules json.RawMessage
		Endpoint, ManagementPeer                    HostRouteLookup
	}{
		observations[0], observations[1], observations[2], observations[3], observations[4],
		endpointLookup, managementLookup,
	})
	if err != nil {
		return uncertain("cannot fingerprint kernel observation")
	}
	fingerprint := sha256.Sum256(observed)
	plan.ObservationSHA256 = hex.EncodeToString(fingerprint[:])
	// Do not hash the limitations or self-referential plan digest.
	intentBytes, err := json.Marshal(struct {
		Endpoint, Peer, Device string
		Table                  int
		Routes                 []PlannedRoute
		Rules                  []PlannedRule
		Observed               string
	}{
		plan.Endpoint, plan.ManagementPeer, plan.TunnelInterface,
		plan.RouteTable, plan.Routes, plan.Rules, plan.ObservationSHA256,
	})
	if err != nil {
		return uncertain("cannot fingerprint advisory plan")
	}
	sum := sha256.Sum256(intentBytes)
	plan.PlanSHA256 = hex.EncodeToString(sum[:])
	if len(plan.Rules) != len(intent.prefixes) {
		return uncertain(fmt.Sprintf("incomplete preview for %d destinations", len(intent.prefixes)))
	}
	return plan, nil
}
