package sc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SelectivePlanRequest represents only historical v1 journal binding.
// New selective staging/activation was retired; this validates old records.
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

// SelectiveRoutePlan reconstructs the exact legacy v1 plan-digest shape.
// It is not an operator preview or permission to apply any host policy.
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

// These historic v1 destination bounds are necessary for validating a
// persisted journal, not a limit on current native Smart Routing.
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
	// encoding/json silently leaves non-pointer integers at zero for null.
	// A missing kernel numeric selector must never become a trusted zero.
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0, false
	}
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

// Parse the actual native iproute2 rule selector without guessing the
// prefix length of a bare IP. Older CIDR-shaped JSON is accepted, but
// mismatched/unknown split selectors must never prove non-interference.
func selectiveRuleDestination(row map[string]json.RawMessage, ipv6 bool) (netip.Prefix, bool, error) {
	invalid := func() (netip.Prefix, bool, error) {
		return netip.Prefix{}, false, Fault("route_plan_uncertain", "policy rule destination prefix is incomplete or unsupported")
	}
	raw, lengthRaw := row["dst"], row["dstlen"]
	if len(raw) == 0 {
		if len(lengthRaw) != 0 {
			return invalid()
		}
		return netip.Prefix{}, false, nil
	}
	name := selectiveText(raw)
	if name == "all" || name == "default" {
		if len(lengthRaw) != 0 {
			length, ok := selectiveInt(lengthRaw)
			if !ok || length != 0 {
				return invalid()
			}
		}
		return netip.Prefix{}, false, nil
	}
	prefix, err := netip.ParsePrefix(name)
	if err == nil {
		if len(lengthRaw) != 0 {
			length, ok := selectiveInt(lengthRaw)
			if !ok || length != prefix.Bits() {
				return invalid()
			}
		}
	} else {
		address, parseErr := netip.ParseAddr(name)
		if parseErr != nil || len(lengthRaw) == 0 {
			return invalid()
		}
		length, ok := selectiveInt(lengthRaw)
		if !ok || length > address.BitLen() {
			return invalid()
		}
		prefix = netip.PrefixFrom(address, length)
	}
	if !prefix.IsValid() || prefix.Addr().Zone() != "" ||
		prefix.Addr().Is4In6() || prefix.Addr().Is6() != ipv6 ||
		prefix.Masked() != prefix {
		return invalid()
	}
	return prefix, true, nil
}

// Persisted v1 journal hashes must continue to validate byte-equivalent
// resource identity after removing the obsolete advisory planner.
func selectivePlanDigest(plan SelectiveRoutePlan) (string, error) {
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
		return "", err
	}
	sum := sha256.Sum256(intentBytes)
	return hex.EncodeToString(sum[:]), nil
}
