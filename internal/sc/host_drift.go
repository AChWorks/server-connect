package sc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"syscall"
)

const hostDriftBaselineMaxBytes = 8 << 20

// HostDriftComponent records only a semantic fingerprint, never raw host
// networking details from a potentially sensitive operator baseline.
type HostDriftComponent struct {
	Name           string `json:"name"`
	BaselineSHA256 string `json:"baseline_sha256"`
	ObservedSHA256 string `json:"observed_sha256"`
	Changed        bool   `json:"changed"`
}

// HostDriftReport compares two independent read-only observations. Neither
// the comparison nor a match confers ownership or permits tunnel activation.
type HostDriftReport struct {
	Mode            string               `json:"mode"`
	ReadOnly        bool                 `json:"read_only"`
	ActivationReady bool                 `json:"activation_ready"`
	SnapshotAtomic  bool                 `json:"snapshot_atomic"`
	Endpoint        string               `json:"endpoint,omitempty"`
	ManagementPeer  string               `json:"management_peer,omitempty"`
	CurrentObserved bool                 `json:"current_observed"`
	Changed         bool                 `json:"changed"`
	Components      []HostDriftComponent `json:"components,omitempty"`
	Outcome         string               `json:"outcome"`
	Limitations     []string             `json:"limitations"`
}

func newHostDriftReport(baseline HostPreflight) HostDriftReport {
	report := HostDriftReport{
		Mode: "host_drift_diagnostic", ReadOnly: true,
		ActivationReady: false, SnapshotAtomic: false,
		Outcome: "not_observed",
		Limitations: []string{
			"Both observations are non-atomic and can be stale immediately after collection.",
			"Equality does not prove VPN endpoint reachability, firewall/conntrack ownership, SSH or HTTP(S) reply safety.",
			"Baseline files are operator-supplied and are not authenticated; a matching observation never authorizes route mutation.",
			"Semantic JSON comparison does not attest host state between observations or preserve a recoverable network journal.",
		},
	}
	if baseline.Endpoint != nil {
		report.Endpoint = baseline.Endpoint.Target
	}
	if baseline.ManagementPeer != nil {
		report.ManagementPeer = baseline.ManagementPeer.Target
	}
	return report
}

// readHostDriftBaseline accepts only a complete successful --json host-preflight
// envelope saved as a private regular file. O_NOFOLLOW and O_NONBLOCK reject
// symlinks and FIFOs without following/hanging on operator-controlled paths.
// Content is bounded before decoding; no path or baseline bytes enter errors.
func readHostDriftBaseline(path string) (HostPreflight, error) {
	bad := func() error {
		return Fault("invalid_baseline", "host drift requires a private, regular, complete host-preflight JSON file")
	}
	if path == "" || strings.TrimSpace(path) != path || path == "-" {
		return HostPreflight{}, bad()
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return HostPreflight{}, bad()
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 ||
		stat.Size() <= 0 || stat.Size() > hostDriftBaselineMaxBytes {
		return HostPreflight{}, bad()
	}
	data, err := io.ReadAll(io.LimitReader(f, hostDriftBaselineMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > hostDriftBaselineMaxBytes {
		return HostPreflight{}, bad()
	}
	var envelope struct {
		OK    *bool           `json:"ok"`
		Data  json.RawMessage `json:"data"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(data, &envelope) != nil || envelope.OK == nil ||
		!*envelope.OK || len(envelope.Error) != 0 || len(envelope.Data) == 0 {
		return HostPreflight{}, bad()
	}
	// Decode safety assertions as pointers: decoding directly into bools
	// silently treats missing or null fields as the safe-looking false
	// values. A valid source must explicitly assert every safety field.
	var assertions struct {
		ReadOnly        *bool `json:"read_only"`
		SnapshotAtomic  *bool `json:"snapshot_atomic"`
		ActivationReady *bool `json:"activation_ready"`
	}
	if json.Unmarshal(envelope.Data, &assertions) != nil ||
		assertions.ReadOnly == nil || !*assertions.ReadOnly ||
		assertions.SnapshotAtomic == nil || *assertions.SnapshotAtomic ||
		assertions.ActivationReady == nil || *assertions.ActivationReady {
		return HostPreflight{}, bad()
	}
	var snapshot HostPreflight
	if json.Unmarshal(envelope.Data, &snapshot) != nil || validateHostDriftSnapshot(snapshot) != nil {
		return HostPreflight{}, bad()
	}
	return snapshot, nil
}

// Reject malformed or incomplete source evidence before executing iproute2.
// This only validates shape and asserted mode, not authenticity or freshness.
func validateHostDriftSnapshot(snapshot HostPreflight) error {
	bad := func() error { return errors.New("missing or unsupported host-preflight evidence") }
	if snapshot.Mode != "observation_only" || !snapshot.ReadOnly ||
		snapshot.SnapshotAtomic || snapshot.ActivationReady {
		return bad()
	}
	// A successful Linux link inventory cannot be empty: even a private
	// namespace has loopback. Interface indexes and names identify links
	// without assuming any specific type or host naming convention.
	if !validHostDriftLinks(snapshot.Links) ||
		!validHostDriftRoutes(snapshot.IPv4Routes, false) ||
		!validHostDriftRoutes(snapshot.IPv6Routes, true) {
		return bad()
	}
	if !validHostDriftPolicyRules(snapshot.IPv4Rules) ||
		!validHostDriftPolicyRules(snapshot.IPv6Rules) {
		return bad()
	}
	for _, lookup := range []*HostRouteLookup{snapshot.Endpoint, snapshot.ManagementPeer} {
		if lookup == nil {
			continue
		}
		ip, err := parsePreflightAddress(lookup.Target, "target")
		if err != nil || !ip.IsValid() || ip.String() != lookup.Target {
			return bad()
		}
		family := "ipv4"
		if ip.Is6() {
			family = "ipv6"
		}
		if lookup.Family != family {
			return bad()
		}
		arr, err := decodeRouteArray(lookup.KernelRoute)
		if err != nil {
			return bad()
		}
		var items []json.RawMessage
		if json.Unmarshal(arr, &items) != nil || len(items) != 1 ||
			!validHostDriftLookupRoute(items[0], ip) {
			return bad()
		}
	}
	return nil
}

// These checks establish minimal usable *shape* for a successful iproute2
// snapshot, not trust in an operator-supplied baseline. We must not require
// any IPv4/IPv6 routes or a normal device on blackhole/local routes.
func hostDriftObjects(raw json.RawMessage) ([]map[string]json.RawMessage, bool) {
	canonical, err := decodeRouteArray(raw)
	if err != nil {
		return nil, false
	}
	var entries []json.RawMessage
	if json.Unmarshal(canonical, &entries) != nil {
		return nil, false
	}
	rows := make([]map[string]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		var obj map[string]json.RawMessage
		if json.Unmarshal(entry, &obj) != nil || len(obj) == 0 {
			return nil, false
		}
		rows = append(rows, obj)
	}
	return rows, true
}

func hostDriftString(obj map[string]json.RawMessage, key string) string {
	var value string
	if json.Unmarshal(obj[key], &value) != nil || value == "" || strings.TrimSpace(value) != value {
		return ""
	}
	return value
}

func validHostDriftLinks(raw json.RawMessage) bool {
	rows, ok := hostDriftObjects(raw)
	if !ok || len(rows) == 0 {
		return false
	}
	byIndex := make(map[int]bool, len(rows))
	byName := make(map[string]bool, len(rows))
	for _, link := range rows {
		name := hostDriftString(link, "ifname")
		var index int
		if name == "" || json.Unmarshal(link["ifindex"], &index) != nil || index <= 0 ||
			byIndex[index] || byName[name] {
			return false
		}
		byIndex[index], byName[name] = true, true
	}
	return true
}

func hostDriftRouteDestination(obj map[string]json.RawMessage, ipv6 bool) bool {
	dst := hostDriftString(obj, "dst")
	if dst == "default" {
		return true
	}
	if dst == "" {
		return false
	}
	if prefix, err := netip.ParsePrefix(dst); err == nil {
		return prefix.Addr().Is6() == ipv6 && !prefix.Addr().Is4In6()
	}
	addr, err := netip.ParseAddr(dst)
	return err == nil && addr.Is6() == ipv6 && !addr.Is4In6()
}

func hostDriftRouteHasIdentity(obj map[string]json.RawMessage) bool {
	if hostDriftString(obj, "dev") != "" {
		return true
	}
	if gateway := hostDriftString(obj, "gateway"); gateway != "" {
		if ip, err := netip.ParseAddr(gateway); err == nil && ip.IsValid() {
			return true
		}
	}
	// iproute2 can return a valid terminal action with no output device.
	switch hostDriftString(obj, "type") {
	case "local", "broadcast", "anycast", "multicast", "blackhole", "unreachable", "prohibit", "throw", "nat":
		return true
	}
	var nhid int
	if json.Unmarshal(obj["nhid"], &nhid) == nil && nhid > 0 {
		return true
	}
	var nexthops []json.RawMessage
	if json.Unmarshal(obj["nexthops"], &nexthops) == nil && len(nexthops) > 0 {
		for _, raw := range nexthops {
			var hop map[string]json.RawMessage
			if json.Unmarshal(raw, &hop) != nil || len(hop) == 0 ||
				(hostDriftString(hop, "dev") == "" && hostDriftString(hop, "gateway") == "") {
				return false
			}
		}
		return true
	}
	return false
}

func validHostDriftRoutes(raw json.RawMessage, ipv6 bool) bool {
	// Empty route families are unusual but possible in isolated hosts.
	rows, ok := hostDriftObjects(raw)
	if !ok {
		return false
	}
	for _, route := range rows {
		if !hostDriftRouteDestination(route, ipv6) ||
			!hostDriftRouteHasIdentity(route) {
			return false
		}
	}
	return true
}

func validHostDriftLookupRoute(raw json.RawMessage, target netip.Addr) bool {
	var route map[string]json.RawMessage
	if json.Unmarshal(raw, &route) != nil || len(route) == 0 ||
		!hostDriftRouteHasIdentity(route) {
		return false
	}
	// 'ip -j route get <literal>' returns the queried destination in dst,
	// even when it was selected through a default route.
	dst, err := netip.ParseAddr(hostDriftString(route, "dst"))
	return err == nil && dst == target
}

// Native 'ip -j rule show' gives every rule a numeric priority and a
// lookup/action. Selectors alone (src, fwmark, UID, etc.) are not sufficient
// evidence that a policy-rule record was successfully captured. Rule arrays
// may legitimately be empty on some isolated Linux hosts.
func validHostDriftRuleTable(raw json.RawMessage) bool {
	var name *string
	if json.Unmarshal(raw, &name) == nil && name != nil &&
		*name != "" && strings.TrimSpace(*name) == *name {
		return true
	}
	var number *uint32
	return json.Unmarshal(raw, &number) == nil && number != nil && *number > 0
}

func validHostDriftPolicyRules(raw json.RawMessage) bool {
	rows, ok := hostDriftObjects(raw)
	if !ok {
		return false
	}
	for _, rule := range rows {
		// A pointer distinguishes priority 0 from an omitted/null priority.
		var priority *uint32
		if json.Unmarshal(rule["priority"], &priority) != nil || priority == nil {
			return false
		}
		action := false
		if value, exists := rule["table"]; exists {
			if !validHostDriftRuleTable(value) {
				return false
			}
			action = true
		}
		if value, exists := rule["lookup"]; exists {
			if !validHostDriftRuleTable(value) {
				return false
			}
			action = true
		}
		if value, exists := rule["goto"]; exists {
			var gotoPriority *uint32
			if json.Unmarshal(value, &gotoPriority) != nil || gotoPriority == nil || *gotoPriority == 0 {
				return false
			}
			action = true
		}
		if value, exists := rule["l3mdev"]; exists {
			var enabled *bool
			if json.Unmarshal(value, &enabled) != nil || enabled == nil {
				return false
			}
			if *enabled {
				action = true
			}
		}
		if _, exists := rule["type"]; exists {
			ruleType := hostDriftString(rule, "type")
			if ruleType == "" {
				return false
			}
			switch ruleType {
			case "blackhole", "unreachable", "prohibit", "nop", "nat":
				action = true
			}
		}
		if !action {
			return false
		}
	}
	return true
}

// Semantic fingerprints normalize object key order and whitespace. For links
// and routes kernel enumeration order is irrelevant; policy rules intentionally
// preserve priority/order, including ties that can change routing semantics.
func hostDriftFingerprint(raw json.RawMessage, unordered bool) (string, error) {
	arr, err := decodeRouteArray(raw)
	if err != nil {
		return "", err
	}
	var elements []json.RawMessage
	if err := json.Unmarshal(arr, &elements); err != nil {
		return "", err
	}
	canonical := make([]string, 0, len(elements))
	for _, elem := range elements {
		// Never coerce large kernel counters/IDs through float64, where
		// distinct values above 2^53 would silently acquire one digest.
		var parsed any
		decoder := json.NewDecoder(bytes.NewReader(elem))
		decoder.UseNumber()
		if err := decoder.Decode(&parsed); err != nil {
			return "", err
		}
		normalized, err := json.Marshal(parsed)
		if err != nil {
			return "", err
		}
		canonical = append(canonical, string(normalized))
	}
	if unordered {
		sort.Strings(canonical)
	}
	digest, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(digest)
	return hex.EncodeToString(hash[:]), nil
}

// compareHostDriftSnapshots is pure and can be tested with real routing
// fixtures without mutating host tables. A mismatch is a warning, not a
// decision to restore, rewrite or take ownership of anything.
func compareHostDriftSnapshots(baseline, observed HostPreflight) (HostDriftReport, error) {
	report := newHostDriftReport(baseline)
	if validateHostDriftSnapshot(baseline) != nil || validateHostDriftSnapshot(observed) != nil {
		return report, Fault("host_drift_unavailable", "cannot compare incomplete host route observations")
	}
	type component struct {
		name        string
		before, now json.RawMessage
		unordered   bool
	}
	components := []component{
		{"links", baseline.Links, observed.Links, true},
		{"ipv4_routes", baseline.IPv4Routes, observed.IPv4Routes, true},
		{"ipv6_routes", baseline.IPv6Routes, observed.IPv6Routes, true},
		{"ipv4_rules", baseline.IPv4Rules, observed.IPv4Rules, false},
		{"ipv6_rules", baseline.IPv6Rules, observed.IPv6Rules, false},
	}
	for _, lookup := range []struct {
		name string
		old  *HostRouteLookup
		now  *HostRouteLookup
	}{
		{"endpoint_route", baseline.Endpoint, observed.Endpoint},
		{"management_route", baseline.ManagementPeer, observed.ManagementPeer},
	} {
		if (lookup.old == nil) != (lookup.now == nil) {
			return report, Fault("host_drift_unavailable", "the observed lookup target differs from baseline")
		}
		if lookup.old != nil {
			if lookup.old.Target != lookup.now.Target || lookup.old.Family != lookup.now.Family {
				return report, Fault("host_drift_unavailable", "the observed lookup target differs from baseline")
			}
			components = append(components, component{lookup.name, lookup.old.KernelRoute, lookup.now.KernelRoute, false})
		}
	}
	report.CurrentObserved = true
	for _, c := range components {
		before, err := hostDriftFingerprint(c.before, c.unordered)
		if err != nil {
			return report, Fault("host_drift_unavailable", "invalid baseline host route observation")
		}
		now, err := hostDriftFingerprint(c.now, c.unordered)
		if err != nil {
			return report, Fault("host_drift_unavailable", "invalid current host route observation")
		}
		changed := before != now
		report.Changed = report.Changed || changed
		report.Components = append(report.Components, HostDriftComponent{
			Name: c.name, BaselineSHA256: before, ObservedSHA256: now, Changed: changed,
		})
	}
	if report.Changed {
		report.Outcome = "observations_changed"
		return report, Fault("host_drift_detected", "host routes, rules or links differ from recorded baseline")
	}
	report.Outcome = "matching_observations"
	return report, nil
}

// InspectHostDrift is always observational: it never calls the state manager
// or modifies routes, firewall, DNS, services, profile state or the baseline.
// An invalid baseline is rejected before any native command or network query.
func InspectHostDrift(baselineFile string) (HostDriftReport, error) {
	baseline, err := readHostDriftBaseline(baselineFile)
	if err != nil {
		return HostDriftReport{}, err
	}
	report := newHostDriftReport(baseline)
	observed, err := InspectHostRoutes(report.Endpoint, report.ManagementPeer)
	if err != nil {
		report.Outcome = "observation_failed"
		return report, err
	}
	return compareHostDriftSnapshots(baseline, observed)
}
