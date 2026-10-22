package sc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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
	for _, component := range []json.RawMessage{
		snapshot.Links, snapshot.IPv4Routes, snapshot.IPv6Routes,
		snapshot.IPv4Rules, snapshot.IPv6Rules,
	} {
		if _, err := decodeRouteArray(component); err != nil {
			return bad()
		}
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
		if json.Unmarshal(arr, &items) != nil || len(items) != 1 {
			return bad()
		}
	}
	return nil
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
