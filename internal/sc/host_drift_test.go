package sc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func driftFixture() HostPreflight {
	return HostPreflight{
		Mode: "observation_only", ReadOnly: true, SnapshotAtomic: false,
		ActivationReady: false,
		Links:           json.RawMessage(`[{"ifname":"eth0","ifindex":2},{"ifname":"lo","ifindex":1}]`),
		IPv4Routes:      json.RawMessage(`[{"dst":"198.51.100.0/24","dev":"eth0"},{"dst":"default","dev":"eth0"}]`),
		IPv6Routes:      json.RawMessage(`[]`),
		IPv4Rules:       json.RawMessage(`[{"priority":0,"table":"local"},{"priority":32766,"table":"main"}]`),
		IPv6Rules:       json.RawMessage(`[{"priority":0,"table":"local"}]`),
		Endpoint:        &HostRouteLookup{Target: "198.51.100.9", Family: "ipv4", KernelRoute: json.RawMessage(`[{"dst":"198.51.100.9","dev":"eth0","table":"main"}]`)},
		ManagementPeer:  &HostRouteLookup{Target: "2001:db8::9", Family: "ipv6", KernelRoute: json.RawMessage(`[{"dst":"2001:db8::9","dev":"eth0","table":"main"}]`)},
	}
}

func TestHostDriftSemanticCompareAndSafetyInvariants(t *testing.T) {
	base := driftFixture()
	other := driftFixture()
	other.Links = json.RawMessage(`[{"ifindex":1, "ifname":"lo"}, {"ifindex":2, "ifname":"eth0"}]`)
	other.IPv4Routes = json.RawMessage(`[{"dev":"eth0","dst":"default"}, {"dev":"eth0","dst":"198.51.100.0/24"}]`)
	report, err := compareHostDriftSnapshots(base, other)
	if err != nil || report.Changed || !report.CurrentObserved || report.Outcome != "matching_observations" ||
		!report.ReadOnly || report.SnapshotAtomic || report.ActivationReady || len(report.Components) != 7 ||
		len(report.Limitations) < 3 {
		t.Fatalf("false drift/readiness or missing comparison evidence: %+v error=%v", report, err)
	}
	serialized, err := json.Marshal(report)
	if err != nil || bytes.Contains(serialized, []byte(base.Endpoint.Target)) ||
		bytes.Contains(serialized, []byte(base.ManagementPeer.Target)) ||
		bytes.Contains(serialized, []byte(`"management_peer"`)) ||
		bytes.Contains(serialized, []byte(`"endpoint"`)) {
		t.Fatalf("private baseline target leaked through report: %s err=%v", serialized, err)
	}
	for _, c := range report.Components {
		if c.Changed || len(c.BaselineSHA256) != 64 || c.BaselineSHA256 != c.ObservedSHA256 {
			t.Fatalf("false component identity: %+v", c)
		}
	}
}

func TestHostDriftLargeNumericKernelValuesDoNotCollide(t *testing.T) {
	one := json.RawMessage(`[{"dst":"default","metric":9007199254740992}]`)
	two := json.RawMessage(`[{"dst":"default","metric":9007199254740993}]`)
	a, err := hostDriftFingerprint(one, true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hostDriftFingerprint(two, true)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("distinct 64-bit kernel values collided after JSON canonicalization")
	}
}

func TestHostDriftDetectsConcreteChangesWithoutRestoringAnything(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		mutate       func(*HostPreflight)
	}{
		{"different_link", "links", func(p *HostPreflight) { p.Links = json.RawMessage(`[{"ifname":"lo","ifindex":1}]`) }},
		{"route", "ipv4_routes", func(p *HostPreflight) { p.IPv4Routes = json.RawMessage(`[{"dst":"default","dev":"eth1"}]`) }},
		{"ipv6", "ipv6_routes", func(p *HostPreflight) { p.IPv6Routes = json.RawMessage(`[{"dst":"::/0","dev":"eth1"}]`) }},
		{"rule_priority", "ipv4_rules", func(p *HostPreflight) {
			p.IPv4Rules = json.RawMessage(`[{"priority":100,"table":"main"},{"priority":32766,"table":"main"}]`)
		}},
		{"rule_order", "ipv4_rules", func(p *HostPreflight) {
			p.IPv4Rules = json.RawMessage(`[{"priority":32766,"table":"main"},{"priority":0,"table":"local"}]`)
		}},
		{"peer", "management_route", func(p *HostPreflight) {
			p.ManagementPeer.KernelRoute = json.RawMessage(`[{"dst":"2001:db8::9","dev":"eth1","table":"main"}]`)
		}},
		{"endpoint", "endpoint_route", func(p *HostPreflight) {
			p.Endpoint.KernelRoute = json.RawMessage(`[{"dst":"198.51.100.9","dev":"eth1","table":"main"}]`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, now := driftFixture(), driftFixture()
			tc.mutate(&now)
			report, err := compareHostDriftSnapshots(base, now)
			if ErrorCode(err) != "host_drift_detected" || !report.ReadOnly || report.ActivationReady ||
				!report.CurrentObserved || !report.Changed || report.Outcome != "observations_changed" {
				t.Fatalf("drift did not fail closed: %+v error=%v", report, err)
			}
			count := 0
			for _, c := range report.Components {
				if c.Changed {
					count++
					if c.Name != tc.target || c.BaselineSHA256 == c.ObservedSHA256 {
						t.Fatalf("unexpected drift component: %+v", c)
					}
				}
			}
			if count != 1 {
				t.Fatalf("expected only one change, got %d: %+v", count, report.Components)
			}
		})
	}
}

func writeDriftBaseline(t *testing.T, dir string, snapshot HostPreflight) string {
	t.Helper()
	doc, err := json.Marshal(struct {
		OK   bool          `json:"ok"`
		Data HostPreflight `json:"data"`
	}{OK: true, Data: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, doc, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHostDriftBaselineRejectsIncompleteAndUntrustedFiles(t *testing.T) {
	dir := t.TempDir()
	ok := driftFixture()
	cases := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"bad_json", []byte("{"), 0600},
		{"zero_length", nil, 0600},
		{"empty_object", []byte("{}"), 0600},
		{"wrong_mode", []byte(`{"ok":true,"data":{"mode":"underlay_tcp_diagnostic"}}`), 0600},
		{"failed_envelope", []byte(`{"ok":false,"data":{}}`), 0600},
		{"null_data", []byte(`{"ok":true,"data":null}`), 0600},
		{"world_readable", []byte(`{"ok":true}`), 0644},
		{"oversized", bytes.Repeat([]byte("a"), hostDriftBaselineMaxBytes+1), 0600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "case-"+tc.name)
			if err := os.WriteFile(path, tc.data, tc.mode); err != nil {
				t.Fatal(err)
			}
			report, err := InspectHostDrift(path)
			if ErrorCode(err) != "invalid_baseline" || report.Mode != "" ||
				strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "baseline.json") {
				t.Fatalf("bad baseline processed or leaked path: %+v err=%v", report, err)
			}
		})
	}
	filename := writeDriftBaseline(t, dir, ok)
	if err := os.Symlink(filename, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectHostDrift(filepath.Join(dir, "alias")); ErrorCode(err) != "invalid_baseline" {
		t.Fatalf("followed baseline symlink: %v", err)
	}
	if _, err := InspectHostDrift(filepath.Join(dir, "nonexistent")); ErrorCode(err) != "invalid_baseline" {
		t.Fatalf("missing file: %v", err)
	}
	if runtime.GOOS == "linux" {
		fifo := filepath.Join(dir, "unsupported-fifo")
		if err := syscall.Mkfifo(fifo, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := InspectHostDrift(fifo); ErrorCode(err) != "invalid_baseline" {
			t.Fatalf("FIFO was followed or blocked: %v", err)
		}
	}
	badVersions := []func(*HostPreflight){
		func(p *HostPreflight) { p.ReadOnly = false },
		func(p *HostPreflight) { p.ActivationReady = true },
		func(p *HostPreflight) { p.SnapshotAtomic = true },
		func(p *HostPreflight) { p.Links = nil },
		func(p *HostPreflight) { p.IPv4Routes = json.RawMessage(`[true]`) },
		func(p *HostPreflight) { p.Endpoint.Target = "host.example" },
		func(p *HostPreflight) { p.Endpoint.Family = "ipv6" },
		func(p *HostPreflight) { p.Endpoint.KernelRoute = json.RawMessage(`[]`) },
	}
	for i, mutate := range badVersions {
		bad := driftFixture()
		mutate(&bad)
		path := writeDriftBaseline(t, t.TempDir(), bad)
		if _, err := InspectHostDrift(path); ErrorCode(err) != "invalid_baseline" {
			t.Errorf("invalid baseline version %d accepted: %v", i, err)
		}
	}
}

// Incomplete-but-well-formed success envelopes must fail before any
// invocation of trusted native iproute2. This checks the reader directly,
// as well as the public observation path.
func TestHostDriftRejectsStructurallyIncompleteBaselines(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*HostPreflight)
	}{
		{"empty_links", func(p *HostPreflight) { p.Links = json.RawMessage(`[]`) }},
		{"empty_link_object", func(p *HostPreflight) { p.Links = json.RawMessage(`[{}]`) }},
		{"missing_link_index", func(p *HostPreflight) { p.Links = json.RawMessage(`[{"ifname":"eth0"}]`) }},
		{"zero_link_index", func(p *HostPreflight) { p.Links = json.RawMessage(`[{"ifname":"eth0","ifindex":0}]`) }},
		{"string_link_index", func(p *HostPreflight) { p.Links = json.RawMessage(`[{"ifname":"eth0","ifindex":"2"}]`) }},
		{"missing_link_name", func(p *HostPreflight) { p.Links = json.RawMessage(`[{"ifindex":2}]`) }},
		{"duplicate_link_index", func(p *HostPreflight) {
			p.Links = json.RawMessage(`[{"ifname":"eth0","ifindex":2},{"ifname":"eth1","ifindex":2}]`)
		}},
		{"endpoint_empty_route_object", func(p *HostPreflight) { p.Endpoint.KernelRoute = json.RawMessage(`[{}]`) }},
		{"management_empty_route_object", func(p *HostPreflight) { p.ManagementPeer.KernelRoute = json.RawMessage(`[{}]`) }},
		{"endpoint_destination_only", func(p *HostPreflight) { p.Endpoint.KernelRoute = json.RawMessage(`[{"dst":"198.51.100.9"}]`) }},
		{"management_destination_only", func(p *HostPreflight) { p.ManagementPeer.KernelRoute = json.RawMessage(`[{"dst":"2001:db8::9"}]`) }},
		{"endpoint_route_missing_destination", func(p *HostPreflight) { p.Endpoint.KernelRoute = json.RawMessage(`[{"dev":"eth0"}]`) }},
		{"endpoint_route_wrong_destination", func(p *HostPreflight) {
			p.Endpoint.KernelRoute = json.RawMessage(`[{"dst":"198.51.100.8","dev":"eth0"}]`)
		}},
		{"management_route_wrong_family", func(p *HostPreflight) {
			p.ManagementPeer.KernelRoute = json.RawMessage(`[{"dst":"198.51.100.9","dev":"eth0"}]`)
		}},
		{"empty_ipv4_route_object", func(p *HostPreflight) { p.IPv4Routes = json.RawMessage(`[{}]`) }},
		{"ipv4_route_without_destination", func(p *HostPreflight) { p.IPv4Routes = json.RawMessage(`[{"dev":"eth0"}]`) }},
		{"ipv4_destination_only", func(p *HostPreflight) { p.IPv4Routes = json.RawMessage(`[{"dst":"default"}]`) }},
		{"wrong_family_ipv6_route", func(p *HostPreflight) { p.IPv6Routes = json.RawMessage(`[{"dst":"198.51.100.0/24","dev":"eth0"}]`) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := driftFixture()
			tc.mutate(&base)
			path := writeDriftBaseline(t, t.TempDir(), base)
			if _, err := readHostDriftBaseline(path); ErrorCode(err) != "invalid_baseline" {
				t.Fatalf("incomplete evidence passed pre-native reader: %v", err)
			}
			report, err := InspectHostDrift(path)
			if ErrorCode(err) != "invalid_baseline" || report.Mode != "" || strings.Contains(err.Error(), path) {
				t.Fatalf("invalid input reached observation or leaked path: %+v, %v", report, err)
			}
		})
	}
}

func TestHostDriftSpecialRoutesAndEmptyFamiliesRemainSupported(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*HostPreflight)
	}{
		{"empty_route_families", func(p *HostPreflight) { p.IPv4Routes = json.RawMessage(`[]`); p.IPv6Routes = json.RawMessage(`[]`) }},
		{"local_route_without_device", func(p *HostPreflight) {
			p.IPv4Routes = json.RawMessage(`[{"type":"local","dst":"127.0.0.1","table":"local"}]`)
		}},
		{"blackhole_route_without_device", func(p *HostPreflight) {
			p.IPv6Routes = json.RawMessage(`[{"type":"blackhole","dst":"2001:db8::/48","table":"main"}]`)
		}},
		{"blackhole_lookup_without_device", func(p *HostPreflight) {
			p.Endpoint.KernelRoute = json.RawMessage(`[{"type":"blackhole","dst":"198.51.100.9"}]`)
		}},
		{"gateway_only_route", func(p *HostPreflight) { p.IPv4Routes = json.RawMessage(`[{"dst":"default","gateway":"192.0.2.1"}]`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := driftFixture()
			tc.change(&p)
			path := writeDriftBaseline(t, t.TempDir(), p)
			if _, err := readHostDriftBaseline(path); err != nil {
				t.Fatalf("valid special Linux representation rejected: %v", err)
			}
		})
	}
}

// Baseline validation runs before trusted native iproute2. The success
// envelope must contain explicitly asserted safety flags, and each policy
// rule must carry an actual priority and kernel action rather than [{}].
func TestHostDriftRuleRecordsAndExplicitSafetyAssertions(t *testing.T) {
	invalid := []struct {
		name   string
		mutate func(*HostPreflight)
	}{
		{"ipv4_rules_empty_object", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{}]`) }},
		{"ipv6_rules_empty_object", func(p *HostPreflight) { p.IPv6Rules = json.RawMessage(`[{}]`) }},
		{"ipv4_rule_priority_only", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{"priority":100}]`) }},
		{"ipv6_rule_priority_only", func(p *HostPreflight) { p.IPv6Rules = json.RawMessage(`[{"priority":100,"src":"all"}]`) }},
		{"ipv4_rule_no_priority", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{"src":"all","table":"main"}]`) }},
		{"ipv6_rule_no_priority", func(p *HostPreflight) { p.IPv6Rules = json.RawMessage(`[{"type":"unreachable","src":"all"}]`) }},
		{"ipv4_rule_null_priority", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{"priority":null,"table":"main"}]`) }},
		{"ipv4_rule_string_priority", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{"priority":"100","table":"main"}]`) }},
		{"ipv4_rule_negative_priority", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{"priority":-1,"table":"main"}]`) }},
		{"ipv4_rule_fractional_priority", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{"priority":1.5,"table":"main"}]`) }},
		{"ipv4_rule_oversized_priority", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{"priority":4294967296,"table":"main"}]`) }},
		{"ipv4_rule_null_table", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{"priority":1,"table":null}]`) }},
		{"ipv4_rule_empty_table", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{"priority":1,"table":"  "}]`) }},
		{"ipv4_rule_zero_table", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{"priority":1,"table":0}]`) }},
		{"ipv4_rule_unknown_action", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{"priority":1,"action":"unknown"}]`) }},
		{"ipv4_rule_false_l3mdev", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{"priority":1,"l3mdev":false}]`) }},
		{"ipv4_rule_empty_goto", func(p *HostPreflight) { p.IPv4Rules = json.RawMessage(`[{"priority":1,"goto":null}]`) }},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := driftFixture()
			tc.mutate(&snapshot)
			path := writeDriftBaseline(t, t.TempDir(), snapshot)
			if _, err := readHostDriftBaseline(path); ErrorCode(err) != "invalid_baseline" {
				t.Fatalf("accepted a structurally incomplete policy rule: %v", err)
			}
			report, err := InspectHostDrift(path)
			if ErrorCode(err) != "invalid_baseline" || report.Mode != "" || strings.Contains(err.Error(), path) {
				t.Fatalf("invalid policy rule reached native inspection or leaked private path: %+v %v", report, err)
			}
		})
	}
	for _, field := range []string{"snapshot_atomic", "activation_ready", "read_only", "mode"} {
		t.Run("missing_"+field, func(t *testing.T) {
			baseline := writeDriftBaseline(t, t.TempDir(), driftFixture())
			bytes, err := os.ReadFile(baseline)
			if err != nil {
				t.Fatal(err)
			}
			var envelope map[string]json.RawMessage
			if err = json.Unmarshal(bytes, &envelope); err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(envelope["data"], &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, field)
			if envelope["data"], err = json.Marshal(fields); err != nil {
				t.Fatal(err)
			}
			if bytes, err = json.Marshal(envelope); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(baseline, bytes, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = readHostDriftBaseline(baseline); ErrorCode(err) != "invalid_baseline" {
				t.Fatalf("accepted omitted mandatory %s assertion: %v", field, err)
			}
			report, err := InspectHostDrift(baseline)
			if ErrorCode(err) != "invalid_baseline" || report.Mode != "" {
				t.Fatalf("partial success envelope accepted: %+v %v", report, err)
			}
		})
		t.Run("null_"+field, func(t *testing.T) {
			baseline := writeDriftBaseline(t, t.TempDir(), driftFixture())
			bytes, err := os.ReadFile(baseline)
			if err != nil {
				t.Fatal(err)
			}
			var envelope map[string]json.RawMessage
			if err = json.Unmarshal(bytes, &envelope); err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(envelope["data"], &fields); err != nil {
				t.Fatal(err)
			}
			fields[field] = json.RawMessage("null")
			if envelope["data"], err = json.Marshal(fields); err != nil {
				t.Fatal(err)
			}
			if bytes, err = json.Marshal(envelope); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(baseline, bytes, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = readHostDriftBaseline(baseline); ErrorCode(err) != "invalid_baseline" {
				t.Fatalf("accepted null mandatory %s assertion: %v", field, err)
			}
		})
	}
}

func TestHostDriftSupportedPolicyRuleShapeFixtures(t *testing.T) {
	cases := []struct {
		name  string
		rules json.RawMessage
	}{
		{"empty", json.RawMessage(`[]`)},
		{"ordinary", json.RawMessage(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`)},
		{"numeric_table", json.RawMessage(`[{"priority":100,"src":"all","table":100}]`)},
		{"source_uid_and_mark", json.RawMessage(`[{"priority":100,"src":"192.0.2.0","srclen":24,"fwmark":"0x1","uid_start":0,"uid_end":1000,"table":"100"}]`)},
		{"unreachable", json.RawMessage(`[{"priority":100,"src":"all","action":"unreachable"}]`)},
		{"blackhole", json.RawMessage(`[{"priority":100,"src":"all","action":"blackhole"}]`)},
		{"prohibit", json.RawMessage(`[{"priority":100,"src":"all","action":"prohibit"}]`)},
		{"goto", json.RawMessage(`[{"priority":100,"goto":200}]`)},
		{"nop", json.RawMessage(`[{"priority":100,"src":"all","nop":null}]`)},
		{"l3mdev", json.RawMessage(`[{"priority":100,"src":"all","l3mdev":null}]`)},
		{"throw", json.RawMessage(`[{"priority":100,"src":"all","action":"throw"}]`)},
		{"anycast", json.RawMessage(`[{"priority":100,"src":"all","action":"anycast"}]`)},
		{"multicast", json.RawMessage(`[{"priority":100,"src":"all","action":"multicast"}]`)},
		{"xresolve", json.RawMessage(`[{"priority":100,"src":"all","action":"xresolve"}]`)},
		{"nat_masquerade", json.RawMessage(`[{"priority":100,"src":"all","table":"main","masquerade":null}]`)},
		{"nat_gateway", json.RawMessage(`[{"priority":100,"src":"all","table":"main","nat_gateway":"198.51.100.1"}]`)},
	}
	for _, tc := range cases {
		for _, family := range []string{"ipv4", "ipv6"} {
			t.Run(family+"_"+tc.name, func(t *testing.T) {
				s := driftFixture()
				if family == "ipv4" {
					s.IPv4Rules = tc.rules
				} else {
					s.IPv6Rules = tc.rules
				}
				path := writeDriftBaseline(t, t.TempDir(), s)
				if _, err := readHostDriftBaseline(path); err != nil {
					t.Fatalf("valid policy rule rejected: %v", err)
				}
			})
		}
	}
}

// The fixture formats below are grounded in actual iproute2 6.15
// "ip -j rule show" output, NOT the similarly named "ip -j route" schema.
// See iproute2 v6.15.0 ip/iprule.c, print_rule().
func TestHostDriftRejectsNonNativePolicyActionMarkers(t *testing.T) {
	invalid := []struct {
		name  string
		rules json.RawMessage
	}{
		{"route_style_unreachable", json.RawMessage(`[{"priority":100,"type":"unreachable"}]`)},
		{"route_style_blackhole", json.RawMessage(`[{"priority":100,"type":"blackhole"}]`)},
		{"route_style_nop", json.RawMessage(`[{"priority":100,"type":"nop"}]`)},
		{"route_style_nat", json.RawMessage(`[{"priority":100,"type":"nat"}]`)},
		{"route_type_with_table", json.RawMessage(`[{"priority":100,"table":"main","type":"unreachable"}]`)},
		{"bool_l3mdev", json.RawMessage(`[{"priority":100,"l3mdev":true}]`)},
		{"false_l3mdev_with_table", json.RawMessage(`[{"priority":100,"table":"main","l3mdev":false}]`)},
		{"bool_nop", json.RawMessage(`[{"priority":100,"nop":true}]`)},
		{"invalid_nop_with_table", json.RawMessage(`[{"priority":100,"table":"main","nop":"noop"}]`)},
		{"empty_action", json.RawMessage(`[{"priority":100,"action":""}]`)},
		{"unknown_action", json.RawMessage(`[{"priority":100,"action":"arbitrary"}]`)},
		{"unknown_action_with_table", json.RawMessage(`[{"priority":100,"table":"main","action":"arbitrary"}]`)},
		{"masquerade_bool", json.RawMessage(`[{"priority":100,"masquerade":true}]`)},
		{"nat_gateway_not_ip", json.RawMessage(`[{"priority":100,"nat_gateway":"example.invalid"}]`)},
		{"nat_gateway_ipv6", json.RawMessage(`[{"priority":100,"nat_gateway":"2001:db8::1"}]`)},
		{"malformed_nat_with_table", json.RawMessage(`[{"priority":100,"table":"main","nat_gateway":false}]`)},
	}
	for _, tc := range invalid {
		for _, family := range []string{"ipv4", "ipv6"} {
			t.Run(family+"_"+tc.name, func(t *testing.T) {
				snap := driftFixture()
				if family == "ipv4" {
					snap.IPv4Rules = tc.rules
				} else {
					snap.IPv6Rules = tc.rules
				}
				path := writeDriftBaseline(t, t.TempDir(), snap)
				if _, err := readHostDriftBaseline(path); ErrorCode(err) != "invalid_baseline" {
					t.Fatalf("accepted impossible/native-invalid rule action as source evidence: %s err=%v", tc.name, err)
				}
				report, err := InspectHostDrift(path)
				if report.Mode != "" || ErrorCode(err) != "invalid_baseline" || strings.Contains(err.Error(), path) {
					t.Fatalf("invalid rule accepted or leaked source path: %+v %v", report, err)
				}
			})
		}
	}
}

// Exact iproute2 6.15 native JSON captured on Debian 13 in an isolated
// unshare -Urn user/network namespace. Unlike synthetic per-action cases,
// these fixed captures always run in GitHub CI even when namespaces are
// disallowed there. Actual source: /usr/bin/ip -j -4/-6 rule show.
func TestHostDriftCapturedDebian13NativeSpecialRuleArrays(t *testing.T) {
	captures := []struct {
		name string
		ipv4 bool
		raw  json.RawMessage
	}{
		{
			"ipv4", true, json.RawMessage(`[{"priority":0,"src":"all","table":"local"},{"priority":121,"src":"all","action":"blackhole"},{"priority":122,"src":"all","action":"unreachable"},{"priority":123,"src":"all","action":"prohibit"},{"priority":124,"src":"all","l3mdev":null},{"priority":125,"src":"all","goto":150},{"priority":126,"src":"all","nop":null},{"priority":127,"src":"all","action":"anycast"},{"priority":128,"src":"all","action":"multicast"},{"priority":129,"src":"all","action":"xresolve"},{"priority":130,"src":"all","action":"throw"},{"priority":131,"src":"all","table":"main","masquerade":null},{"priority":150,"src":"all","table":"main"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`),
		},
		{
			"ipv6", false, json.RawMessage(`[{"priority":0,"src":"all","table":"local"},{"priority":121,"src":"all","action":"blackhole"},{"priority":122,"src":"all","action":"unreachable"},{"priority":123,"src":"all","action":"prohibit"},{"priority":124,"src":"all","l3mdev":null},{"priority":125,"src":"all","goto":150},{"priority":126,"src":"all","nop":null},{"priority":127,"src":"all","action":"anycast"},{"priority":128,"src":"all","action":"multicast"},{"priority":129,"src":"all","action":"xresolve"},{"priority":130,"src":"all","action":"throw"},{"priority":131,"src":"all","table":"main","masquerade":null},{"priority":150,"src":"all","table":"main"},{"priority":32766,"src":"all","table":"main"}]`),
		},
	}
	for _, tc := range captures {
		t.Run(tc.name, func(t *testing.T) {
			if !validHostDriftPolicyRules(tc.raw) {
				t.Fatal("literal native Debian 13 iproute2 capture rejected")
			}
			s := driftFixture()
			if tc.ipv4 {
				s.IPv4Rules = tc.raw
			} else {
				s.IPv6Rules = tc.raw
			}
			path := writeDriftBaseline(t, t.TempDir(), s)
			if _, err := readHostDriftBaseline(path); err != nil {
				t.Fatalf("complete host-preflight with real rule inventory rejected: %v", err)
			}
		})
	}
}

// Native special-policy serialization is captured in a short-lived disposable
// user+network namespace. The only "ip rule add" commands are shell arguments
// to /usr/bin/unshare -Urn; Go has no marker-controlled mutating child branch.
// Thus even a forged environment variable cannot run those commands on the host.
// The fixed Debian 13 captures above remain the CI fallback when unshare is
// forbidden by the runner.
func TestHostDriftNativeSpecialPolicyRuleJSONPrivateNamespace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux required")
	}
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("native iproute2 missing")
	}
	if _, err := os.Stat("/usr/bin/unshare"); err != nil {
		t.Skip("unshare unavailable")
	}
	if output, err := exec.Command("/usr/bin/unshare", "-Urn", "/usr/bin/true").CombinedOutput(); err != nil {
		t.Skipf("private user/network namespace unavailable: %v %s", err, output)
	}
	// Unshare must succeed before /usr/bin/sh can execute a single policy
	// mutation. This script is never invoked directly or selected by an env
	// marker; it lives only in the argv of the trusted unshare executable.
	const capture = `set -eu
for family in -4 -6; do
	/usr/bin/ip "$family" rule add pref 121 blackhole
	/usr/bin/ip "$family" rule add pref 122 unreachable
	/usr/bin/ip "$family" rule add pref 123 prohibit
	/usr/bin/ip "$family" rule add pref 124 l3mdev
	/usr/bin/ip "$family" rule add pref 125 goto 150
	/usr/bin/ip "$family" rule add pref 126 nop
	/usr/bin/ip "$family" rule add pref 127 anycast
	/usr/bin/ip "$family" rule add pref 128 multicast
	/usr/bin/ip "$family" rule add pref 129 xresolve
	/usr/bin/ip "$family" rule add pref 130 throw
	/usr/bin/ip "$family" rule add pref 150 table main
	/usr/bin/ip "$family" rule add pref 131 nat 192.0.2.1
done
/usr/bin/ip -j -4 rule show
/usr/bin/ip -j -6 rule show`
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/unshare", "-Urn", "/usr/bin/sh", "-c", capture)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil || ctx.Err() != nil {
		t.Fatalf("isolated native policy serialization failed: %v timeout=%v stderr=%s", err, ctx.Err(), stderr.String())
	}
	// Only the two native JSON arrays cross back to the parent. All parsing,
	// baseline writing and assertions happen outside the disposable namespace.
	arrays := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
	if len(arrays) != 2 {
		t.Fatalf("expected exactly IPv4 and IPv6 native JSON arrays, got %d", len(arrays))
	}
	for idx, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			raw := json.RawMessage(arrays[idx])
			if !validHostDriftPolicyRules(raw) {
				t.Fatalf("native special policy rules rejected: %s", raw)
			}
			var items []map[string]json.RawMessage
			if err := json.Unmarshal(raw, &items); err != nil {
				t.Fatal(err)
			}
			expected := map[string]bool{
				"action_unreachable": false, "action_blackhole": false,
				"action_prohibit": false, "action_anycast": false,
				"action_multicast": false, "action_xresolve": false,
				"action_throw": false, "l3mdev_null": false,
				"nop_null": false, "goto_numeric": false, "nat": false,
			}
			for _, item := range items {
				var action string
				if json.Unmarshal(item["action"], &action) == nil {
					if _, ok := expected["action_"+action]; ok {
						expected["action_"+action] = true
					}
				}
				for _, marker := range []string{"l3mdev", "nop"} {
					if bytes.Equal(item[marker], []byte("null")) {
						expected[marker+"_null"] = true
					}
				}
				var gotoPriority uint32
				if json.Unmarshal(item["goto"], &gotoPriority) == nil && gotoPriority == 150 {
					expected["goto_numeric"] = true
				}
				if bytes.Equal(item["masquerade"], []byte("null")) {
					expected["nat"] = true
				}
				if ip := hostDriftString(item, "nat_gateway"); ip != "" {
					if addr, err := netip.ParseAddr(ip); err == nil && addr.Is4() {
						expected["nat"] = true
					}
				}
			}
			for key, present := range expected {
				if !present {
					t.Errorf("missing native %s policy action %s", family, key)
				}
			}
			snapshot := driftFixture()
			if family == "ipv4" {
				snapshot.IPv4Rules = raw
			} else {
				snapshot.IPv6Rules = raw
			}
			path := writeDriftBaseline(t, t.TempDir(), snapshot)
			if _, err := readHostDriftBaseline(path); err != nil {
				t.Fatalf("genuine native policy inventory rejected: %v", err)
			}
		})
	}
}

func TestHostDriftActualNativeIPv4IPv6RoutesRemainUnchanged(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux required")
	}
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("native iproute2 not installed")
	}
	if err := trustedHostIPExecutable(); err != nil {
		t.Skipf("native iproute2 trust boundary unavailable: %v", err)
	}
	snapshot := func(args ...string) []byte {
		t.Helper()
		data, err := exec.Command(nativeIPPath, args...).Output()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	readState := func() []byte {
		var b bytes.Buffer
		for _, a := range [][]string{
			{"-j", "-4", "route", "show", "table", "all"},
			{"-j", "-6", "route", "show", "table", "all"},
			{"-j", "-4", "rule", "show"},
			{"-j", "-6", "rule", "show"},
		} {
			b.Write(snapshot(a...))
		}
		return b.Bytes()
	}
	before := readState()
	base, err := InspectHostRoutes("127.0.0.1", "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	path := writeDriftBaseline(t, t.TempDir(), base)
	report, err := InspectHostDrift(path)
	if err != nil || !report.ReadOnly || report.ActivationReady || !report.CurrentObserved ||
		report.SnapshotAtomic || report.Changed || report.Outcome != "matching_observations" ||
		len(report.Components) != 7 {
		t.Fatalf("actual read-only kernel comparison inaccurate: %+v error=%v", report, err)
	}
	after := readState()
	if !bytes.Equal(before, after) {
		t.Fatal("host-drift changed kernel routing state")
	}
	// Inject a synthetic observation delta into a copied private baseline:
	// real Linux data is compared again; no host mutation is needed.
	base.IPv4Routes = append(json.RawMessage(nil), base.IPv4Routes...)
	base.IPv4Routes = append(base.IPv4Routes[:len(base.IPv4Routes)-1], []byte(`,{"dst":"203.0.113.0/24","dev":"fake"}]`)...)
	path = writeDriftBaseline(t, t.TempDir(), base)
	report, err = InspectHostDrift(path)
	if ErrorCode(err) != "host_drift_detected" || !report.Changed || report.ActivationReady ||
		!report.ReadOnly || !report.CurrentObserved {
		t.Fatalf("real observed route delta not detected: %+v err=%v", report, err)
	}
	if !bytes.Equal(before, readState()) {
		t.Fatal("drift diagnosis changed host routing")
	}
}
