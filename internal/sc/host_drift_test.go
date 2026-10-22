package sc

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
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
		report.Endpoint != base.Endpoint.Target || report.ManagementPeer != base.ManagementPeer.Target ||
		len(report.Limitations) < 3 {
		t.Fatalf("false drift/readiness or missing comparison evidence: %+v error=%v", report, err)
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

func TestHostDriftValidNativePolicyRuleShapes(t *testing.T) {
	cases := []struct {
		name  string
		rules json.RawMessage
	}{
		{"empty", json.RawMessage(`[]`)},
		{"ordinary", json.RawMessage(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`)},
		{"numeric_table", json.RawMessage(`[{"priority":100,"src":"all","table":100}]`)},
		{"source_uid_and_mark", json.RawMessage(`[{"priority":100,"src":"192.0.2.0","srclen":24,"fwmark":"0x1","uid_start":0,"uid_end":1000,"table":"100"}]`)},
		{"unreachable", json.RawMessage(`[{"priority":100,"type":"unreachable"}]`)},
		{"blackhole", json.RawMessage(`[{"priority":100,"type":"blackhole","src":"all"}]`)},
		{"prohibit", json.RawMessage(`[{"priority":100,"type":"prohibit"}]`)},
		{"goto", json.RawMessage(`[{"priority":100,"goto":200}]`)},
		{"nop", json.RawMessage(`[{"priority":100,"type":"nop"}]`)},
		{"l3mdev", json.RawMessage(`[{"priority":100,"l3mdev":true}]`)},
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
