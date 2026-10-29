package sc

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Exact shape of nftables -j list ruleset output as documented in
// libnftables-json(5), including required metadata even for empty rulesets.
const nftMeta = `{"metainfo":{"version":"1.1.3","release_name":"Commodore Bullmoose #4","json_schema_version":1}}`
const exampleNFT = `{"nftables":[` + nftMeta + `,{"table":{"family":"inet","name":"foreign-user"}},{"chain":{"family":"inet","table":"foreign-user","name":"output","type":"filter","hook":"output","prio":0,"policy":"accept"}},{"rule":{"family":"inet","table":"foreign-user","chain":"output","expr":[{"counter":{"packets":12,"bytes":8192}},{"match":{"left":{"payload":{"protocol":"ip","field":"daddr"}},"op":"==","right":"8.8.8.8"}}]}}]}`

func TestFirewallCanonicalFingerprintAndVolatileCounters(t *testing.T) {
	a, err := decodeNFTSnapshot([]byte(exampleNFT))
	if err != nil || !a.Observed || a.ObjectCount != 4 || !firewallDigest.MatchString(a.RulesetSHA256) {
		t.Fatalf("valid nftables evidence rejected: %+v, %v", a, err)
	}
	reordered := `{"nftables":[{"metainfo":{"json_schema_version":1,"release_name":"Commodore Bullmoose #4","version":"1.1.3"}},{"table":{"name":"foreign-user","family":"inet"}},{"chain":{"policy":"accept","prio":0,"hook":"output","type":"filter","name":"output","table":"foreign-user","family":"inet"}},{"rule":{"expr":[{"counter":{"bytes":9999999999,"packets":999}},{"match":{"right":"8.8.8.8","op":"==","left":{"payload":{"field":"daddr","protocol":"ip"}}}}],"chain":"output","table":"foreign-user","family":"inet"}}]}`
	b, err := decodeNFTSnapshot([]byte(reordered))
	if err != nil || b.RulesetSHA256 != a.RulesetSHA256 {
		t.Fatalf("packet counters, whitespace or object key order caused false drift: %+v vs %+v err=%v", a, b, err)
	}
	// Quotas change effective packet admission as they are consumed:
	// unlike a passive counter, changing quota usage MUST trigger drift.
	quota1 := `{"nftables":[` + nftMeta + `,{"rule":{"family":"inet","table":"t","chain":"c","expr":[{"quota":{"val":4096,"used":1,"unit":"bytes"}}]}}]}`
	quota2 := `{"nftables":[` + nftMeta + `,{"rule":{"family":"inet","table":"t","chain":"c","expr":[{"quota":{"val":4096,"used":4096,"unit":"bytes"}}]}}]}`
	q1, e1 := decodeNFTSnapshot([]byte(quota1))
	q2, e2 := decodeNFTSnapshot([]byte(quota2))
	if e1 != nil || e2 != nil || q1.RulesetSHA256 == q2.RulesetSHA256 {
		t.Fatal("effective quota exhaustion disappeared from the firewall snapshot")
	}
	mutation := strings.Replace(exampleNFT, "8.8.8.8", "9.9.9.9", 1)
	c, err := decodeNFTSnapshot([]byte(mutation))
	if err != nil || c.RulesetSHA256 == a.RulesetSHA256 {
		t.Fatalf("different nftables routing/firewall decision did not change hash: %+v err=%v", c, err)
	}
	// Ordered firewall rules are semantically meaningful, unlike object
	// member ordering. Reordering two rules must change the fingerprint.
	first := `{"nftables":[` + nftMeta + `,{"rule":{"family":"inet","chain":"c","table":"t","expr":[{"accept":null}]}},{"rule":{"family":"inet","chain":"c","table":"t","expr":[{"drop":null}]}}]}`
	second := `{"nftables":[` + nftMeta + `,{"rule":{"family":"inet","chain":"c","table":"t","expr":[{"drop":null}]}},{"rule":{"family":"inet","chain":"c","table":"t","expr":[{"accept":null}]}}]}`
	f, err1 := decodeNFTSnapshot([]byte(first))
	g, err2 := decodeNFTSnapshot([]byte(second))
	if err1 != nil || err2 != nil || f.RulesetSHA256 == g.RulesetSHA256 {
		t.Fatalf("ordered firewall decisions collided: %v %v", err1, err2)
	}
}

func TestFirewallAcceptsGenuineEmptyAndRecognizedRulesetKinds(t *testing.T) {
	empty, err := decodeNFTSnapshot([]byte(`{"nftables":[` + nftMeta + `]}`))
	if err != nil || !empty.Observed || empty.ObjectCount != 1 ||
		!firewallDigest.MatchString(empty.RulesetSHA256) {
		t.Fatalf("valid native empty ruleset wrongly rejected: %+v err=%v", empty, err)
	}
	// Recognized native categories are hashed opaquely after their minimum
	// documented identities are validated. Do not implement a rule engine
	// or reject valid site firewalls merely for using named objects.
	for _, entry := range []string{
		`{"table":{"family":"ip","name":"filter"}}`,
		`{"chain":{"family":"inet","table":"t","name":"input"}}`,
		`{"rule":{"family":"inet","table":"t","chain":"input","expr":[{"accept":null}]}}`,
		`{"set":{"family":"inet","table":"t","name":"s","type":"ipv4_addr"}}`,
		`{"set":{"family":"inet","table":"t","name":"s","type":{"typeof":{"payload":{"protocol":"ip","field":"saddr"}}}}}`,
		`{"map":{"family":"inet","table":"t","name":"m","type":"ipv4_addr","map":"verdict"}}`,
		`{"element":{"family":"inet","table":"t","name":"s","elem":["8.8.8.8"]}}`,
		`{"flowtable":{"family":"inet","table":"t","name":"f","hook":"ingress","prio":0,"dev":"eth0"}}`,
		`{"counter":{"family":"inet","table":"t","name":"count","packets":0,"bytes":0}}`,
		`{"quota":{"family":"inet","table":"t","name":"limit","bytes":500,"used":0}}`,
		`{"ct helper":{"family":"inet","table":"t","name":"ftp"}}`,
		`{"ct timeout":{"family":"inet","table":"t","name":"conn"}}`,
		`{"ct expectation":{"family":"inet","table":"t","name":"expected"}}`,
		`{"limit":{"family":"inet","table":"t","name":"throttle"}}`,
	} {
		got, err := decodeNFTSnapshot([]byte(`{"nftables":[` + nftMeta + `,` + entry + `]}`))
		if err != nil || !got.Observed || got.ObjectCount != 2 {
			t.Errorf("documented native object kind not recognized: %s, %+v, %v", entry, got, err)
		}
	}
}

func TestFirewallLargeNumbersAndMalformedJSONFailClosed(t *testing.T) {
	first, err := decodeNFTSnapshot([]byte(`{"nftables":[` + nftMeta + `,{"table":{"family":"inet","name":"t","handle":9007199254740992}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := decodeNFTSnapshot([]byte(`{"nftables":[` + nftMeta + `,{"table":{"family":"inet","name":"t","handle":9007199254740993}}]}`))
	if err != nil || first.RulesetSHA256 == second.RulesetSHA256 {
		t.Fatal("distinct 64-bit kernel IDs collided")
	}
	for _, raw := range []string{
		"", "{}", "null", "[]", `{"nftables":null}`,
		`{"nftables":[]}`, // Missing metadata is NOT a valid empty ruleset.
		`{"nftables":[{"table":{"family":"inet","name":"t"}}]}`,
		`{"nftables":[{"metainfo":{"version":"1.1.3"}}]}`,
		`{"nftables":[{"metainfo":{"version":"1.1.3","release_name":"r"}}]}`,
		`{"nftables":[{"metainfo":{"version":12,"release_name":"r","json_schema_version":1}}]}`,
		`{"nftables":[{"metainfo":{"version":"1","release_name":null,"json_schema_version":1}}]}`,
		`{"nftables":[{"metainfo":{"version":"1","release_name":"r","json_schema_version":"1"}}]}`,
		`{"nftables":[{"metainfo":{"version":"1","release_name":"r","json_schema_version":1.0}}]}`,
		`{"nftables":[{"metainfo":{"version":"1","release_name":"r","json_schema_version":2}}]}`,
		`{"nftables":[{"metainfo":{"version":"1","release_name":"r","json_schema_version":0}}]}`,
		`{"nftables":[{"metainfo":{}}]}`,
		`{"nftables":[{"metainfo":123}]}`,
		`{"nftables":[` + nftMeta + `,` + nftMeta + `]}`,
		`{"nftables":[` + nftMeta + `,{"table":123}]}`,
		`{"nftables":[` + nftMeta + `,{"chain":[]}]}`,
		`{"nftables":[` + nftMeta + `,{"rule":{}}]}`,
		`{"nftables":[` + nftMeta + `,{"table":{}}]}`,
		`{"nftables":[` + nftMeta + `,{"table":{"family":12,"name":"t"}}]}`,
		`{"nftables":[` + nftMeta + `,{"table":{"family":"inet"}}]}`,
		`{"nftables":[` + nftMeta + `,{"chain":{"family":"inet","name":"c"}}]}`,
		`{"nftables":[` + nftMeta + `,{"rule":{"family":"inet","table":"t","chain":"c"}}]}`,
		`{"nftables":[` + nftMeta + `,{"rule":{"family":"inet","table":"t","chain":"c","expr":[]}}]}`,
		`{"nftables":[` + nftMeta + `,{"rule":{"family":"inet","table":"t","chain":"c","expr":[13]}}]}`,
		`{"nftables":[` + nftMeta + `,{"rule":{"family":"inet","table":"t","chain":"c","expr":[{}]}}]}`,
		`{"nftables":[` + nftMeta + `,{"set":{"family":"inet","table":"t","name":"s"}}]}`,
		`{"nftables":[` + nftMeta + `,{"map":{"family":"inet","table":"t","name":"m","type":"ipv4_addr"}}]}`,
		`{"nftables":[` + nftMeta + `,{"unsupported":{"family":"inet","table":"t","name":"x"}}]}`,
		`{"nftables":[` + nftMeta + `,{"flush":{"ruleset":null}}]}`,
		`{"nftables":{}}`, `{"nftables":[null]}`,
		`{"nftables":[1]}`, `{"nftables":[{}]}`,
		`{"nftables":[{"table":null}]}`,
		`{"nftables":[{"table":{},"rule":{}}]}`,
		`{"nftables":[],"forged_ready":true}`,
		`{"nftables":[]}` + "trailing",
	} {
		if report, err := decodeNFTSnapshot([]byte(raw)); ErrorCode(err) != "host_preflight_unavailable" ||
			report.Observed || report.RulesetSHA256 != "" || report.ObjectCount != 0 {
			t.Fatalf("malformed ruleset produced successful/partial firewall evidence: %q, %+v, %v", raw, report, err)
		}
	}
	var limited boundedFirewallOutput
	if _, err := limited.Write(bytes.Repeat([]byte("x"), firewallSnapshotMaxBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := limited.Write([]byte("x")); err == nil || limited.Len() != firewallSnapshotMaxBytes {
		t.Fatal("nftables output bound was bypassed")
	}
}

func TestFirewallNativeCommandBoundedAndNoPATHShadow(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific native nftables inspection")
	}
	for _, tc := range []struct {
		name, script string
		expected     string
	}{
		{"valid", "#!/bin/sh\nprintf '%s\\n' '" + exampleNFT + "'\n", ""},
		{"malformed", "#!/bin/sh\nprintf '%s\\n' '{\"nftables\":[]}'\n", "host_preflight_unavailable"},
		{"failed", "#!/bin/sh\nexit 71\n", "host_preflight_unavailable"},
		{"oversize", "#!/bin/sh\nhead -c 4300000 /dev/zero\n", "host_preflight_unavailable"},
		{"timeout", "#!/bin/sh\nexec sleep 9\n", "host_preflight_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "qa-nft")
			if err := os.WriteFile(binary, []byte(tc.script), 0700); err != nil {
				t.Fatal(err)
			}
			duration := 2 * time.Second
			if tc.name == "timeout" {
				duration = 80 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), duration)
			defer cancel()
			start := time.Now()
			report, err := runNFTJSONCommand(ctx, binary)
			if ErrorCode(err) != tc.expected || (tc.expected == "" && !report.Observed) ||
				(tc.expected != "" && (report.Observed || report.RulesetSHA256 != "" || report.ObjectCount != 0)) ||
				time.Since(start) >= 3*time.Second {
				t.Fatalf("nft command verdict or timeout wrong: %+v err=%v", report, err)
			}
		})
	}
	// Test only the native path if installed; all filename/systemd fixtures
	// execute in minimal source CI even without nftables installed.
	if _, err := os.Lstat(nativeNFTPath); os.IsNotExist(err) {
		t.Log("native nftables stage deferred to disconnected Debian 13 guest")
	} else if err != nil {
		t.Fatal(err)
	} else if os.Geteuid() == 0 {
		shadow := filepath.Join(t.TempDir(), "nft")
		if err := os.WriteFile(shadow, []byte("#!/bin/sh\nexit 89\n"), 0755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", filepath.Dir(shadow))
		report, err := observeNftables()
		if err != nil || !report.Observed || report.RulesetSHA256 == "" {
			t.Fatalf("shadowed PATH or native nftables observation failed: %+v, %v", report, err)
		}
	}
}

func TestFirewallDriftComparesOnlyRequestedPrivateSnapshot(t *testing.T) {
	base, now := driftFixture(), driftFixture()
	observed, err := decodeNFTSnapshot([]byte(exampleNFT))
	if err != nil {
		t.Fatal(err)
	}
	base.Mode, now.Mode = "observation_with_nftables", "observation_with_nftables"
	base.Firewall, now.Firewall = &observed, &observed
	report, err := compareHostDriftSnapshots(base, now)
	if err != nil || report.Changed || len(report.Components) != 8 ||
		report.Components[7].Name != "nftables_ruleset" ||
		report.Components[7].BaselineSHA256 != observed.RulesetSHA256 {
		t.Fatalf("firewall drift false positive or missing component: %+v err=%v", report, err)
	}
	// A private baseline with the firewall member removed is NOT a valid
	// full-coverage baseline; an ordinary route-only baseline is separate.
	without := base
	without.Firewall = nil
	if err := validateHostDriftSnapshot(without); err == nil {
		t.Fatal("firewall coverage silently downgraded")
	}
	bad := base
	bad.Firewall = &HostFirewallObservation{Observed: true, RulesetSHA256: "bad", ObjectCount: 5}
	if err := validateHostDriftSnapshot(bad); err == nil {
		t.Fatal("invalid nftables digest accepted")
	}
	changed := now
	other, err := decodeNFTSnapshot([]byte(strings.Replace(exampleNFT, "8.8.8.8", "9.9.9.9", 1)))
	if err != nil {
		t.Fatal(err)
	}
	changed.Firewall = &other
	report, err = compareHostDriftSnapshots(base, changed)
	if ErrorCode(err) != "host_drift_detected" || !report.Changed ||
		!report.Components[7].Changed || report.Components[7].Name != "nftables_ruleset" {
		t.Fatalf("firewall mutation not detected: %+v err=%v", report, err)
	}
	data, err := json.Marshal(report)
	if err != nil || bytes.Contains(data, []byte("8.8.8.8")) ||
		bytes.Contains(data, []byte("foreign-user")) {
		t.Fatalf("private firewall rule content leaked: %s err=%v", data, err)
	}
	mismatch := base
	mismatch.Mode, mismatch.Firewall = "observation_only", nil
	if _, err := compareHostDriftSnapshots(base, mismatch); ErrorCode(err) != "host_drift_unavailable" {
		t.Fatalf("different firewall observation scopes compared as matching: %v", err)
	}
}
