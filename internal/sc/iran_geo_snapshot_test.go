package sc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestBundledIRGeoEstimateSnapshotIsOfflineAndNotAutoRouted(t *testing.T) {
	raw, err := iranGeoSnapshotFiles.ReadFile("data/iran-dbip-lite-2026-10.json")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := decodeIranGeoSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Country != "IR" || len(parsed.IPv4) != 2024 || len(parsed.IPv6) != 1014 ||
		parsed.IPv4[5] != "5.22.0.0/17" {
		t.Fatalf("unexpected pinned allocation snapshot: %s %d %d", parsed.Country, len(parsed.IPv4), len(parsed.IPv6))
	}
	status, err := iranGeoStatus(raw, time.Date(2026, 10, 29, 23, 59, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if status.AgeDays != 28 || status.StaleOver30Days ||
		status.SafeForGeographicRouting || status.ActivationReady || status.PublisherSignatureVerified ||
		!status.FormatAndChecksumVerified {
		t.Fatalf("registration must never imply geographic location or publisher trust: %+v", status)
	}
	stale, err := iranGeoStatus(raw, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || !stale.StaleOver30Days {
		t.Fatalf("staleness not reported: %+v %v", stale, err)
	}
	if _, err = iranGeoStatus(raw, time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("future-dated data accepted")
	}
}

func marshalRIR(t *testing.T, x iranGeoSnapshot) []byte {
	t.Helper()
	b, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rehashRIR(x *iranGeoSnapshot) {
	h := sha256.New()
	for _, family := range []struct {
		label  string
		values []string
	}{{"ipv4", x.IPv4}, {"ipv6", x.IPv6}} {
		for _, prefix := range family.values {
			fmt.Fprintf(h, "%s:%s\n", family.label, prefix)
		}
	}
	x.PrefixSHA256 = hex.EncodeToString(h.Sum(nil))
}

func TestIRGeoEstimateSnapshotRejectsAmbiguousAndUnsafeSources(t *testing.T) {
	raw, err := iranGeoSnapshotFiles.ReadFile("data/iran-dbip-lite-2026-10.json")
	if err != nil {
		t.Fatal(err)
	}
	var base iranGeoSnapshot
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		corrupt func(*iranGeoSnapshot)
		recalc  bool
	}{
		{"wrong-country", func(x *iranGeoSnapshot) { x.Country = "US" }, false},
		{"wrong-basis", func(x *iranGeoSnapshot) { x.Basis = "rir_registration_country_not_geolocation" }, false},
		{"wrong-license", func(x *iranGeoSnapshot) { x.License = "proprietary" }, false},
		{"wrong-attribution", func(x *iranGeoSnapshot) { x.Attribution = "unattributed" }, false},
		{"wrong-changes", func(x *iranGeoSnapshot) { x.Changes = "untouched" }, false},
		{"wrong-source-sha", func(x *iranGeoSnapshot) { x.SourceSHA256 = strings.Repeat("0", 64) }, false},
		{"unversioned-source", func(x *iranGeoSnapshot) { x.Source = "https://stat.ripe.net/latest" }, false},
		{"future-schema", func(x *iranGeoSnapshot) { x.SchemaVersion = 2 }, false},
		{"invalid-date", func(x *iranGeoSnapshot) { x.AsOf = "2026-13-01" }, false},
		{"digest-mismatch", func(x *iranGeoSnapshot) { x.IPv4[0] = "2.57.4.0/24" }, false},
		// This remains canonical, sorted and disjoint; the self-rehashed
		// metadata alone must not authorize a substituted prefix set.
		{"self-rehashed-valid-substitution", func(x *iranGeoSnapshot) { x.IPv4[0] = "2.57.3.0/25" }, true},
		{"duplicate-prefix", func(x *iranGeoSnapshot) { x.IPv4[1] = x.IPv4[0] }, true},
		{"overlapping-prefix", func(x *iranGeoSnapshot) { x.IPv4[1] = "2.57.3.0/25" }, true},
		{"not-ordered", func(x *iranGeoSnapshot) { x.IPv4[0], x.IPv4[1] = x.IPv4[1], x.IPv4[0] }, true},
		{"noncanonical", func(x *iranGeoSnapshot) { x.IPv4[0] = "2.57.3.1/24" }, true},
		{"private-ipv4", func(x *iranGeoSnapshot) { x.IPv4[0] = "10.0.0.0/8" }, true},
		{"documentation-ipv4", func(x *iranGeoSnapshot) { x.IPv4[0] = "192.0.2.0/24" }, true},
		{"bad-family", func(x *iranGeoSnapshot) { x.IPv6[0] = "2.57.3.0/24" }, true},
		{"documentation-ipv6", func(x *iranGeoSnapshot) { x.IPv6[0] = "2001:db8::/32" }, true},
		{"empty-v6", func(x *iranGeoSnapshot) { x.IPv6 = nil }, true},
		{"bad-hash", func(x *iranGeoSnapshot) { x.PrefixSHA256 = strings.Repeat("z", 64) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := base
			snapshot.IPv4 = append([]string(nil), base.IPv4...)
			snapshot.IPv6 = append([]string(nil), base.IPv6...)
			tc.corrupt(&snapshot)
			if tc.recalc {
				rehashRIR(&snapshot)
			}
			if _, err := decodeIranGeoSnapshot(marshalRIR(t, snapshot)); err == nil {
				t.Fatal("unsafe registry snapshot accepted")
			}
		})
	}
	rawRoot := bytes.TrimSpace(raw)
	if _, err := decodeIranGeoSnapshot(append(bytes.Clone(rawRoot), []byte(" {}")...)); err == nil {
		t.Fatal("trailing JSON object accepted")
	}
	if _, err := decodeIranGeoSnapshot(append(bytes.Clone(rawRoot), []byte("\\n\\n")...)); err == nil {
		t.Fatal("invalid extra tokens accepted")
	}
	// The rest of the document is valid: only the duplicated root key is new.
	duplicateRoot := append([]byte(`{"schema_version":1,`), rawRoot[1:]...)
	if _, err := decodeIranGeoSnapshot(duplicateRoot); err == nil {
		t.Fatal("duplicate JSON root members accepted")
	}
	caseVariant := append([]byte(`{"Country":"IR",`), rawRoot[1:]...)
	if _, err := decodeIranGeoSnapshot(caseVariant); err == nil {
		t.Fatal("case-variant schema member accepted")
	}
	if _, err := decodeIranGeoSnapshot(append([]byte(`{"unknown":true,`), rawRoot[1:]...)); err == nil {
		t.Fatal("unknown schema member accepted")
	}
	if _, err := decodeIranGeoSnapshot(append(bytes.Clone(rawRoot), make([]byte, 1024*1024)...)); err == nil {
		t.Fatal("oversized snapshot accepted")
	}
}
