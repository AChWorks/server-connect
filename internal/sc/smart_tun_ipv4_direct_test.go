package sc

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// A rejected candidate must never return a partially runnable sing-box config.
func assertIPv4DirectCandidate(t *testing.T, opts SmartTUNCandidateOptions, accepted bool) {
	t.Helper()
	profile, _ := smartTUNFixture()
	raw, err := SmartTUNCandidateConfig(profile, opts)
	if accepted && (err != nil || len(raw) == 0) {
		t.Fatalf("valid IPv4 Direct candidate rejected: %v", err)
	}
	if !accepted && (err == nil || len(raw) != 0) {
		t.Fatalf("unsafe IPv4 Direct candidate returned config (%d bytes): %v", len(raw), err)
	}
}

func TestSmartTUNIPv4OperatorDirectBreadthAndAggregate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cidr     string
		via      string
		accepted bool
	}{
		{"single-direct-32", "20.0.0.1/32", "direct", true},
		{"direct-24", "20.0.0.0/24", "direct", true},
		{"direct-23-too-broad", "20.0.0.0/23", "direct", false},
		{"near-global-direct", "0.0.0.0/1", "direct", false},
		{"vpn-only-broad-is-not-direct", "20.0.0.0/8", "vpn", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, opts := smartTUNFixture()
			opts.Exceptions = []SmartTUNCIDRException{{CIDR: tc.cidr, Via: tc.via}}
			assertIPv4DirectCandidate(t, opts, tc.accepted)
		})
	}
	for _, count := range []int{64, 65} {
		t.Run(fmt.Sprintf("distinct-24s-%d", count), func(t *testing.T) {
			_, opts := smartTUNFixture()
			opts.Exceptions = nil
			for i := 0; i < count; i++ {
				addr := netip.AddrFrom4([4]byte{20, byte(i), 0, 0})
				opts.Exceptions = append(opts.Exceptions, SmartTUNCIDRException{
					CIDR: netip.PrefixFrom(addr, 24).String(), Via: "direct",
				})
			}
			assertIPv4DirectCandidate(t, opts, count == 64)
		})
	}
	// Many exact hosts in the same /24 spend only one distinct-/24 budget.
	_, narrow := smartTUNFixture()
	narrow.Exceptions = nil
	for i := 1; i <= 65; i++ {
		narrow.Exceptions = append(narrow.Exceptions, SmartTUNCIDRException{
			CIDR: fmt.Sprintf("20.0.0.%d/32", i), Via: "direct",
		})
	}
	assertIPv4DirectCandidate(t, narrow, true)

	// Bound collections even when every rule is narrow and independently
	// admitted; the overlap checker is quadratic in the exception count.
	_, tooMany := smartTUNFixture()
	tooMany.Exceptions = nil
	for i := 1; i <= 129; i++ {
		tooMany.Exceptions = append(tooMany.Exceptions, SmartTUNCIDRException{
			CIDR: fmt.Sprintf("20.0.0.%d/32", i), Via: "direct",
		})
	}
	allowedMax := tooMany
	allowedMax.Exceptions = tooMany.Exceptions[:128]
	assertIPv4DirectCandidate(t, allowedMax, true)
	assertIPv4DirectCandidate(t, tooMany, false)
	_, tooManyProtected := smartTUNFixture()
	// Every entry is a valid, redundant host already covered by private
	// underlay protections. The old compiler would have accepted all 65.
	tooManyProtected.ProtectedCIDRs = make([]string, 65)
	for i := range tooManyProtected.ProtectedCIDRs {
		tooManyProtected.ProtectedCIDRs[i] = "10.0.0.1/32"
	}
	allowedProtected := tooManyProtected
	allowedProtected.ProtectedCIDRs = tooManyProtected.ProtectedCIDRs[:64]
	assertIPv4DirectCandidate(t, allowedProtected, true)
	assertIPv4DirectCandidate(t, tooManyProtected, false)
}

func TestSmartTUNIPv4DomesticDirectCoverage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cidrs    []string
		accepted bool
	}{
		{"one-8", []string{"8.0.0.0/8"}, true},
		{"two-8s-exact-budget", []string{"8.0.0.0/8", "9.0.0.0/8"}, true},
		{"three-8s-exceed-budget", []string{"8.0.0.0/8", "9.0.0.0/8", "11.0.0.0/8"}, false},
		{"near-global", []string{"0.0.0.0/1"}, false},
		{"too-broad-7", []string{"8.0.0.0/7"}, false},
		{"private", []string{"10.0.0.0/8"}, false},
		{"carrier-grade-nat", []string{"100.64.0.0/10"}, false},
		{"documentation", []string{"192.0.2.0/24"}, false},
		{"overlapping", []string{"8.8.0.0/16", "8.8.8.0/24"}, false},
		{"reverse-overlap", []string{"8.8.8.0/24", "8.8.0.0/16"}, false},
		{"duplicates", []string{"8.8.8.0/24", "8.8.8.0/24"}, false},
		{"two-neighboring", []string{"8.8.8.0/24", "8.8.9.0/24"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, opts := smartTUNFixture()
			opts.DomesticCIDRs = tc.cidrs
			assertIPv4DirectCandidate(t, opts, tc.accepted)
		})
	}

	for _, count := range []int{512, 513} {
		t.Run(fmt.Sprintf("many-narrow-blocks-%d", count), func(t *testing.T) {
			_, opts := smartTUNFixture()
			opts.DomesticCIDRs = nil
			for i := 0; i < count; i++ {
				// Avoid private 10/8 so failure at 513 is aggregate-only.
				first := byte(8 + i/256)
				if i >= 512 {
					first = 11
				}
				addr := netip.AddrFrom4([4]byte{first, byte(i % 256), 0, 0})
				opts.DomesticCIDRs = append(opts.DomesticCIDRs, netip.PrefixFrom(addr, 16).String())
			}
			assertIPv4DirectCandidate(t, opts, count == 512)
		})
	}
	_, huge := smartTUNFixture()
	// 10,001 unique, valid public /32s total only 10,001 addresses.
	// Rejecting them is specific to the collection-size limit, not invalid
	// CIDRs, overlaps, special-purpose blocks, or aggregate address coverage.
	huge.DomesticCIDRs = make([]string, 0, 10001)
	for i := 0; i <= 10000; i++ {
		addr := netip.AddrFrom4([4]byte{20, 0, byte(i / 256), byte(i % 256)})
		huge.DomesticCIDRs = append(huge.DomesticCIDRs, netip.PrefixFrom(addr, 32).String())
	}
	allowedMax := huge
	allowedMax.DomesticCIDRs = huge.DomesticCIDRs[:10000]
	assertIPv4DirectCandidate(t, allowedMax, true)
	assertIPv4DirectCandidate(t, huge, false)
}

// A network address may be public while its entire CIDR contains a private,
// link-local or deprecated special-purpose allocation. All such candidates
// must be rejected before even a synthetic runnable config is returned.
func TestSmartTUNIPv4RejectsWholeSpecialPurposeCIDR(t *testing.T) {
	cases := []struct {
		name     string
		unsafe   string
		neighbor string
	}{
		{"rfc1918-inside-public-starting-8", "172.0.0.0/8", "172.15.0.0/16"},
		{"link-local-inside-public-starting-8", "169.0.0.0/8", "169.253.0.0/16"},
		{"cgnat-inside-public-starting-8", "100.0.0.0/8", "100.63.0.0/16"},
		{"deprecated-six-to-four", "192.88.99.0/24", "192.88.100.0/24"},
		{"six-a44-relay-anycast", "192.88.99.2/32", "192.88.98.0/24"},
		{"as112-ipv4", "192.31.196.0/24", "192.31.195.0/24"},
		{"amt-ipv4", "192.52.193.0/24", "192.52.192.0/24"},
		{"as112-direct-delegation", "192.175.48.0/24", "192.175.49.0/24"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profile, opts := smartTUNFixture()
			opts.DomesticCIDRs = []string{tc.unsafe}
			config, err := SmartTUNCandidateConfig(profile, opts)
			if err == nil || err.Error() != "IPv4 domestic Direct prefix intersects special-purpose or nonpublic space" || len(config) != 0 {
				t.Fatalf("unsafe CIDR %s accepted or rejected for the wrong reason: error=%v, config_bytes=%d", tc.unsafe, err, len(config))
			}
			opts.DomesticCIDRs = []string{tc.neighbor}
			config, err = SmartTUNCandidateConfig(profile, opts)
			if err != nil || len(config) == 0 {
				t.Fatalf("public neighbor %s unexpectedly rejected: %v", tc.neighbor, err)
			}
		})
	}

	// Special-use destinations may still be explicitly classified VPN-only:
	// the restriction must not interfere with the existing operator hierarchy.
	profile, opts := smartTUNFixture()
	opts.Exceptions = []SmartTUNCIDRException{{CIDR: "192.88.99.2/32", Via: "vpn"}}
	if raw, err := SmartTUNCandidateConfig(profile, opts); err != nil || len(raw) == 0 {
		t.Fatalf("special-use VPN-only operator rule was rejected: %v", err)
	}
}

// A complete embedded IR estimate may be compiled only when explicitly
// supplied by the caller. This is NOT authenticated Iranian routing, automatic
// admission, or permission to enable a real host TUN.
func TestSmartTUNIPv4CandidateCanRepresentFullPinnedIREstimate(t *testing.T) {
	source, err := iranGeoSnapshotFiles.ReadFile("data/iran-dbip-lite-2026-10.json")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := decodeIranGeoSnapshot(source)
	if err != nil {
		t.Fatal(err)
	}
	profile, opts := smartTUNFixture()
	opts.DomesticCIDRs = append([]string(nil), snapshot.IPv4...)
	raw, err := SmartTUNCandidateConfig(profile, opts)
	if err != nil {
		t.Fatalf("bounded verified fixture rejected: %v", err)
	}
	var parsed struct {
		Route struct {
			Rules []struct {
				CIDRs    []string `json:"ip_cidr"`
				Outbound string   `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Route.Rules) < 3 || parsed.Route.Rules[len(parsed.Route.Rules)-1].Outbound != "direct" ||
		len(parsed.Route.Rules[len(parsed.Route.Rules)-1].CIDRs) != len(snapshot.IPv4) {
		t.Fatal("explicit dataset was silently truncated or omitted")
	}
	if strings.Contains(string(raw), iranGeoArchiveSHA256) {
		t.Fatal("runtime routing config must not advertise source metadata as proof of geographic safety")
	}
}
