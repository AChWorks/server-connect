package sc

import (
	"net/netip"
	"testing"
)

func TestChocolateIranSourceAndExactConsensus(t *testing.T) {
	chocolate, err := chocolateIranPrefixes()
	if err != nil {
		t.Fatal(err)
	}
	if len(chocolate) != 2810 {
		t.Fatalf("expected pinned source 2810 prefixes, got %d", len(chocolate))
	}
	raw, err := iranGeoSnapshotFiles.ReadFile("data/iran-dbip-lite-2026-10.json")
	if err != nil {
		t.Fatal(err)
	}
	dbip, err := decodeIranGeoSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	consensus, err := intersectIranPrefixes(append(dbip.IPv4, dbip.IPv6...), chocolate)
	if err != nil {
		t.Fatal(err)
	}
	if len(consensus) != 2917 {
		t.Fatalf("incorrect exact overlap of two pinned sources: %d", len(consensus))
	}
	for _, s := range consensus {
		p := netip.MustParsePrefix(s)
		foundDBIP, foundChoco := false, false
		for _, q := range append(dbip.IPv4, dbip.IPv6...) {
			if netip.MustParsePrefix(q).Contains(p.Addr()) {
				foundDBIP = true
				break
			}
		}
		for _, q := range chocolate {
			if q.Contains(p.Addr()) {
				foundChoco = true
				break
			}
		}
		if !foundDBIP || !foundChoco {
			t.Fatalf("consensus range not independently corroborated: %s", s)
		}
	}
	// Some Chocolate4U routes correspond to remote cloud hosts, and must
	// not be made Direct purely by the second source's country categorization.
	loneCloud := netip.MustParseAddr("116.202.90.180")
	for _, s := range consensus {
		if netip.MustParsePrefix(s).Contains(loneCloud) {
			t.Fatal("Chocolate4U-only foreign provider was admitted as Iran Direct")
		}
	}
}

func TestIranCIDRIntersectionDifferentPrefixLengths(t *testing.T) {
	others := []netip.Prefix{
		netip.MustParsePrefix("2.144.0.0/15"),
		netip.MustParsePrefix("2.146.128.0/17"),
		netip.MustParsePrefix("2001:4860:1::/48"),
	}
	first := []string{"2.144.0.0/14", "2001:4860::/32"}
	got, err := intersectIranPrefixes(first, others)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"2.144.0.0/15", "2.146.128.0/17", "2001:4860:1::/48"}
	if len(got) != len(expected) {
		t.Fatalf("got %v, want %v", got, expected)
	}
	for i := range got {
		if got[i] != expected[i] {
			t.Fatalf("got %v, want %v", got, expected)
		}
	}
}
