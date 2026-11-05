package sc

import "slices"

// A complete source-pinned estimate can contain allocations broader than
// synthetic manual-policy bounds. Only the exact, independently pinned
// dual-stack source qualifies for that separate compile-only path. It does
// not authenticate its publisher or geographic precision, or authorize Apply.
func sourcePinnedBundledDualStackEstimate(o SmartTUNCandidateOptions) bool {
	if len(o.DomesticCIDRs) != 2024 || len(o.DomesticIPv6CIDRs) != 1014 {
		return false
	}
	raw, err := iranGeoSnapshotFiles.ReadFile("data/iran-dbip-lite-2026-10.json")
	if err != nil {
		return false
	}
	snapshot, err := decodeIranGeoSnapshot(raw)
	return err == nil && slices.Equal(o.DomesticCIDRs, snapshot.IPv4) &&
		slices.Equal(o.DomesticIPv6CIDRs, snapshot.IPv6)
}

func bundledIranGeoIPv6ForPreview() ([]string, error) {
	raw, err := iranGeoSnapshotFiles.ReadFile("data/iran-dbip-lite-2026-10.json")
	if err != nil {
		return nil, err
	}
	snapshot, err := decodeIranGeoSnapshot(raw)
	if err != nil {
		return nil, err
	}
	return append([]string(nil), snapshot.IPv6...), nil
}
