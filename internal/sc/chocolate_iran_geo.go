package sc

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
)

// Chocolate4U is a second, separately licensed *estimate*, not a source of
// direct-routing authority by itself. In particular its geoip-ir.srs includes
// non-Iran-hosted cloud-provider addresses. The default strict intersection
// with DB-IP avoids treating these external-only entries as domestic Direct.
// Source: https://github.com/Chocolate4U/Iran-sing-box-rules/tree/085deb78a67cc3452ee0ad071ed476024d34d92f
// Original rule-set SHA256: b17601400d00fc26ecdda16b13469460878d929f3c35311e666f9149015f8ba4
// Decompiled with official sing-box 1.14.3; source and GPLv3 terms retained.
const chocolateIranRevision = "085deb78a67cc3452ee0ad071ed476024d34d92f"
const chocolateIranSRS_SHA256 = "b17601400d00fc26ecdda16b13469460878d929f3c35311e666f9149015f8ba4"
const chocolateIranJSON_SHA256 = "c80922639511fc817957f1ecb018b0f13855decc59c5fbe492fac5bdb6638616"
const chocolateIranLicense = "GPL-3.0-only (upstream sources retain their own terms)"

//go:embed data/iran-chocolate4u-2026-11.json
var chocolateIranFiles embed.FS

func chocolateIranPrefixes() ([]netip.Prefix, error) {
	raw, err := chocolateIranFiles.ReadFile("data/iran-chocolate4u-2026-11.json")
	if err != nil || len(raw) == 0 || len(raw) > 128*1024 {
		return nil, errors.New("bundled Chocolate4U Iran source unavailable")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != chocolateIranJSON_SHA256 {
		return nil, errors.New("bundled Chocolate4U Iran data digest changed")
	}
	var v struct {
		Version int `json:"version"`
		Rules   []struct {
			IPCIDR []string `json:"ip_cidr"`
		} `json:"rules"`
	}
	if json.Unmarshal(raw, &v) != nil || v.Version != 1 || len(v.Rules) != 1 || len(v.Rules[0].IPCIDR) != 2810 {
		return nil, errors.New("bundled Chocolate4U Iran data schema mismatch")
	}
	out := make([]netip.Prefix, 0, 2810)
	seen := map[netip.Prefix]bool{}
	for _, s := range v.Rules[0].IPCIDR {
		p, e := netip.ParsePrefix(s)
		if e != nil || !p.IsValid() || p.String() != s || p.Masked() != p || !p.Addr().IsGlobalUnicast() || p.Addr().IsPrivate() || overlapsSpecialPurpose(p) || (p.Addr().Is6() && !conservativelyPublicIPv6Prefix(p)) || seen[p] {
			return nil, errors.New("bundled Chocolate4U Iran data contains invalid prefixes")
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Addr() == b.Addr() {
			return a.Bits() < b.Bits()
		}
		return a.Addr().Compare(b.Addr()) < 0
	})
	return out, nil
}

// intersectIranPrefixes computes the CIDR-precise address intersection, not
// an exact-string intersection (sources may choose different prefix lengths).
// Both operands are sorted into disjoint prefix order. The more-specific
// prefix is their exact intersection, and only that subnet becomes Direct.
func intersectIranPrefixes(dbip []string, second []netip.Prefix) ([]string, error) {
	first := make([]netip.Prefix, 0, len(dbip))
	for _, s := range dbip {
		p, e := netip.ParsePrefix(s)
		if e != nil {
			return nil, e
		}
		first = append(first, p)
	}
	sort.Slice(first, func(i, j int) bool {
		a, b := first[i], first[j]
		if a.Addr() == b.Addr() {
			return a.Bits() < b.Bits()
		}
		return a.Addr().Compare(b.Addr()) < 0
	})
	out := make([]string, 0, len(first))
	i, j := 0, 0
	for i < len(first) && j < len(second) {
		a, b := first[i], second[j]
		if a.Addr().Is4() != b.Addr().Is4() {
			if a.Addr().Is4() {
				i++
			} else {
				j++
			}
			continue
		}
		if a.Overlaps(b) {
			if a.Bits() >= b.Bits() {
				out = append(out, a.String())
			} else {
				out = append(out, b.String())
			}
		}
		// In overlapping CIDR sets, the more-specific subnet ends first;
		// for separated blocks, compare the last address, not only the base.
		ae := a.Addr().Next()
		be := b.Addr().Next()
		if a.Bits() != a.Addr().BitLen() {
			ae = prefixEnd(a)
		}
		if b.Bits() != b.Addr().BitLen() {
			be = prefixEnd(b)
		}
		switch ae.Compare(be) {
		case -1:
			i++
		case 1:
			j++
		default:
			i++
			j++
		}
	}
	if len(out) == 0 {
		return nil, errors.New("independent Iran datasets have no overlapping public prefixes")
	}
	return out, nil
}

func prefixEnd(p netip.Prefix) netip.Addr {
	// The final address of a masked prefix is obtained by setting all host
	// bits to one. This is only used in source-data compilation, not routing.
	raw := p.Addr().As16()
	offset := 0
	if p.Addr().Is4() {
		offset = 12
	}
	for bit := p.Bits(); bit < p.Addr().BitLen(); bit++ {
		byteIndex := offset + bit/8
		raw[byteIndex] |= 1 << uint(7-bit%8)
	}
	if p.Addr().Is4() {
		return netip.AddrFrom4([4]byte{raw[12], raw[13], raw[14], raw[15]})
	}
	return netip.AddrFrom16(raw)
}
