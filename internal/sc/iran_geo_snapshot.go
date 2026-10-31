package sc

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
)

// DB-IP Lite estimates a country for an address, but estimates have gaps and
// cannot certify actual location or current packet routes. These prefixes
// cannot become host Direct exemptions without independent field acceptance.
const iranGeoBasis = "dbip_lite_country_geolocation_estimate"

//go:embed data/iran-dbip-lite-2026-10.json
var iranGeoSnapshotFiles embed.FS

type iranGeoSnapshot struct {
	SchemaVersion int      `json:"schema_version"`
	Country       string   `json:"country"`
	Basis         string   `json:"basis"`
	AsOf          string   `json:"as_of"`
	Source        string   `json:"source"`
	PrefixSHA256  string   `json:"prefix_sha256"`
	SourceSHA256  string   `json:"source_sha256"`
	License       string   `json:"license"`
	Attribution   string   `json:"attribution"`
	Changes       string   `json:"changes"`
	IPv4          []string `json:"ipv4"`
	IPv6          []string `json:"ipv6"`
}

// IranGeoSnapshotStatus reports an offline, attributed geolocation *estimate*.
// Reading it never accesses the network or private state, changes the host or
// proves the safety of using these prefixes for geographic Direct routing.
type IranGeoSnapshotStatus struct {
	Country                    string `json:"country"`
	Basis                      string `json:"basis"`
	AsOf                       string `json:"as_of"`
	Source                     string `json:"source"`
	PrefixSHA256               string `json:"prefix_sha256"`
	SourceSHA256               string `json:"source_sha256"`
	License                    string `json:"license"`
	Attribution                string `json:"attribution"`
	Changes                    string `json:"changes"`
	IPv4Count                  int    `json:"ipv4_count"`
	IPv6Count                  int    `json:"ipv6_count"`
	AgeDays                    int    `json:"age_days"`
	StaleOver30Days            bool   `json:"stale_over_30_days"`
	FormatAndChecksumVerified  bool   `json:"format_and_checksum_verified"`
	PublisherSignatureVerified bool   `json:"publisher_signature_verified"`
	SafeForGeographicRouting   bool   `json:"safe_for_geographic_routing"`
	ActivationReady            bool   `json:"activation_ready"`
}

// Only this exact dated, attributed free CSV may back the embedded snapshot.
// It is source-byte pinned but has no publisher signature: report that fact.
const iranGeoArchiveSHA256 = "097426b8ddae89157d444a59ac1847e873f7943c32d52becc4371c8b0273af80"

// Independent, reviewed source-code pin. A self-consistent JSON metadata
// digest is insufficient: an altered prefix set could simply be rehashed.
const iranGeoPrefixSHA256 = "edb8fc88cff754e9622695e03d980afec6640939cf53627f8800ac54d9170f0e"
const iranGeoArchiveURL = "https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz"
const iranGeoLicense = "CC-BY-4.0"
const iranGeoAttribution = "IP Geolocation by DB-IP (https://db-ip.com)"
const iranGeoChanges = "IR rows extracted; IP intervals converted to canonical CIDR prefixes."

func decodeIranGeoSnapshot(raw []byte) (iranGeoSnapshot, error) {
	fail := errors.New("invalid or untrusted DB-IP Lite IR country estimate")
	if len(raw) == 0 || len(raw) > 1024*1024 {
		return iranGeoSnapshot{}, fail
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return iranGeoSnapshot{}, fail
	}
	// Check exact schema keys and duplicate/case-variant fields independently
	// before decoding. Arrays contain strings only, so no nested objects.
	allowed := map[string]bool{"schema_version": true, "country": true, "basis": true,
		"as_of": true, "source": true, "prefix_sha256": true, "source_sha256": true,
		"license": true, "attribution": true, "changes": true, "ipv4": true, "ipv6": true}
	seen := map[string]bool{}
	for d.More() {
		keyToken, err := d.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || !allowed[key] || seen[strings.ToLower(key)] {
			return iranGeoSnapshot{}, fail
		}
		seen[strings.ToLower(key)] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return iranGeoSnapshot{}, fail
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != len(allowed) {
		return iranGeoSnapshot{}, fail
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return iranGeoSnapshot{}, fail
	}
	var snapshot iranGeoSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil || snapshot.SchemaVersion != 1 ||
		snapshot.Country != "IR" || snapshot.Basis != iranGeoBasis ||
		snapshot.AsOf != "2026-10-01" || snapshot.Source != iranGeoArchiveURL ||
		snapshot.SourceSHA256 != iranGeoArchiveSHA256 ||
		snapshot.License != iranGeoLicense || snapshot.Attribution != iranGeoAttribution ||
		snapshot.Changes != iranGeoChanges ||
		snapshot.PrefixSHA256 != iranGeoPrefixSHA256 {
		return iranGeoSnapshot{}, fail
	}
	if _, err := hex.DecodeString(snapshot.PrefixSHA256); err != nil ||
		snapshot.PrefixSHA256 != strings.ToLower(snapshot.PrefixSHA256) {
		return iranGeoSnapshot{}, fail
	}
	date, err := time.Parse("2006-01-02", snapshot.AsOf)
	if err != nil || date.Format("2006-01-02") != snapshot.AsOf {
		return iranGeoSnapshot{}, fail
	}
	h := sha256.New()
	for _, family := range []struct {
		label  string
		v4     bool
		values []string
	}{{"ipv4", true, snapshot.IPv4}, {"ipv6", false, snapshot.IPv6}} {
		if len(family.values) < 20 || len(family.values) > 10000 {
			return iranGeoSnapshot{}, fail
		}
		var prev netip.Prefix
		seenPrefixes := map[netip.Prefix]bool{}
		for _, rawPrefix := range family.values {
			p, err := netip.ParsePrefix(rawPrefix)
			if err != nil || !p.IsValid() || p.String() != rawPrefix || p.Masked() != p ||
				p.Addr().Is4() != family.v4 || !p.Addr().IsGlobalUnicast() ||
				p.Addr().IsPrivate() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() ||
				p.Addr().IsMulticast() || p.Addr().IsUnspecified() ||
				overlapsSpecialPurpose(p) {
				return iranGeoSnapshot{}, fail
			}
			if prev.IsValid() && (prev.Addr().Compare(p.Addr()) > 0 ||
				(prev.Addr() == p.Addr() && prev.Bits() >= p.Bits())) {
				return iranGeoSnapshot{}, fail
			}
			for bits := 0; bits < p.Bits(); bits++ {
				if seenPrefixes[netip.PrefixFrom(p.Addr(), bits).Masked()] {
					return iranGeoSnapshot{}, fail
				}
			}
			seenPrefixes[p] = true
			prev = p
			fmt.Fprintf(h, "%s:%s\n", family.label, rawPrefix)
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != snapshot.PrefixSHA256 {
		return iranGeoSnapshot{}, fail
	}
	return snapshot, nil
}

// Conservative, pinned offline IANA IPv4 and IPv6 Special-Purpose Address
// Space as of 2025-10-09 (the IANA registry date at review):
// https://www.iana.org/assignments/iana-ipv4-special-registry
// https://www.iana.org/assignments/iana-ipv6-special-registry
// Reject all listed blocks for operator public routing, even when an entry
// describes a globally reachable special-use anycast. IPv4 0/8, 192.0.0/24
// and 192.88.99/24 include their more-specific IANA entries; IPv6 2001::/23
// includes Teredo, benchmark, ORCHID and other protocol assignments.
// This is conservative *address admission*, not geo or field path evidence.
// Regenerate/review this list when IANA changes the authoritative registry.
var specialPurposeExclusions = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), // Multicast (outside the unicast IANA registry).
	netip.MustParsePrefix("240.0.0.0/4"),
	// All distinct IANA IPv6 special-purpose roots, including globally
	// reachable special-use cases and all registered descendants of /23.
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// IANA IPv6 Address Space allocates global-unicast address space from
// 2000::/3. netip.IsGlobalUnicast alone also accepts special or not-yet
// allocated ranges. This offline snapshot intentionally fails closed until
// a future registry review admits additional public IPv6 space.
var ianaIPv6AllocatedUnicast = netip.MustParsePrefix("2000::/3")

func conservativelyPublicIPv6Prefix(p netip.Prefix) bool {
	return p.IsValid() && p.Addr().Is6() &&
		p.Bits() >= ianaIPv6AllocatedUnicast.Bits() &&
		ianaIPv6AllocatedUnicast.Contains(p.Addr()) &&
		!overlapsSpecialPurpose(p)
}

func overlapsSpecialPurpose(p netip.Prefix) bool {
	for _, reserved := range specialPurposeExclusions {
		// Prefix.Overlaps examines the full address range, not only Addr().
		// Different address families never overlap.
		if p.Overlaps(reserved) {
			return true
		}
	}
	return false
}

func iranGeoStatus(raw []byte, now time.Time) (IranGeoSnapshotStatus, error) {
	snapshot, err := decodeIranGeoSnapshot(raw)
	if err != nil {
		return IranGeoSnapshotStatus{}, err
	}
	asOf, _ := time.Parse("2006-01-02", snapshot.AsOf)
	today := now.UTC().Truncate(24 * time.Hour)
	if asOf.After(today) {
		return IranGeoSnapshotStatus{}, errors.New("IR country estimate date is in the future")
	}
	days := int(today.Sub(asOf) / (24 * time.Hour))
	return IranGeoSnapshotStatus{
		Country: snapshot.Country, Basis: snapshot.Basis, AsOf: snapshot.AsOf,
		Source: snapshot.Source, PrefixSHA256: snapshot.PrefixSHA256,
		SourceSHA256: snapshot.SourceSHA256, License: snapshot.License,
		Attribution: snapshot.Attribution, Changes: snapshot.Changes,
		IPv4Count: len(snapshot.IPv4), IPv6Count: len(snapshot.IPv6),
		AgeDays: days, StaleOver30Days: days > 30,
		FormatAndChecksumVerified:  true,
		PublisherSignatureVerified: false,
		SafeForGeographicRouting:   false,
		ActivationReady:            false,
	}, nil
}

// BundledIranGeoSnapshotStatus uses CC BY 4.0 embedded, offline data. Neither
// this estimate nor its integrity digest proves geographic routing safety.
func BundledIranGeoSnapshotStatus() (IranGeoSnapshotStatus, error) {
	raw, err := iranGeoSnapshotFiles.ReadFile("data/iran-dbip-lite-2026-10.json")
	if err != nil {
		return IranGeoSnapshotStatus{}, errors.New("embedded IR country estimate unavailable")
	}
	return iranGeoStatus(raw, time.Now().UTC())
}
