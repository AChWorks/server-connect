package sc

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const endpointNameTimeout = 3 * time.Second
const maxEndpointNameAnswers = 32

type endpointNameLookup func(context.Context, string) ([]netip.Addr, error)

// validateEndpointHostname accepts only an explicit ASCII DNS name with at
// least two labels. Names cannot be URL strings, unscoped service names,
// IP literals, wildcards, control characters or DNS search-domain shortcuts.
// This is intentionally narrower than a generic system hostname.
func validateEndpointHostname(input string) (string, error) {
	if len(input) == 0 || len(input) > 254 {
		return "", Fault("invalid_arguments", "hostname must be a bounded ASCII DNS name")
	}
	name := strings.TrimSuffix(strings.ToLower(input), ".")
	if len(name) == 0 || len(name) > 253 || !strings.Contains(name, ".") {
		return "", Fault("invalid_arguments", "hostname requires two or more explicit DNS labels")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", Fault("invalid_arguments", "hostname must not be a literal IP")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", Fault("invalid_arguments", "hostname contains an invalid DNS label")
		}
		for i := 0; i < len(label); i++ {
			b := label[i]
			alpha := b >= 'a' && b <= 'z'
			digit := b >= '0' && b <= '9'
			if !alpha && !digit && !(b == '-' && i > 0 && i < len(label)-1) {
				return "", Fault("invalid_arguments", "hostname contains characters outside ASCII DNS-label syntax")
			}
		}
	}
	return name, nil
}

// InspectUnderlayTCPWithHostname performs an additional *host-configured*
// name resolution before connecting to exactly the explicit pinned IP.
// Matching a resolver answer is diagnostic consistency evidence, NOT proof
// of independent pre-VPN DNS or future endpoint reachability.
func InspectUnderlayTCPWithHostname(endpointIP, hostname string, port int) (UnderlayTCPReport, error) {
	resolver := &net.Resolver{PreferGo: true}
	return inspectUnderlayWithNameLookup(endpointIP, hostname, port, func(ctx context.Context, name string) ([]netip.Addr, error) {
		return resolver.LookupNetIP(ctx, "ip", name)
	})
}

func inspectUnderlayWithNameLookup(endpointIP, hostname string, port int, lookup endpointNameLookup) (UnderlayTCPReport, error) {
	ip, err := validateUnderlayTCPArgs(endpointIP, port)
	if err != nil {
		return UnderlayTCPReport{}, err
	}
	name, err := validateEndpointHostname(hostname)
	if err != nil {
		return UnderlayTCPReport{}, err
	}
	report := newUnderlayTCPReport(ip, port)
	report.Hostname = name
	if err := trustedHostIPExecutable(); err != nil {
		report.Outcome = "unavailable"
		return report, err
	}

	// Do not contact a TCP endpoint unless its operator-pinned literal is
	// present among all current host resolver answers. Avoid picking/falling
	// back to a different name result silently.
	ctx, cancel := context.WithTimeout(context.Background(), endpointNameTimeout)
	defer cancel()
	start := time.Now()
	// Use an absolute DNS-style name to avoid resolver search-domain
	// suffixes (including ndots policies) selecting an unrelated target.
	addrs, err := lookup(ctx, name+".")
	report.ResolutionMs = time.Since(start).Milliseconds()
	if err != nil || ctx.Err() != nil {
		report.Outcome = "name_resolution_failed"
		return report, Fault("underlay_name_unavailable", "host name resolution failed or timed out before TCP probing")
	}
	if len(addrs) == 0 || len(addrs) > maxEndpointNameAnswers {
		report.Outcome = "name_resolution_unsupported"
		return report, Fault("underlay_name_unavailable", "hostname returned no answers or exceeded the bounded address limit")
	}

	seen := make(map[netip.Addr]bool, len(addrs))
	unique := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if !addr.IsValid() || addr.Zone() != "" || addr.Is4In6() || addr.IsLinkLocalUnicast() ||
			(!addr.IsGlobalUnicast() && !addr.IsLoopback()) {
			report.Outcome = "name_resolution_unsupported"
			return report, Fault("underlay_name_unavailable", "hostname returned an unsupported unicast address")
		}
		if !seen[addr] {
			seen[addr] = true
			unique = append(unique, addr)
		}
	}
	sort.Slice(unique, func(i, j int) bool { return unique[i].Compare(unique[j]) < 0 })
	for _, addr := range unique {
		report.ResolvedAddresses = append(report.ResolvedAddresses, addr.String())
	}
	report.NameResolved = true
	if !seen[ip] {
		report.Outcome = "hostname_mismatch"
		return report, Fault("underlay_name_mismatch", "host name resolution does not contain the explicitly pinned endpoint IP; TCP probe refused")
	}
	report.NameMatched = true

	// The actual TCP path remains the existing fixed-native-iproute2,
	// interface-bound, no-application-data probe. No unbound fallback.
	tcp, err := InspectUnderlayTCP(ip.String(), port)
	tcp.Hostname = report.Hostname
	tcp.NameResolved = report.NameResolved
	tcp.NameMatched = report.NameMatched
	tcp.ResolvedAddresses = report.ResolvedAddresses
	tcp.ResolutionMs = report.ResolutionMs
	return tcp, err
}
