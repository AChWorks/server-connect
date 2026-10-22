package sc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

const explicitResolverTimeout = 4 * time.Second

// UnderlayDNSReport describes an explicit resolver-to-pinned-address check.
// No result authorizes activation: a later tunnel could change routing,
// DNS reply authenticity is unverified, and the host/SSH safety guards do not exist.
type UnderlayDNSReport struct {
	Mode                 string   `json:"mode"`
	ReadOnly             bool     `json:"read_only"`
	ActivationReady      bool     `json:"activation_ready"`
	DNSBootstrapVerified bool     `json:"dns_bootstrap_verified"`
	Hostname             string   `json:"hostname"`
	Endpoint             string   `json:"endpoint"`
	Resolver             string   `json:"resolver"`
	ResolverPort         int      `json:"resolver_port"`
	ResolverRouteDevice  string   `json:"resolver_route_device,omitempty"`
	ResolverRouteGateway string   `json:"resolver_route_gateway,omitempty"`
	ResolverRouteSource  string   `json:"resolver_route_source,omitempty"`
	InterfaceBound       bool     `json:"interface_bound"`
	ResolverDialCount    int64    `json:"resolver_dial_count"`
	RouteStable          bool     `json:"route_stable"`
	NameResolved         bool     `json:"name_resolved"`
	NameMatched          bool     `json:"name_matched"`
	ResolvedAddresses    []string `json:"resolved_addresses,omitempty"`
	DurationMs           int64    `json:"duration_ms"`
	Outcome              string   `json:"outcome"`
	Limitations          []string `json:"limitations"`
}

// DNS may fall back from UDP to TCP. Each route uses the same kernel
// flow selectors as the socket that net.Resolver will request.
func resolverFlowRoute(ip netip.Addr, port, uid int, proto string) (underlayRoute, error) {
	route, err := inspectUnderlayRoute(ip, "ipproto", proto, "dport", strconv.Itoa(port), "uid", strconv.Itoa(uid))
	if err != nil {
		return underlayRoute{}, err
	}
	if route.UID != nil && *route.UID != uint32(uid) {
		return underlayRoute{}, Fault("underlay_policy_unsupported", "kernel DNS route contradicted the requested process UID")
	}
	return route, nil
}

// The standard Go resolver can retry UDP as TCP. Treat path divergence as
// unsupported rather than advertising a single resolved interface for two
// policy-routed socket flows.
func matchingResolverTransportRoute(ip netip.Addr, port, uid int) (underlayRoute, error) {
	udp, err := resolverFlowRoute(ip, port, uid, "udp")
	if err != nil {
		return underlayRoute{}, err
	}
	tcp, err := resolverFlowRoute(ip, port, uid, "tcp")
	if err != nil || !sameUnderlayRoute(udp, tcp) {
		return underlayRoute{}, Fault("underlay_policy_unsupported", "UDP and TCP DNS select different or unavailable kernel routes")
	}
	return udp, nil
}

// InspectUnderlayDNS resolves an absolute hostname exclusively through the
// operator-supplied literal DNS server/port. Every resolver connection is bound
// to the kernel-selected device using SO_BINDTODEVICE; neither host configured
// DNS servers nor an HTTP proxy may substitute for the pinned resolver.
// Standard Go DNS parsing is used rather than implementing a new DNS protocol.
// Queries are initiated only on explicit operator invocation; this method
// changes no Linux routes, rules, firewall, DNS settings or product state.
func InspectUnderlayDNS(hostname, endpointIP, resolverIP string, resolverPort int) (UnderlayDNSReport, error) {
	endpoint, err := parsePreflightAddress(endpointIP, "endpoint")
	if err != nil || !endpoint.IsValid() {
		return UnderlayDNSReport{}, Fault("invalid_arguments", "underlay DNS endpoint must be a literal unicast IPv4/IPv6 address")
	}
	resolver, err := parsePreflightAddress(resolverIP, "resolver")
	if err != nil || !resolver.IsValid() {
		return UnderlayDNSReport{}, Fault("invalid_arguments", "DNS resolver must be a literal unicast IPv4/IPv6 address")
	}
	name, err := validateEndpointHostname(hostname)
	if err != nil {
		return UnderlayDNSReport{}, err
	}
	if resolverPort < 1 || resolverPort > 65535 {
		return UnderlayDNSReport{}, Fault("invalid_arguments", "DNS resolver port must be between 1 and 65535")
	}
	report := UnderlayDNSReport{
		Mode: "explicit_resolver_diagnostic", ReadOnly: true,
		ActivationReady: false, DNSBootstrapVerified: false,
		Hostname: name, Endpoint: endpoint.String(),
		Resolver: resolver.String(), ResolverPort: resolverPort,
		Outcome: "not_tested",
		Limitations: []string{
			"DNS results are not cryptographically authenticated; the operator must trust the selected resolver.",
			"UDP and TCP route selection uses the exact DNS port and process UID; unsupported policy and differing paths are refused.",
			"An interface-bound DNS reply today does not prove independent pre-VPN routing or DNS after a tunnel changes policy.",
			"Host routes are observed non-atomically; endpoint reachability, SSH/ingress, ownership and independent activation/recovery guards are unverified.",
			"Queries are sent to the explicitly selected resolver and can disclose the hostname to that server.",
		},
	}
	if err = trustedHostIPExecutable(); err != nil {
		report.Outcome = "unavailable"
		return report, err
	}
	// Both UDP and TCP can carry this DNS resolution. Verify the
	// actual flow-qualified kernel route for each protocol before dialing.
	// Different paths or unmodeled selectors fail closed without any query.
	if os.Getuid() != os.Geteuid() {
		report.Outcome = "resolver_policy_unsupported"
		return report, Fault("underlay_policy_unsupported", "real and effective user IDs differ")
	}
	policyBefore, err := inspectTCPPolicyRules(resolver)
	if err != nil {
		report.Outcome = "resolver_policy_unsupported"
		return report, err
	}
	uid := os.Geteuid()
	before, err := matchingResolverTransportRoute(resolver, resolverPort, uid)
	if err != nil {
		report.Outcome = "resolver_policy_unsupported"
		return report, err
	}
	report.ResolverRouteDevice, report.ResolverRouteGateway, report.ResolverRouteSource =
		before.Device, before.Gateway, before.Source

	var boundDials atomic.Int64
	var failedBinds atomic.Int64
	// A custom Dial pins every UDP and TCP DNS attempt to one literal
	// resolver address. The Go resolver may retry or fall back to TCP, but
	// cannot use an alternate DNS server or an unbound socket.
	dialer := net.Dialer{
		Timeout: 2 * time.Second,
		Control: func(_ string, _ string, raw syscall.RawConn) error {
			var setErr error
			if err := raw.Control(func(fd uintptr) {
				setErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, before.Device)
			}); err != nil {
				failedBinds.Add(1)
				return err
			}
			if setErr != nil {
				failedBinds.Add(1)
			} else {
				boundDials.Add(1)
			}
			return setErr
		},
	}
	pinnedResolver := net.JoinHostPort(resolver.String(), strconv.Itoa(resolverPort))
	dns := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Go asks for udp/tcp connections as necessary. No fallback
			// to the host-configured address supplied by the resolver.
			return dialer.DialContext(ctx, network, pinnedResolver)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), explicitResolverTimeout)
	defer cancel()
	start := time.Now()
	answers, lookupErr := dns.LookupNetIP(ctx, "ip", name+".")
	report.DurationMs = time.Since(start).Milliseconds()
	report.ResolverDialCount = boundDials.Load()
	report.InterfaceBound = report.ResolverDialCount > 0 && failedBinds.Load() == 0

	afterUDP, udpErr := resolverFlowRoute(resolver, resolverPort, uid, "udp")
	afterTCP, tcpErr := resolverFlowRoute(resolver, resolverPort, uid, "tcp")
	policyAfter, policyErr := inspectTCPPolicyRules(resolver)
	if udpErr != nil || tcpErr != nil || policyErr != nil ||
		!sameUnderlayRoute(before, afterUDP) || !sameUnderlayRoute(before, afterTCP) ||
		!bytes.Equal(policyBefore, policyAfter) {
		report.Outcome = "route_changed_or_unavailable"
		return report, Fault("underlay_unavailable", "resolver UDP/TCP route or policy changed during DNS query")
	}
	report.RouteStable = true
	// A hosts-file or local shortcut can resolve without our custom Dial.
	// That must never masquerade as an independently requested DNS answer.
	if !report.InterfaceBound {
		report.Outcome = "resolver_not_interface_bound"
		return report, Fault("underlay_dns_unavailable", "no verified interface-bound DNS query to the selected resolver")
	}
	if lookupErr != nil || ctx.Err() != nil {
		report.Outcome = "dns_resolution_failed"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			report.Outcome = "dns_timeout"
		}
		return report, Fault("underlay_dns_unavailable", "explicit resolver failed or timed out")
	}
	if len(answers) == 0 || len(answers) > maxEndpointNameAnswers {
		report.Outcome = "dns_answers_unsupported"
		return report, Fault("underlay_dns_unavailable", "explicit resolver returned no addresses or exceeded answer limit")
	}
	seen := make(map[netip.Addr]struct{}, len(answers))
	valid := make([]netip.Addr, 0, len(answers))
	for _, a := range answers {
		if !a.IsValid() || a.Zone() != "" || a.Is4In6() || a.IsLinkLocalUnicast() ||
			(!a.IsGlobalUnicast() && !a.IsLoopback()) {
			report.Outcome = "dns_answers_unsupported"
			return report, Fault("underlay_dns_unavailable", "explicit resolver returned an unsupported address")
		}
		if _, ok := seen[a]; !ok {
			seen[a] = struct{}{}
			valid = append(valid, a)
		}
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].Compare(valid[j]) < 0 })
	for _, a := range valid {
		report.ResolvedAddresses = append(report.ResolvedAddresses, a.String())
	}
	report.NameResolved = true
	if _, ok := seen[endpoint]; !ok {
		report.Outcome = "pinned_endpoint_mismatch"
		return report, Fault("underlay_dns_mismatch", "explicit DNS answer does not contain the pinned endpoint IP")
	}
	report.NameMatched = true
	report.Outcome = "name_matched"
	return report, nil
}
