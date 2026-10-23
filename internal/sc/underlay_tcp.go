package sc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// UnderlayTCPReport deliberately reports only a TCP socket attempt bound to
// the interface currently selected by the kernel for a literal endpoint.
// It cannot attest VPN protocol/TLS, DNS, management replies or future routing.
type UnderlayTCPReport struct {
	Mode                 string   `json:"mode"`
	ReadOnly             bool     `json:"read_only"`
	ActivationReady      bool     `json:"activation_ready"`
	Endpoint             string   `json:"endpoint"`
	Hostname             string   `json:"hostname,omitempty"`
	NameResolved         bool     `json:"name_resolved"`
	NameMatched          bool     `json:"name_matched"`
	ResolvedAddresses    []string `json:"resolved_addresses,omitempty"`
	ResolutionMs         int64    `json:"resolution_ms,omitempty"`
	DNSBootstrapVerified bool     `json:"dns_bootstrap_verified"`
	Port                 int      `json:"port"`
	Protocol             string   `json:"protocol"`
	RouteDevice          string   `json:"route_device,omitempty"`
	RouteGateway         string   `json:"route_gateway,omitempty"`
	RouteSource          string   `json:"route_source,omitempty"`
	InterfaceBound       bool     `json:"interface_bound"`
	RouteStable          bool     `json:"route_stable"`
	SocketConnected      bool     `json:"socket_connected"`
	SocketLocalAddress   string   `json:"socket_local_address,omitempty"`
	Outcome              string   `json:"outcome"`
	DurationMs           int64    `json:"duration_ms"`
	Limitations          []string `json:"limitations"`
}

type underlayRoute struct {
	Dst     string          `json:"dst"`
	Device  string          `json:"dev"`
	Gateway string          `json:"gateway"`
	Source  string          `json:"prefsrc"`
	Kind    string          `json:"type"`
	Table   json.RawMessage `json:"table"`
	UID     *uint32         `json:"uid,omitempty"`
}

// The optional route-get selectors are validated, fixed CLI tokens constructed
// only by internal callers. Generic lookups remain available to the separate
// observational DNS diagnostic, but TCP never uses a destination-only route.
func inspectUnderlayRoute(addr netip.Addr, flow ...string) (underlayRoute, error) {
	var data json.RawMessage
	if len(flow) == 0 {
		lookup, err := lookupHostRoute(addr)
		if err != nil {
			return underlayRoute{}, err
		}
		if lookup == nil {
			return underlayRoute{}, Fault("underlay_unavailable", "kernel did not return a route to endpoint")
		}
		data = lookup.KernelRoute
	} else {
		family := "-4"
		if addr.Is6() {
			family = "-6"
		}
		var err error
		args := append([]string{"-j", family, "route", "get", addr.String()}, flow...)
		data, err = nativeIPJSON(args...)
		if err != nil {
			return underlayRoute{}, err
		}
	}
	var rows []underlayRoute
	if json.Unmarshal(data, &rows) != nil || len(rows) != 1 {
		return underlayRoute{}, Fault("underlay_unavailable", "kernel did not return one unambiguous route to endpoint")
	}
	route := rows[0]
	// The kernel-supplied interface must be usable as an exact SO_BINDTODEVICE
	// value. Do not silently perform an unbound fallback.
	if route.Device == "" || len(route.Device) > 15 ||
		strings.ContainsAny(route.Device, "\x00 \t\r\n/\\") {
		return underlayRoute{}, Fault("underlay_unavailable", "kernel endpoint route lacks a valid interface")
	}
	for _, literal := range []string{route.Source, route.Gateway} {
		if literal == "" {
			continue
		}
		ip, err := netip.ParseAddr(literal)
		if err != nil || !ip.IsValid() || ip.Zone() != "" || ip.Is4() != addr.Is4() {
			return underlayRoute{}, Fault("underlay_unavailable", "kernel route returned an unsupported source/gateway address")
		}
	}
	if route.Dst != addr.String() {
		return underlayRoute{}, Fault("underlay_unavailable", "kernel route destination differs from the requested literal endpoint")
	}
	if route.Kind != "" && route.Kind != "unicast" && route.Kind != "local" {
		return underlayRoute{}, Fault("underlay_unavailable", "kernel endpoint route type is not a deliverable unicast/local path")
	}
	dev, err := net.InterfaceByName(route.Device)
	if err != nil || dev.Flags&net.FlagUp == 0 {
		return underlayRoute{}, Fault("underlay_unavailable", "endpoint route interface is missing or down")
	}
	return route, nil
}

func sameUnderlayRoute(a, b underlayRoute) bool {
	return a.Dst == b.Dst && a.Device == b.Device && a.Gateway == b.Gateway &&
		a.Source == b.Source && a.Kind == b.Kind && bytes.Equal(a.Table, b.Table) &&
		((a.UID == nil && b.UID == nil) || (a.UID != nil && b.UID != nil && *a.UID == *b.UID))
}

// inspectTCPPolicyRules captures policy identity before choosing an interface.
// Some Linux selectors (source IP, ephemeral source port, socket mark,
// bound output interface/VRF, incoming interface, traffic class) cannot be
// inferred from the unconnected Go TCP socket. Refuse these configurations
// instead of mislabeling an intentionally interface-bound attempt as proof of
// the ordinary TCP route. UID range and destination port rules ARE modeled by
// the flow-qualified kernel route get. No policy-rule mutation is performed.
func inspectTCPPolicyRules(addr netip.Addr) (json.RawMessage, error) {
	family := "-4"
	if addr.Is6() {
		family = "-6"
	}
	data, err := nativeIPJSON("-j", family, "rule", "show")
	if err != nil {
		return nil, err
	}
	if err := validateTCPPolicyRules(data); err != nil {
		return nil, err
	}
	return data, nil
}

// validateTCPPolicyRules also permits deterministic regression tests for
// complex Linux policy selectors without changing the runner's host network.
func validateTCPPolicyRules(data []byte) error {
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(data, &rules); err != nil || rules == nil {
		return Fault("underlay_policy_unsupported", "kernel policy-rule snapshot is unavailable")
	}
	// Explicitly allowed keys are metadata or selectors supplied to route get.
	// Unrecognized policy selectors are not assumed safe as iproute2 evolves.
	allowed := map[string]bool{
		"priority": true, "pref": true, "src": true, "dst": true,
		"srclen": true, "dstlen": true, "table": true,
		"ipproto": true, "dport": true, "dport_start": true, "dport_end": true,
		"uid_start": true, "uid_end": true, "uidrange": true,
		"protocol": true, "action": true, "flags": true,
	}
	for _, rule := range rules {
		if len(rule["priority"]) == 0 {
			return Fault("underlay_policy_unsupported", "kernel policy-rule identity is incomplete")
		}
		for key, raw := range rule {
			if !allowed[key] {
				return Fault("underlay_policy_unsupported", "flow policy includes a selector unsupported by bound TCP diagnosis")
			}
			if key == "src" && string(raw) != `"all"` ||
				key == "srclen" && string(raw) != "0" ||
				key == "flags" && string(raw) != "[]" && string(raw) != "null" {
				return Fault("underlay_policy_unsupported", "source or inverted policy requires an explicit socket flow identity")
			}
		}
	}
	return nil
}

// A TCP connect made by this manager uses an ordinary locally initiated socket
// with no supplied SO_MARK or source port. The UID and destination port are
// known; source-sensitive policies are rejected by inspectTCPPolicyRules.
func tcpFlowRoute(addr netip.Addr, port, uid int) (underlayRoute, error) {
	route, err := inspectUnderlayRoute(addr, "ipproto", "tcp", "dport", strconv.Itoa(port), "uid", strconv.Itoa(uid))
	if err != nil {
		return underlayRoute{}, err
	}
	// IPv6 route-get omits the uid field in native iproute2 JSON even
	// when the UID is applied to the kernel query. Reject contradictory
	// returned identity, but do not require an echo on IPv6/local routes.
	if route.UID != nil && *route.UID != uint32(uid) {
		return underlayRoute{}, Fault("underlay_policy_unsupported", "kernel TCP route contradicted the requested process UID")
	}
	return route, nil
}

// validateUnderlayTCPArgs runs before any native tool, hostname resolution or
// socket attempt. The optional DNS consistency mode shares this boundary.
func validateUnderlayTCPArgs(endpointIP string, port int) (netip.Addr, error) {
	ip, err := parsePreflightAddress(endpointIP, "endpoint")
	if err != nil || !ip.IsValid() {
		return netip.Addr{}, Fault("invalid_arguments", "underlay TCP endpoint must be a literal unicast IPv4/IPv6 address")
	}
	if port < 1 || port > 65535 {
		return netip.Addr{}, Fault("invalid_arguments", "underlay TCP port must be between 1 and 65535")
	}
	return ip, nil
}

func newUnderlayTCPReport(ip netip.Addr, port int) UnderlayTCPReport {
	return UnderlayTCPReport{
		Mode: "underlay_tcp_diagnostic", ReadOnly: true, ActivationReady: false,
		Endpoint: ip.String(), Port: port, Protocol: "tcp", Outcome: "not_tested",
		DNSBootstrapVerified: false,
		Limitations: []string{
			"Successful TCP connection does not prove VPN handshake, TLS identity, authenticated proxy operation or UDP transport.",
			"Interface binding does not establish an unmodified underlay, ingress/SSH reply safety or network/firewall ownership.",
			"TCP route selection includes protocol, destination port and process UID; source-port, source-rule, mark, VRF and other ambiguous policies are refused.",
			"Kernel route/policy observations are non-atomic; hostname resolution does not prove DNS underlay, management safety, activation or rollback guards.",
		},
	}
}

// interfaceBoundTCPControl is also tested against actual kernel policy routes
// inside disposable network namespaces; no unbound fallback is possible.
func interfaceBoundTCPControl(device string, bound *atomic.Bool) func(string, string, syscall.RawConn) error {
	return func(_ string, _ string, raw syscall.RawConn) error {
		var optErr error
		if err := raw.Control(func(fd uintptr) {
			optErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
		}); err != nil {
			return err
		}
		if optErr == nil {
			bound.Store(true)
		}
		return optErr
	}
}

// InspectUnderlayTCP makes an explicit, bounded TCP connection attempt; it
// sends no application data, uses no DNS or proxy environment variables, and
// does not change host route tables, firewall, profile state or systemd units.
// SO_BINDTODEVICE fails closed if the current route interface cannot be bound.
// Even successful TCP evidence MUST NOT authorize tunnel activation.
func InspectUnderlayTCP(endpointIP string, port int) (UnderlayTCPReport, error) {
	ip, err := validateUnderlayTCPArgs(endpointIP, port)
	if err != nil {
		return UnderlayTCPReport{}, err
	}
	report := newUnderlayTCPReport(ip, port)
	if err = trustedHostIPExecutable(); err != nil {
		report.Outcome = "unavailable"
		return report, err
	}
	// Reconcile the route query with the actual socket's known flow identity.
	// Setuid execution and source-selective or marked routing cannot be safely
	// modeled by this diagnostic and must fail before any TCP dial.
	if os.Getuid() != os.Geteuid() {
		report.Outcome = "flow_identity_unsupported"
		return report, Fault("underlay_policy_unsupported", "real and effective user IDs differ")
	}
	policyBefore, err := inspectTCPPolicyRules(ip)
	if err != nil {
		report.Outcome = "flow_policy_unsupported"
		return report, err
	}
	uid := os.Geteuid()
	before, err := tcpFlowRoute(ip, port, uid)
	if err != nil {
		report.Outcome = "route_unavailable"
		return report, err
	}
	report.RouteDevice, report.RouteGateway, report.RouteSource = before.Device, before.Gateway, before.Source

	// The dialer does not consult HTTP(S)_PROXY or DNS. It binds the exact
	// kernel-reported interface before connect, never falling back to an
	// ordinary unbound socket if binding is denied.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var bound atomic.Bool
	dialer := net.Dialer{
		Timeout: 3 * time.Second,
		Control: interfaceBoundTCPControl(before.Device, &bound),
	}
	start := time.Now()
	conn, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	report.DurationMs = time.Since(start).Milliseconds()
	report.InterfaceBound = bound.Load()
	var localSource netip.Addr
	if dialErr == nil {
		report.SocketConnected = true
		report.Outcome = "tcp_connected"
		report.SocketLocalAddress = conn.LocalAddr().String()
		if tcpLocal, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			localSource, _ = netip.AddrFromSlice(tcpLocal.IP)
		}
		_ = conn.Close()
	} else {
		switch {
		case !report.InterfaceBound:
			report.Outcome = "interface_binding_failed"
		case errors.Is(dialErr, syscall.ECONNREFUSED):
			report.Outcome = "tcp_refused"
		case errors.Is(dialErr, context.DeadlineExceeded):
			report.Outcome = "tcp_timeout"
		default:
			var netErr net.Error
			if errors.As(dialErr, &netErr) && netErr.Timeout() {
				report.Outcome = "tcp_timeout"
			} else {
				report.Outcome = "tcp_unreachable"
			}
		}
	}
	after, routeErr := tcpFlowRoute(ip, port, uid)
	policyAfter, policyErr := inspectTCPPolicyRules(ip)
	if routeErr != nil || policyErr != nil || !bytes.Equal(policyBefore, policyAfter) ||
		!sameUnderlayRoute(before, after) ||
		(localSource.IsValid() && before.Source != "" && localSource.String() != before.Source) {
		// The comparison includes policy table identity. An unstable
		// observation is not reliable diagnostic evidence.
		report.RouteStable = false
		report.Outcome = "route_changed_or_unavailable"
		return report, Fault("underlay_unavailable", "TCP flow route/policy or observed socket source changed or became unavailable during probe")
	}
	report.RouteStable = true
	if dialErr != nil {
		return report, Fault("underlay_unreachable", "interface-bound TCP probe failed; inspect outcome and endpoint transport")
	}
	return report, nil
}
