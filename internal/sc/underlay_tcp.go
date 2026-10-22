package sc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
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
	Mode               string   `json:"mode"`
	ReadOnly           bool     `json:"read_only"`
	ActivationReady    bool     `json:"activation_ready"`
	Endpoint           string   `json:"endpoint"`
	Port               int      `json:"port"`
	Protocol           string   `json:"protocol"`
	RouteDevice        string   `json:"route_device,omitempty"`
	RouteGateway       string   `json:"route_gateway,omitempty"`
	RouteSource        string   `json:"route_source,omitempty"`
	InterfaceBound     bool     `json:"interface_bound"`
	RouteStable        bool     `json:"route_stable"`
	SocketConnected    bool     `json:"socket_connected"`
	SocketLocalAddress string   `json:"socket_local_address,omitempty"`
	Outcome            string   `json:"outcome"`
	DurationMs         int64    `json:"duration_ms"`
	Limitations        []string `json:"limitations"`
}

type underlayRoute struct {
	Dst     string          `json:"dst"`
	Device  string          `json:"dev"`
	Gateway string          `json:"gateway"`
	Source  string          `json:"prefsrc"`
	Kind    string          `json:"type"`
	Table   json.RawMessage `json:"table"`
}

func inspectUnderlayRoute(addr netip.Addr) (underlayRoute, error) {
	lookup, err := lookupHostRoute(addr)
	if err != nil {
		return underlayRoute{}, err
	}
	var rows []underlayRoute
	if lookup == nil || json.Unmarshal(lookup.KernelRoute, &rows) != nil || len(rows) != 1 {
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
		a.Source == b.Source && a.Kind == b.Kind && bytes.Equal(a.Table, b.Table)
}

// InspectUnderlayTCP makes an explicit, bounded TCP connection attempt; it
// sends no application data, uses no DNS or proxy environment variables, and
// does not change host route tables, firewall, profile state or systemd units.
// SO_BINDTODEVICE fails closed if the current route interface cannot be bound.
// Even successful TCP evidence MUST NOT authorize tunnel activation.
func InspectUnderlayTCP(endpointIP string, port int) (UnderlayTCPReport, error) {
	ip, err := parsePreflightAddress(endpointIP, "endpoint")
	if err != nil || !ip.IsValid() || (!ip.IsGlobalUnicast() && !ip.IsLoopback()) {
		return UnderlayTCPReport{}, Fault("invalid_arguments", "underlay TCP endpoint must be a literal unicast IPv4/IPv6 address")
	}
	if port < 1 || port > 65535 {
		return UnderlayTCPReport{}, Fault("invalid_arguments", "underlay TCP port must be between 1 and 65535")
	}
	report := UnderlayTCPReport{
		Mode: "underlay_tcp_diagnostic", ReadOnly: true, ActivationReady: false,
		Endpoint: ip.String(), Port: port, Protocol: "tcp", Outcome: "not_tested",
		Limitations: []string{
			"Successful TCP connection does not prove VPN handshake, TLS identity, authenticated proxy operation or UDP transport.",
			"Interface binding does not establish an unmodified underlay, ingress/SSH reply safety or network/firewall ownership.",
			"Kernel route observations are non-atomic; DNS, management safety, activation and runtime rollback guards remain unverified.",
		},
	}
	if err = trustedHostIPExecutable(); err != nil {
		report.Outcome = "unavailable"
		return report, err
	}
	before, err := inspectUnderlayRoute(ip)
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
		Control: func(_ string, _ string, raw syscall.RawConn) error {
			var optErr error
			if err := raw.Control(func(fd uintptr) {
				optErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, before.Device)
			}); err != nil {
				return err
			}
			if optErr == nil {
				bound.Store(true)
			}
			return optErr
		},
	}
	start := time.Now()
	conn, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	report.DurationMs = time.Since(start).Milliseconds()
	report.InterfaceBound = bound.Load()
	if dialErr == nil {
		report.SocketConnected = true
		report.Outcome = "tcp_connected"
		report.SocketLocalAddress = conn.LocalAddr().String()
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
	after, routeErr := inspectUnderlayRoute(ip)
	if routeErr != nil || !sameUnderlayRoute(before, after) {
		// The comparison includes policy table identity. An unstable
		// observation is not reliable diagnostic evidence.
		report.RouteStable = false
		report.Outcome = "route_changed_or_unavailable"
		return report, Fault("underlay_unavailable", "endpoint kernel route changed or became unavailable during probe")
	}
	report.RouteStable = true
	if dialErr != nil {
		return report, Fault("underlay_unreachable", "interface-bound TCP probe failed; inspect outcome and endpoint transport")
	}
	return report, nil
}
