//go:build linux

package sc

// Host health witnesses bind a single operation to explicit kernel paths.
// HTTPS authenticates the observed egress address. DNS establishes fresh,
// path-bound UDP/DNS reachability; it is not an authenticated egress oracle.
// The caller must revalidate the operation, boot, native ownership and guard
// lease before publishing evidence measured outside its manager lock.

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type HostHealthTraceTarget struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	ServerName string `json:"server_name"`
	Path       string `json:"path"`
}

type HostHealthFamilyPlan struct {
	// Only IPv6 may explicitly lack a physical Direct path while its VPN
	// family remains enabled over an IPv4 outer transport.
	DirectUnavailable bool                  `json:"direct_unavailable"`
	Enabled           bool                  `json:"enabled"`
	UnderlaySource    string                `json:"underlay_source"`
	DNSResolver       string                `json:"dns_resolver"`
	Trace             HostHealthTraceTarget `json:"trace"`
	ExpectedDirectIP  string                `json:"expected_direct_ip"`
	ExpectedVPNIP     string                `json:"expected_vpn_ip"`
}

// Value-only fields make a copy independent of concurrent caller mutations.
// Expected exits are separately measured through Direct and the selected
// profile before activation, then bound to the immutable configuration digest.
type HostHealthPlan struct {
	Round             uint64               `json:"round"`
	OperationID       string               `json:"operation_id"`
	BootID            string               `json:"boot_id"`
	ConfigSHA256      string               `json:"config_sha256"`
	TunnelInterface   string               `json:"tunnel_interface"`
	UnderlayInterface string               `json:"underlay_interface"`
	EndpointIP        string               `json:"endpoint_ip"`
	EndpointPort      int                  `json:"endpoint_port"`
	IPv4              HostHealthFamilyPlan `json:"ipv4"`
	IPv6              HostHealthFamilyPlan `json:"ipv6"`
	// Zero value means no domestic witness requested. It cannot be reported as
	// verified domestic connectivity or full product acceptance.
	Domestic HostHealthTraceTarget `json:"domestic"`
}

type HostHealthResult struct {
	Result     string `json:"result"`
	HTTPStatus int    `json:"http_status"`
	ObservedIP string `json:"observed_ip,omitempty"`
}

type HostHealthFamilyEvidence struct {
	DirectUnavailable bool             `json:"direct_unavailable"`
	Enabled           bool             `json:"enabled"`
	SelectedHTTPS     HostHealthResult `json:"selected_https"`
	DirectHTTPS       HostHealthResult `json:"direct_https"`
	TCP               string           `json:"tcp"`
	UDP               string           `json:"udp"`
	DNS               string           `json:"dns"`
	EgressVerified    bool             `json:"egress_verified"`
	DirectVerified    bool             `json:"direct_verified"`
}

type HostHealthEvidence struct {
	Round             uint64                   `json:"round"`
	StartedUptimeMS   int64                    `json:"started_uptime_ms"`
	CompletedUptimeMS int64                    `json:"completed_uptime_ms"`
	OperationID       string                   `json:"operation_id"`
	BootID            string                   `json:"boot_id"`
	ConfigSHA256      string                   `json:"config_sha256"`
	PlanSHA256        string                   `json:"plan_sha256"`
	IPv4              HostHealthFamilyEvidence `json:"ipv4"`
	IPv6              HostHealthFamilyEvidence `json:"ipv6"`
	EndpointTCP       string                   `json:"endpoint_tcp"`
	DomesticHTTPS     HostHealthResult         `json:"domestic_https"`
	DomesticVerified  bool                     `json:"domestic_verified"`
	Healthy           bool                     `json:"healthy"`
	ProbeCount        int                      `json:"probe_count"`
	ElapsedMS         int64                    `json:"elapsed_ms"`
	Reason            string                   `json:"reason"`
}

func hostHealthFault(message string) error {
	return Fault("host_health_plan_invalid", message)
}
func hostHealthPublicIP(text string, family int) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(text)
	if err != nil || ip.String() != text || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() ||
		ip.IsLoopback() || ip.IsLinkLocalUnicast() || (family == 4 && !ip.Is4()) || (family == 6 && !ip.Is6()) {
		return netip.Addr{}, false
	}
	if overlapsSpecialPurpose(netip.PrefixFrom(ip, ip.BitLen())) {
		return netip.Addr{}, false
	}
	if ip.Is6() && !conservativelyPublicIPv6Prefix(netip.PrefixFrom(ip, 128)) {
		return netip.Addr{}, false
	}
	return ip, true
}
func hostHealthSourceIP(text string, family int) bool {
	ip, err := netip.ParseAddr(text)
	return err == nil && ip.String() == text && !ip.Is4In6() && ip.Zone() == "" &&
		ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		((family == 4 && ip.Is4()) || (family == 6 && ip.Is6()))
}
func validateHostHealthTrace(t HostHealthTraceTarget, family int) error {
	if _, ok := hostHealthPublicIP(t.Address, family); !ok || t.Port < 1 || t.Port > 65535 {
		return hostHealthFault("trace requires a canonical public literal address and port")
	}
	name, err := canonicalSmartTUNDomain(t.ServerName, false)
	if err != nil || name != t.ServerName {
		return hostHealthFault("trace requires a canonical TLS DNS identity")
	}
	if len(t.Path) == 0 || len(t.Path) > 256 || t.Path[0] != '/' || strings.Contains(t.Path, "//") {
		return hostHealthFault("trace path must be a bounded absolute path")
	}
	for _, c := range t.Path {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/_.~-", c)) {
			return hostHealthFault("trace path contains unsupported request controls")
		}
	}
	return nil
}

// Validation is activation-grade for the requested families: no missing exit
// identity, disabled-family payload, guessed address family or silent downgrade.
// This validates a plan, not actual network or geographic availability.
func ValidateHostHealthPlan(p HostHealthPlan) error {
	if p.Round == 0 || !journalHex32.MatchString(p.OperationID) || !trialBootIDPattern.MatchString(p.BootID) ||
		!journalHex64.MatchString(p.ConfigSHA256) || !smartTUNDeviceName.MatchString(p.TunnelInterface) ||
		!smartTUNDeviceName.MatchString(p.UnderlayInterface) || p.TunnelInterface == p.UnderlayInterface ||
		p.TunnelInterface == "lo" || p.UnderlayInterface == "lo" || !p.IPv4.Enabled ||
		p.EndpointPort < 1 || p.EndpointPort > 65535 {
		return hostHealthFault("operation, configuration, devices or endpoint invalid")
	}
	endpoint, ok := hostHealthPublicIP(p.EndpointIP, 0)
	if !ok || (endpoint.Is6() && (!p.IPv6.Enabled || p.IPv6.DirectUnavailable)) {
		return hostHealthFault("endpoint family has no protected underlay plan")
	}
	for i, f := range []HostHealthFamilyPlan{p.IPv4, p.IPv6} {
		family := 4
		if i == 1 {
			family = 6
		}
		if !f.Enabled {
			if f != (HostHealthFamilyPlan{}) {
				return hostHealthFault("disabled address family must have no ignored plan fields")
			}
			continue
		}
		if f.DirectUnavailable {
			if family != 6 || f.UnderlaySource != "" || f.ExpectedDirectIP != "" {
				return hostHealthFault("only IPv6 may explicitly lack Direct, without ignored source/egress fields")
			}
		} else if !hostHealthSourceIP(f.UnderlaySource, family) {
			return hostHealthFault("underlay source address invalid")
		}
		if _, ok := hostHealthPublicIP(f.DNSResolver, family); !ok {
			return hostHealthFault("DNS target must be a canonical public address in its declared family")
		}
		if err := validateHostHealthTrace(f.Trace, family); err != nil {
			return err
		}
		if _, ok := hostHealthPublicIP(f.ExpectedDirectIP, family); !f.DirectUnavailable && !ok {
			return hostHealthFault("independently measured Direct egress is required")
		}
		if _, ok := hostHealthPublicIP(f.ExpectedVPNIP, family); !ok || f.ExpectedVPNIP == f.ExpectedDirectIP {
			return hostHealthFault("independently measured distinct selected VPN egress is required")
		}
	}
	if p.Domestic != (HostHealthTraceTarget{}) {
		family := 4
		if ip, err := netip.ParseAddr(p.Domestic.Address); err == nil && ip.Is6() {
			family = 6
		}
		if family == 6 && (!p.IPv6.Enabled || p.IPv6.DirectUnavailable) {
			return hostHealthFault("domestic target has no protected underlay family")
		}
		if err := validateHostHealthTrace(p.Domestic, family); err != nil {
			return err
		}
	}
	return nil
}

type hostHealthProbe struct {
	role     string
	family   int
	target   HostHealthTraceTarget
	expected string
	address  string
	port     int
	device   string
	source   string
	bypass   bool
}
type hostHealthSample struct {
	probe  hostHealthProbe
	result HostHealthResult
}

func hostHealthProbes(p HostHealthPlan) []hostHealthProbe {
	probes := []hostHealthProbe{}
	for i, f := range []HostHealthFamilyPlan{p.IPv4, p.IPv6} {
		if !f.Enabled {
			continue
		}
		family := 4
		if i == 1 {
			family = 6
		}
		probes = append(probes,
			hostHealthProbe{role: "selected", family: family, target: f.Trace, expected: f.ExpectedVPNIP, device: p.TunnelInterface},
			hostHealthProbe{role: "dns", family: family, address: f.DNSResolver, port: 53, device: p.TunnelInterface})
		if !f.DirectUnavailable {
			probes = append(probes, hostHealthProbe{role: "direct", family: family, target: f.Trace, expected: f.ExpectedDirectIP, device: p.UnderlayInterface, source: f.UnderlaySource, bypass: true})
		}
	}
	family, f := 4, p.IPv4
	if ip, err := netip.ParseAddr(p.EndpointIP); err == nil && ip.Is6() {
		family, f = 6, p.IPv6
	}
	probes = append(probes, hostHealthProbe{role: "endpoint", family: family, address: p.EndpointIP, port: p.EndpointPort, device: p.UnderlayInterface, source: f.UnderlaySource, bypass: true})
	if p.Domestic != (HostHealthTraceTarget{}) {
		family, f = 4, p.IPv4
		if ip, err := netip.ParseAddr(p.Domestic.Address); err == nil && ip.Is6() {
			family, f = 6, p.IPv6
		}
		probes = append(probes, hostHealthProbe{role: "domestic", family: family, target: p.Domestic, expected: f.ExpectedDirectIP, device: p.UnderlayInterface, source: f.UnderlaySource, bypass: true})
	}
	return probes
}
func hostHealthNotRun(p HostHealthPlan) HostHealthEvidence {
	f := func(plan HostHealthFamilyPlan) HostHealthFamilyEvidence {
		e := HostHealthFamilyEvidence{Enabled: plan.Enabled, DirectUnavailable: plan.DirectUnavailable,
			SelectedHTTPS: HostHealthResult{Result: "not_run"}, DirectHTTPS: HostHealthResult{Result: "not_run"},
			TCP: "not_run", UDP: "not_run", DNS: "not_run"}
		if plan.DirectUnavailable {
			e.DirectHTTPS.Result = "unavailable"
		}
		return e
	}
	raw, _ := json.Marshal(p)
	return HostHealthEvidence{Round: p.Round, OperationID: p.OperationID, BootID: p.BootID, ConfigSHA256: p.ConfigSHA256,
		PlanSHA256: sha256Hex(raw), IPv4: f(p.IPv4), IPv6: f(p.IPv6), EndpointTCP: "not_run", DomesticHTTPS: HostHealthResult{Result: "not_run"}}
}

// ProbeHostHealth joins all bounded workers before returning. It never writes
// an operation journal, renews a lease, restores networking or claims native
// containment. Those actions belong to the independent supervising caller.
func ProbeHostHealth(parent context.Context, p HostHealthPlan) HostHealthEvidence {
	e := hostHealthNotRun(p)
	if ValidateHostHealthPlan(p) != nil {
		e.Reason = "invalid_plan"
		return e
	}
	boot, err := trialBootIdentity()
	if err != nil || boot != p.BootID {
		e.Reason = "boot_identity_mismatch"
		return e
	}
	return runHostHealth(parent, p, probeHostHealthEndpoint)
}
func runHostHealth(parent context.Context, p HostHealthPlan, probe func(context.Context, hostHealthProbe) HostHealthResult) HostHealthEvidence {
	started := time.Now()
	e := hostHealthNotRun(p)
	if ValidateHostHealthPlan(p) != nil {
		e.Reason = "invalid_plan"
		return e
	}
	now, clockErr := smartTUNUptimeMillis()
	if clockErr != nil {
		e.Reason = "clock_unavailable"
		return e
	}
	e.StartedUptimeMS = now
	ctx, cancel := context.WithTimeout(parent, smartTUNHealthRoundTimeout)
	defer cancel()
	if ctx.Err() != nil {
		e.Reason = "round_canceled"
		return e
	}
	requests := hostHealthProbes(p)
	results := make(chan hostHealthSample, len(requests))
	for _, request := range requests {
		go func(r hostHealthProbe) { results <- hostHealthSample{probe: r, result: probe(ctx, r)} }(request)
	}
	samples := make([]hostHealthSample, 0, len(requests))
	for range requests {
		samples = append(samples, <-results)
	}
	deadline, _ := ctx.Deadline()
	e = summarizeHostHealth(p, samples, ctx.Err() != nil || !time.Now().Before(deadline))
	e.StartedUptimeMS = now
	e.ElapsedMS = time.Since(started).Milliseconds()
	completed, clockErr := smartTUNUptimeMillis()
	if clockErr != nil || completed < e.StartedUptimeMS {
		e.Healthy = false
		if e.Reason != "path_mismatch" {
			e.Reason = "clock_unavailable"
		}
	} else {
		e.CompletedUptimeMS = completed
		if completed-now > smartTUNHealthRoundTimeout.Milliseconds() {
			e.Healthy = false
			if e.Reason != "path_mismatch" {
				e.Reason = "round_canceled"
			}
		}
	}
	return e
}
func summarizeHostHealth(p HostHealthPlan, samples []hostHealthSample, canceled bool) HostHealthEvidence {
	e := hostHealthNotRun(p)
	mismatch := false
	for _, sample := range samples {
		r, result := sample.probe, sample.result
		e.ProbeCount++
		if r.role != "dns" && r.role != "endpoint" && result.Result == "pass" {
			if result.ObservedIP != "" && result.ObservedIP != r.expected {
				result.Result = "path_mismatch"
			} else if result.HTTPStatus != 200 || result.ObservedIP != r.expected {
				result.Result = "invalid_result"
			}
		}
		if result.Result == "path_mismatch" {
			mismatch = true
		}
		f := &e.IPv4
		if r.family == 6 {
			f = &e.IPv6
		}
		switch r.role {
		case "selected":
			f.SelectedHTTPS = result
			f.TCP = result.Result
			f.EgressVerified = result.Result == "pass"
		case "direct":
			f.DirectHTTPS = result
			f.DirectVerified = result.Result == "pass"
		case "dns":
			f.UDP = result.Result
			f.DNS = result.Result
		case "endpoint":
			e.EndpointTCP = result.Result
		case "domestic":
			e.DomesticHTTPS = result
			e.DomesticVerified = result.Result == "pass"
		}
	}
	complete := func(f HostHealthFamilyEvidence) bool {
		return !f.Enabled || f.EgressVerified && (f.DirectVerified || f.DirectUnavailable) && f.TCP == "pass" && f.UDP == "pass" && f.DNS == "pass"
	}
	e.Healthy = complete(e.IPv4) && complete(e.IPv6) && e.EndpointTCP == "pass" &&
		(p.Domestic == (HostHealthTraceTarget{}) || e.DomesticVerified) && !mismatch && !canceled
	switch {
	case mismatch:
		e.Reason = "path_mismatch"
	case canceled:
		e.Reason = "round_canceled"
	case e.EndpointTCP != "pass":
		e.Reason = "endpoint_underlay_failed"
	case !e.IPv4.DirectVerified || e.IPv6.Enabled && !e.IPv6.DirectUnavailable && !e.IPv6.DirectVerified:
		e.Reason = "direct_egress_failed"
	case p.Domestic != (HostHealthTraceTarget{}) && !e.DomesticVerified:
		e.Reason = "domestic_underlay_failed"
	case !complete(e.IPv4):
		e.Reason = "selected_ipv4_failed"
	case !complete(e.IPv6):
		e.Reason = "selected_ipv6_failed"
	default:
		e.Reason = "healthy"
	}
	return e
}

func hostHealthSocketControl(device string, bypass bool) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
			if socketErr != nil {
				return
			}
			mark := 0
			if bypass {
				mark = int(nativeTUNBypassMark)
			}
			socketErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
		}); err != nil {
			return err
		}
		return socketErr
	}
}

func probeHostHealthEndpoint(parent context.Context, p hostHealthProbe) HostHealthResult {
	ctx, cancel := context.WithTimeout(parent, smartTUNHealthProbeTimeout)
	defer cancel()
	network := "tcp"
	address, port := p.address, p.port
	if p.role == "dns" {
		network = "udp"
	} else if p.role != "endpoint" {
		address, port = p.target.Address, p.target.Port
	}
	network += strconv.Itoa(p.family)
	dialer := net.Dialer{Timeout: smartTUNHealthProbeTimeout, Control: hostHealthSocketControl(p.device, p.bypass)}
	if p.source != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(p.source)}
	}
	connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		return HostHealthResult{Result: smartTUNHealthTransportFailure(ctx, err)}
	}
	return exchangeHostHealthConnection(ctx, connection, p, nil)
}
