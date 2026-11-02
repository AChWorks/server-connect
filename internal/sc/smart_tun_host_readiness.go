package sc

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
)

// SmartTUNHostReadiness is a read-only diagnostic bound to the selected saved
// outbound. It is NOT an admission token, an activation plan, or a guarantee
// that a real host can be protected by the experimental VM-only guard.
type SmartTUNHostReadiness struct {
	Mode                string   `json:"mode"`
	ReadOnly            bool     `json:"read_only"`
	ActivationReady     bool     `json:"activation_ready"`
	GeneralHostAdmitted bool     `json:"general_host_admitted"`
	SelectedTransport   string   `json:"selected_transport,omitempty"`
	EndpointKind        string   `json:"endpoint_kind,omitempty"`
	DNS                 string   `json:"dns"`
	TCP                 string   `json:"tcp"`
	HostRoutes          string   `json:"host_routes"`
	NativeNFT           string   `json:"native_nft"`
	ProxyOnly           string   `json:"proxy_only"`
	Reasons             []string `json:"reasons"`
	Limitations         []string `json:"limitations"`
}

type smartTUNHostReadinessProbes struct {
	dns    func(string, string, string, int, string) (UnderlayDNSReport, error)
	tcp    func(string, int, string) (UnderlayTCPReport, error)
	routes func(string, string) (HostPreflight, error)
	nft    func() (HostFirewallObservation, error)
	proxy  func(*Manager) (string, error)
}

func defaultSmartTUNHostReadinessProbes() smartTUNHostReadinessProbes {
	return smartTUNHostReadinessProbes{
		dns:    inspectUnderlayDNSOnDevice,
		tcp:    inspectUnderlayTCPOnDevice,
		routes: InspectHostRoutes,
		nft:    observeNftables,
		proxy:  (*Manager).unitActive,
	}
}

// supportedSelectedTransport validates the selected TCP transport's known
// sing-box 1.14 fields. Importing arbitrary outbound JSON is permitted by
// profile storage, so recognizing a type string alone is insufficient.
func supportedSelectedTransport(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "tcp", true
	}
	var t struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &t) != nil {
		return "", false
	}
	var shape any
	switch t.Type {
	case "ws":
		shape = &struct {
			Type                string          `json:"type"`
			Path                string          `json:"path"`
			Headers             json.RawMessage `json:"headers"`
			MaxEarlyData        uint32          `json:"max_early_data"`
			EarlyDataHeaderName string          `json:"early_data_header_name"`
		}{}
	case "httpupgrade":
		shape = &struct {
			Type    string          `json:"type"`
			Host    string          `json:"host"`
			Path    string          `json:"path"`
			Headers json.RawMessage `json:"headers"`
		}{}
	case "http":
		shape = &struct {
			Type        string          `json:"type"`
			Host        json.RawMessage `json:"host"`
			Path        string          `json:"path"`
			Method      string          `json:"method"`
			Headers     json.RawMessage `json:"headers"`
			IdleTimeout string          `json:"idle_timeout"`
			PingTimeout string          `json:"ping_timeout"`
		}{}
	default:
		// QUIC is UDP; gRPC is unavailable in the bundled default core.
		return "", false
	}
	// Reject malformed/unknown transport options rather than treating an
	// unparseable selected stream as a known usable TCP-based transport.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(shape) != nil {
		return "", false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return "", false
	}
	if v, has := fields["host"]; has && t.Type == "http" && !validTransportStringList(v) {
		return "", false
	}
	if v, has := fields["headers"]; has {
		var headers map[string]json.RawMessage
		if json.Unmarshal(v, &headers) != nil || headers == nil {
			return "", false
		}
		for _, values := range headers {
			if !validTransportStringList(values) {
				return "", false
			}
		}
	}
	return t.Type, true
}

// String lists in the pinned sing-box transport schema can be represented
// by a string or an array of strings. Never accept numbers or object values.
func validTransportStringList(raw json.RawMessage) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil && string(raw) != "null" {
		return true
	}
	var many []string
	return json.Unmarshal(raw, &many) == nil && many != nil
}

// selectedSmartTUNHostEndpoint binds the selected VLESS endpoint to a known
// TCP-based transport without exposing its credential or hostname. QUIC/UDP
// and explicit alternate dial-path selectors cannot inherit TCP evidence.
func selectedSmartTUNHostEndpoint(profile Profile, pinned netip.Addr) (kind, hostname, transport string, port int, err error) {
	var outbound struct {
		Type       string          `json:"type"`
		Server     string          `json:"server"`
		ServerPort int             `json:"server_port"`
		Network    string          `json:"network"`
		Transport  json.RawMessage `json:"transport"`
	}
	unsupported := func() (string, string, string, int, error) {
		return "", "", "", 0, Fault("selected_transport_unsupported", "selected VLESS transport or alternate dial path is not supported by the TCP diagnostic")
	}
	if json.Unmarshal(profile.Outbound, &outbound) != nil ||
		outbound.Type != "vless" || outbound.ServerPort < 1 || outbound.ServerPort > 65535 ||
		(outbound.Network != "" && outbound.Network != "tcp") {
		return unsupported()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(profile.Outbound, &fields) != nil {
		return unsupported()
	}
	// These sing-box Dial Fields can independently redirect, mark, bind or
	// resolve the selected outbound. Ignore absent/default-valued fields,
	// but never silently claim equivalence when a path selector is enabled.
	for _, key := range []string{
		"detour", "bind_interface", "inet4_bind_address", "inet6_bind_address",
		"routing_mark", "netns", "domain_resolver", "domain_strategy",
		"network_strategy", "network_type", "fallback_network_type",
		"fallback_delay", "bind_address_no_port", "tcp_multi_path",
	} {
		if raw, ok := fields[key]; ok {
			switch strings.TrimSpace(string(raw)) {
			case "null", `""`, "0", "false", "[]":
				// No effective alternative path requested.
			default:
				return unsupported()
			}
		}
	}
	transport, ok := supportedSelectedTransport(outbound.Transport)
	if !ok {
		return unsupported()
	}
	if literal, parseErr := netip.ParseAddr(outbound.Server); parseErr == nil {
		if literal != pinned {
			return "", "", "", 0, Fault("underlay_name_mismatch", "operator-pinned IP differs from selected literal endpoint")
		}
		return "ipv4", "", transport, outbound.ServerPort, nil
	}
	hostname, err = validateEndpointHostname(outbound.Server)
	if err != nil {
		return "", "", "", 0, Fault("trial_unsupported", "selected endpoint hostname is not supported")
	}
	return "hostname", hostname, transport, outbound.ServerPort, nil
}

// A route lookup is useful only when it is for the exact requested address
// and actually selects the operator's expected underlay. Its existence
// alone cannot prove that an SSH/hosting reply survives future interception.
func selectedHostRouteOnUnderlay(lookup *HostRouteLookup, ip netip.Addr, underlay string) bool {
	if lookup == nil || lookup.Target != ip.String() {
		return false
	}
	family := "ipv4"
	if ip.Is6() {
		family = "ipv6"
	}
	if lookup.Family != family {
		return false
	}
	var rows []struct {
		Dst  string `json:"dst"`
		Dev  string `json:"dev"`
		Type string `json:"type"`
	}
	if json.Unmarshal(lookup.KernelRoute, &rows) != nil || len(rows) != 1 {
		return false
	}
	return rows[0].Dst == ip.String() && rows[0].Dev == underlay &&
		(rows[0].Type == "" || rows[0].Type == "unicast")
}

func (m *Manager) InspectSelectedSmartTUNHost(pinnedIP, managementPeer, underlayInterface, resolverIP string, resolverPort int) (SmartTUNHostReadiness, error) {
	return m.inspectSelectedSmartTUNHostWith(pinnedIP, managementPeer, underlayInterface, resolverIP, resolverPort,
		defaultSmartTUNHostReadinessProbes())
}

// All expected failed checks are structured findings, not successful
// admission. Command success means this non-atomic diagnostic completed.
func (m *Manager) inspectSelectedSmartTUNHostWith(pinnedIP, managementPeer, underlayInterface, resolverIP string, resolverPort int, p smartTUNHostReadinessProbes) (SmartTUNHostReadiness, error) {
	ip, err := validateUnderlayTCPArgs(pinnedIP, 443)
	if err != nil || !ip.Is4() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		overlapsSpecialPurpose(netip.PrefixFrom(ip, 32)) {
		return SmartTUNHostReadiness{}, Fault("invalid_arguments", "selected host check requires an explicit public IPv4 diagnostic pin")
	}
	peer, err := parsePreflightAddress(managementPeer, "management peer")
	if err != nil || !peer.IsValid() {
		return SmartTUNHostReadiness{}, Fault("invalid_arguments", "selected host check requires a literal management peer")
	}
	if !smartTUNDeviceName.MatchString(underlayInterface) || resolverPort < 1 || resolverPort > 65535 {
		return SmartTUNHostReadiness{}, Fault("invalid_arguments", "invalid expected interface or DNS port")
	}
	if resolverIP != "" {
		resolver, resolverErr := parsePreflightAddress(resolverIP, "resolver")
		if resolverErr != nil || !resolver.Is4() {
			return SmartTUNHostReadiness{}, Fault("invalid_arguments", "resolver must be a literal IPv4 address")
		}
	}
	result := SmartTUNHostReadiness{
		Mode: "selected_host_readiness", ReadOnly: true,
		DNS: "not_checked", TCP: "not_checked", HostRoutes: "not_checked",
		NativeNFT: "not_checked", ProxyOnly: "not_checked",
		Reasons: []string{}, Limitations: []string{
			"Physical-host native Apply is not admitted; no activation authorization is issued.",
			"Selected TCP is not authenticated VPN transport, TLS or live TUN health.",
			"DNS and network snapshots are not atomic, do not protect foreign SSH/hosting replies, and do not prove bootstrap after TUN activation.",
			"Independent activation/runtime guards and exact native ownership remain separately unverified.",
		},
	}
	add := func(code string) { result.Reasons = append(result.Reasons, code) }
	state, stateErr := m.load()
	if stateErr != nil || state.Selected == "" {
		add("selected_profile_unavailable")
		return result, nil
	}
	if state.Desired != "direct" {
		add("product_not_direct")
		return result, nil
	}
	profile, profileErr := m.profile(state.Selected)
	if profileErr != nil {
		add("selected_profile_unavailable")
		return result, nil
	}
	kind, hostname, transport, port, endpointErr := selectedSmartTUNHostEndpoint(profile, ip)
	if endpointErr != nil {
		if ErrorCode(endpointErr) == "selected_transport_unsupported" {
			add("selected_transport_unsupported")
		} else {
			add("selected_endpoint_not_pinned")
		}
		return result, nil
	}
	result.SelectedTransport, result.EndpointKind = transport, kind
	if (kind == "hostname" && resolverIP == "") || (kind == "ipv4" && (resolverIP != "" || resolverPort != 53)) {
		return SmartTUNHostReadiness{}, Fault("invalid_arguments", "hostname requires an explicit resolver; literal endpoint requires none")
	}
	if p.proxy == nil || p.dns == nil || p.tcp == nil || p.routes == nil || p.nft == nil {
		return SmartTUNHostReadiness{}, Fault("trial_unsupported", "incomplete host readiness probes")
	}
	activity, proxyErr := p.proxy(m)
	if proxyErr != nil || activity != "inactive" {
		result.ProxyOnly = "unavailable_or_active"
		add("proxy_not_inactive")
	} else {
		result.ProxyOnly = "inactive_observed"
	}
	dnsOK := kind == "ipv4"
	if dnsOK {
		result.DNS = "literal_endpoint"
	} else {
		observation, dnsErr := p.dns(hostname, ip.String(), resolverIP, resolverPort, underlayInterface)
		if dnsErr == nil && observation.NameMatched && observation.InterfaceBound && observation.RouteStable &&
			observation.ResolverRouteDevice == underlayInterface && !observation.ActivationReady {
			result.DNS, dnsOK = "pinned_resolver_observed", true
		} else {
			result.DNS = "unavailable_or_wrong_underlay"
			add("endpoint_dns_unverified")
		}
	}
	if dnsOK {
		observation, tcpErr := p.tcp(ip.String(), port, underlayInterface)
		if tcpErr == nil && observation.SocketConnected && observation.InterfaceBound && observation.RouteStable &&
			observation.RouteDevice == underlayInterface && !observation.ActivationReady {
			result.TCP = "bound_tcp_connected"
		} else {
			result.TCP = "unavailable_or_wrong_underlay"
			add("selected_tcp_unverified")
		}
	}
	network, networkErr := p.routes(ip.String(), peer.String())
	if networkErr == nil && network.Mode != "" && network.ReadOnly && !network.ActivationReady &&
		selectedHostRouteOnUnderlay(network.Endpoint, ip, underlayInterface) &&
		selectedHostRouteOnUnderlay(network.ManagementPeer, peer, underlayInterface) {
		result.HostRoutes = "endpoint_and_management_on_expected_underlay"
	} else {
		result.HostRoutes = "unavailable_or_wrong_underlay"
		add("host_routes_unverified")
	}
	firewall, nftErr := p.nft()
	if nftErr == nil && firewall.Observed {
		result.NativeNFT = "ruleset_observed"
	} else {
		result.NativeNFT = "unavailable"
		add("native_nft_unavailable")
	}
	// A previously inactive Proxy Only service can start during the
	// non-atomic network observations. Do not end with a stale inactive claim.
	finalActivity, finalProxyErr := p.proxy(m)
	if finalProxyErr != nil || finalActivity != activity {
		result.ProxyOnly = "changed_or_unavailable"
		add("proxy_state_changed_during_diagnostic")
	}
	// A profile selection or outbound may change during multiple non-atomic
	// network observations. Refuse to present stale evidence as observations
	// of the CURRENT selected profile. This is not an atomic reservation.
	current, currentErr := m.load()
	if currentErr != nil || current != state {
		add("selected_profile_changed_during_diagnostic")
	} else if selectedNow, selectedErr := m.profile(current.Selected); selectedErr != nil ||
		!bytes.Equal(selectedNow.Outbound, profile.Outbound) {
		add("selected_profile_changed_during_diagnostic")
	}
	// This diagnostic cannot authenticate the SSH session, reserve nftables
	// ownership or establish an independent health/recovery guard. Do not
	// infer admission from an empty list of other findings.
	add("general_host_admission_not_implemented")
	return result, nil
}
