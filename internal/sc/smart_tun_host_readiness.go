package sc

import (
	"encoding/json"
	"net/netip"
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
	dns    func(string, string, string, int) (UnderlayDNSReport, error)
	tcp    func(string, int) (UnderlayTCPReport, error)
	routes func(string, string) (HostPreflight, error)
	nft    func() (HostFirewallObservation, error)
	proxy  func(*Manager) (string, error)
}

func defaultSmartTUNHostReadinessProbes() smartTUNHostReadinessProbes {
	return smartTUNHostReadinessProbes{
		dns:    InspectUnderlayDNS,
		tcp:    InspectUnderlayTCP,
		routes: InspectHostRoutes,
		nft:    observeNftables,
		proxy:  (*Manager).unitActive,
	}
}

// selectedSmartTUNHostEndpoint binds the operator's literal diagnostic IP to
// the actual selected outbound without publishing credentials or hostnames.
// Hostname DNS is separately checked via a fixed, interface-bound resolver;
// it never silently selects an arbitrary hostname answer for a TCP dial.
func selectedSmartTUNHostEndpoint(profile Profile, pinned netip.Addr) (kind, hostname string, port int, err error) {
	var outbound struct {
		Type       string `json:"type"`
		Server     string `json:"server"`
		ServerPort int    `json:"server_port"`
	}
	if json.Unmarshal(profile.Outbound, &outbound) != nil ||
		outbound.Type != "vless" || outbound.ServerPort < 1 || outbound.ServerPort > 65535 {
		return "", "", 0, Fault("trial_unsupported", "selected profile must have a valid VLESS TCP endpoint")
	}
	if literal, parseErr := netip.ParseAddr(outbound.Server); parseErr == nil {
		if literal != pinned {
			return "", "", 0, Fault("underlay_name_mismatch", "operator-pinned IP differs from selected literal endpoint")
		}
		return "ipv4", "", outbound.ServerPort, nil
	}
	hostname, err = validateEndpointHostname(outbound.Server)
	if err != nil {
		return "", "", 0, Fault("trial_unsupported", "selected endpoint hostname is not supported")
	}
	return "hostname", hostname, outbound.ServerPort, nil
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
	kind, hostname, port, endpointErr := selectedSmartTUNHostEndpoint(profile, ip)
	if endpointErr != nil {
		add("selected_endpoint_not_pinned")
		return result, nil
	}
	result.SelectedTransport, result.EndpointKind = "vless", kind
	if (kind == "hostname" && resolverIP == "") || (kind == "ipv4" && resolverIP != "") {
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
		observation, dnsErr := p.dns(hostname, ip.String(), resolverIP, resolverPort)
		if dnsErr == nil && observation.NameMatched && observation.InterfaceBound && observation.RouteStable &&
			observation.ResolverRouteDevice == underlayInterface && !observation.ActivationReady {
			result.DNS, dnsOK = "pinned_resolver_observed", true
		} else {
			result.DNS = "unavailable_or_wrong_underlay"
			add("endpoint_dns_unverified")
		}
	}
	if dnsOK {
		observation, tcpErr := p.tcp(ip.String(), port)
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
		network.Endpoint != nil && network.ManagementPeer != nil {
		result.HostRoutes = "endpoint_and_management_observed"
	} else {
		result.HostRoutes = "unavailable"
		add("host_routes_unverified")
	}
	firewall, nftErr := p.nft()
	if nftErr == nil && firewall.Observed {
		result.NativeNFT = "ruleset_observed"
	} else {
		result.NativeNFT = "unavailable"
		add("native_nft_unavailable")
	}
	// This diagnostic cannot authenticate the SSH session, reserve nftables
	// ownership or establish an independent health/recovery guard. Do not
	// infer admission from an empty list of other findings.
	add("general_host_admission_not_implemented")
	return result, nil
}
