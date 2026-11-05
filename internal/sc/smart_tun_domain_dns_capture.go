package sc

// SmartTUNDNSCapture is the deterministic native-integration contract for a
// DNS-correlated compiler result. It is required policy input, not evidence
// that the host has actually captured DNS or reserved these synthetic pools.
type SmartTUNDNSCapture struct {
	NameSource            string   `json:"name_source"`
	IPv4Pool              string   `json:"ipv4_pool"`
	IPv6Pool              string   `json:"ipv6_pool,omitempty"`
	DNSPort               int      `json:"dns_port"`
	DNSNetworks           []string `json:"dns_networks"`
	HijackBeforeProtected bool     `json:"hijack_before_protected"`
	RealIPReverseMapping  bool     `json:"real_ip_reverse_mapping"`
	ActivationReady       bool     `json:"activation_ready"`
}

func SmartTUNDomainDNSCapture(o SmartTUNCandidateOptions) SmartTUNDNSCapture {
	result := SmartTUNDNSCapture{NameSource: "operation_owned_core_fakeip_map", IPv4Pool: SmartTUNDomainFakeIPv4,
		DNSPort: 53, DNSNetworks: []string{"tcp", "udp"}, HijackBeforeProtected: true}
	if o.TunnelIPv6 != "" {
		result.IPv6Pool = SmartTUNDomainFakeIPv6
	}
	return result
}
