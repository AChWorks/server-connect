//go:build linux

package sc

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
)

// SmartTUNHostBoundary is an operator-facing, read-only gap assessment.
// None of the observations, individually or combined, issues an Apply token.
// In particular a same-host SSH command never proves independent console
// recovery, protected hosted replies or a real selected VPN exit.
type SmartTUNHostBoundary struct {
	Mode                string   `json:"mode"`
	ReadOnly            bool     `json:"read_only"`
	GeneralHostAdmitted bool     `json:"general_host_admitted"`
	ActivationReady     bool     `json:"activation_ready"`
	InstalledTarget     string   `json:"installed_target"`
	NativePlatform      string   `json:"native_platform"`
	SSHReturnPath       string   `json:"ssh_return_path"`
	InterfaceInventory  string   `json:"interface_inventory"`
	IPv4Policy          string   `json:"ipv4_policy"`
	IPv6Policy          string   `json:"ipv6_policy"`
	ForeignNFT          string   `json:"foreign_nft"`
	DockerNATShape      string   `json:"docker_nat_shape"`
	HostedReplySessions string   `json:"hosted_reply_sessions"`
	HostedReplyScope    string   `json:"hosted_reply_scope"`
	TCPMarkInheritance  string   `json:"tcp_mark_inheritance"`
	OutOfBandRecovery   string   `json:"out_of_band_recovery"`
	Reasons             []string `json:"reasons"`
	Limitations         []string `json:"limitations"`
}

type smartTUNHostBoundaryObservations struct {
	target              string
	targetErr           error
	sshPath             generalHostSSHPath
	sshErr              error
	links               json.RawMessage
	linksErr            error
	ipv4Rules           json.RawMessage
	ipv4RulesErr        error
	ipv6Err             error
	nft                 []map[string]any
	nftErr              error
	dockerNATShape      string
	hostedReplySessions string
	hostedReplyErr      error
	markBefore          int
	markBeforeErr       error
	markAfter           int
	markAfterErr        error
}

// Distinguish foreign owners for operator diagnosis without granting them
// any mutation authority or weakening native Apply's fail-closed firewall
// validation. Opaque OUTPUT conntrack targets may break hosting replies.
type generalHostNFTProfile struct {
	PacketEffects       int
	OpaqueOutputCT      bool
	ForeignNAT          bool
	OutputXTCTCount     int
	NativeOutputNotrack bool
}

type generalHostNFTChainKey struct{ Family, Table, Name string }

func generalHostNFTObjectText(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}

func generalHostForeignNFTEffects(objects []map[string]any) (generalHostNFTProfile, error) {
	var result generalHostNFTProfile
	if objects == nil {
		return result, errors.New("nft inventory unavailable")
	}
	hooks := map[generalHostNFTChainKey]string{}
	// An unknown extension target in a NAT chain must fail closed even if
	// its name is not one of the familiar SNAT/DNAT/MASQUERADE spellings.
	// Docker's user chain lacks a base-chain type; ip/nat table membership
	// independently binds its nested rules to NAT semantics.
	natChains := map[generalHostNFTChainKey]bool{}
	for _, item := range objects {
		if len(item) != 1 {
			return result, errors.New("ambiguous foreign nft object")
		}
		value, isChain := item["chain"]
		if !isChain {
			continue
		}
		fields, ok := value.(map[string]any)
		if !ok {
			return result, errors.New("invalid foreign nft chain")
		}
		key := generalHostNFTChainKey{
			Family: generalHostNFTObjectText(fields, "family"),
			Table:  generalHostNFTObjectText(fields, "table"),
			Name:   generalHostNFTObjectText(fields, "name"),
		}
		if key.Family == "" || key.Table == "" || key.Name == "" {
			return result, errors.New("incomplete foreign nft chain identity")
		}
		if _, exists := hooks[key]; exists {
			return result, errors.New("duplicate foreign nft chain")
		}
		hooks[key] = generalHostNFTObjectText(fields, "hook")
		if fields["type"] == "nat" || key.Table == "nat" {
			natChains[key] = true
		}
	}
	for _, item := range objects {
		for kind, value := range item {
			fields, ok := value.(map[string]any)
			if !ok {
				return result, errors.New("invalid foreign nft object")
			}
			switch kind {
			case "flowtable":
				result.PacketEffects++
			case "rule":
				key := generalHostNFTChainKey{
					Family: generalHostNFTObjectText(fields, "family"),
					Table:  generalHostNFTObjectText(fields, "table"),
					Name:   generalHostNFTObjectText(fields, "chain"),
				}
				hook, present := hooks[key]
				if !present {
					return result, errors.New("foreign nft rule lacks a bound chain")
				}
				if natChains[key] && !nativeNFTForeignRulePassive(fields) {
					result.ForeignNAT = true
				}
				expressions, ok := fields["expr"].([]any)
				if !ok || len(expressions) == 0 {
					return result, errors.New("foreign nft rule expressions unavailable")
				}
				for _, raw := range expressions {
					expr, ok := raw.(map[string]any)
					if !ok || len(expr) != 1 {
						return result, errors.New("ambiguous foreign nft expression")
					}
					if _, notrack := expr["notrack"]; notrack && hook == "output" {
						result.OpaqueOutputCT = true
						result.NativeOutputNotrack = true
					}
					if xt, ok := expr["xt"].(map[string]any); ok {
						if xt["type"] == "target" && xt["name"] == "CT" && hook == "output" {
							result.OpaqueOutputCT = true
							result.OutputXTCTCount++
						}
						if xt["type"] == "target" && (xt["name"] == "MASQUERADE" ||
							xt["name"] == "SNAT" || xt["name"] == "DNAT" || xt["name"] == "REDIRECT") {
							result.ForeignNAT = true
						}
					}
					for _, word := range []string{"masquerade", "snat", "dnat", "redirect"} {
						if _, present := expr[word]; present {
							result.ForeignNAT = true
						}
					}
				}
				if !nativeNFTForeignRulePassive(fields) {
					result.PacketEffects++
				}
			case "chain":
				// A drop policy can change traffic even if the chain is empty.
				if policy, present := fields["policy"]; present && policy != "accept" {
					result.PacketEffects++
					if fields["type"] == "nat" || fields["table"] == "nat" {
						result.ForeignNAT = true
					}
				}
			}
		}
	}
	return result, nil
}

// No address/port, profile, firewall expression or credential is ever copied
// into a report. A valid result is a list of *remaining gates*, not a PASS.
func assessSmartTUNHostBoundary(o smartTUNHostBoundaryObservations, expectedUnderlay string) SmartTUNHostBoundary {
	r := SmartTUNHostBoundary{
		Mode: "general_host_boundary_observation", ReadOnly: true,
		InstalledTarget: "unavailable", NativePlatform: "unsupported_or_unverified",
		SSHReturnPath: "unverified", InterfaceInventory: "unverified",
		IPv4Policy: "unverified", IPv6Policy: "unverified",
		ForeignNFT: "unverified", DockerNATShape: dockerNATAbsent, HostedReplySessions: hostRepliesUnverified,
		HostedReplyScope:   "ipv4_af_inet_tcp_only",
		TCPMarkInheritance: "unverified", OutOfBandRecovery: "not_verified",
		Reasons: []string{}, Limitations: []string{
			"A fresh authenticated SSH transport is not proved by this passive kernel route observation.",
			"An SSH session is not an independent provider-console rescue or host rollback channel.",
			"Non-atomic kernel observations cannot reserve foreign routes, conntrack, hosting replies or firewall state.",
			"Safe native Apply, owned-resource rollback, health supervision and selected-VPN egress still require independent evidence.",
			"Hosted-reply diagnostics observe AF_INET IPv4 TCP only; IPv6 and IPv4-mapped AF_INET6 sockets are not inventoried. No snapshot reserves socket generations or protects tuple reuse.",
		},
	}
	add := func(code string) { r.Reasons = append(r.Reasons, code) }
	// A shared host's tcp_fwmark_accept is not a CAS-owned resource. The
	// general-host ingress stage may use only an already-enabled setting.
	// Reobserve it after other slow, non-atomic kernel probes: even a transient
	// 1->0->1 remains beyond the authority of this diagnostic to accept.
	switch {
	case o.markBeforeErr != nil || o.markAfterErr != nil ||
		(o.markBefore != 0 && o.markBefore != 1) ||
		(o.markAfter != 0 && o.markAfter != 1):
		add("tcp_fwmark_accept_unverified")
	case o.markBefore != o.markAfter:
		r.TCPMarkInheritance = "changed_during_observation"
		add("tcp_fwmark_accept_changed_during_observation")
	case o.markBefore == 0:
		r.TCPMarkInheritance = "disabled_operator_prerequisite"
		add("tcp_fwmark_accept_preexisting_enabled_required")
	default:
		r.TCPMarkInheritance = "enabled_observed_only"
	}
	if o.targetErr == nil && o.target != "" {
		r.InstalledTarget = o.target
		if o.target == "debian-13-amd64" {
			r.NativePlatform = "debian13_experimental_native_candidate"
		}
	}
	if r.NativePlatform == "unsupported_or_unverified" {
		add("native_apply_platform_not_supported")
	}
	if o.sshErr == nil && o.sshPath.Interface == expectedUnderlay &&
		o.sshPath.Index > 1 && o.sshPath.Peer.Is4() && o.sshPath.Local.Is4() {
		r.SSHReturnPath = "single_source_route_observed"
	} else {
		add("ssh_return_path_not_verified")
	}
	if o.linksErr == nil {
		rows, err := selectiveRows(o.links)
		if err == nil && len(rows) >= 2 {
			names := make(map[string]bool, len(rows))
			unique := make(map[int]bool, len(rows))
			valid := true
			for _, row := range rows {
				n := selectiveText(row["ifname"])
				idx, ok := selectiveInt(row["ifindex"])
				if !ok || idx < 1 || !smartTUNDeviceName.MatchString(n) ||
					names[n] || unique[idx] || (n == "lo") != (idx == 1) {
					valid = false
					break
				}
				names[n], unique[idx] = true, true
			}
			if valid && names["lo"] && names[expectedUnderlay] && len(rows) == 2 {
				r.InterfaceInventory = "loopback_and_single_underlay_observed"
			} else if valid && names["lo"] && names[expectedUnderlay] {
				r.InterfaceInventory = "additional_interfaces_present"
				add("foreign_interface_coexistence_unverified")
			}
		}
	}
	if r.InterfaceInventory == "unverified" {
		add("interface_inventory_unverified")
	}

	if o.ipv4RulesErr == nil && smartTUNVMIngressDefaultRulesValid(o.ipv4Rules) {
		r.IPv4Policy = "kernel_default_rules_observed"
	} else {
		add("foreign_ipv4_policy_unverified")
	}
	if o.ipv6Err == nil {
		r.IPv6Policy = "local_only_routes_observed"
	} else {
		r.IPv6Policy = "public_indirect_or_unverified"
		add("public_ipv6_without_supported_tun")
	}
	if o.nftErr == nil {
		risk, err := generalHostForeignNFTEffects(o.nft)
		if err == nil {
			if risk.OpaqueOutputCT {
				add("foreign_output_conntrack_opaque")
				// Even a zero-match socket snapshot cannot grant safety:
				// an old four-tuple can be reused by a new socket generation.
				// A static tuple bypass would then silently exempt new traffic.
				add("untracked_reply_socket_generation_not_reserved")
				if o.hostedReplyErr == nil && o.hostedReplySessions != "" {
					r.HostedReplySessions = o.hostedReplySessions
				}
				if r.HostedReplySessions == hostRepliesPresent {
					add("preexisting_untracked_hosted_reply_sessions")
				} else if r.HostedReplySessions == hostRepliesUnverified {
					add("untracked_hosted_reply_sessions_unverified")
				}
			} else {
				r.HostedReplySessions = hostRepliesNoXT
			}
			if risk.ForeignNAT {
				// A static Docker NAT signature can help identify the actual
				// owner, but it never proves future changes, ingress/hosting
				// protection or final-egress guard coexistence. Preserve the
				// foreign-NAT activation blocker even when the shape matches.
				r.DockerNATShape = dockerNATUnverified
				if o.dockerNATShape == dockerNATObservedShape {
					r.DockerNATShape = dockerNATObservedShape
				}
				add("foreign_nat_ownership_unverified")
			}
			if risk.PacketEffects == 0 {
				r.ForeignNFT = "no_foreign_packet_effects_observed"
			} else {
				r.ForeignNFT = "foreign_packet_effects_present"
				add("foreign_nft_coexistence_unverified")
			}
		}
	}
	if r.ForeignNFT == "unverified" {
		add("foreign_nft_unverified")
	}
	add("out_of_band_recovery_not_verified")
	add("general_host_admission_not_implemented")
	return r
}

// InspectSmartTUNHostBoundary performs NO application/systemd/route/rule/nft
// mutation, attempts no VPN, and requires no selected profile. It is usable
// on an already installed Linux host before deciding whether field testing is
// even safe. Failure of any native observer is reported as an explicit gate.
func InspectSmartTUNHostBoundary(managementPeer, underlay string) (SmartTUNHostBoundary, error) {
	peer, e := netip.ParseAddr(managementPeer)
	if e != nil || !plausibleHostManagementAddress(peer) ||
		!smartTUNDeviceName.MatchString(underlay) || underlay == "lo" {
		return SmartTUNHostBoundary{}, Fault("invalid_arguments", "host boundary requires an explicit valid IPv4 SSH peer and underlay")
	}
	if os.Geteuid() != 0 {
		return SmartTUNHostBoundary{}, Fault("invalid_arguments", "host boundary needs privileged read-only kernel inspection")
	}
	o := smartTUNHostBoundaryObservations{}
	o.markBefore, o.markBeforeErr = readHostIngressSysctl()
	o.target, o.targetErr = currentInstallerHostTarget()
	o.sshPath, o.sshErr = observeGeneralHostSSHPath(managementPeer, underlay)
	o.links, o.linksErr = nativeIPJSON("-j", "link", "show")
	o.ipv4Rules, o.ipv4RulesErr = nativeIPJSON("-j", "-4", "rule", "show")
	o.ipv6Err = nativeIPv4OnlyIPv6Current(nativeIPJSON)
	var nftRaw []byte
	nftRaw, o.nftErr = nativeTUNRunNFT(nil, nil, "-n", "-j", "-a", "list", "ruleset")
	if o.nftErr == nil {
		o.nft, o.nftErr = nativeTUNNftObjects(nftRaw)
		if o.nftErr == nil {
			if risk, err := generalHostForeignNFTEffects(o.nft); err == nil && risk.ForeignNAT {
				if observeDockerNATShape(o.nft, underlay) {
					o.dockerNATShape = dockerNATObservedShape
				}
			}
			if risk, err := generalHostForeignNFTEffects(o.nft); err == nil && risk.OpaqueOutputCT {
				if risk.OutputXTCTCount > 0 && !risk.NativeOutputNotrack {
					o.hostedReplySessions, o.hostedReplyErr = observeExistingHostReplySessions(risk.OutputXTCTCount)
				}
			}
		}
	}
	o.markAfter, o.markAfterErr = readHostIngressSysctl()
	return assessSmartTUNHostBoundary(o, underlay), nil
}
