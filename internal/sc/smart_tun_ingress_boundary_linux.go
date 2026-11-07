//go:build linux

package sc

import (
	"strconv"
	"strings"
)

// Input-only NOTRACK also prevents a reply from carrying conntrack direction.
// Therefore protect the union of exact PREROUTING dports and OUTPUT sports;
// never assume an absent OUTPUT rule establishes a tracked hosted session.
func strictHostIngressRawPorts(raw []byte) (map[uint16]bool, error) {
	if len(raw) == 0 || len(raw) > 64*1024 || strings.ContainsRune(string(raw), 0) {
		return nil, ingressFault("raw inventory unavailable or oversized")
	}
	ports := map[uint16]bool{}
	policies := map[string]bool{}
	rules := 0
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		w := strings.Fields(line)
		if len(w) == 3 && w[0] == "-P" && (w[1] == "PREROUTING" || w[1] == "OUTPUT") && w[2] == "ACCEPT" {
			if policies[w[1]] {
				return nil, ingressFault("duplicate raw policy")
			}
			policies[w[1]] = true
			continue
		}
		if len(w) != 10 && len(w) != 11 {
			return nil, ingressFault("unsupported foreign raw rule")
		}
		portKey := "--dport"
		if w[1] == "OUTPUT" {
			portKey = "--sport"
		}
		if w[0] != "-A" || (w[1] != "PREROUTING" && w[1] != "OUTPUT") || w[2] != "-p" || w[3] != "tcp" ||
			w[4] != "-m" || w[5] != "tcp" || w[6] != portKey || w[8] != "-j" ||
			!((len(w) == 10 && w[9] == "NOTRACK") || (len(w) == 11 && w[9] == "CT" && w[10] == "--notrack")) {
			return nil, ingressFault("foreign raw semantics cannot be verified")
		}
		port, err := strconv.ParseUint(w[7], 10, 16)
		if err != nil || port == 0 || strconv.FormatUint(port, 10) != w[7] || rules >= 256 {
			return nil, ingressFault("invalid or excessive raw NOTRACK port")
		}
		ports[uint16(port)] = true
		rules++
	}
	if len(policies) != 2 || len(ports) > 128 {
		return nil, ingressFault("incomplete or excessive raw inventory")
	}
	return ports, nil
}

func hostIngressMarkBoundary(r hostIngressStage) error {
	// Reuse the native RPDB conflict parser without granting any TUN identity
	// or allowing a preexisting native capture rule.
	record := smartTUNTrialJournal{UnderlayInterface: r.Underlay, TunnelInterface: "scingstage0",
		Native: &smartTUNNativeLedger{UnderlayIndex: r.UnderlayIndex,
			IPv4: smartTUNNativeFamily{Table: nativeTUNTable4, Address: "172.31.99.1/30"},
			IPv6: smartTUNNativeFamily{Table: nativeTUNTable6}}}
	for _, family := range []int{4, 6} {
		present, _, err := nativeTUNObserveResource(record, family, "rule")
		if err != nil {
			return err
		}
		if present {
			return ingressFault("reserved capture rule is occupied before ingress staging")
		}
	}
	raw, err := nativeTUNRunNFT(nil, nil, "-n", "-j", "-a", "list", "ruleset")
	if err != nil {
		return err
	}
	objects, err := nativeTUNNftObjects(raw)
	if err != nil {
		return err
	}
	if err := hostIngressForeignNATBoundary(r, objects); err != nil {
		return err
	}
	return hostIngressForeignNFTBoundary(r, record, objects)
}

// A foreign NAT rule is *never* inherited as an activation or rollback
// resource. During ingress-only preparation, accept as an observed foreign
// prerequisite only the exact independently cross-checked Docker bridge NAT
// grammar. A published Docker port, changed bridge, second NAT backend or
// unknown translation rule refuses before any ownership can be claimed.
// This is not a reservation: full-host Apply still needs a common journal,
// verified ingress/egress ordering and its own independently running guard.
func hostIngressForeignNATBoundary(r hostIngressStage, objects []map[string]any) error {
	return hostIngressForeignNATBoundaryWithLegacy(r, objects, observeHostLegacyPacketPolicy)
}

// The argument-local observer exercises the production boundary without
// requiring unit tests to inspect or modify a real legacy firewall.
func hostIngressForeignNATBoundaryWithLegacy(r hostIngressStage, objects []map[string]any,
	readLegacy func() (hostLegacyPacketSnapshot, error)) error {
	profile, err := generalHostForeignNFTEffects(objects)
	if err != nil {
		return ingressFault("foreign firewall inventory is ambiguous")
	}
	// nft absence cannot prove the independent legacy hooks are inert.
	// Inspect all registered IPv4/IPv6 legacy tables, even without Docker.
	if readLegacy == nil {
		return hostLegacyPolicyUnverified()
	}
	legacy, err := readLegacy()
	if err != nil {
		return err
	}
	if !strictEmptyLegacyRawPolicy(legacy.raw[0]) || !strictEmptyLegacyRawPolicy(legacy.raw[1]) || !strictEmptyLegacyNAT(legacy.nat4) {
		return hostLegacyPolicyUnverified()
	}
	if profile.ForeignNAT && !observeDockerNATShapeWithLegacy(objects, r.Underlay, legacy) {
		return Fault("foreign_nat_unverified", "unverified foreign NAT prevents host ingress preparation")
	}
	return nil
}
func hostIngressForeignNFTBoundary(r hostIngressStage, record smartTUNTrialJournal, objects []map[string]any) error {
	for _, item := range objects {
		for kind, value := range item {
			fields, ok := value.(map[string]any)
			if !ok {
				return ingressFault("invalid foreign nft object")
			}
			if fields["family"] == "inet" && ((kind == "table" && fields["name"] == "scin_"+r.OperationID) || (kind != "table" && fields["table"] == "scin_"+r.OperationID)) {
				continue
			}
			if kind == "flowtable" || nativeNFTForeignConflict(fields, record) {
				return ingressFault("foreign nft mark or offload effects conflict with ingress staging")
			}
			// A native NOTRACK or opaque CT outside the separately corroborated
			// iptables raw table is not explained by its textual inventory.
			if kind == "rule" {
				exprs, ok := fields["expr"].([]any)
				if !ok {
					return ingressFault("foreign rule expressions unavailable")
				}
				for _, value := range exprs {
					expr, ok := value.(map[string]any)
					if !ok {
						return ingressFault("foreign rule expression malformed")
					}
					if _, ok := expr["notrack"]; ok {
						return ingressFault("native NOTRACK owner is not covered by raw staging")
					}
					if xt, ok := expr["xt"].(map[string]any); ok && xt["type"] == "target" && xt["name"] == "CT" {
						if fields["table"] != "raw" || (fields["family"] != "ip" && fields["family"] != "ip6") ||
							(fields["chain"] != "PREROUTING" && fields["chain"] != "OUTPUT") {
							return ingressFault("opaque foreign conntrack target outside verified raw chains")
						}
					}
				}
			}
		}
	}
	return nil
}
