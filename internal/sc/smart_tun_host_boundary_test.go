//go:build linux

package sc

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func hostBoundaryFixture() smartTUNHostBoundaryObservations {
	return smartTUNHostBoundaryObservations{
		target:     "debian-13-amd64",
		markBefore: 1, markAfter: 1,
		sshPath: generalHostSSHPath{Interface: "ens3", Index: 2,
			Local: netip.MustParseAddr("10.20.30.40"), Peer: netip.MustParseAddr("8.8.8.8")},
		links:     json.RawMessage(`[{"ifindex":1,"ifname":"lo"},{"ifindex":2,"ifname":"ens3"}]`),
		ipv4Rules: json.RawMessage(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`),
		nft:       []map[string]any{},
	}
}

func hostNFTFixture(hook string, expressions ...any) []map[string]any {
	return []map[string]any{
		{"table": map[string]any{"family": "ip", "name": "foreign"}},
		{"chain": map[string]any{"family": "ip", "table": "foreign", "name": "C", "hook": hook, "type": "filter", "prio": 0, "policy": "accept"}},
		{"rule": map[string]any{"family": "ip", "table": "foreign", "chain": "C", "expr": expressions}},
	}
}

func TestGeneralHostBoundaryNeverAdmitsNormalOrUntrustedHost(t *testing.T) {
	base := hostBoundaryFixture()
	cases := []struct {
		name   string
		mutate func(*smartTUNHostBoundaryObservations)
		want   string
		field  string
	}{
		{"clean", func(*smartTUNHostBoundaryObservations) {}, "general_host_admission_not_implemented", ""},
		{"debian12", func(o *smartTUNHostBoundaryObservations) { o.target = "debian-12-amd64" }, "native_apply_platform_not_supported", "native_platform"},
		{"unknownOS", func(o *smartTUNHostBoundaryObservations) { o.targetErr = errors.New("no identity") }, "native_apply_platform_not_supported", "native_platform"},
		{"SSHrouteUnverified", func(o *smartTUNHostBoundaryObservations) { o.sshErr = errors.New("source changed") }, "ssh_return_path_not_verified", "ssh_return_path"},
		{"unexpectedPeer", func(o *smartTUNHostBoundaryObservations) { o.sshPath.Peer = netip.Addr{} }, "ssh_return_path_not_verified", "ssh_return_path"},
		{"foreignDockerLink", func(o *smartTUNHostBoundaryObservations) {
			o.links = json.RawMessage(`[{"ifindex":1,"ifname":"lo"},{"ifindex":2,"ifname":"ens3"},{"ifindex":3,"ifname":"docker0"}]`)
		}, "foreign_interface_coexistence_unverified", "interface_inventory"},
		{"missingLink", func(o *smartTUNHostBoundaryObservations) { o.links = json.RawMessage(`[{"ifindex":1,"ifname":"lo"}]`) }, "interface_inventory_unverified", "interface_inventory"},
		{"duplicateLink", func(o *smartTUNHostBoundaryObservations) {
			o.links = json.RawMessage(`[{"ifindex":1,"ifname":"lo"},{"ifindex":2,"ifname":"ens3"},{"ifindex":2,"ifname":"docker0"}]`)
		}, "interface_inventory_unverified", "interface_inventory"},
		{"badNetlink", func(o *smartTUNHostBoundaryObservations) { o.linksErr = errors.New("ip failed") }, "interface_inventory_unverified", "interface_inventory"},
		{"foreignPolicy", func(o *smartTUNHostBoundaryObservations) {
			o.ipv4Rules = json.RawMessage(`[{"priority":0,"src":"all","table":"local"},{"priority":100,"src":"all","table":"100"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`)
		}, "foreign_ipv4_policy_unverified", "ipv4_policy"},
		{"IPv6public", func(o *smartTUNHostBoundaryObservations) { o.ipv6Err = errors.New("public route") }, "public_ipv6_without_supported_tun", "ipv6_policy"},
		{"missingNFT", func(o *smartTUNHostBoundaryObservations) { o.nftErr = errors.New("nft unavailable"); o.nft = nil }, "foreign_nft_unverified", "foreign_nft"},
		{"DockerNAT", func(o *smartTUNHostBoundaryObservations) {
			o.nft = hostNFTFixture("postrouting", map[string]any{"masquerade": nil})
		}, "foreign_nft_coexistence_unverified", "foreign_nft"},
		{"opaqueXT", func(o *smartTUNHostBoundaryObservations) {
			o.nft = hostNFTFixture("output", map[string]any{"xt": map[string]any{"name": "CT", "type": "target"}})
		}, "foreign_nft_coexistence_unverified", "foreign_nft"},
		{"defaultDrop", func(o *smartTUNHostBoundaryObservations) {
			o.nft = []map[string]any{{"chain": map[string]any{"family": "ip", "table": "foreign", "name": "C", "hook": "output", "policy": "drop"}}}
		}, "foreign_nft_coexistence_unverified", "foreign_nft"},
		{"flowtable", func(o *smartTUNHostBoundaryObservations) {
			o.nft = []map[string]any{{"flowtable": map[string]any{"name": "foreign"}}}
		}, "foreign_nft_coexistence_unverified", "foreign_nft"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sample := base
			tc.mutate(&sample)
			r := assessSmartTUNHostBoundary(sample, "ens3")
			if !r.ReadOnly || r.ActivationReady || r.GeneralHostAdmitted ||
				!hasBoundaryReason(r, "out_of_band_recovery_not_verified") ||
				!hasBoundaryReason(r, "general_host_admission_not_implemented") ||
				!hasBoundaryReason(r, tc.want) {
				t.Fatalf("false positive or missing blocker: %+v", r)
			}
			switch tc.field {
			case "native_platform":
				if tc.name != "clean" && r.NativePlatform != "unsupported_or_unverified" {
					t.Fatal(r)
				}
			case "ssh_return_path":
				if r.SSHReturnPath != "unverified" {
					t.Fatal(r)
				}
			case "interface_inventory":
				if tc.name == "foreignDockerLink" && r.InterfaceInventory != "additional_interfaces_present" {
					t.Fatal(r)
				}
			case "ipv4_policy":
				if r.IPv4Policy != "unverified" {
					t.Fatal(r)
				}
			case "ipv6_policy":
				if r.IPv6Policy != "public_indirect_or_unverified" {
					t.Fatal(r)
				}
			case "foreign_nft":
				if r.ForeignNFT == "no_foreign_packet_effects_observed" {
					t.Fatal(r)
				}
			}
			b, _ := json.Marshal(r)
			for _, secret := range []string{"10.20.30.40", "8.8.8.8", "docker0", "CT"} {
				if strings.Contains(string(b), secret) {
					t.Fatalf("private metadata leaked: %s", secret)
				}
			}
		})
	}
}

func hasBoundaryReason(r SmartTUNHostBoundary, reason string) bool {
	for _, s := range r.Reasons {
		if s == reason {
			return true
		}
	}
	return false
}

func TestGeneralHostNFTEffectsRefuseOpaqueAndMutation(t *testing.T) {
	passive := hostNFTFixture("output", map[string]any{"match": map[string]any{"left": "a", "right": "b", "op": "=="}}, map[string]any{"counter": map[string]any{"packets": json.Number("0"), "bytes": json.Number("0")}}, map[string]any{"accept": nil})
	got, err := generalHostForeignNFTEffects(passive)
	if err != nil || got != (generalHostNFTProfile{}) {
		t.Fatalf("passive owner rejected %+v %v", got, err)
	}
	for _, tc := range []struct {
		name        string
		hook        string
		effect      map[string]any
		nat, opaque bool
	}{
		{"native NAT", "postrouting", map[string]any{"masquerade": nil}, true, false},
		{"opaque OUTPUT CT", "output", map[string]any{"xt": map[string]any{"name": "CT", "type": "target"}}, false, true},
		{"opaque INPUT CT", "input", map[string]any{"xt": map[string]any{"name": "CT", "type": "target"}}, false, false},
		{"opaque Docker NAT", "postrouting", map[string]any{"xt": map[string]any{"name": "MASQUERADE", "type": "target"}}, true, false},
		{"mark mutation", "output", map[string]any{"mangle": map[string]any{"key": "mark", "value": 1}}, false, false},
		{"notrack", "output", map[string]any{"notrack": nil}, false, true},
		{"DNAT", "prerouting", map[string]any{"dnat": map[string]any{}}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := generalHostForeignNFTEffects(hostNFTFixture(tc.hook, tc.effect))
			if e != nil || r.PacketEffects != 1 || r.ForeignNAT != tc.nat || r.OpaqueOutputCT != tc.opaque {
				t.Fatalf("foreign packet effect misclassified %+v %v", r, e)
			}
		})
	}
	output, err := generalHostForeignNFTEffects(hostNFTFixture("output", map[string]any{"xt": map[string]any{"name": "CT", "type": "target"}}))
	if err != nil || output.OutputXTCTCount != 1 || !output.OpaqueOutputCT || output.NativeOutputNotrack {
		t.Fatalf("kernel OUTPUT xt CT count lost: %+v %v", output, err)
	}
	native, err := generalHostForeignNFTEffects(hostNFTFixture("output", map[string]any{"notrack": nil}))
	if err != nil || native.OutputXTCTCount != 0 || !native.NativeOutputNotrack || !native.OpaqueOutputCT {
		t.Fatalf("native OUTPUT NOTRACK does not fail closed: %+v %v", native, err)
	}
	if _, err := generalHostForeignNFTEffects(nil); err == nil {
		t.Fatal("absent inventory admitted")
	}
	if _, err := generalHostForeignNFTEffects([]map[string]any{{"rule": map[string]any{"family": "ip", "table": "t", "chain": "c", "expr": []any{map[string]any{"xt": map[string]any{"name": "CT", "type": "target"}}}}}}); err == nil {
		t.Fatal("unbound chain admitted")
	}
}

// Foreign NAT is not limited to four well-known target spellings. An
// opaque extension in a NAT chain/table or a nonaccept NAT policy must be
// treated as unverified, not omitted from the capture-preflight risk profile.
func TestGeneralHostForeignNATUnknownExtensionFailsClosed(t *testing.T) {
	nat := func(family, table, chain string, kind string, value any) []map[string]any {
		return []map[string]any{
			{"table": map[string]any{"family": family, "name": table}},
			{"chain": map[string]any{"family": family, "table": table, "name": chain, "type": "nat", "hook": "output", "policy": "accept"}},
			{"rule": map[string]any{"family": family, "table": table, "chain": chain, "expr": []any{map[string]any{kind: value}}}},
		}
	}
	unknown := map[string]any{"type": "target", "name": "FUTURE_NAT"}
	for _, tc := range []struct {
		name    string
		objects []map[string]any
	}{
		{"unknown xt target in ip nat", nat("ip", "nat", "OUTPUT", "xt", unknown)},
		{"unknown xt target in inet custom nat", nat("inet", "other-nat", "OUTPUT", "xt", unknown)},
		{"unknown expression in ip nat", nat("ip", "nat", "OUTPUT", "future_translate", map[string]any{"mode": "rewrite"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, e := generalHostForeignNFTEffects(tc.objects)
			if e != nil || !profile.ForeignNAT || profile.PacketEffects == 0 {
				t.Fatalf("opaque NAT effect missed: %+v %v", profile, e)
			}
			o := hostBoundaryFixture()
			o.nft = tc.objects
			r := assessSmartTUNHostBoundary(o, "ens3")
			if !hasBoundaryReason(r, "foreign_nat_ownership_unverified") || r.ActivationReady || r.GeneralHostAdmitted || r.DockerNATShape != dockerNATUnverified {
				t.Fatalf("unknown NAT extension falsely admitted: %+v", r)
			}
			// This is the installed preparation entry, not just a read-only
			// diagnostic result. The old v6 parent must never stage a table
			// after seeing a nat-type unknown effect.
			stage := hostIngressStage{Underlay: "ens3", OperationID: "abababababababababababababababab"}
			if got := ErrorCode(hostIngressForeignNATBoundary(stage, tc.objects)); got != "foreign_nat_unverified" {
				t.Fatalf("product ingress accepted unknown NAT: %s", got)
			}
		})
	}
	chain := nat("ip", "nat", "OUTPUT", "counter", map[string]any{"packets": json.Number("0"), "bytes": json.Number("0")})
	chain[1]["chain"].(map[string]any)["policy"] = "drop"
	got, e := generalHostForeignNFTEffects(chain)
	if e != nil || !got.ForeignNAT {
		t.Fatalf("foreign NAT chain policy overlooked: %+v %v", got, e)
	}
	// Ordinary foreign raw/OUTPUT CT is a separate NOTRACK owner, not
	// permission to adopt NAT or a false positive for NAT detection.
	ct := hostNFTFixture("output", map[string]any{"xt": map[string]any{"type": "target", "name": "CT"}})
	risk, e := generalHostForeignNFTEffects(ct)
	if e != nil || risk.ForeignNAT || !risk.OpaqueOutputCT {
		t.Fatalf("NOTRACK confused with NAT: %+v %v", risk, e)
	}
}

func TestGeneralHostDockerAndHostedReplyConntrackRemainBlocked(t *testing.T) {
	o := hostBoundaryFixture()
	docker := hostNFTFixture("postrouting", map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "ip", "field": "saddr"}}, "right": map[string]any{"prefix": map[string]any{"addr": "172.17.0.0", "len": 16}}}}, map[string]any{"xt": map[string]any{"type": "target", "name": "MASQUERADE"}})
	raw := hostNFTFixture("output", map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "tcp", "field": "sport"}}, "right": 80}}, map[string]any{"xt": map[string]any{"type": "target", "name": "CT"}})
	for _, entry := range raw {
		for _, value := range entry {
			if object, ok := value.(map[string]any); ok {
				if object["name"] == "foreign" {
					object["name"] = "foreign_raw"
				}
				if object["table"] == "foreign" {
					object["table"] = "foreign_raw"
				}
			}
		}
	}
	o.nft = append(docker, raw...)
	result := assessSmartTUNHostBoundary(o, "ens3")
	for _, reason := range []string{"foreign_output_conntrack_opaque", "foreign_nat_ownership_unverified", "foreign_nft_coexistence_unverified"} {
		if !hasBoundaryReason(result, reason) {
			t.Fatalf("missing concrete blocker %s: %+v", reason, result)
		}
	}
	if result.ForeignNFT != "foreign_packet_effects_present" || result.GeneralHostAdmitted || result.ActivationReady {
		t.Fatalf("unsupported host incorrectly admitted: %+v", result)
	}
	serialized, _ := json.Marshal(result)
	for _, secret := range []string{"172.17.0.0", "MASQUERADE", "foreign_raw", "80"} {
		if strings.Contains(string(serialized), secret) {
			t.Fatalf("private nft metadata leaked %s", secret)
		}
	}
}

func TestGeneralHostExistingUntrackedRepliesNeverAdmit(t *testing.T) {
	for _, tc := range []struct{ label, status, reason string }{
		{"present", hostRepliesPresent, "preexisting_untracked_hosted_reply_sessions"},
		{"none", hostRepliesNone, ""},
		{"unverified", hostRepliesUnverified, "untracked_hosted_reply_sessions_unverified"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			o := hostBoundaryFixture()
			o.nft = hostNFTFixture("output", map[string]any{"xt": map[string]any{"type": "target", "name": "CT"}})
			o.hostedReplySessions = tc.status
			r := assessSmartTUNHostBoundary(o, "ens3")
			if r.HostedReplySessions != tc.status || r.ActivationReady || r.GeneralHostAdmitted ||
				!hasBoundaryReason(r, "foreign_output_conntrack_opaque") ||
				!hasBoundaryReason(r, "untracked_reply_socket_generation_not_reserved") ||
				(tc.reason != "" && !hasBoundaryReason(r, tc.reason)) {
				t.Fatalf("hosted reply risk lost: %+v", r)
			}
		})
	}
}

// The shared sysctl is an operator-owned host prerequisite, never an
// implicitly acquired mutation right. Non-atomic observation cannot issue a
// stable activation receipt even if both endpoint values happen to be 1.
func TestGeneralHostBoundaryMarkInheritanceIsReadOnlyAndFailClosed(t *testing.T) {
	cases := []struct {
		name                string
		before, after       int
		beforeErr, afterErr error
		state, reason       string
	}{
		{"preenabled", 1, 1, nil, nil, "enabled_observed_only", ""},
		{"disabled", 0, 0, nil, nil, "disabled_operator_prerequisite", "tcp_fwmark_accept_preexisting_enabled_required"},
		{"disabled_to_enabled", 0, 1, nil, nil, "changed_during_observation", "tcp_fwmark_accept_changed_during_observation"},
		{"enabled_to_disabled", 1, 0, nil, nil, "changed_during_observation", "tcp_fwmark_accept_changed_during_observation"},
		{"read_before_failed", 0, 1, errors.New("read failed"), nil, "unverified", "tcp_fwmark_accept_unverified"},
		{"read_after_failed", 1, 0, nil, errors.New("read failed"), "unverified", "tcp_fwmark_accept_unverified"},
		{"unexpected_kernel_value", 2, 2, nil, nil, "unverified", "tcp_fwmark_accept_unverified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := hostBoundaryFixture()
			o.markBefore, o.markAfter = tc.before, tc.after
			o.markBeforeErr, o.markAfterErr = tc.beforeErr, tc.afterErr
			r := assessSmartTUNHostBoundary(o, "ens3")
			if !r.ReadOnly || r.ActivationReady || r.GeneralHostAdmitted ||
				r.TCPMarkInheritance != tc.state ||
				!hasBoundaryReason(r, "general_host_admission_not_implemented") ||
				(tc.reason != "" && !hasBoundaryReason(r, tc.reason)) {
				t.Fatalf("shared sysctl ownership misreported: %+v", r)
			}
		})
	}
}
