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
		target: "debian-13-amd64",
		sshPath: generalHostSSHPath{Interface: "ens3", Index: 2,
			Local: netip.MustParseAddr("10.20.30.40"), Peer: netip.MustParseAddr("8.8.8.8")},
		links:     json.RawMessage(`[{"ifindex":1,"ifname":"lo"},{"ifindex":2,"ifname":"ens3"}]`),
		ipv4Rules: json.RawMessage(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`),
		nft:       []map[string]any{},
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
			o.nft = []map[string]any{{"rule": map[string]any{"expr": []any{map[string]any{"masquerade": nil}}}}}
		}, "foreign_nft_coexistence_unverified", "foreign_nft"},
		{"opaqueXT", func(o *smartTUNHostBoundaryObservations) {
			o.nft = []map[string]any{{"rule": map[string]any{"expr": []any{map[string]any{"xt": map[string]any{"name": "CT", "type": "target"}}}}}}
		}, "foreign_nft_coexistence_unverified", "foreign_nft"},
		{"defaultDrop", func(o *smartTUNHostBoundaryObservations) {
			o.nft = []map[string]any{{"chain": map[string]any{"policy": "drop", "hook": "output"}}}
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
	passive := []map[string]any{
		{"table": map[string]any{"family": "inet", "name": "thirdparty"}},
		{"rule": map[string]any{"expr": []any{map[string]any{"match": map[string]any{"left": "a", "right": "b", "op": "=="}}, map[string]any{"counter": map[string]any{"packets": json.Number("0"), "bytes": json.Number("0")}}, map[string]any{"accept": nil}}}},
	}
	n, err := generalHostForeignNFTEffects(passive)
	if err != nil || n != 0 {
		t.Fatalf("passive owner incorrectly rejected: %d %v", n, err)
	}
	for _, effect := range []map[string]any{
		{"masquerade": nil}, {"xt": map[string]any{"name": "CT", "type": "target"}},
		{"mangle": map[string]any{"key": "mark", "value": 1}},
		{"notrack": nil}, {"dnat": map[string]any{}},
	} {
		input := append(append([]map[string]any{}, passive...), map[string]any{"rule": map[string]any{"expr": []any{effect}}})
		count, e := generalHostForeignNFTEffects(input)
		if e != nil || count != 1 {
			t.Fatalf("foreign packet effect silently permitted: %v count=%d", effect, count)
		}
	}
	if _, err := generalHostForeignNFTEffects(nil); err == nil {
		t.Fatal("absent inventory admitted")
	}
	if _, err := generalHostForeignNFTEffects([]map[string]any{{"table": map[string]any{}, "rule": map[string]any{}}}); err == nil {
		t.Fatal("ambiguous inventory admitted")
	}
}
