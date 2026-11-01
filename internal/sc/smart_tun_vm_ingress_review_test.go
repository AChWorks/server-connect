package sc

import (
	"encoding/json"
	"strings"
	"testing"
)

// Focused exact-peer and kernel-routing regressions for review REQUIRED-01/02.
// These are synthetic validator tests; separate installed KVM tests must prove
// the actual kernel/iproute2 JSON produces these observable shapes.
func TestSmartTUNVMIngressPinnedNamespaceAndPeer(t *testing.T) {
	root := testVMIngressRows(t, `[{"ifindex":4,"link_index":3,"link_netnsid":0,"ifname":"scqavh0","flags":["BROADCAST","UP","LOWER_UP"],"operstate":"UP","mtu":1500,"promiscuity":0,"linkinfo":{"info_kind":"veth"}}]`)[0]
	validNames := `[{"nsid":0,"name":"scqa-foreign"}]`
	if !smartTUNVMIngressNamedNamespaceValid(0, testVMIngressRows(t, validNames)) {
		t.Fatal("named kernel namespace ID mapping was refused")
	}
	for _, tc := range []struct {
		name, raw string
		nsid      int
	}{
		{"other-valid-namespace", `[{"nsid":0,"name":"other-test-namespace"}]`, 0},
		{"mapped-wrong-id", `[{"nsid":2,"name":"scqa-foreign"}]`, 0},
		{"missing-name", `[{"nsid":0}]`, 0},
		{"missing-nsid", `[{"name":"scqa-foreign"}]`, 0},
		{"namespace-substitution", `[{"nsid":0,"name":"scqa-foreign"},{"nsid":1,"name":"other-test-namespace"}]`, 0},
		{"invalid-id", validNames, -1},
		{"ambiguous-duplicate", `[{"nsid":0,"name":"scqa-foreign"},{"nsid":0,"name":"scqa-foreign"}]`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if smartTUNVMIngressNamedNamespaceValid(tc.nsid, testVMIngressRows(t, tc.raw)) {
				t.Fatal("foreign or ambiguous namespace admitted")
			}
		})
	}
	peer := `[{"ifindex":3,"link_index":4,"link_netnsid":0,"ifname":"scqavn0","flags":["BROADCAST","UP","LOWER_UP"],"operstate":"UP","mtu":1500,"promiscuity":0,"linkinfo":{"info_kind":"veth"}}]`
	if !smartTUNVMIngressPeerLinkValid(root, testVMIngressRows(t, peer)[0]) {
		t.Fatal("reciprocal QEMU peer identity refused")
	}
	for _, tc := range []struct{ name, old, next string }{
		{"peer-index-mismatch", `"ifindex":3`, `"ifindex":5`},
		{"reciprocal-link-index-mismatch", `"link_index":4`, `"link_index":99`},
		{"peer-name", `"ifname":"scqavn0"`, `"ifname":"other0"`},
		{"different-link-kind", `"veth"`, `"dummy"`},
		{"peer-netnsid-missing", `"link_netnsid":0`, `"link_netnsid":null`},
		{"peer-bridge", `"link_netnsid":0`, `"link_netnsid":0,"master":"br1"`},
		{"peer-mtu", `"mtu":1500`, `"mtu":1400`},
		{"peer-down", `"operstate":"UP"`, `"operstate":"DOWN"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := testVMIngressRows(t, strings.Replace(peer, tc.old, tc.next, 1))[0]
			if smartTUNVMIngressPeerLinkValid(root, bad) {
				t.Fatal("invalid kernel reciprocal peer accepted")
			}
		})
	}
	good4 := json.RawMessage(`[{"ifname":"scqavn0","addr_info":[{"local":"198.51.100.2","prefixlen":30,"scope":"global"}]}]`)
	if !smartTUNVMIngressAddressValidFor(good4, smartTUNVMIngressPeer, smartTUNVMIngressPeerIP, false) {
		t.Fatal("peer expected IPv4 rejected")
	}
	for _, invalid := range []json.RawMessage{
		json.RawMessage(strings.Replace(string(good4), `"198.51.100.2"`, `"198.51.100.3"`, 1)),
		json.RawMessage(strings.Replace(string(good4), `"scqavn0"`, `"scqavh0"`, 1)),
		json.RawMessage(strings.Replace(string(good4), `"prefixlen":30`, `"prefixlen":32`, 1)),
	} {
		if smartTUNVMIngressAddressValidFor(invalid, smartTUNVMIngressPeer, smartTUNVMIngressPeerIP, false) {
			t.Fatal("incorrect peer-side IPv4 config admitted")
		}
	}
	route := `[{"dst":"198.51.100.0/30","dev":"scqavn0","protocol":"kernel","scope":"link","prefsrc":"198.51.100.2","flags":[]}]`
	if !smartTUNVMIngressPeerRoutesValid(testVMIngressRows(t, route)) {
		t.Fatal("exact peer route rejected")
	}
	for _, invalid := range []string{
		strings.Replace(route, `"scqavn0"`, `"ens3"`, 1),
		strings.Replace(route, `"198.51.100.2"`, `"198.51.100.1"`, 1),
		strings.Replace(route, `"kernel"`, `"static"`, 1),
		strings.TrimSuffix(route, "]") + `,{"dst":"default","dev":"scqavn0"}]`,
	} {
		if smartTUNVMIngressPeerRoutesValid(testVMIngressRows(t, invalid)) {
			t.Fatal("invalid peer route passed")
		}
	}
}

func TestSmartTUNVMIngressRPDBAndEffectiveReply(t *testing.T) {
	expected := `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`
	if !smartTUNVMIngressDefaultRulesValid(json.RawMessage(expected)) {
		t.Fatal("native Debian 13 default RPDB refused")
	}
	for _, invalid := range []string{
		strings.TrimSuffix(expected, "]") + `,{"priority":100,"src":"198.51.100.1","table":"100"}]`,
		strings.Replace(expected, `"table":"main"`, `"table":"100"`, 1),
		strings.Replace(expected, `"priority":32766`, `"priority":100`, 1),
		strings.Replace(expected, `"src":"all"`, `"src":"198.51.100.1"`, 1),
		strings.Replace(expected, `"src":"all"`, `"src":"all","fwmark":"0x1"`, 1),
		`[{"priority":0,"src":"all","table":"local"},{"priority":32767,"src":"all","table":"default"}]`,
	} {
		if smartTUNVMIngressDefaultRulesValid(json.RawMessage(invalid)) {
			t.Fatal("foreign RPDB policy admitted")
		}
	}
	success := `[{"dst":"198.51.100.2","from":"198.51.100.1","dev":"scqavh0","flags":[],"uid":0,"cache":[]}]`
	if !smartTUNVMIngressReplyRouteValid(json.RawMessage(success)) {
		t.Fatal("actual KVM reply-route proof refused")
	}
	for _, invalid := range []string{
		strings.Replace(success, `"scqavh0"`, `"ens3"`, 1),
		strings.Replace(success, `"198.51.100.2"`, `"198.51.100.3"`, 1),
		strings.Replace(success, `"198.51.100.1"`, `"10.0.2.15"`, 1),
		strings.Replace(success, `"flags":[]`, `"flags":["onlink"]`, 1),
		strings.Replace(success, `"flags":[]`, `"gateway":"10.0.2.2","flags":[]`, 1),
		strings.Replace(success, `"flags":[]`, `"nhid":5,"flags":[]`, 1),
	} {
		if smartTUNVMIngressReplyRouteValid(json.RawMessage(invalid)) {
			t.Fatal("foreign or ambiguous FIB reply admitted")
		}
	}
}

func TestSmartTUNVMIngressAllTablesRejectForeignRouting(t *testing.T) {
	main := `{"dst":"198.51.100.0/30","dev":"scqavh0","protocol":"kernel","scope":"link","prefsrc":"198.51.100.1","flags":[]}`
	def := `{"dst":"default","gateway":"10.0.2.2","dev":"ens3","protocol":"dhcp","prefsrc":"10.0.2.15","metric":100,"flags":[]}`
	local := `{"type":"local","dst":"198.51.100.1","dev":"scqavh0","table":"local","protocol":"kernel","scope":"host","prefsrc":"198.51.100.1","flags":[]}`
	broadcast := `{"type":"broadcast","dst":"198.51.100.3","dev":"scqavh0","table":"local","protocol":"kernel","scope":"link","prefsrc":"198.51.100.1","flags":[]}`
	success := "[" + main + "," + def + "," + local + "," + broadcast + "]"
	if !smartTUNVMIngressAllTablesValid(testVMIngressRows(t, success)) {
		t.Fatal("expected main/local route inventory refused")
	}
	for _, invalid := range []struct{ name, route string }{
		{"multipath-ingress-device", `{"dst":"192.0.2.0/24","nexthops":[{"dev":"scqavh0","weight":1},{"dev":"ens3","weight":1}],"flags":[]}`},
		{"multipath-other-device", `{"dst":"192.0.2.0/24","nexthops":[{"dev":"ens3","weight":1}],"flags":[]}`},
		{"referenced-nexthop-object", `{"dst":"192.0.2.0/24","nhid":15,"flags":[]}`},
		{"nested-metadata-malformed", `{"dst":"192.0.2.0/24","nexthops":{"unexpected":1}}`},
		{"foreign-high-prio-table-use-ingress", `{"dst":"198.51.100.2/32","table":"100","dev":"ens3","protocol":"static"}`},
		{"foreign-table-uses-ingress", `{"dst":"192.0.2.0/24","table":"100","dev":"scqavh0","protocol":"static"}`},
		{"extra-ingress-local", `{"type":"local","dst":"198.51.100.2","table":"local","dev":"scqavh0","protocol":"kernel"}`},
		{"foreign-overlap", `{"dst":"198.51.100.2/32","table":"100","dev":"ens3","protocol":"static"}`},
		{"foreign-source", `{"dst":"192.0.2.0/24","table":"100","dev":"ens3","prefsrc":"198.51.100.1"}`},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			rows := testVMIngressRows(t, strings.TrimSuffix(success, "]")+","+invalid.route+"]")
			if smartTUNVMIngressAllTablesValid(rows) {
				t.Fatal("foreign or ambiguous all-table route passed")
			}
		})
	}
	if smartTUNVMIngressRouteValid(testVMIngressRows(t, "["+main+","+def+","+`{"dst":"192.0.2.0/24","nexthops":[{"dev":"scqavh0"}]}`+"]")) {
		t.Fatal("hidden ingress multipath route passed primary main-table check")
	}
	// Ordinary, independently owned default via ens3 remains permitted.
}
