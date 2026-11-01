package sc

import (
	"encoding/json"
	"strings"
	"testing"
)

func testVMIngressRows(t *testing.T, raw string) []map[string]json.RawMessage {
	t.Helper()
	rows, err := selectiveRows(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestSmartTUNVMIngressInventoryRequiresOnlyExactGuestLinks(t *testing.T) {
	base := `[{"ifname":"lo","ifindex":1},{"ifname":"ens3","ifindex":2}]`
	extended := `[{"ifname":"lo","ifindex":1},{"ifname":"ens3","ifindex":2},{"ifname":"scqavh0","ifindex":4}]`
	if !smartTUNTrialLinkInventoryAllowed(testVMIngressRows(t, base), smartTUNVMUnderlay, smartTUNVMInterface) {
		t.Fatal("original VM admission regressed")
	}
	if !smartTUNTrialLinkInventoryAllowed(testVMIngressRows(t, extended), smartTUNVMUnderlay, smartTUNVMInterface) {
		t.Fatal("exact VM ingress QA refused")
	}
	dockerBase := `[ {"ifname":"lo","ifindex":1}, {"ifname":"scqaedge0","ifindex":2} ]`
	if !smartTUNTrialLinkInventoryAllowed(testVMIngressRows(t, dockerBase), "scqaedge0", "sctunqa0") {
		t.Fatal("original Docker lane refused")
	}
	if smartTUNTrialLinkInventoryAllowed(testVMIngressRows(t, extended), "scqaedge0", "sctunqa0") {
		t.Fatal("Docker lane adopted VM ingress")
	}
	for _, tc := range []struct{ name, input string }{
		{"wrong-ifindex", strings.Replace(extended, `"ifindex":4`, `"ifindex":2`, 1)},
		{"lo-identity", strings.Replace(extended, `"ifindex":1`, `"ifindex":8`, 1)},
		{"missing-underlay", strings.Replace(extended, `"ens3"`, `"foreign0"`, 1)},
		{"other-ingress", strings.Replace(extended, `"scqavh0"`, `"eth1"`, 1)},
		{"reused-name", strings.Replace(extended, `"scqavh0"`, `"ens3"`, 1)},
		{"occupied-owned-tun", strings.Replace(extended, `"scqavh0"`, `"scqavm0"`, 1)},
		{"extra-device", strings.TrimSuffix(extended, "]") + `,{"ifname":"other0","ifindex":9}]`},
		{"ambiguous-index", strings.Replace(extended, `"ifindex":4`, `"ifindex":null`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if smartTUNTrialLinkInventoryAllowed(testVMIngressRows(t, tc.input), smartTUNVMUnderlay, smartTUNVMInterface) {
				t.Fatal("unsupported guest network inventory admitted")
			}
		})
	}
}

func TestSmartTUNVMIngressLinkRejectsUntrustedPeerIdentity(t *testing.T) {
	valid := `[{"ifindex":4,"link_index":3,"link_netnsid":0,"ifname":"scqavh0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP","mtu":1500,"promiscuity":0,"linkinfo":{"info_kind":"veth"}}]`
	if !smartTUNVMIngressLinkValid(testVMIngressRows(t, valid)[0]) {
		t.Fatal("exact veth boundary refused")
	}
	for _, tc := range []struct{ name, old, next string }{
		{"device-name", `"scqavh0"`, `"eth0"`},
		{"veth-kind", `"veth"`, `"dummy"`},
		{"link-index", `"ifindex":4`, `"ifindex":1`},
		{"peer-index", `"link_index":3`, `"link_index":0`},
		{"self-peer", `"link_index":3`, `"link_index":4`},
		{"mtu-drift", `"mtu":1500`, `"mtu":1400`},
		{"promiscuous", `"promiscuity":0`, `"promiscuity":1`},
		{"bridge-member", `"link_netnsid":0`, `"master":"br0","link_netnsid":0`},
		{"alias", `"ifname":"scqavh0"`, `"ifname":"scqavh0","ifalias":"foreign"`},
		{"not-operational", `"operstate":"UP"`, `"operstate":"DOWN"`},
		{"peer-missing", `"link_index":3`, `"link_index":null`},
		{"peer-namespace", `"link_netnsid":0`, `"link_netnsid":null`},
		{"peer-missing-field", `"link_netnsid":0,`, ``},
		{"not-up", `"UP"`, `"DOWN"`},
		{"no-carrier", `"LOWER_UP"`, `"NO-CARRIER"`},
		{"duplicate-flag", `"UP","LOWER_UP"`, `"UP","UP","LOWER_UP"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := testVMIngressRows(t, strings.Replace(valid, tc.old, tc.next, 1))[0]
			if smartTUNVMIngressLinkValid(row) {
				t.Fatal("foreign or incomplete guest veth identity admitted")
			}
		})
	}
}

func TestSmartTUNVMIngressAddressAndRouteArePinned(t *testing.T) {
	valid4 := `[{"ifname":"scqavh0","addr_info":[{"local":"198.51.100.1","prefixlen":30,"scope":"global"}]}]`
	valid6 := `[{"ifname":"scqavh0","addr_info":[{"local":"fe80::1234","prefixlen":64,"scope":"link"}]}]`
	no6 := `[{"ifname":"scqavh0","addr_info":[]}]`
	route := `[{"dst":"198.51.100.0/30","dev":"scqavh0","protocol":"kernel","scope":"link","prefsrc":"198.51.100.1"}]`
	for _, tc := range []struct {
		name string
		raw  string
		ipv6 bool
	}{
		{"ipv4", valid4, false},
		{"ipv6", valid6, true},
		{"ipv6-disabled", no6, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !smartTUNVMIngressAddressValid(json.RawMessage(tc.raw), tc.ipv6) {
				t.Fatal("exact guest address rejected")
			}
		})
	}
	if !smartTUNVMIngressRouteValid(testVMIngressRows(t, route)) {
		t.Fatal("exact connected-route proof refused")
	}
	// Real Debian 13 iproute2: an explicit "show dev scqavh0" filters the
	// kernel rows but omits their "dev" JSON property. Only a full main
	// table observation can bind the route to this independently owned link.
	if smartTUNVMIngressRouteValid(testVMIngressRows(t, strings.Replace(route, `"dev":"scqavh0",`, "", 1))) {
		t.Fatal("device-filtered route without identity passed")
	}
	mainRoutes := `[{"dst":"default","gateway":"10.0.2.2","dev":"ens3","protocol":"dhcp","prefsrc":"10.0.2.15","metric":100,"flags":[]},` +
		strings.TrimPrefix(route, "[")
	if !smartTUNVMIngressRouteValid(testVMIngressRows(t, mainRoutes)) {
		t.Fatal("full Debian 13 main table rejected exact fixture")
	}
	for _, invalid := range []string{
		strings.TrimSuffix(mainRoutes, "]") + `,{"dst":"198.51.100.2/32","dev":"scqavh0","protocol":"static"}]`,
		strings.Replace(mainRoutes, `"dev":"scqavh0"`, `"dev":"ens3"`, 1),
		strings.TrimSuffix(mainRoutes, "]") + `,{"dst":"198.51.100.0/30","dev":"other0","protocol":"static"}]`,
		strings.TrimSuffix(mainRoutes, "]") + `,{"dst":"198.51.100.2/32","dev":"ens3","protocol":"static"}]`,
		strings.TrimSuffix(mainRoutes, "]") + `,{"dst":"198.51.100.1","dev":"ens3","protocol":"static"}]`,
		strings.TrimSuffix(mainRoutes, "]") + `,{"dst":"198.51.100.0/31","dev":"ens3","protocol":"static"}]`,
		strings.TrimSuffix(mainRoutes, "]") + `,{"dst":"8.8.8.0/24","dev":"ens3","prefsrc":"198.51.100.1"}]`,
	} {
		if smartTUNVMIngressRouteValid(testVMIngressRows(t, invalid)) {
			t.Fatal("extra, displaced or foreign-owned fixture route admitted")
		}
	}
	for _, tc := range []struct{ name, old, next string }{
		{"wrong-link", `"scqavh0"`, `"eth1"`},
		{"wrong-IP", `"198.51.100.1"`, `"198.51.100.2"`},
		{"broad-prefix", `"prefixlen":30`, `"prefixlen":24`},
		{"wrong-scope", `"global"`, `"link"`},
		{"second-address", `"addr_info":[`, `"addr_info":[{"local":"1.1.1.1","prefixlen":32,"scope":"global"},`},
	} {
		t.Run("ipv4-"+tc.name, func(t *testing.T) {
			if smartTUNVMIngressAddressValid(json.RawMessage(strings.Replace(valid4, tc.old, tc.next, 1)), false) {
				t.Fatal("untrusted root fixture IPv4 address admitted")
			}
		})
	}
	for _, raw := range []string{
		strings.Replace(valid6, `"fe80::1234"`, `"2606:4700::1"`, 1),
		strings.Replace(valid6, `"prefixlen":64`, `"prefixlen":48`, 1),
		strings.Replace(valid6, `"scope":"link"`, `"scope":"global"`, 1),
		strings.Replace(valid6, `"addr_info":[`, `"addr_info":[{"local":"fe80::abcd","prefixlen":64,"scope":"link"},`, 1),
	} {
		if smartTUNVMIngressAddressValid(json.RawMessage(raw), true) {
			t.Fatal("untrusted extra global/multiple IPv6 address admitted")
		}
	}
	for _, tc := range []struct{ name, old, next string }{
		{"wrong-destination", `"198.51.100.0/30"`, `"198.51.100.0/24"`},
		{"wrong-device", `"scqavh0"`, `"ens3"`},
		{"manual-route", `"kernel"`, `"static"`},
		{"wrong-scope", `"link"`, `"global"`},
		{"wrong-source", `"198.51.100.1"`, `"198.51.100.2"`},
		{"extra-route", `]`, `,{"dst":"default","dev":"scqavh0"}]`},
		{"foreign-nexthop", `"scope":"link"`, `"scope":"link","nhid":5`},
		{"nonempty-flags", `"scope":"link"`, `"scope":"link","flags":["onlink"]`},
	} {
		t.Run("route-"+tc.name, func(t *testing.T) {
			r := testVMIngressRows(t, strings.Replace(route, tc.old, tc.next, 1))
			if smartTUNVMIngressRouteValid(r) {
				t.Fatal("untrusted extra route admitted")
			}
		})
	}
}
