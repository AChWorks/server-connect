//go:build linux

package sc

import (
	"encoding/json"
	"strings"
	"testing"
)

const hostSSHLinkFixture = `[{"ifindex":2,"ifname":"ens3","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether"}]`
const hostSSHAddressFixture = `[{"ifindex":2,"ifname":"ens3","addr_info":[{"family":"inet","local":"10.20.30.40","prefixlen":24,"scope":"global"}]}]`
const hostSSHRouteFixture = `[{"dst":"8.8.8.8","gateway":"10.20.30.1","dev":"ens3","prefsrc":"10.20.30.40","flags":[]}]`

func TestGeneralHostSSHUnderlayBindingStrict(t *testing.T) {
	got, err := generalHostSSHPathFromKernel("8.8.8.8", "ens3",
		json.RawMessage(hostSSHLinkFixture), json.RawMessage(hostSSHAddressFixture), json.RawMessage(hostSSHRouteFixture))
	if err != nil || got.Interface != "ens3" || got.Index != 2 || got.Local.String() != "10.20.30.40" ||
		got.Peer.String() != "8.8.8.8" || got.Gateway.String() != "10.20.30.1" {
		t.Fatalf("valid canonical IPv4 management path refused: %+v %v", got, err)
	}
	// An on-link private peer (e.g. over a directly connected management VLAN)
	// also needs no gateway and has no global public-address requirement.
	route := `[{"dst":"10.20.30.1","dev":"ens3","src":"10.20.30.40","flags":[]}]`
	got, err = generalHostSSHPathFromKernel("10.20.30.1", "ens3",
		json.RawMessage(hostSSHLinkFixture), json.RawMessage(hostSSHAddressFixture), json.RawMessage(route))
	if err != nil || got.Gateway.IsValid() || got.Peer.String() != "10.20.30.1" {
		t.Fatalf("direct private SSH peer refused: %+v %v", got, err)
	}
	// A sourced route lookup on Debian 12 can replace "prefsrc" with
	// "from" and include an empty cache plus exact uid. Preserve this
	// observed kernel shape without accepting an alternate route table.
	sourced := `[{"cache":[],"dev":"ens3","dst":"8.8.8.8","flags":[],"from":"10.20.30.40","gateway":"10.20.30.1","uid":0}]`
	got, err = generalHostSSHPathFromKernel("8.8.8.8", "ens3",
		json.RawMessage(hostSSHLinkFixture), json.RawMessage(hostSSHAddressFixture), json.RawMessage(sourced))
	if err != nil || got.Local.String() != "10.20.30.40" || got.Gateway.String() != "10.20.30.1" {
		t.Fatalf("source-specific Debian kernel route refused: %+v %v", got, err)
	}
}

func TestGeneralHostSSHUnderlayBindingFailClosed(t *testing.T) {
	const peer, dev = "8.8.8.8", "ens3"
	tests := []struct {
		name, peer, dev, links, addresses, route string
	}{
		{"different-interface", peer, "ens4", hostSSHLinkFixture, hostSSHAddressFixture, hostSSHRouteFixture},
		{"unsafe-underlay-name", peer, "../ens3", hostSSHLinkFixture, hostSSHAddressFixture, hostSSHRouteFixture},
		{"loopback-device", peer, "lo", hostSSHLinkFixture, hostSSHAddressFixture, hostSSHRouteFixture},
		{"ipv6-client", "2606:4700:4700::1111", dev, hostSSHLinkFixture, hostSSHAddressFixture, hostSSHRouteFixture},
		{"documentation-client", "203.0.113.9", dev, hostSSHLinkFixture, hostSSHAddressFixture, hostSSHRouteFixture},
		{"mapped-client", "::ffff:8.8.8.8", dev, hostSSHLinkFixture, hostSSHAddressFixture, hostSSHRouteFixture},
		{"self-client", "10.20.30.40", dev, hostSSHLinkFixture, hostSSHAddressFixture, hostSSHRouteFixture},
		{"wrong-link-type", peer, dev, strings.Replace(hostSSHLinkFixture, "\"ether\"", "\"veth\"", 1), hostSSHAddressFixture, hostSSHRouteFixture},
		{"foreign-link-master", peer, dev, strings.Replace(hostSSHLinkFixture, "\"ifindex\":2", "\"ifindex\":2,\"master\":9", 1), hostSSHAddressFixture, hostSSHRouteFixture},
		{"foreign-network-namespace", peer, dev, strings.Replace(hostSSHLinkFixture, "\"ifindex\":2", "\"ifindex\":2,\"link_netnsid\":1", 1), hostSSHAddressFixture, hostSSHRouteFixture},
		{"link-down", peer, dev, strings.Replace(hostSSHLinkFixture, ",\"LOWER_UP\"", "", 1), hostSSHAddressFixture, hostSSHRouteFixture},
		{"wrong-index", peer, dev, strings.Replace(hostSSHLinkFixture, "\"ifindex\":2", "\"ifindex\":3", 1), hostSSHAddressFixture, hostSSHRouteFixture},
		{"no-link", peer, dev, `[]`, hostSSHAddressFixture, hostSSHRouteFixture},
		{"duplicate-link", peer, dev, strings.Replace(hostSSHLinkFixture, "]", ","+strings.Trim(hostSSHLinkFixture, "[]")+"]", 1), hostSSHAddressFixture, hostSSHRouteFixture},
		{"duplicate-key-link", peer, dev, strings.Replace(hostSSHLinkFixture, "\"ifname\":\"ens3\"", "\"ifname\":\"ens3\",\"ifname\":\"ens3\"", 1), hostSSHAddressFixture, hostSSHRouteFixture},
		{"different-local-interface", peer, dev, hostSSHLinkFixture, strings.Replace(hostSSHAddressFixture, "\"ens3\"", "\"ens4\"", 1), hostSSHRouteFixture},
		{"wrong-local-ifindex", peer, dev, hostSSHLinkFixture, strings.Replace(hostSSHAddressFixture, "\"ifindex\":2", "\"ifindex\":3", 1), hostSSHRouteFixture},
		{"multiple-local-addresses", peer, dev, hostSSHLinkFixture, strings.Replace(hostSSHAddressFixture, "\"addr_info\":[", "\"addr_info\":[{\"family\":\"inet\",\"local\":\"10.20.30.41\",\"prefixlen\":24,\"scope\":\"global\"},", 1), hostSSHRouteFixture},
		{"linklocal-source", peer, dev, hostSSHLinkFixture, strings.Replace(hostSSHAddressFixture, "10.20.30.40", "169.254.2.3", 1), hostSSHRouteFixture},
		{"documentation-source", peer, dev, hostSSHLinkFixture, strings.Replace(hostSSHAddressFixture, "10.20.30.40", "192.0.2.10", 1), hostSSHRouteFixture},
		{"no-route", peer, dev, hostSSHLinkFixture, hostSSHAddressFixture, `[]`},
		{"wrong-route-target", peer, dev, hostSSHLinkFixture, hostSSHAddressFixture, strings.Replace(hostSSHRouteFixture, "8.8.8.8", "8.8.4.4", 1)},
		{"wrong-route-interface", peer, dev, hostSSHLinkFixture, hostSSHAddressFixture, strings.Replace(hostSSHRouteFixture, "\"ens3\"", "\"ens4\"", 1)},
		{"wrong-route-source", peer, dev, hostSSHLinkFixture, hostSSHAddressFixture, strings.Replace(hostSSHRouteFixture, "\"prefsrc\":\"10.20.30.40\"", "\"prefsrc\":\"10.20.30.41\"", 1)},
		{"wrong-from-source", peer, dev, hostSSHLinkFixture, hostSSHAddressFixture, strings.Replace(hostSSHRouteFixture, "\"flags\"", "\"from\":\"10.20.30.41\",\"flags\"", 1)},
		{"nonmain-table", peer, dev, hostSSHLinkFixture, hostSSHAddressFixture, strings.Replace(hostSSHRouteFixture, "\"flags\"", "\"table\":\"200\",\"flags\"", 1)},
		{"table-unknown-nexthop", peer, dev, hostSSHLinkFixture, hostSSHAddressFixture, strings.Replace(hostSSHRouteFixture, "\"flags\"", "\"nhid\":8,\"flags\"", 1)},
		{"policy-encapsulation", peer, dev, hostSSHLinkFixture, hostSSHAddressFixture, strings.Replace(hostSSHRouteFixture, "\"flags\"", "\"encap\":{},\"flags\"", 1)},
		{"unicast-type-changed", peer, dev, hostSSHLinkFixture, hostSSHAddressFixture, strings.Replace(hostSSHRouteFixture, "\"flags\"", "\"type\":\"blackhole\",\"flags\"", 1)},
		{"linkdown-route", peer, dev, hostSSHLinkFixture, hostSSHAddressFixture, strings.Replace(hostSSHRouteFixture, "\"flags\":[]", "\"flags\":[\"linkdown\"]", 1)},
		{"unsafe-route-gateway", peer, dev, hostSSHLinkFixture, hostSSHAddressFixture, strings.Replace(hostSSHRouteFixture, "10.20.30.1", "127.0.0.1", 1)},
		{"duplicate-route-key", peer, dev, hostSSHLinkFixture, hostSSHAddressFixture, strings.Replace(hostSSHRouteFixture, "\"dev\":\"ens3\"", "\"dev\":\"ens3\",\"dev\":\"ens3\"", 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := generalHostSSHPathFromKernel(tc.peer, tc.dev,
				json.RawMessage(tc.links), json.RawMessage(tc.addresses), json.RawMessage(tc.route))
			if err == nil {
				t.Fatalf("accepted an untrusted or ambiguous management source/return path: %+v", tc)
			}
		})
	}
}

func TestGeneralHostSSHCannotForgeConfirmationWithEnvironment(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "8.8.8.8 9999 10.20.30.40 22")
	t.Setenv("SSH_CLIENT", "8.8.8.8 9999 22")
	// Not running inside a valid remote OpenSSH ancestor. An environment
	// value is neither fresh transport ownership nor a general-host ticket.
	if _, err := observeFreshManagementSocket("8.8.8.8", "10.20.30.40", 1); err == nil {
		t.Fatal("unauthenticated user-provided SSH metadata accepted")
	}
}
