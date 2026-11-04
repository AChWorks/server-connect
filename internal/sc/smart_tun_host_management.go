//go:build linux

package sc

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
)

// A general-host SSH witness must be bound to the actual source address and
// underlay route, not a client-controlled SSH_CONNECTION environment value.
// These read-only observations are necessary for host activation, but are
// deliberately NOT sufficient to authorize any native network mutation.
type generalHostSSHPath struct {
	Interface string
	Index     int
	Local     netip.Addr
	Peer      netip.Addr
	Gateway   netip.Addr
}

// RFC1918 administration is common behind a private underlay; public paths
// must be ordinary globally routable addresses, not documentation, carrier
// NAT, multicast, link-local or other special-purpose networks.
func plausibleHostManagementAddress(addr netip.Addr) bool {
	return addr.Is4() && !addr.Is4In6() && addr.IsGlobalUnicast() &&
		!addr.IsLoopback() && !addr.IsLinkLocalUnicast() &&
		(addr.IsPrivate() || !overlapsSpecialPurpose(netip.PrefixFrom(addr, 32)))
}

func generalHostSSHPathFromKernel(peer, underlay string, links, addresses, route json.RawMessage) (generalHostSSHPath, error) {
	denied := func() (generalHostSSHPath, error) {
		return generalHostSSHPath{}, managementFault("general-host SSH underlay identity, source or route cannot be proven")
	}
	addr, err := netip.ParseAddr(peer)
	if err != nil || !plausibleHostManagementAddress(addr) ||
		!smartTUNDeviceName.MatchString(underlay) || underlay == "lo" {
		return denied()
	}
	for _, data := range []json.RawMessage{links, addresses, route} {
		if rejectAmbiguousJournalJSON(data) != nil {
			return denied()
		}
	}

	var linkRows []map[string]json.RawMessage
	if json.Unmarshal(links, &linkRows) != nil || len(linkRows) != 1 ||
		selectiveText(linkRows[0]["ifname"]) != underlay {
		return denied()
	}
	link := linkRows[0]
	idx, ok := selectiveInt(link["ifindex"])
	if !ok || idx < 2 || link["master"] != nil || link["link_netnsid"] != nil ||
		link["linkinfo"] != nil || selectiveText(link["link_type"]) != "ether" {
		return denied()
	}
	var flags []string
	if json.Unmarshal(link["flags"], &flags) != nil || len(flags) < 2 {
		return denied()
	}
	up, lowerUp := false, false
	for _, flag := range flags {
		if flag == "UP" {
			up = true
		}
		if flag == "LOWER_UP" {
			lowerUp = true
		}
	}
	if !up || !lowerUp {
		return denied()
	}

	var addressRows []struct {
		IfName  string `json:"ifname"`
		IfIndex int    `json:"ifindex"`
		Info    []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			Scope     string `json:"scope"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(addresses, &addressRows) != nil || len(addressRows) != 1 ||
		addressRows[0].IfName != underlay || addressRows[0].IfIndex != idx ||
		len(addressRows[0].Info) != 1 || addressRows[0].Info[0].Family != "inet" ||
		addressRows[0].Info[0].Scope != "global" || addressRows[0].Info[0].PrefixLen < 1 ||
		addressRows[0].Info[0].PrefixLen > 32 {
		return denied()
	}
	local, err := netip.ParseAddr(addressRows[0].Info[0].Local)
	if err != nil || !plausibleHostManagementAddress(local) || local == addr {
		return denied()
	}
	// Require an exact source-specific kernel route, without multipath,
	// policy-table redirection, tunnel encapsulation or ambiguous flags.
	var rows []map[string]json.RawMessage
	if json.Unmarshal(route, &rows) != nil || len(rows) != 1 || rows[0] == nil {
		return denied()
	}
	row := rows[0]
	allowed := map[string]bool{
		"dst": true, "from": true, "src": true, "prefsrc": true,
		"dev": true, "gateway": true, "table": true, "type": true,
		"flags": true, "cache": true, "uid": true, "metric": true,
	}
	for key, raw := range row {
		if !allowed[key] || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return denied()
		}
	}
	if selectiveText(row["dst"]) != addr.String() || selectiveText(row["dev"]) != underlay {
		return denied()
	}
	for _, field := range []string{"from", "src", "prefsrc"} {
		if raw, present := row[field]; present && selectiveText(raw) != local.String() {
			return denied()
		}
	}
	if raw, present := row["table"]; present &&
		selectiveText(raw) != "main" && string(raw) != "254" {
		return denied()
	}
	if raw, present := row["type"]; present && selectiveText(raw) != "unicast" {
		return denied()
	}
	if raw, present := row["flags"]; present {
		var values []string
		if json.Unmarshal(raw, &values) != nil || values == nil || len(values) != 0 {
			return denied()
		}
	}
	if raw, present := row["cache"]; present && string(raw) != "[]" && string(raw) != "{}" {
		return denied()
	}
	if raw, present := row["uid"]; present {
		n, ok := selectiveInt(raw)
		if !ok || n < 0 {
			return denied()
		}
	}
	if raw, present := row["metric"]; present {
		n, ok := selectiveInt(raw)
		if !ok || n < 0 {
			return denied()
		}
	}
	var gateway netip.Addr
	if raw, present := row["gateway"]; present {
		gateway, err = netip.ParseAddr(selectiveText(raw))
		if err != nil || !plausibleHostManagementAddress(gateway) || gateway == local {
			return denied()
		}
	}
	return generalHostSSHPath{Interface: underlay, Index: idx, Local: local, Peer: addr, Gateway: gateway}, nil
}

func observeGeneralHostSSHPath(peer, underlay string) (generalHostSSHPath, error) {
	// Reject untrusted/unsupported destinations before invoking any native
	// inspector. Executing iproute2 is only a bounded read, never Apply.
	addr, parseErr := netip.ParseAddr(peer)
	if parseErr != nil || !plausibleHostManagementAddress(addr) ||
		!smartTUNDeviceName.MatchString(underlay) || underlay == "lo" {
		return generalHostSSHPath{}, managementFault("invalid general-host SSH observation target")
	}
	if os.Geteuid() != 0 || trustedHostIPExecutable() != nil {
		return generalHostSSHPath{}, managementFault("general-host SSH inspection requires trusted privileged iproute2")
	}
	links, e1 := nativeIPJSON("-d", "-j", "link", "show", "dev", underlay)
	addresses, e2 := nativeIPJSON("-j", "-4", "address", "show", "dev", underlay)
	route, e3 := nativeIPJSON("-j", "-4", "route", "get", peer)
	if e1 != nil || e2 != nil || e3 != nil {
		return generalHostSSHPath{}, managementFault("general-host SSH underlay observations unavailable")
	}
	// A generic route lookup may choose another source. Require an explicit
	// from-local replay after the first trusted link/address observation.
	path, err := generalHostSSHPathFromKernel(peer, underlay, links, addresses, route)
	if err != nil {
		return path, err
	}
	sourced, err := nativeIPJSON("-j", "-4", "route", "get", peer, "from", path.Local.String())
	if err != nil {
		return generalHostSSHPath{}, managementFault("source-specific general-host SSH route unavailable")
	}
	return generalHostSSHPathFromKernel(peer, underlay, links, addresses, sourced)
}

// observeFreshGeneralHostSSH uses exactly the same kernel inet_diag/OpenSSH
// ancestry and boot-time replay resistance as disposable QA confirmation.
// The underlay is checked both before and after, against the same observed
// local address, ifindex and next hop. This proof is not a provider-console
// recovery channel and cannot alone admit real-host Smart TUN Apply.
func observeFreshGeneralHostSSH(peer, underlay string, afterMS int64) (smartTUNManagementProof, error) {
	before, err := observeGeneralHostSSHPath(peer, underlay)
	if err != nil {
		return smartTUNManagementProof{}, err
	}
	witness, err := observeFreshManagementSocket(peer, before.Local.String(), afterMS)
	if err != nil {
		return smartTUNManagementProof{}, err
	}
	after, err := observeGeneralHostSSHPath(peer, underlay)
	if err != nil || before != after || witness.LocalIP != before.Local.String() ||
		witness.PeerIP != before.Peer.String() {
		return smartTUNManagementProof{}, managementFault("general-host SSH underlay identity changed across confirmation")
	}
	return witness, nil
}
