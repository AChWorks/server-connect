package sc

// Non-Docker admission is intentionally limited to the isolated US01 QEMU
// Debian 13 validation guest. It is not a general VM/hosting admission flag:
// the exact guest identity, installed systemd, network and private management
// topology must all agree before any privileged Smart TUN operation.
import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
)

const (
	smartTUNVMEndpoint  = "10.0.2.2"
	smartTUNVMUnderlay  = "ens3"
	smartTUNVMInterface = "scqavm0"
	smartTUNVMGuestIP   = "10.0.2.15"
	smartTUNVMIngress   = "scqavh0"
	smartTUNVMIngressIP = "198.51.100.1"
)

func smartTUNVMPolicySupported(o SmartTUNCandidateOptions) bool {
	if o.TunnelInterface != smartTUNVMInterface || o.UnderlayInterface != smartTUNVMUnderlay ||
		o.TunnelIPv4 != "172.31.99.1/30" || o.TunnelIPv6 != "" ||
		len(o.ProtectedCIDRs) != 1 || o.ProtectedCIDRs[0] != smartTUNVMEndpoint+"/32" ||
		len(o.DomesticCIDRs) != 1 || o.DomesticCIDRs[0] != "5.22.0.10/32" ||
		len(o.DomesticIPv6CIDRs) != 0 || len(o.ProtectedIPv6CIDRs) != 0 ||
		len(o.IPv6Exceptions) != 0 || len(o.DomainExceptions) != 0 ||
		len(o.Exceptions) > 8 {
		return false
	}
	// User-selected explicit IPv4 exceptions are supported inside the compiler's
	// bounded, disjoint public-CIDR policy; no unstated domain authority is added.
	for _, r := range o.Exceptions {
		if r.Via != "direct" && r.Via != "vpn" {
			return false
		}
		prefix, err := canonicalRoutePrefix(r.CIDR)
		if err != nil || routePrefixesOverlap(prefix, netip.MustParsePrefix("1.0.0.1/32")) {
			// The exact HTTPS health witness must remain VPN-required.
			return false
		}
	}
	return true
}

// smartTUNTrialLinkInventoryAllowed keeps the original Docker admission
// unchanged. A third link is admissible only as the fixed QEMU ingress fixture;
// the concrete kernel identity and address/route graph are checked separately.
func smartTUNTrialLinkInventoryAllowed(rows []map[string]json.RawMessage, underlay, tunnel string) bool {
	if len(rows) != 2 && len(rows) != 3 {
		return false
	}
	allowIngress := len(rows) == 3 && underlay == smartTUNVMUnderlay && tunnel == smartTUNVMInterface
	seen := map[string]bool{}
	indices := map[int]bool{}
	for _, row := range rows {
		name := selectiveText(row["ifname"])
		index, ok := selectiveInt(row["ifindex"])
		if !ok || index < 1 || indices[index] || name == "" || seen[name] || name == tunnel {
			return false
		}
		indices[index], seen[name] = true, true
		if name != "lo" && name != underlay && !(allowIngress && name == smartTUNVMIngress) {
			return false
		}
		if name == "lo" && index != 1 {
			return false
		}
	}
	return seen["lo"] && seen[underlay] && (len(rows) == 2 || seen[smartTUNVMIngress])
}

// The extra guest interface simulates a preexisting foreign-facing hosted
// origin, using RFC5737 TEST-NET-2 addresses inside a private QEMU guest.
// This is deliberately NOT public ingress or geographic-routing evidence.
func smartTUNVMIngressFixture() error {
	denied := func() error {
		return Fault("trial_unsupported", "VM ingress QA requires the exact isolated veth/address/route topology")
	}
	if err := smartTUNQAVMContext(); err != nil {
		return denied()
	}
	linkRaw, err := nativeIPJSON("-d", "-j", "link", "show", "dev", smartTUNVMIngress)
	if err != nil {
		return denied()
	}
	links, err := selectiveRows(linkRaw)
	if err != nil || len(links) != 1 || selectiveText(links[0]["ifname"]) != smartTUNVMIngress {
		return denied()
	}
	if !smartTUNVMIngressLinkValid(links[0]) {
		return denied()
	}
	ipv4, err := nativeIPJSON("-j", "-4", "address", "show", "dev", smartTUNVMIngress)
	if err != nil || !smartTUNVMIngressAddressValid(ipv4, false) {
		return denied()
	}
	ipv6, err := nativeIPJSON("-j", "-6", "address", "show", "dev", smartTUNVMIngress)
	if err != nil || !smartTUNVMIngressAddressValid(ipv6, true) {
		return denied()
	}
	routeRaw, err := nativeIPJSON("-j", "-4", "route", "show", "dev", smartTUNVMIngress)
	if err != nil {
		return denied()
	}
	routes, err := selectiveRows(routeRaw)
	if err != nil || !smartTUNVMIngressRouteValid(routes) {
		return denied()
	}
	return nil
}

func smartTUNVMIngressLinkValid(link map[string]json.RawMessage) bool {
	index, indexOK := selectiveInt(link["ifindex"])
	peerIndex, peerOK := selectiveInt(link["link_index"])
	_, nsOK := selectiveInt(link["link_netnsid"])
	var info struct {
		Kind string `json:"info_kind"`
	}
	var flags []string
	mtu, mtuOK := selectiveInt(link["mtu"])
	promiscuity, promOK := selectiveInt(link["promiscuity"])
	return indexOK && index >= 3 && peerOK && peerIndex > 1 && peerIndex != index && nsOK &&
		mtuOK && mtu == 1500 && promOK && promiscuity == 0 &&
		selectiveText(link["ifname"]) == smartTUNVMIngress &&
		selectiveText(link["operstate"]) == "UP" &&
		len(link["master"]) == 0 && len(link["ifalias"]) == 0 &&
		json.Unmarshal(link["linkinfo"], &info) == nil &&
		json.Unmarshal(link["flags"], &flags) == nil &&
		info.Kind == "veth" && linkFlagsContain(flags, "UP", "LOWER_UP", "BROADCAST")
}

func smartTUNVMIngressRouteValid(routes []map[string]json.RawMessage) bool {
	if len(routes) != 1 {
		return false
	}
	row := routes[0]
	for key, value := range row {
		switch key {
		case "dst", "dev", "protocol", "scope", "prefsrc":
		case "flags":
			var flags []string
			if json.Unmarshal(value, &flags) != nil || len(flags) != 0 {
				return false
			}
		default:
			return false
		}
	}
	return selectiveText(row["dst"]) == "198.51.100.0/30" &&
		selectiveText(row["dev"]) == smartTUNVMIngress &&
		selectiveText(row["protocol"]) == "kernel" &&
		selectiveText(row["scope"]) == "link" &&
		selectiveText(row["prefsrc"]) == smartTUNVMIngressIP
}

func linkFlagsContain(flags []string, wanted ...string) bool {
	present := map[string]bool{}
	for _, flag := range flags {
		if present[flag] {
			return false
		}
		present[flag] = true
	}
	for _, flag := range wanted {
		if !present[flag] {
			return false
		}
	}
	return true
}

func smartTUNVMIngressAddressValid(raw json.RawMessage, ipv6 bool) bool {
	var links []struct {
		Name string `json:"ifname"`
		Info []struct {
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
			Scope  string `json:"scope"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(raw, &links) != nil || len(links) != 1 ||
		links[0].Name != smartTUNVMIngress {
		return false
	}
	if !ipv6 {
		return len(links[0].Info) == 1 &&
			links[0].Info[0].Local == smartTUNVMIngressIP &&
			links[0].Info[0].Prefix == 30 &&
			links[0].Info[0].Scope == "global"
	}
	if len(links[0].Info) > 1 {
		return false
	}
	if len(links[0].Info) == 0 {
		return true // The exact disposable guest may have IPv6 disabled.
	}
	addr, err := netip.ParseAddr(links[0].Info[0].Local)
	return err == nil && addr.Is6() && addr.IsLinkLocalUnicast() &&
		links[0].Info[0].Prefix == 64 && links[0].Info[0].Scope == "link"
}

func smartTUNQAVMContext() error {
	denied := func() error {
		return Fault("unsupported_host", "Smart TUN non-Docker trials require the exact isolated Debian 13 US01 QEMU guest")
	}
	if os.Geteuid() != 0 {
		return denied()
	}
	if _, err := os.Stat("/.dockerenv"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return denied()
	}
	inspect := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 4096 {
			return ""
		}
		return strings.TrimSpace(string(data))
	}
	if inspect("/proc/1/comm") != "systemd" ||
		inspect("/sys/class/dmi/id/sys_vendor") != "QEMU" ||
		inspect("/sys/class/dmi/id/product_name") != "Standard PC (i440FX + PIIX, 1996)" {
		return denied()
	}
	host, err := os.Hostname()
	if err != nil || host != "sc-qa-vm-us01" {
		return denied()
	}
	release := inspect("/etc/os-release")
	if !strings.Contains("\n"+release+"\n", "\nID=debian\n") ||
		!strings.Contains("\n"+release+"\n", "\nVERSION_ID=\"13\"\n") {
		return denied()
	}
	if err := trustedHostIPExecutable(); err != nil {
		return err
	}
	tun, err := os.Stat("/dev/net/tun")
	if err != nil || tun.Mode()&os.ModeDevice == 0 || tun.Mode()&os.ModeCharDevice == 0 {
		return denied()
	}
	raw, err := nativeIPJSON("-j", "-4", "address", "show", "dev", smartTUNVMUnderlay)
	if err != nil {
		return denied()
	}
	var devices []struct {
		IfName string `json:"ifname"`
		Info   []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(raw, &devices) != nil || len(devices) != 1 ||
		devices[0].IfName != smartTUNVMUnderlay || len(devices[0].Info) != 1 ||
		devices[0].Info[0].Local != smartTUNVMGuestIP || devices[0].Info[0].PrefixLen != 24 {
		return denied()
	}
	if !bytes.Contains(raw, []byte(smartTUNVMGuestIP)) {
		return denied()
	}
	// A fresh SSH proof and the complete route/nft snapshot are checked by the
	// existing admission and confirmation paths, never inferred from DMI.
	return nil
}

func smartTUNNativeHostContext() error {
	if err := trialDisposableContext(); err == nil {
		return nil
	}
	return smartTUNQAVMContext()
}

func smartTUNNativeCandidateContext(opts SmartTUNCandidateOptions, peer string) error {
	if smartTUNTrialFixturePolicySupported(opts) && peer == "10.254.72.2" {
		return trialDisposableContext()
	}
	if smartTUNVMPolicySupported(opts) && peer == smartTUNVMEndpoint {
		return smartTUNQAVMContext()
	}
	return Fault("trial_unsupported", "unrecognized native Smart TUN trial topology or saved policy")
}

func smartTUNNativeJournalIdentity(record smartTUNTrialJournal) bool {
	if record.EndpointIP == "10.254.72.2" && record.ManagementPeerIP == "10.254.72.2" &&
		record.TunnelInterface == "sctunqa0" && record.UnderlayInterface == "scqaedge0" {
		return true
	}
	return record.EndpointIP == smartTUNVMEndpoint && record.ManagementPeerIP == smartTUNVMEndpoint &&
		record.TunnelInterface == smartTUNVMInterface && record.UnderlayInterface == smartTUNVMUnderlay &&
		record.Native != nil && record.Native.IPv4.Address == "172.31.99.1/30" &&
		record.Native.IPv6.Address == ""
}
