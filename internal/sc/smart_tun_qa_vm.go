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
	"syscall"
)

const (
	smartTUNVMEndpoint         = "10.0.2.2"
	smartTUNVMUnderlay         = "ens3"
	smartTUNVMInterface        = "scqavm0"
	smartTUNVMGuestIP          = "10.0.2.15"
	smartTUNVMIngress          = "scqavh0"
	smartTUNVMIngressIP        = "198.51.100.1"
	smartTUNVMIngressPeer      = "scqavn0"
	smartTUNVMIngressPeerIP    = "198.51.100.2"
	smartTUNVMIngressNamespace = "scqa-foreign"
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
	// A VPN DNS server is an explicit VM-only policy: never let it be
	// loopback/private/underlay, the protected HTTPS witness, a domestic
	// Direct target, or an operator-selected Direct exception.
	if o.DNSResolverIPv4 != "" {
		resolver, err := netip.ParseAddr(o.DNSResolverIPv4)
		if err != nil || !resolver.Is4() || !resolver.IsGlobalUnicast() || resolver.IsPrivate() ||
			resolver.IsLoopback() || resolver.IsLinkLocalUnicast() ||
			resolver.String() == "1.0.0.1" || resolver.String() == "5.22.0.10" {
			return false
		}
		for _, r := range o.Exceptions {
			prefix, err := canonicalRoutePrefix(r.CIDR)
			if err != nil || (r.Via == "direct" && prefix.Contains(resolver)) {
				return false
			}
		}
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
	// The local link_netnsid alone does NOT identify a named namespace.
	// Require the kernel NSID's exact named mapping and the pinned nsfs
	// inode, then verify the actual reciprocal peer inside that namespace.
	if !smartTUNVMIngressPeerFixture(links[0]) {
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
	// iproute2 omits "dev" from JSON when filtering by "dev". Inspect
	// the complete main table instead: every allowed fixture route must
	// carry an observable device identity in the kernel result.
	routeRaw, err := nativeIPJSON("-j", "-4", "route", "show", "table", "main")
	if err != nil {
		return denied()
	}
	routes, err := selectiveRows(routeRaw)
	if err != nil || !smartTUNVMIngressRouteValid(routes) {
		return denied()
	}
	// Existing RPDB policy must not redirect hosted replies around main.
	rulesRaw, err := nativeIPJSON("-j", "-4", "rule", "show")
	if err != nil || !smartTUNVMIngressDefaultRulesValid(rulesRaw) {
		return denied()
	}
	allRaw, err := nativeIPJSON("-j", "-4", "route", "show", "table", "all")
	all, allErr := selectiveRows(allRaw)
	if err != nil || allErr != nil || !smartTUNVMIngressAllTablesValid(all) {
		return denied()
	}
	// The effective FIB lookup uses current RPDB and MUST resolve replies
	// from the hosted IP back to the exact ingress device, no gateway.
	lookupRaw, err := nativeIPJSON("-j", "-4", "route", "get", smartTUNVMIngressPeerIP, "from", smartTUNVMIngressIP)
	if err != nil || !smartTUNVMIngressReplyRouteValid(lookupRaw) {
		return denied()
	}
	return nil
}

// The fixed peer is identified by the kernel's namespace ID mapping AND the
// root-owned named NSFS inode. A structurally valid veth in some other netns
// must not be admitted. Re-observe the namespace mount after inspecting it.
func smartTUNVMIngressNamedNamespaceValid(nsid int, rows []map[string]json.RawMessage) bool {
	if nsid < 0 || len(rows) != 1 ||
		selectiveText(rows[0]["name"]) != smartTUNVMIngressNamespace {
		return false
	}
	got, ok := selectiveInt(rows[0]["nsid"])
	return ok && got == nsid
}

func smartTUNVMIngressNamespaceIdentity() (uint64, uint64, bool) {
	const nsfsMagic = 0x6e736673 // Linux NSFS_MAGIC
	fd, err := syscall.Open("/run/netns/"+smartTUNVMIngressNamespace,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, 0, false
	}
	defer syscall.Close(fd)
	var named syscall.Stat_t
	var fs syscall.Statfs_t
	if syscall.Fstat(fd, &named) != nil || syscall.Fstatfs(fd, &fs) != nil ||
		uint64(fs.Type) != nsfsMagic || named.Uid != 0 || named.Ino == 0 {
		return 0, 0, false
	}
	rootDev, rootIno, err := nativeTUNNamespace()
	if err != nil || (uint64(named.Dev) == rootDev && named.Ino == rootIno) {
		return 0, 0, false
	}
	return uint64(named.Dev), named.Ino, true
}

// Bind both directions: root link's peer ifindex in named namespace, peer's
// reciprocal link_index back to root, and the exact peer subnet/route.
func smartTUNVMIngressPeerLinkValid(root, peer map[string]json.RawMessage) bool {
	localIf, okLocal := selectiveInt(root["ifindex"])
	peerIf, okPeer := selectiveInt(root["link_index"])
	observedIf, okObserved := selectiveInt(peer["ifindex"])
	back, okBack := selectiveInt(peer["link_index"])
	_, nsBack := selectiveInt(peer["link_netnsid"])
	mtu, okMTU := selectiveInt(peer["mtu"])
	prom, okProm := selectiveInt(peer["promiscuity"])
	var info struct {
		Kind string `json:"info_kind"`
	}
	var flags []string
	return okLocal && okPeer && okObserved && okBack && nsBack &&
		localIf > 1 && peerIf > 1 && peerIf == observedIf && back == localIf &&
		okMTU && mtu == 1500 && okProm && prom == 0 &&
		selectiveText(peer["ifname"]) == smartTUNVMIngressPeer &&
		selectiveText(peer["operstate"]) == "UP" &&
		len(peer["master"]) == 0 && len(peer["ifalias"]) == 0 &&
		json.Unmarshal(peer["linkinfo"], &info) == nil && info.Kind == "veth" &&
		json.Unmarshal(peer["flags"], &flags) == nil &&
		linkFlagsContain(flags, "UP", "LOWER_UP", "BROADCAST")
}

func smartTUNVMIngressPeerRoutesValid(rows []map[string]json.RawMessage) bool {
	if len(rows) != 1 || smartTUNVMIngressAmbiguousRoute(rows[0]) {
		return false
	}
	row := rows[0]
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
		selectiveText(row["dev"]) == smartTUNVMIngressPeer &&
		selectiveText(row["protocol"]) == "kernel" &&
		selectiveText(row["scope"]) == "link" &&
		selectiveText(row["prefsrc"]) == smartTUNVMIngressPeerIP
}

func smartTUNVMIngressPeerFixture(root map[string]json.RawMessage) bool {
	nsid, ok := selectiveInt(root["link_netnsid"])
	if !ok || nsid < 0 {
		return false
	}
	dev, ino, ok := smartTUNVMIngressNamespaceIdentity()
	if !ok {
		return false
	}
	idsRaw, err := nativeIPJSON("-j", "netns", "list-id")
	if err != nil {
		return false
	}
	ids, err := selectiveRows(idsRaw)
	if err != nil || !smartTUNVMIngressNamedNamespaceValid(nsid, ids) {
		return false
	}
	linkRaw, err := nativeIPJSON("-d", "-j", "-n", smartTUNVMIngressNamespace, "link", "show")
	if err != nil {
		return false
	}
	links, err := selectiveRows(linkRaw)
	if err != nil || len(links) != 2 {
		return false
	}
	var peer map[string]json.RawMessage
	seenLo := false
	for _, row := range links {
		if selectiveText(row["ifname"]) == "lo" {
			idx, ok := selectiveInt(row["ifindex"])
			if !ok || idx != 1 || seenLo {
				return false
			}
			seenLo = true
		} else if selectiveText(row["ifname"]) == smartTUNVMIngressPeer && peer == nil {
			peer = row
		} else {
			return false
		}
	}
	if !seenLo || peer == nil || !smartTUNVMIngressPeerLinkValid(root, peer) {
		return false
	}
	addr4, err := nativeIPJSON("-j", "-n", smartTUNVMIngressNamespace, "-4", "address", "show", "dev", smartTUNVMIngressPeer)
	if err != nil || !smartTUNVMIngressAddressValidFor(addr4, smartTUNVMIngressPeer, smartTUNVMIngressPeerIP, false) {
		return false
	}
	addr6, err := nativeIPJSON("-j", "-n", smartTUNVMIngressNamespace, "-6", "address", "show", "dev", smartTUNVMIngressPeer)
	if err != nil || !smartTUNVMIngressAddressValidFor(addr6, smartTUNVMIngressPeer, smartTUNVMIngressPeerIP, true) {
		return false
	}
	routeRaw, err := nativeIPJSON("-j", "-n", smartTUNVMIngressNamespace, "-4", "route", "show", "table", "main")
	if err != nil {
		return false
	}
	routes, err := selectiveRows(routeRaw)
	if err != nil || !smartTUNVMIngressPeerRoutesValid(routes) {
		return false
	}
	peerRules, err := nativeIPJSON("-j", "-n", smartTUNVMIngressNamespace, "-4", "rule", "show")
	if err != nil || !smartTUNVMIngressDefaultRulesValid(peerRules) {
		return false
	}
	lastDev, lastIno, ok := smartTUNVMIngressNamespaceIdentity()
	return ok && dev == lastDev && ino == lastIno
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
	matched := 0
	for _, row := range routes {
		if smartTUNVMIngressAmbiguousRoute(row) {
			return false
		}
		if selectiveText(row["dev"]) != smartTUNVMIngress {
			// A foreign route for a host or any overlapping prefix can
			// silently steal reply packets even while our connected route
			// remains installed. The original underlay default and unrelated
			// local routes are retained, never adopted as task-owned.
			if smartTUNVMIngressForeignDestinationOverlaps(selectiveText(row["dst"])) ||
				selectiveText(row["prefsrc"]) == smartTUNVMIngressIP {
				return false
			}
			continue
		}
		matched++
		if matched != 1 {
			return false
		}
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
		if selectiveText(row["dst"]) != "198.51.100.0/30" ||
			selectiveText(row["protocol"]) != "kernel" ||
			selectiveText(row["scope"]) != "link" ||
			selectiveText(row["prefsrc"]) != smartTUNVMIngressIP {
			return false
		}
	}
	return matched == 1
}

// Any nested device reference, external nexthop ID or unknown routing
// indirection is deliberately unsupported in this exact QA-only topology.
// Such rows cannot silently pass just because they omit a top-level "dev".
func smartTUNVMIngressAmbiguousRoute(row map[string]json.RawMessage) bool {
	for _, key := range []string{"nexthops", "multipath", "nhid", "via", "encap", "encap_type"} {
		if _, exists := row[key]; exists {
			return true
		}
	}
	return false
}

// Kernel defaults are the only allowed IPv4 RPDB rules for this fixture.
// Any new priority, lookup table or selector must fail before Guard prearm.
func smartTUNVMIngressDefaultRulesValid(raw json.RawMessage) bool {
	rows, err := selectiveRows(raw)
	if err != nil || len(rows) != 3 {
		return false
	}
	want := map[int]string{0: "local", 32766: "main", 32767: "default"}
	for _, row := range rows {
		p, ok := selectiveInt(row["priority"])
		if !ok || len(row) != 3 || selectiveText(row["src"]) != "all" ||
			selectiveText(row["table"]) != want[p] {
			return false
		}
		delete(want, p)
	}
	return len(want) == 0
}

func smartTUNVMIngressAllTablesValid(routes []map[string]json.RawMessage) bool {
	main := []map[string]json.RawMessage{}
	localHost, localBroadcast := 0, 0
	for _, row := range routes {
		if smartTUNVMIngressAmbiguousRoute(row) {
			return false
		}
		table := selectiveText(row["table"])
		if table == "" || table == "main" {
			main = append(main, row)
			continue
		}
		dev := selectiveText(row["dev"])
		if dev != smartTUNVMIngress {
			if smartTUNVMIngressForeignDestinationOverlaps(selectiveText(row["dst"])) ||
				selectiveText(row["prefsrc"]) == smartTUNVMIngressIP {
				return false
			}
			continue
		}
		if table != "local" || selectiveText(row["protocol"]) != "kernel" ||
			selectiveText(row["prefsrc"]) != smartTUNVMIngressIP {
			return false
		}
		var flags []string
		if json.Unmarshal(row["flags"], &flags) != nil || len(flags) != 0 ||
			len(row) != 8 { // exact local type,dst,dev,table,protocol,scope,prefsrc,flags
			return false
		}
		if selectiveText(row["type"]) == "local" &&
			selectiveText(row["dst"]) == smartTUNVMIngressIP &&
			selectiveText(row["scope"]) == "host" {
			localHost++
		} else if selectiveText(row["type"]) == "broadcast" &&
			selectiveText(row["dst"]) == "198.51.100.3" &&
			selectiveText(row["scope"]) == "link" {
			localBroadcast++
		} else {
			return false
		}
	}
	return localHost == 1 && localBroadcast == 1 && smartTUNVMIngressRouteValid(main)
}

func smartTUNVMIngressReplyRouteValid(raw json.RawMessage) bool {
	rows, err := selectiveRows(raw)
	if err != nil || len(rows) != 1 {
		return false
	}
	row := rows[0]
	if smartTUNVMIngressAmbiguousRoute(row) ||
		selectiveText(row["dst"]) != smartTUNVMIngressPeerIP ||
		selectiveText(row["from"]) != smartTUNVMIngressIP ||
		selectiveText(row["dev"]) != smartTUNVMIngress ||
		len(row["gateway"]) != 0 {
		return false
	}
	var flags []string
	return json.Unmarshal(row["flags"], &flags) == nil && len(flags) == 0
}

// The default underlay route is intentionally allowed, but no more-specific
// foreign path may intersect the independently verified fixture subnet.
func smartTUNVMIngressForeignDestinationOverlaps(dst string) bool {
	if dst == "default" {
		return false
	}
	fixture := netip.MustParsePrefix("198.51.100.0/30")
	if prefix, err := netip.ParsePrefix(dst); err == nil {
		return prefix.Overlaps(fixture)
	}
	if addr, err := netip.ParseAddr(dst); err == nil {
		return fixture.Contains(addr)
	}
	return true // Unknown kernel destination is not provably disjoint.
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
	return smartTUNVMIngressAddressValidFor(raw, smartTUNVMIngress, smartTUNVMIngressIP, ipv6)
}

func smartTUNVMIngressAddressValidFor(raw json.RawMessage, name, expectedIP string, ipv6 bool) bool {
	var links []struct {
		Name string `json:"ifname"`
		Info []struct {
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
			Scope  string `json:"scope"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(raw, &links) != nil || len(links) != 1 ||
		links[0].Name != name {
		return false
	}
	if !ipv6 {
		return len(links[0].Info) == 1 &&
			links[0].Info[0].Local == expectedIP &&
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
