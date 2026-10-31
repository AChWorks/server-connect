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
