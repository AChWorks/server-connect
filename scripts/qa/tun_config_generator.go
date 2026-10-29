//go:build linux

// QA-only config generator. The pinned test credentials and IPs are synthetic;
// no real VPN profile, release artifact, or production Apply is involved.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/AChWorks/server-connect/internal/sc"
	"os"
)

func main() {
	profile := sc.Profile{Outbound: json.RawMessage(`{"type":"vless","tag":"upstream","server":"10.254.72.2","server_port":19182,"uuid":"c2902f3a-1c25-41ef-a8dc-760b483aa247"}`)}
	opts := sc.SmartTUNCandidateOptions{
		TunnelInterface:   "sctunqa0",
		UnderlayInterface: "scqaedge0",
		TunnelIPv4:        "172.31.99.1/30",
		ProtectedCIDRs:    []string{"10.254.72.0/30"},
		// Test prefix denotes the simulated domestic endpoint in the guest.
		// This is NOT an authenticated or complete Iran-prefix database.
		DomesticCIDRs: []string{"5.22.0.10/32"},
		DomainExceptions: []sc.SmartTUNDomainException{
			{Domain: "scqa.test", Suffix: true, Via: "vpn"},
			{Domain: "only-exact.test", Via: "vpn"},
		},
	}
	// Fail-closed IPv4 input trials are configuration generation ONLY;
	// the disconnected guest never starts a TUN using these invalid values.
	switch os.Getenv("SC_QA_TUN_IPV4_ADMISSION") {
	case "":
	case "broad-operator-direct":
		opts.Exceptions = []sc.SmartTUNCIDRException{{CIDR: "20.0.0.0/8", Via: "direct"}}
	case "aggregate-operator-direct":
		for i := 0; i < 65; i++ {
			opts.Exceptions = append(opts.Exceptions, sc.SmartTUNCIDRException{
				CIDR: fmt.Sprintf("20.%d.0.0/24", i), Via: "direct",
			})
		}
	case "broad-domestic-direct":
		opts.DomesticCIDRs = []string{"8.0.0.0/7"}
	case "aggregate-domestic-direct":
		opts.DomesticCIDRs = []string{"8.0.0.0/8", "9.0.0.0/8", "11.0.0.0/8"}
	case "domestic-rfc1918-overlap":
		opts.DomesticCIDRs = []string{"172.0.0.0/8"}
	case "domestic-link-local-overlap":
		opts.DomesticCIDRs = []string{"169.0.0.0/8"}
	case "domestic-special-anycast":
		opts.DomesticCIDRs = []string{"192.88.99.2/32"}
	default:
		fmt.Fprintln(os.Stderr, "Unsupported isolated IPv4 admission QA mode")
		os.Exit(2)
	}
	// Dual-stack is an isolated-guest-only explicitly opted-in proof.
	// All addresses below are synthetic: no real Iran/foreign classification.
	switch os.Getenv("SC_QA_TUN_IPV6") {
	case "":
	case "yes":
		opts.TunnelIPv6 = "fd73:99::1/64"
		opts.DomesticIPv6CIDRs = []string{"2001:db8:5::/64"}
		opts.IPv6Exceptions = []sc.SmartTUNCIDRException{
			{CIDR: "2001:db8:5::10/128", Via: "vpn"},
			{CIDR: "2001:db8:8::9/128", Via: "direct"},
		}
	default:
		fmt.Fprintln(os.Stderr, "Unsupported isolated IPv6 QA mode")
		os.Exit(2)
	}
	cfg, err := sc.SmartTUNCandidateConfig(profile, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "QA candidate generation failed:", err)
		os.Exit(1)
	}
	if _, err = os.Stdout.Write(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "QA output failed")
		os.Exit(1)
	}
}
