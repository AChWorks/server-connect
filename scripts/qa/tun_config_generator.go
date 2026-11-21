//go:build linux

// This is an isolated-guest-only configuration generator for Native DNS
// packet witnesses. It imports only the same official-Core Native compiler
// used by the installed product; there is no parallel TUN policy engine.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/AChWorks/server-connect/internal/sc"
)

func main() {
	mode := os.Getenv("SC_QA_TUN_NATIVE_DNS_MODE")
	if os.Getenv("SC_QA_TUN_NATIVE_DNS") != "yes" ||
		os.Getenv("SC_QA_TUN_IPV6") != "yes" ||
		(mode != "default" && mode != "bypass_iran") {
		fmt.Fprintln(os.Stderr, "Native DNS QA requires an explicit mode and dual-stack isolation")
		os.Exit(2)
	}
	profile := sc.Profile{Outbound: json.RawMessage(`{"type":"vless","tag":"upstream","server":"10.254.72.2","server_port":19182,"uuid":"c2902f3a-1c25-41ef-a8dc-760b483aa247"}`)}
	raw, err := sc.NativeSmartRoutingConfig(profile, sc.NativePolicyOptions{
		InterfaceName: "sctunqa0", UnderlayInterface: "scqaedge0",
		IPv4Address: "172.31.99.1/30", IPv6Address: "fd73:99::1/64",
		Mode: mode,
	}, []sc.SmartRoutingRule{
		{Type: "cidr", Value: "5.22.0.11/32", Via: "vpn"},
		{Type: "cidr", Value: "9.9.9.9/32", Via: "direct"},
		{Type: "cidr", Value: "2001:470:f486::11/128", Via: "vpn"},
		{Type: "cidr", Value: "2606:4700:5::10/128", Via: "vpn"},
		{Type: "cidr", Value: "2606:4700:5::11/128", Via: "direct"},
		{Type: "cidr", Value: "2606:4700:8::9/128", Via: "direct"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Native DNS QA config failed:", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(raw); err != nil {
		fmt.Fprintln(os.Stderr, "Native DNS QA output failed")
		os.Exit(1)
	}
}
