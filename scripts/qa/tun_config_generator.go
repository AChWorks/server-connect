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
	cfg, err := sc.SmartTUNCandidateConfig(profile, sc.SmartTUNCandidateOptions{
		TunnelInterface:   "sctunqa0",
		UnderlayInterface: "scqaedge0",
		TunnelIPv4:        "172.31.99.1/30",
		ProtectedCIDRs:    []string{"10.254.72.0/30"},
		// Test prefix denotes the simulated domestic endpoint in the guest.
		// This is NOT an authenticated or complete Iran-prefix database.
		DomesticCIDRs: []string{"5.22.0.10/32"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "QA candidate generation failed:", err)
		os.Exit(1)
	}
	if _, err = os.Stdout.Write(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "QA output failed")
		os.Exit(1)
	}
}
