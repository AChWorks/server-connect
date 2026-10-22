package sc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

const nativeIPPath = "/usr/bin/ip"
const hostSnapshotMaxBytes = 1 << 20

// HostRouteLookup records what the local Linux kernel would route, not
// evidence that packets reach the target or that a tunnel is safe to activate.
type HostRouteLookup struct {
	Target      string          `json:"target"`
	Family      string          `json:"family"`
	KernelRoute json.RawMessage `json:"kernel_route"`
}

// HostPreflight is observational only. The multi-command snapshot is not
// atomic and must never be used as an activation journal or ownership proof.
type HostPreflight struct {
	Mode            string           `json:"mode"`
	ReadOnly        bool             `json:"read_only"`
	SnapshotAtomic  bool             `json:"snapshot_atomic"`
	ActivationReady bool             `json:"activation_ready"`
	Links           json.RawMessage  `json:"links"`
	IPv4Routes      json.RawMessage  `json:"ipv4_routes"`
	IPv6Routes      json.RawMessage  `json:"ipv6_routes"`
	IPv4Rules       json.RawMessage  `json:"ipv4_rules"`
	IPv6Rules       json.RawMessage  `json:"ipv6_rules"`
	Endpoint        *HostRouteLookup `json:"endpoint,omitempty"`
	ManagementPeer  *HostRouteLookup `json:"management_peer,omitempty"`
	Limitations     []string         `json:"limitations"`
}

func parsePreflightAddress(value, label string) (netip.Addr, error) {
	if value == "" {
		return netip.Addr{}, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.IsValid() || addr.Zone() != "" || addr.Is4In6() ||
		addr.IsUnspecified() || addr.IsMulticast() {
		return netip.Addr{}, Fault("invalid_arguments", label+" requires a literal unicast IPv4 or IPv6 address (no hostname or DNS lookup)")
	}
	return addr, nil
}

// A fixed, root-owned native iproute2 executable prevents PATH or loader
// hijacking when an operator invokes the manager with elevated privileges.
func trustedHostIPExecutable() error {
	if runtime.GOOS != "linux" {
		return Fault("host_preflight_unavailable", "host network inspection requires Linux")
	}
	for _, path := range []string{"/", "/usr", "/usr/bin", nativeIPPath} {
		info, err := os.Lstat(path)
		if err != nil {
			return Fault("host_preflight_unavailable", "native iproute2 executable unavailable")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return Fault("host_preflight_unavailable", "native iproute2 path is not trusted")
		}
		if path == nativeIPPath {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
				return Fault("host_preflight_unavailable", "native iproute2 executable unavailable")
			}
		} else if !info.IsDir() {
			return Fault("host_preflight_unavailable", "native iproute2 directory is not trusted")
		}
	}
	return nil
}

type boundedIPOutput struct {
	bytes.Buffer
}

func (b *boundedIPOutput) Write(p []byte) (int, error) {
	if len(p) > hostSnapshotMaxBytes-b.Len() {
		return 0, errors.New("native route inspection output exceeded limit")
	}
	return b.Buffer.Write(p)
}

func decodeRouteArray(data []byte) (json.RawMessage, error) {
	var rows []json.RawMessage
	if err := json.Unmarshal(data, &rows); err != nil || rows == nil {
		return nil, Fault("host_preflight_unavailable", "native route inspection returned invalid JSON")
	}
	for _, row := range rows {
		if len(row) == 0 || row[0] != '{' {
			return nil, Fault("host_preflight_unavailable", "native route inspection returned unexpected JSON")
		}
	}
	return json.RawMessage(bytes.TrimSpace(data)), nil
}

func nativeIPJSON(args ...string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, nativeIPPath, args...)
	// No inherited PATH, LD_*, APT or user-specific execution policy.
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin"}
	var out boundedIPOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, Fault("host_preflight_unavailable", "native route inspection failed; check iproute2 and permissions")
	}
	return decodeRouteArray(out.Bytes())
}

func lookupHostRoute(addr netip.Addr) (*HostRouteLookup, error) {
	if !addr.IsValid() {
		return nil, nil
	}
	family, flag := "ipv4", "-4"
	if addr.Is6() {
		family, flag = "ipv6", "-6"
	}
	data, err := nativeIPJSON("-j", flag, "route", "get", addr.String())
	if err != nil {
		return nil, err
	}
	return &HostRouteLookup{Target: addr.String(), Family: family, KernelRoute: data}, nil
}

// InspectHostRoutes performs no route, rule, DNS, firewall, service, profile or
// state changes. It cannot authorize tunnel activation, even when all lookups
// succeed. Only literal IPs are accepted; it deliberately never uses DNS.
func InspectHostRoutes(endpointIP, managementPeerIP string) (HostPreflight, error) {
	endpoint, err := parsePreflightAddress(endpointIP, "endpoint")
	if err != nil {
		return HostPreflight{}, err
	}
	peer, err := parsePreflightAddress(managementPeerIP, "management peer")
	if err != nil {
		return HostPreflight{}, err
	}
	if err = trustedHostIPExecutable(); err != nil {
		return HostPreflight{}, err
	}
	report := HostPreflight{
		Mode:            "observation_only",
		ReadOnly:        true,
		SnapshotAtomic:  false,
		ActivationReady: false,
		Limitations: []string{
			"Kernel route lookup does not prove endpoint reachability or DNS bootstrap.",
			"Snapshot is non-atomic and does not establish route, interface or firewall ownership.",
			"SSH reply safety, ingress, nftables/conntrack, activation and runtime recovery guards are not verified.",
		},
	}
	for _, observation := range []struct {
		args []string
		dst  *json.RawMessage
	}{
		{[]string{"-j", "link", "show"}, &report.Links},
		{[]string{"-j", "-4", "route", "show", "table", "all"}, &report.IPv4Routes},
		{[]string{"-j", "-6", "route", "show", "table", "all"}, &report.IPv6Routes},
		{[]string{"-j", "-4", "rule", "show"}, &report.IPv4Rules},
		{[]string{"-j", "-6", "rule", "show"}, &report.IPv6Rules},
	} {
		data, e := nativeIPJSON(observation.args...)
		if e != nil {
			return report, e
		}
		*observation.dst = data
	}
	if report.Endpoint, err = lookupHostRoute(endpoint); err != nil {
		return report, err
	}
	if report.ManagementPeer, err = lookupHostRoute(peer); err != nil {
		return report, err
	}
	return report, nil
}
