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
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const nativeIPPath = "/usr/bin/ip"
const hostSnapshotMaxBytes = 1 << 20
const nativeIPCommandTimeout = 5 * time.Second
const nativeIPPipeWaitDelay = 250 * time.Millisecond

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
	// GlobalUnicast includes RFC1918 IPv4 and IPv6 ULA, but excludes the
	// IPv4 limited broadcast address. Loopback is intentionally supported.
	// Reject both families' link-local destinations: this CLI does not take
	// an interface scope and cannot unambiguously identify their route.
	if err != nil || !addr.IsValid() || addr.Zone() != "" || addr.Is4In6() ||
		(!addr.IsGlobalUnicast() && !addr.IsLoopback()) || addr.IsLinkLocalUnicast() {
		return netip.Addr{}, Fault("invalid_arguments", label+" requires a literal unicast IPv4 or IPv6 address (no broadcast, link-local or DNS lookup)")
	}
	return addr, nil
}

// A fixed, root-owned native iproute2 executable prevents PATH or loader
// hijacking when an operator invokes the manager with elevated privileges.
func trustedHostIPExecutable() error {
	if runtime.GOOS != "linux" {
		return Fault("host_preflight_unavailable", "host network inspection requires Linux")
	}
	return verifyTrustedIPPath("/", nativeIPPath, 0)
}

// verifyTrustedIPPath checks each directory starting at root and the final
// executable using Lstat, never following symlinks. The configurable owner
// and root exist only to test the same production trust boundary with private
// filesystem fixtures; production always specifies /usr/bin/ip and UID 0.
func verifyTrustedIPPath(root, executable string, ownerUID uint32) error {
	badPath := func() error {
		return Fault("host_preflight_unavailable", "native iproute2 path is not trusted")
	}
	if !filepath.IsAbs(root) || !filepath.IsAbs(executable) ||
		filepath.Clean(root) != root || filepath.Clean(executable) != executable {
		return badPath()
	}
	relative, err := filepath.Rel(root, executable)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return badPath()
	}
	parts := strings.Split(relative, string(filepath.Separator))
	current := root
	for i := 0; i <= len(parts); i++ {
		if i > 0 {
			current = filepath.Join(current, parts[i-1])
		}
		info, err := os.Lstat(current)
		if err != nil {
			return badPath()
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != ownerUID || info.Mode().Perm()&0022 != 0 {
			return badPath()
		}
		if i < len(parts) {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return badPath()
			}
		} else if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 ||
			info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return Fault("host_preflight_unavailable", "native iproute2 executable unavailable or untrusted")
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
	ctx, cancel := context.WithTimeout(context.Background(), nativeIPCommandTimeout)
	defer cancel()
	// No production caller can select another executable.
	return runIPJSONCommand(ctx, nativeIPPath, args...)
}

// runIPJSONCommand is shared with controlled process-lifecycle regression
// fixtures; production always uses the fixed, previously trust-checked
// /usr/bin/ip. WaitDelay bounds post-exit pipes held open by descendants.
func runIPJSONCommand(ctx context.Context, executable string, args ...string) (json.RawMessage, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.WaitDelay = nativeIPPipeWaitDelay
	// No inherited PATH, LD_*, APT or user-specific execution policy.
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin"}
	var out boundedIPOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, Fault("host_preflight_unavailable", "native route inspection timed out")
		}
		if errors.Is(err, exec.ErrWaitDelay) {
			return nil, Fault("host_preflight_unavailable", "native route inspection output pipe did not close in time")
		}
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
