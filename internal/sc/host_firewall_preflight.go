package sc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const nativeNFTPath = "/usr/sbin/nft"
const firewallSnapshotMaxBytes = 4 << 20
const firewallCommandTimeout = 5 * time.Second
const firewallPipeWaitDelay = 250 * time.Millisecond
const firewallMaxObjects = 10000

var firewallDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// HostFirewallObservation is a privacy-preserving fingerprint of ONE
// independent, non-atomic nftables observation. It does not authenticate
// firewall ownership or indicate that any VPN/activation guard is safe.
type HostFirewallObservation struct {
	Observed      bool   `json:"observed"`
	RulesetSHA256 string `json:"ruleset_sha256"`
	ObjectCount   int    `json:"object_count"`
}

// Counted traffic must not be reported as a policy edit. Strip only
// packet/byte counters: quota consumption, limits, timeouts and all other
// potentially decision-relevant values must remain observable as drift.
func normalizeNftVolatile(value any) {
	switch node := value.(type) {
	case []any:
		for _, child := range node {
			normalizeNftVolatile(child)
		}
	case map[string]any:
		for key, child := range node {
			if key == "counter" {
				if stats, ok := child.(map[string]any); ok {
					delete(stats, "packets")
					delete(stats, "bytes")
				}
			}
			normalizeNftVolatile(child)
		}
	}
}

// decodeNFTSnapshot accepts only the actual nft -j list ruleset envelope.
// Its fingerprint preserves ordered rules and precise large integer values,
// without exposing potentially sensitive firewall/hosting addresses.
func decodeNFTSnapshot(raw []byte) (HostFirewallObservation, error) {
	bad := func() error {
		return Fault("host_preflight_unavailable", "native nftables observation is malformed or unsupported")
	}
	if len(raw) == 0 || len(raw) > firewallSnapshotMaxBytes {
		return HostFirewallObservation{}, bad()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var top map[string]any
	if err := decoder.Decode(&top); err != nil || len(top) != 1 {
		return HostFirewallObservation{}, bad()
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return HostFirewallObservation{}, bad()
	}
	entries, ok := top["nftables"].([]any)
	if !ok || len(entries) > firewallMaxObjects {
		return HostFirewallObservation{}, bad()
	}
	for _, entry := range entries {
		item, ok := entry.(map[string]any)
		if !ok || len(item) != 1 {
			return HostFirewallObservation{}, bad()
		}
		for key, value := range item {
			if strings.TrimSpace(key) == "" || value == nil {
				return HostFirewallObservation{}, bad()
			}
		}
	}
	normalizeNftVolatile(top)
	canonical, err := json.Marshal(top)
	if err != nil {
		return HostFirewallObservation{}, bad()
	}
	sha := sha256.Sum256(canonical)
	return HostFirewallObservation{
		Observed: true, RulesetSHA256: hex.EncodeToString(sha[:]),
		ObjectCount: len(entries),
	}, nil
}

// observeNftables always runs one fixed root-owned native binary, never a
// shell or PATH-selected executable. The test seam takes an explicit path
// only inside tests; the product performs no nftables mutation or restore.
func observeNftables() (HostFirewallObservation, error) {
	if err := verifyTrustedIPPath("/", nativeNFTPath, 0); err != nil {
		return HostFirewallObservation{}, Fault("host_preflight_unavailable", "trusted native nftables executable unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), firewallCommandTimeout)
	defer cancel()
	return runNFTJSONCommand(ctx, nativeNFTPath)
}

func runNFTJSONCommand(ctx context.Context, executable string) (HostFirewallObservation, error) {
	command := exec.CommandContext(ctx, executable, "-j", "list", "ruleset")
	command.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin"}
	command.Dir = "/"
	command.WaitDelay = firewallPipeWaitDelay
	var stdout boundedFirewallOutput
	command.Stdout = &stdout
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return HostFirewallObservation{}, Fault("host_preflight_unavailable", "native nftables observation timed out")
		}
		return HostFirewallObservation{}, Fault("host_preflight_unavailable", "native nftables observation failed or did not finish")
	}
	return decodeNFTSnapshot(stdout.Bytes())
}

type boundedFirewallOutput struct{ bytes.Buffer }

func (b *boundedFirewallOutput) Write(data []byte) (int, error) {
	if len(data) > firewallSnapshotMaxBytes-b.Len() {
		return 0, errors.New("native nftables output exceeds limit")
	}
	return b.Buffer.Write(data)
}

// InspectHostRoutesAndFirewall upgrades the normal read-only route preflight
// with a separately observed firewall fingerprint. The two snapshots are not
// atomic; they do NOT authorize host mutation, reserve ownership, or prove
// activation readiness. Failure of either observation returns no false proof.
func InspectHostRoutesAndFirewall(endpointIP, managementPeerIP string) (HostPreflight, error) {
	report, err := InspectHostRoutes(endpointIP, managementPeerIP)
	if err != nil {
		return HostPreflight{}, err
	}
	firewall, err := observeNftables()
	if err != nil {
		return HostPreflight{}, err
	}
	report.Firewall = &firewall
	report.Mode = "observation_with_nftables" // A caller cannot drop only the required field.
	report.Limitations = append(report.Limitations,
		"nftables is fingerprinted read-only; traffic counters are ignored, but firewall ownership, conntrack and atomic Apply remain unverified.")
	return report, nil
}
