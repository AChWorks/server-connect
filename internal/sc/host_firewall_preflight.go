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
	"strconv"
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

// Native -j list ruleset counter output contains both packet and byte counts,
// each a uint64 JSON integer. Optional initial values are valid for nft JSON
// input only. Validate complete output before removing volatile fields.
func validNftCounterValues(counter map[string]any) bool {
	for _, field := range []string{"packets", "bytes"} {
		value, present := counter[field]
		if !present {
			return false
		}
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		if _, err := strconv.ParseUint(number.String(), 10, 64); err != nil {
			return false
		}
	}
	return true
}

// Counted traffic must not be reported as a policy edit. Validate native
// named/anonymous counters before stripping their volatile packet/byte values.
// A named-counter reference is a string and must not be normalized away.
// Quota consumption, limits and other policy-relevant values remain hashed.
func normalizeNftVolatile(value any) bool {
	switch node := value.(type) {
	case []any:
		for _, child := range node {
			if !normalizeNftVolatile(child) {
				return false
			}
		}
	case map[string]any:
		for key, child := range node {
			if key == "counter" {
				switch stats := child.(type) {
				case map[string]any:
					if !validNftCounterValues(stats) {
						return false
					}
					delete(stats, "packets")
					delete(stats, "bytes")
				case string:
					if stats == "" {
						return false
					}
				default:
					return false
				}
			}
			if !normalizeNftVolatile(child) {
				return false
			}
		}
	}
	return true
}

// validNftObject checks the documented libnftables JSON envelope and the
// minimum identity of each supported ruleset object. It is NOT an nftables
// rule interpreter: opaque rule/set expressions are still hashed exactly.
// Unknown output kinds or incomplete object identities fail closed.
func validNftObject(kind string, value any) bool {
	fields, ok := value.(map[string]any)
	if !ok || len(fields) == 0 {
		return false
	}
	presentString := func(name string) bool {
		text, ok := fields[name].(string)
		return ok && text != "" && strings.TrimSpace(text) == text
	}
	// Native rules are identified by their table/chain/handle rather than
	// a name. Other listed objects are named. Only tables have no parent.
	if !presentString("family") ||
		(kind != "rule" && !presentString("name")) ||
		(kind != "table" && !presentString("table")) {
		return false
	}
	switch kind {
	case "table", "chain", "counter", "quota", "ct helper", "limit",
		"ct timeout", "ct expectation":
	case "rule":
		if !presentString("chain") {
			return false
		}
		expressions, ok := fields["expr"].([]any)
		if !ok || len(expressions) == 0 {
			return false
		}
		for _, expression := range expressions {
			statement, ok := expression.(map[string]any)
			if !ok || len(statement) != 1 {
				return false
			}
			for name := range statement {
				if name == "" || strings.TrimSpace(name) != name {
					return false
				}
			}
		}
	case "set", "map":
		// Datatypes may be a string, concatenated list or typeof object.
		switch datatype := fields["type"].(type) {
		case string:
			if datatype == "" {
				return false
			}
		case []any:
			if len(datatype) == 0 {
				return false
			}
			for _, part := range datatype {
				value, ok := part.(string)
				if !ok || value == "" {
					return false
				}
			}
		case map[string]any:
			if len(datatype) != 1 || datatype["typeof"] == nil {
				return false
			}
		default:
			return false
		}
		if kind == "map" && !presentString("map") {
			return false
		}
	case "element":
		if fields["elem"] == nil {
			return false
		}
	case "flowtable":
		if !presentString("hook") {
			return false
		}
		priority, ok := fields["prio"].(json.Number)
		if !ok {
			return false
		}
		// The Linux flowtable hook priority is a signed 32-bit int.
		// Reject values the native kernel cannot represent, before hashing.
		if _, err := strconv.ParseInt(priority.String(), 10, 32); err != nil {
			return false
		}
		validDevice := func(value any) bool {
			name, ok := value.(string)
			return ok && name != "" && strings.TrimSpace(name) == name
		}
		switch devices := fields["dev"].(type) {
		case string:
			if !validDevice(devices) {
				return false
			}
		case []any:
			if len(devices) == 0 {
				return false
			}
			for _, device := range devices {
				if !validDevice(device) {
					return false
				}
			}
		default:
			return false
		}
	default:
		return false
	}
	return true
}

// A genuine -j list ruleset always begins with libnftables metadata, even
// when the ruleset has no tables. Only schema version 1 is recognized here;
// newer output must be reviewed before its fingerprint may be trusted.
func validNftMetainfo(value any) bool {
	metadata, ok := value.(map[string]any)
	if !ok {
		return false
	}
	for _, key := range []string{"version", "release_name"} {
		text, ok := metadata[key].(string)
		if !ok || text == "" || strings.TrimSpace(text) != text {
			return false
		}
	}
	schema, ok := metadata["json_schema_version"].(json.Number)
	return ok && schema.String() == "1"
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
	if !ok || len(entries) == 0 || len(entries) > firewallMaxObjects {
		return HostFirewallObservation{}, bad()
	}
	first, ok := entries[0].(map[string]any)
	if !ok || len(first) != 1 || !validNftMetainfo(first["metainfo"]) {
		return HostFirewallObservation{}, bad()
	}
	for _, entry := range entries[1:] {
		item, ok := entry.(map[string]any)
		if !ok || len(item) != 1 {
			return HostFirewallObservation{}, bad()
		}
		for kind, value := range item {
			if !validNftObject(kind, value) {
				return HostFirewallObservation{}, bad()
			}
		}
	}
	if !normalizeNftVolatile(top) {
		return HostFirewallObservation{}, bad()
	}
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
