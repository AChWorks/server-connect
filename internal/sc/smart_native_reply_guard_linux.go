//go:build linux

package sc

// Existing inbound TCP may predate conntrack's observation: the first tracked
// packet may be the server's response, classified ORIGINAL, not REPLY. An
// old SSH session was physically reset despite a structurally correct
// reply-only hook. A field-proven *exact accepted socket tuple* protected
// that same old SSH session without exempting new outbound to its public IP.
//
// This one native-owned nft table has a reply-direction rule plus two
// O(1) tuple sets for accepted IPv4/IPv6 TCP sockets at activation. The
// snapshot is immutable for the short native session; new ingress naturally
// gets standard conntrack REPLY treatment. Kernel/table ownership includes a
// precommitted canonical snapshot fingerprint and actual table handle.
import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"time"
)

const nativeReplyGuardTable = "sc_reply_guard"
const nativeReplyGuardChain = "output_reply"
const nativeReplyGuardPriority = -150
const nativeReplyGuardV4 = "accepted4"
const nativeReplyGuardV6 = "accepted6"

// nft transactions are submitted as one atomic batch. Neither the table,
// sets nor chain may exist beforehand (admission enforces that separately).
func nativeReplyGuardScript(flows []nativeAcceptedTCPFlow) string {
	var ipv4, ipv6 []string
	for _, f := range flows {
		term := nativeAcceptedTCPScriptElement(f)
		if f.Local.Addr().Is4() {
			ipv4 = append(ipv4, term)
		} else {
			ipv6 = append(ipv6, term)
		}
	}
	// The proc-derived snapshot is already sorted; sorting again ensures
	// stable generation when tests or callers supply a different order.
	sort.Strings(ipv4)
	sort.Strings(ipv6)
	var b strings.Builder
	b.WriteString("table inet sc_reply_guard {\n")
	b.WriteString(" set accepted4 {\n  type ipv4_addr . inet_service . ipv4_addr . inet_service;\n")
	if len(ipv4) > 0 {
		b.WriteString("  elements = { " + strings.Join(ipv4, ", ") + " };\n")
	}
	b.WriteString(" }\n")
	b.WriteString(" set accepted6 {\n  type ipv6_addr . inet_service . ipv6_addr . inet_service;\n")
	if len(ipv6) > 0 {
		b.WriteString("  elements = { " + strings.Join(ipv6, ", ") + " };\n")
	}
	b.WriteString(" }\n")
	b.WriteString(" chain output_reply {\n")
	b.WriteString("  type route hook output priority -150; policy accept;\n")
	b.WriteString("  ct direction reply meta mark 0 meta mark set 0x2024 counter\n")
	b.WriteString("  ct direction original ip saddr . tcp sport . ip daddr . tcp dport @accepted4 meta mark 0 meta mark set 0x2024 counter\n")
	b.WriteString("  ct direction original ip6 saddr . tcp sport . ip6 daddr . tcp dport @accepted6 meta mark 0 meta mark set 0x2024 counter\n")
	b.WriteString(" }\n}\n")
	return b.String()
}

// Keep the empty-snapshot fixture for the existing install/recovery tests.
var nativeReplyGuardNftScript = nativeReplyGuardScript(nil)

type nativeReplyGuardReader interface {
	output(context.Context, string, ...string) (string, error)
}
type nativeReplyGuardWriter interface {
	nativeReplyGuardReader
	applyReplyGuardScript(context.Context, string) error
}

// Conditional nft netlink delete already used by native Core cleanup: table
// handle and complete nft generation are tied to one exact observation.
type nativeReplyGuardCASRunner interface {
	nativeReplyGuardReader
	replyGuardGeneration() (uint32, error)
	deleteReplyGuardCAS(handle uint64, generation uint32) error
}

func (nativeSystemRunner) replyGuardGeneration() (uint32, error) {
	return nativeNFTGeneration()
}
func (nativeSystemRunner) deleteReplyGuardCAS(handle uint64, generation uint32) error {
	return nativeNFTDeleteTableCAS(handle, generation)
}
func (nativeSystemRunner) applyReplyGuardScript(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("native reply guard nft transaction failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func nativeReplyGuardPresent(ctx context.Context, reader nativeReplyGuardReader) (bool, error) {
	raw, err := reader.output(ctx, "nft", "list", "tables")
	if err != nil {
		return false, err
	}
	var found bool
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		if len(parts) != 3 || parts[0] != "table" {
			return false, Fault("guard_unavailable", "native reply guard cannot safely enumerate nft tables")
		}
		if parts[2] != nativeReplyGuardTable {
			continue
		}
		if found || parts[1] != "inet" {
			return false, Fault("service_conflict", "foreign native reply guard table name")
		}
		found = true
	}
	return found, nil
}

func strictReplyGuardJSON(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := d.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing nft JSON")
	}
	return nil
}

type nativeReplyGuardSet struct {
	Family string                       `json:"family"`
	Table  string                       `json:"table"`
	Name   string                       `json:"name"`
	Handle uint64                       `json:"handle"`
	Type   []string                     `json:"type"`
	Elem   []map[string]json.RawMessage `json:"elem"`
}

func nativeReplyGuardSetFlows(raw json.RawMessage, expectedName string) ([]nativeAcceptedTCPFlow, error) {
	var set nativeReplyGuardSet
	if strictReplyGuardJSON(raw, &set) != nil || set.Family != "inet" ||
		set.Table != nativeReplyGuardTable || set.Name != expectedName || set.Handle == 0 {
		return nil, Fault("service_conflict", "native reply guard set ownership or attributes changed")
	}
	family, addr := 4, "ipv4_addr"
	if expectedName == nativeReplyGuardV6 {
		family, addr = 6, "ipv6_addr"
	}
	expectedTypes := []string{addr, "inet_service", addr, "inet_service"}
	if !reflect.DeepEqual(set.Type, expectedTypes) {
		return nil, Fault("service_conflict", "native reply guard set type differs")
	}
	var flows []nativeAcceptedTCPFlow
	seen := map[string]struct{}{}
	for _, element := range set.Elem {
		if len(element) != 1 || element["concat"] == nil {
			return nil, Fault("service_conflict", "native reply guard contains a foreign set element")
		}
		var terms []json.RawMessage
		if strictReplyGuardJSON(element["concat"], &terms) != nil || len(terms) != 4 {
			return nil, Fault("service_conflict", "native reply guard tuple has unexpected width")
		}
		var ips [2]string
		if strictReplyGuardJSON(terms[0], &ips[0]) != nil ||
			strictReplyGuardJSON(terms[2], &ips[1]) != nil {
			return nil, Fault("service_conflict", "native reply guard has invalid tuple addresses")
		}
		local, e1 := netip.ParseAddr(ips[0])
		peer, e2 := netip.ParseAddr(ips[1])
		if e1 != nil || e2 != nil || !local.IsValid() || !peer.IsValid() ||
			local.IsUnspecified() || peer.IsUnspecified() ||
			(family == 4 && (!local.Is4() || !peer.Is4())) ||
			(family == 6 && (!local.Is6() || !peer.Is6() || local.Is4In6() || peer.Is4In6())) {
			return nil, Fault("service_conflict", "native reply guard tuple family differs")
		}
		var ports [2]uint16
		for i, index := range []int{1, 3} {
			var port uint64
			if strictReplyGuardJSON(terms[index], &port) != nil || port == 0 || port > 65535 {
				return nil, Fault("service_conflict", "native reply guard tuple port invalid")
			}
			ports[i] = uint16(port)
		}
		flow := nativeAcceptedTCPFlow{
			Local: netip.AddrPortFrom(local, ports[0]),
			Peer:  netip.AddrPortFrom(peer, ports[1]),
		}
		key := nativeAcceptedTCPKey(flow)
		if _, duplicate := seen[key]; duplicate {
			return nil, Fault("service_conflict", "duplicate accepted tuple in native reply guard")
		}
		seen[key] = struct{}{}
		flows = append(flows, flow)
	}
	return flows, nil
}

func nativeReplyGuardExpectedRuleJSON(family string) string {
	if family == "" {
		return `[
		 {"match":{"op":"==","left":{"ct":{"key":"direction"}},"right":"reply"}},
		 {"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":0}},
		 {"mangle":{"key":{"meta":{"key":"mark"}},"value":8228}}
		]`
	}
	// The only two additional matches select preexisting exact local/peer
	// tuples, never a whole remote IP or generic new outbound connection.
	return fmt.Sprintf(`[
	 {"match":{"op":"==","left":{"ct":{"key":"direction"}},"right":"original"}},
	 {"match":{"op":"==","left":{"concat":[
	   {"payload":{"protocol":"%s","field":"saddr"}},
	   {"payload":{"protocol":"tcp","field":"sport"}},
	   {"payload":{"protocol":"%s","field":"daddr"}},
	   {"payload":{"protocol":"tcp","field":"dport"}}]},"right":"@accepted%s"}},
	 {"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":0}},
	 {"mangle":{"key":{"meta":{"key":"mark"}},"value":8228}}
	]`, family, family, map[string]string{"ip": "4", "ip6": "6"}[family])
}

func nativeReplyGuardRuleMatches(raw json.RawMessage, family string) error {
	var rule struct {
		Family string            `json:"family"`
		Table  string            `json:"table"`
		Chain  string            `json:"chain"`
		Handle uint64            `json:"handle"`
		Expr   []json.RawMessage `json:"expr"`
	}
	if strictReplyGuardJSON(raw, &rule) != nil || rule.Family != "inet" ||
		rule.Table != nativeReplyGuardTable || rule.Chain != nativeReplyGuardChain ||
		rule.Handle == 0 {
		return Fault("service_conflict", "native reply guard rule ownership differs")
	}
	expectedCount := 4
	if family != "" {
		expectedCount = 5
	}
	if len(rule.Expr) != expectedCount {
		return Fault("service_conflict", "native reply guard rule expression count differs")
	}
	var expected, actual any
	actualJSON, err := json.Marshal(rule.Expr[:len(rule.Expr)-1])
	if err != nil {
		return Fault("guard_unavailable", "native reply guard expression serialization failed")
	}
	if json.Unmarshal([]byte(nativeReplyGuardExpectedRuleJSON(family)), &expected) != nil ||
		json.Unmarshal(actualJSON, &actual) != nil ||
		!reflect.DeepEqual(expected, actual) {
		return Fault("service_conflict", "native reply guard rule changed from exact accepted-socket scope")
	}
	var counter struct {
		Counter map[string]json.RawMessage `json:"counter"`
	}
	if strictReplyGuardJSON(rule.Expr[len(rule.Expr)-1], &counter) != nil ||
		len(counter.Counter) != 2 {
		return Fault("service_conflict", "native reply guard counter changed")
	}
	for _, key := range []string{"packets", "bytes"} {
		var value uint64
		rawValue, ok := counter.Counter[key]
		if !ok || strictReplyGuardJSON(rawValue, &value) != nil {
			return Fault("service_conflict", "native reply guard counter invalid")
		}
	}
	return nil
}

func nativeReplyGuardReceipt(raw string) (uint64, string, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if len(raw) == 0 || strictReplyGuardJSON([]byte(raw), &doc) != nil {
		return 0, "", Fault("guard_unavailable", "native reply guard nft JSON invalid")
	}
	rows := doc.Nftables
	if len(rows) > 0 && len(rows[0]) == 1 && rows[0]["metainfo"] != nil {
		rows = rows[1:]
	}
	if len(rows) != 7 {
		return 0, "", Fault("service_conflict", "native reply guard nft objects changed")
	}
	// nft 1.0.6 (Debian 12) lists table, sets, chain, rules; nft 1.1.3
	// (Debian 13) lists table, chain, sets, rules. These are the ONLY
	// accepted layouts. Do not broadly sort objects or adopt reordered
	// rules: all handles, set identities, rule order and policy expressions
	// must still match the exact originally committed native owner.
	isKind := func(index int, name string) bool {
		return len(rows[index]) == 1 && rows[index][name] != nil
	}
	if !isKind(0, "table") || !isKind(4, "rule") ||
		!isKind(5, "rule") || !isKind(6, "rule") {
		return 0, "", Fault("service_conflict", "native reply guard table layout changed")
	}
	chainIndex, firstSetIndex := 1, 2
	switch {
	case isKind(1, "chain") && isKind(2, "set") && isKind(3, "set"):
		// Debian 13 nft ordering.
	case isKind(1, "set") && isKind(2, "set") && isKind(3, "chain"):
		chainIndex, firstSetIndex = 3, 1
	default:
		return 0, "", Fault("service_conflict", "native reply guard table layout changed")
	}
	var table struct {
		Family string `json:"family"`
		Name   string `json:"name"`
		Handle uint64 `json:"handle"`
	}
	var chain struct {
		Family string `json:"family"`
		Table  string `json:"table"`
		Name   string `json:"name"`
		Handle uint64 `json:"handle"`
		Type   string `json:"type"`
		Hook   string `json:"hook"`
		Prio   int    `json:"prio"`
		Policy string `json:"policy"`
	}
	if strictReplyGuardJSON(rows[0]["table"], &table) != nil ||
		strictReplyGuardJSON(rows[chainIndex]["chain"], &chain) != nil ||
		table.Family != "inet" || table.Name != nativeReplyGuardTable || table.Handle == 0 ||
		chain.Family != "inet" || chain.Table != nativeReplyGuardTable ||
		chain.Name != nativeReplyGuardChain || chain.Handle == 0 ||
		chain.Type != "route" || chain.Hook != "output" ||
		chain.Prio != nativeReplyGuardPriority || chain.Policy != "accept" {
		return 0, "", Fault("service_conflict", "native reply guard hook ownership differs")
	}
	all := make([]nativeAcceptedTCPFlow, 0)
	for i, name := range []string{nativeReplyGuardV4, nativeReplyGuardV6} {
		flows, err := nativeReplyGuardSetFlows(rows[firstSetIndex+i]["set"], name)
		if err != nil {
			return 0, "", err
		}
		all = append(all, flows...)
	}
	for i, family := range []string{"", "ip", "ip6"} {
		if err := nativeReplyGuardRuleMatches(rows[i+4]["rule"], family); err != nil {
			return 0, "", err
		}
	}
	return table.Handle, nativeAcceptedTCPFingerprint(all), nil
}

func nativeReplyGuardShape(raw string) error {
	_, _, err := nativeReplyGuardReceipt(raw)
	return err
}
func nativeReplyGuardHandle(raw string) (uint64, error) {
	h, _, err := nativeReplyGuardReceipt(raw)
	return h, err
}
func inspectNativeReplyGuardSnapshot(ctx context.Context, reader nativeReplyGuardReader) (bool, uint64, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	exists, err := nativeReplyGuardPresent(ctx, reader)
	if err != nil || !exists {
		return exists, 0, "", err
	}
	raw, err := reader.output(ctx, "nft", "-j", "list", "table", "inet", nativeReplyGuardTable)
	if err != nil {
		return false, 0, "", Fault("guard_unavailable", "native reply guard disappeared during inspection")
	}
	handle, fingerprint, err := nativeReplyGuardReceipt(raw)
	if err != nil {
		return false, 0, "", err
	}
	return true, handle, fingerprint, nil
}
func inspectNativeReplyGuard(ctx context.Context, reader nativeReplyGuardReader) (bool, error) {
	present, _, _, err := inspectNativeReplyGuardSnapshot(ctx, reader)
	return present, err
}
func requireNativeReplyGuardClaim(ctx context.Context, reader nativeReplyGuardReader, expectedHandle uint64, expectedFingerprint string) error {
	if expectedHandle == 0 || len(expectedFingerprint) != 64 {
		return Fault("guard_pending", "native reply guard has no complete committed ownership receipt")
	}
	if _, err := hex.DecodeString(expectedFingerprint); err != nil {
		return Fault("guard_pending", "native reply guard fingerprint invalid")
	}
	present, handle, fingerprint, err := inspectNativeReplyGuardSnapshot(ctx, reader)
	if err != nil {
		return err
	}
	if !present || handle != expectedHandle || fingerprint != expectedFingerprint {
		return Fault("guard_pending", "native reply guard changed from its committed accepted-socket snapshot")
	}
	return nil
}
func requireNativeReplyGuard(ctx context.Context, reader nativeReplyGuardReader) error {
	present, err := inspectNativeReplyGuard(ctx, reader)
	if err != nil {
		return err
	}
	if !present {
		return Fault("guard_unavailable", "native reply guard absent while Core active")
	}
	return nil
}
func installNativeReplyGuardWithHandle(ctx context.Context, runner nativeReplyGuardWriter, flows []nativeAcceptedTCPFlow, expectedFingerprint string) (uint64, error) {
	present, err := nativeReplyGuardPresent(ctx, runner)
	if err != nil {
		return 0, err
	}
	if present {
		return 0, Fault("service_conflict", "native reply guard already exists before activation")
	}
	if expectedFingerprint != nativeAcceptedTCPFingerprint(flows) {
		return 0, Fault("invalid_state", "native reply guard accepted-socket snapshot changed")
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	if err := runner.applyReplyGuardScript(ctx, nativeReplyGuardScript(flows)); err != nil {
		return 0, err
	}
	present, handle, fingerprint, err := inspectNativeReplyGuardSnapshot(ctx, runner)
	if err != nil {
		return 0, err
	}
	if !present || handle == 0 || fingerprint != expectedFingerprint {
		return 0, Fault("guard_unavailable", "native reply guard kernel snapshot differs from precommitted receipt")
	}
	return handle, nil
}
func installNativeReplyGuard(ctx context.Context, runner nativeReplyGuardWriter) error {
	_, err := installNativeReplyGuardWithHandle(ctx, runner, nil, nativeAcceptedTCPFingerprint(nil))
	return err
}

func recoverNativeReplyGuard(ctx context.Context, runner nativeReplyGuardCASRunner, expectedHandle uint64, expectedFingerprint string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	before, err := runner.replyGuardGeneration()
	if err != nil {
		return Fault("guard_unavailable", "native reply guard nft generation cannot be observed")
	}
	present, handle, fingerprint, err := inspectNativeReplyGuardSnapshot(ctx, runner)
	if err != nil || !present {
		return err
	}
	// Persisted intent MUST precede table creation: even an interrupted
	// ExecStartPre may recover only the exact originally authorized set.
	if len(expectedFingerprint) != 64 || fingerprint != expectedFingerprint {
		return Fault("service_conflict", "native reply guard set differs from the precommitted accepted sockets")
	}
	if expectedHandle != 0 && handle != expectedHandle {
		return Fault("service_conflict", "native reply guard was replaced after activation")
	}
	after, err := runner.replyGuardGeneration()
	if err != nil {
		return Fault("guard_unavailable", "native reply guard nft generation unavailable")
	}
	if before == 0 || before != after {
		return Fault("guard_pending", "nft generation changed during native reply guard ownership check")
	}
	if err := runner.deleteReplyGuardCAS(handle, after); err != nil {
		if exists, checkErr := inspectNativeReplyGuard(ctx, runner); checkErr != nil || exists {
			return Fault("guard_pending", "native reply guard deletion failed or is uncertain")
		}
		return nil
	}
	if exists, err := inspectNativeReplyGuard(ctx, runner); err != nil || exists {
		return Fault("guard_pending", "native reply guard removal cannot be verified")
	}
	return nil
}
