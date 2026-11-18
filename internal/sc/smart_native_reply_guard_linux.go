//go:build linux

package sc

// The pinned sing-box native auto_redirect policy installs its output NAT
// hook after priority -150. A previously established inbound TCP connection
// can otherwise receive a local, spoofed-peer RST during Core activation.
// Marking only unmarked conntrack REPLY packets in an earlier route hook
// keeps their host-originated replies on the real underlay. A NEW locally
// initiated connection to the very same peer address does not match this
// rule, and must still be captured by the selected VPN.
//
// This is not a generic firewall manager. The one fixed inet table is
// installed only after the existing durable native claim and independently
// prearmed guards exist. A native stop/crash must independently attest its
// exact shape before deleting it; foreign/corrupt ownership is never adopted.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"reflect"
	"strings"
	"time"
)

const nativeReplyGuardTable = "sc_reply_guard"
const nativeReplyGuardChain = "output_reply"
const nativeReplyGuardPriority = -150

const nativeReplyGuardNftScript = `create table inet sc_reply_guard
add chain inet sc_reply_guard output_reply { type route hook output priority -150; policy accept; }
add rule inet sc_reply_guard output_reply ct direction reply meta mark 0 meta mark set 0x2024 counter
`

type nativeReplyGuardReader interface {
	output(context.Context, string, ...string) (string, error)
}

type nativeReplyGuardWriter interface {
	nativeReplyGuardReader
	applyReplyGuardScript(context.Context, string) error
}

// Delete by the observed *table handle* only when nftables still has the
// generation that surrounded the exact owner-shape inspection. This avoids
// deleting a foreign replacement between validation and mutation.
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
		// Never interpret an ambiguous nft transaction failure as "no
		// mutation": the prearmed native stop hook must reobserve it.
		return fmt.Errorf("native reply guard nft creation failed: %w (%s)", err, strings.TrimSpace(string(output)))
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
		// An identically named table in a different address family is
		// a conflict even though delete table inet would not touch it.
		if found || parts[1] != "inet" {
			return false, Fault("service_conflict", "foreign native reply guard table name")
		}
		found = true
	}
	return found, nil
}

func strictReplyGuardJSON(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing nft JSON")
	}
	return nil
}

func nativeReplyGuardHandle(raw string) (uint64, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if len(raw) == 0 || len(raw) > 64*1024 || strictReplyGuardJSON([]byte(raw), &doc) != nil {
		return 0, Fault("guard_unavailable", "native reply guard nft JSON invalid")
	}
	rows := doc.Nftables
	if len(rows) == 4 && len(rows[0]) == 1 && rows[0]["metainfo"] != nil {
		rows = rows[1:]
	}
	if len(rows) != 3 {
		return 0, Fault("service_conflict", "native reply guard has unexpected nft objects")
	}
	for i, name := range []string{"table", "chain", "rule"} {
		if len(rows[i]) != 1 || rows[i][name] == nil {
			return 0, Fault("service_conflict", "native reply guard nft object identity changed")
		}
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
	var rule struct {
		Family string            `json:"family"`
		Table  string            `json:"table"`
		Chain  string            `json:"chain"`
		Handle uint64            `json:"handle"`
		Expr   []json.RawMessage `json:"expr"`
	}
	if strictReplyGuardJSON(rows[0]["table"], &table) != nil ||
		strictReplyGuardJSON(rows[1]["chain"], &chain) != nil ||
		strictReplyGuardJSON(rows[2]["rule"], &rule) != nil {
		return 0, Fault("service_conflict", "native reply guard has unknown nft attributes")
	}
	if table.Family != "inet" || table.Name != nativeReplyGuardTable || table.Handle == 0 ||
		chain.Family != "inet" || chain.Table != nativeReplyGuardTable ||
		chain.Name != nativeReplyGuardChain || chain.Handle == 0 ||
		chain.Type != "route" || chain.Hook != "output" || chain.Prio != nativeReplyGuardPriority ||
		chain.Policy != "accept" || rule.Family != "inet" ||
		rule.Table != nativeReplyGuardTable || rule.Chain != nativeReplyGuardChain || rule.Handle == 0 ||
		len(rule.Expr) != 4 {
		return 0, Fault("service_conflict", "native reply guard nft shape does not match owned hook")
	}
	// Readable, static canonical AST of the exact field-proven nft rule.
	// Dynamic counters and kernel-assigned handles are the only ignored
	// values. A foreign ACCEPT/DROP, port, source-IP, broad bypass, mark or
	// additional rule causes refusal before any deletion.
	const expected = `[
	  {"match":{"op":"==","left":{"ct":{"key":"direction"}},"right":"reply"}},
	  {"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":0}},
	  {"mangle":{"key":{"meta":{"key":"mark"}},"value":8228}}
	]`
	var want []any
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		panic("invalid native reply guard static AST")
	}
	var actual []any
	expressions, marshalErr := json.Marshal(rule.Expr[:3])
	if marshalErr != nil {
		return 0, Fault("guard_unavailable", "native reply guard rule encoding unavailable")
	}
	if err := json.Unmarshal(expressions, &actual); err != nil ||
		!reflect.DeepEqual(actual, want) {
		return 0, Fault("service_conflict", "native reply guard mark expression differs from pinned Core policy")
	}

	var counter struct {
		Counter map[string]json.RawMessage `json:"counter"`
	}
	if err := strictReplyGuardJSON(rule.Expr[3], &counter); err != nil ||
		len(counter.Counter) != 2 {
		return 0, Fault("service_conflict", "native reply guard counter shape changed")
	}
	for _, field := range []string{"packets", "bytes"} {
		raw, exists := counter.Counter[field]
		if !exists {
			return 0, Fault("service_conflict", "native reply guard counter field missing")
		}
		var value uint64
		if err := strictReplyGuardJSON(raw, &value); err != nil {
			return 0, Fault("service_conflict", "native reply guard counter value invalid")
		}
	}

	return table.Handle, nil
}

func nativeReplyGuardShape(raw string) error {
	_, err := nativeReplyGuardHandle(raw)
	return err
}

func inspectNativeReplyGuardSnapshot(ctx context.Context, reader nativeReplyGuardReader) (bool, uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	exists, err := nativeReplyGuardPresent(ctx, reader)
	if err != nil || !exists {
		return exists, 0, err
	}
	raw, err := reader.output(ctx, "nft", "-j", "list", "table", "inet", nativeReplyGuardTable)
	if err != nil {
		return false, 0, Fault("guard_unavailable", "native reply guard table disappeared during inspection")
	}
	handle, err := nativeReplyGuardHandle(raw)
	if err != nil {
		return false, 0, err
	}
	return true, handle, nil
}

func inspectNativeReplyGuard(ctx context.Context, reader nativeReplyGuardReader) (bool, error) {
	present, _, err := inspectNativeReplyGuardSnapshot(ctx, reader)
	return present, err
}

func requireNativeReplyGuardClaim(ctx context.Context, reader nativeReplyGuardReader, expectedHandle uint64) error {
	if expectedHandle == 0 {
		return Fault("guard_pending", "native reply guard has no committed kernel ownership handle")
	}
	present, handle, err := inspectNativeReplyGuardSnapshot(ctx, reader)
	if err != nil {
		return err
	}
	if !present || handle != expectedHandle {
		return Fault("guard_pending", "native reply guard changed from the committed kernel receipt")
	}
	return nil
}

func requireNativeReplyGuard(ctx context.Context, reader nativeReplyGuardReader) error {
	present, err := inspectNativeReplyGuard(ctx, reader)
	if err != nil {
		return err
	}
	if !present {
		return Fault("guard_unavailable", "native reply guard is absent while Core is active")
	}
	return nil
}

func installNativeReplyGuardWithHandle(ctx context.Context, runner nativeReplyGuardWriter) (uint64, error) {
	present, err := inspectNativeReplyGuard(ctx, runner)
	if err != nil {
		return 0, err
	}
	if present {
		return 0, Fault("service_conflict", "native reply guard already exists before activation")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := runner.applyReplyGuardScript(ctx, nativeReplyGuardNftScript); err != nil {
		return 0, err
	}
	present, handle, err := inspectNativeReplyGuardSnapshot(ctx, runner)
	if err != nil {
		return 0, err
	}
	if !present || handle == 0 {
		return 0, Fault("guard_unavailable", "native reply guard was not installed")
	}
	return handle, nil
}

func installNativeReplyGuard(ctx context.Context, runner nativeReplyGuardWriter) error {
	_, err := installNativeReplyGuardWithHandle(ctx, runner)
	return err
}

// The native claim is the only authority to invoke this function. It runs
// AFTER verified Core native routing cleanup, while the claim still exists.
// An absent table is fine after ExecStartPre failed before its atomic commit.
func recoverNativeReplyGuard(ctx context.Context, runner nativeReplyGuardCASRunner, expectedHandle uint64) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	before, err := runner.replyGuardGeneration()
	if err != nil {
		return Fault("guard_unavailable", "native reply guard nft generation cannot be observed")
	}
	present, handle, err := inspectNativeReplyGuardSnapshot(ctx, runner)
	if err != nil || !present {
		return err
	}
	// An already committed durable receipt binds our dynamic kernel handle.
	// A zero receipt is allowed only for an interrupted ExecStartPre; the
	// original native intent still gates this one narrow CAS cleanup.
	if expectedHandle != 0 && handle != expectedHandle {
		return Fault("service_conflict", "native reply guard table was replaced after owned activation")
	}
	after, err := runner.replyGuardGeneration()
	if err != nil {
		return Fault("guard_unavailable", "native reply guard nft generation changed or became unavailable")
	}
	if before != after || before == 0 {
		return Fault("guard_pending", "native reply guard nft generation changed during ownership inspection")
	}
	// Reuse the existing native nft netlink generation-conditional deletion.
	// No delete-by-name TOCTOU: table handle and complete ruleset generation
	// are bound to the exact owned table we just inspected.
	if err := runner.deleteReplyGuardCAS(handle, after); err != nil {
		// The kernel may have committed the transaction before a lost ACK.
		// Only absence is proof of success; a retained or foreign table is
		// retryable with its durable native session, never adopted blindly.
		if present, checkErr := inspectNativeReplyGuard(ctx, runner); checkErr != nil || present {
			return Fault("guard_pending", "native reply guard generation-safe deletion failed or is uncertain")
		}
		return nil
	}
	present, err = inspectNativeReplyGuard(ctx, runner)
	if err != nil {
		return err
	}
	if present {
		return Fault("guard_pending", "native reply guard table remains after conditional recovery")
	}
	return nil
}
