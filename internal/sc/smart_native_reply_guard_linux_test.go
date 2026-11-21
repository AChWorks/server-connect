//go:build linux

package sc

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func nativeReplyGuardShape(raw string) error {
	_, _, err := nativeReplyGuardReceipt(raw)
	return err
}

func installNativeReplyGuard(ctx context.Context, runner nativeReplyGuardWriter) error {
	_, err := installNativeReplyGuardWithHandle(ctx, runner, nil, nativeAcceptedTCPFingerprint(nil))
	return err
}

const nativeReplyGuardFixtureJSON = `{"nftables":[
 {"metainfo":{"version":"1.1.3","release_name":"qa","json_schema_version":1}},
 {"table":{"family":"inet","name":"sc_reply_guard","handle":10}},
 {"chain":{"family":"inet","table":"sc_reply_guard","name":"output_reply","handle":1,"type":"route","hook":"output","prio":-150,"policy":"accept"}},
 {"set":{"family":"inet","table":"sc_reply_guard","name":"accepted4","handle":2,"type":["ipv4_addr","inet_service","ipv4_addr","inet_service"]}},
 {"set":{"family":"inet","table":"sc_reply_guard","name":"accepted6","handle":3,"type":["ipv6_addr","inet_service","ipv6_addr","inet_service"]}},
 {"rule":{"family":"inet","table":"sc_reply_guard","chain":"output_reply","handle":4,
  "expr":[{"match":{"op":"==","left":{"ct":{"key":"direction"}},"right":"reply"}},
          {"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":0}},
          {"mangle":{"key":{"meta":{"key":"mark"}},"value":8228}},
          {"counter":{"packets":2,"bytes":208}}]}},
 {"rule":{"family":"inet","table":"sc_reply_guard","chain":"output_reply","handle":5,
  "expr":[{"match":{"op":"==","left":{"ct":{"key":"direction"}},"right":"original"}},
          {"match":{"op":"==","left":{"concat":[
            {"payload":{"protocol":"ip","field":"saddr"}},
            {"payload":{"protocol":"tcp","field":"sport"}},
            {"payload":{"protocol":"ip","field":"daddr"}},
            {"payload":{"protocol":"tcp","field":"dport"}}]},"right":"@accepted4"}},
          {"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":0}},
          {"mangle":{"key":{"meta":{"key":"mark"}},"value":8228}},
          {"counter":{"packets":0,"bytes":0}}]}},
 {"rule":{"family":"inet","table":"sc_reply_guard","chain":"output_reply","handle":6,
  "expr":[{"match":{"op":"==","left":{"ct":{"key":"direction"}},"right":"original"}},
          {"match":{"op":"==","left":{"concat":[
            {"payload":{"protocol":"ip6","field":"saddr"}},
            {"payload":{"protocol":"tcp","field":"sport"}},
            {"payload":{"protocol":"ip6","field":"daddr"}},
            {"payload":{"protocol":"tcp","field":"dport"}}]},"right":"@accepted6"}},
          {"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":0}},
          {"mangle":{"key":{"meta":{"key":"mark"}},"value":8228}},
          {"counter":{"packets":0,"bytes":0}}]}}
]}`

type fakeReplyGuardRunner struct {
	has             bool
	foreign         string
	nftJSON         string
	createErr       error
	deleteErr       error
	deleted         bool
	mutations       []string
	generationDrift bool
	generationCalls int
}

func (r *fakeReplyGuardRunner) output(_ context.Context, bin string, args ...string) (string, error) {
	if bin != "nft" {
		return "", errors.New("unexpected non-nft read")
	}
	switch strings.Join(args, " ") {
	case "list tables":
		if r.has {
			return "table inet sc_reply_guard\n", nil
		}
		if r.foreign != "" {
			return r.foreign, nil
		}
		return "table inet foreign\n", nil
	case "-j list table inet sc_reply_guard":
		if !r.has {
			return "", errors.New("no such table")
		}
		if r.foreign != "" {
			return r.foreign, nil
		}
		if r.nftJSON != "" {
			return r.nftJSON, nil
		}
		return nativeReplyGuardFixtureJSON, nil
	default:
		return "", errors.New("unexpected nft inspection")
	}
}
func (r *fakeReplyGuardRunner) replyGuardGeneration() (uint32, error) {
	r.generationCalls++
	if r.generationDrift && r.generationCalls%2 == 0 {
		return 6, nil
	}
	return 5, nil
}
func (r *fakeReplyGuardRunner) deleteReplyGuardCAS(handle uint64, generation uint32) error {
	if handle != 10 || generation != 5 {
		return errors.New("generation or table handle mismatch")
	}
	r.mutations = append(r.mutations, "delete")
	if r.deleteErr != nil {
		return r.deleteErr
	}
	r.has = false
	r.foreign = ""
	r.deleted = true
	return nil
}

func (r *fakeReplyGuardRunner) applyReplyGuardScript(_ context.Context, script string) error {
	if script != nativeReplyGuardNftScript {
		return errors.New("unexpected native reply guard kernel script")
	}
	r.mutations = append(r.mutations, "create")
	if r.has || r.foreign != "" {
		return errors.New("create table: File exists")
	}
	r.has = true
	return r.createErr
}

func TestNativeReplyGuardShapeOnlyAcceptsExactOwnedHook(t *testing.T) {
	if err := nativeReplyGuardShape(nativeReplyGuardFixtureJSON); err != nil {
		t.Fatalf("official Debian nft JSON fixture refused: %v", err)
	}
	tamper := []struct {
		name, old, replacement string
	}{
		{"foreign-source-mark", `"value":8228`, `"value":8227`},
		{"foreign-original-traffic-bypass", `"right":"reply"`, `"right":"original"`},
		{"wrong-hook-priority", `"prio":-150`, `"prio":-149`},
		{"filter-instead-of-route", `"type":"route"`, `"type":"filter"`},
		{"wrong-chain-policy", `"policy":"accept"`, `"policy":"drop"`},
		{"wrong-mark-match", `"right":0`, `"right":8227`},
		{"foreign-chain-name", `"name":"output_reply"`, `"name":"foreign"`},
		{"foreign-reject-action", `{"counter":{"packets":2,"bytes":208}}`, `{"reject":{"type":"tcp reset"}}`},
		{"unknown-rule-property", `"handle":2,`, `"handle":2,"comment":"foreign",`},
		{"duplicate-extra-rule", `]}}`, `]}},{"rule":{"family":"inet","table":"sc_reply_guard","chain":"output_reply","handle":3,"expr":[]}}`},
		{"missing-counter", `{"counter":{"packets":2,"bytes":208}}`, `{"counter":{}}`},
		{"negative-counter", `"packets":2`, `"packets":-1`},
		{"trailing-json", `]}`, `]}{}`},
		{"zero-handle", `"handle":10`, `"handle":0`},
		{"foreign-address-family", `"family":"inet"`, `"family":"ip"`},
	}
	for _, tc := range tamper {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(nativeReplyGuardFixtureJSON, tc.old) {
				t.Fatalf("bad fixture mutation: %q", tc.old)
			}
			raw := strings.Replace(nativeReplyGuardFixtureJSON, tc.old, tc.replacement, 1)
			if err := nativeReplyGuardShape(raw); err == nil {
				t.Fatalf("foreign or malformed rule accepted: %s", tc.name)
			}
		})
	}
	if err := nativeReplyGuardShape(""); err == nil {
		t.Fatal("empty nft inspection accepted")
	}
}

// This is the actual Debian 12 nft 1.0.6 layout observed during installed
// connect-smart CI. No expression, set or handle is rewritten: only the
// order in which nft enumerates the two sets relative to their chain.
func nativeReplyGuardDebian12Ordering(t *testing.T) string {
	t.Helper()
	var doc struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	debian12JSON := strings.Replace(nativeReplyGuardFixtureJSON,
		`"version":"1.1.3"`, `"version":"1.0.6"`, 1)
	if err := json.Unmarshal([]byte(debian12JSON), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Nftables) != 8 {
		t.Fatalf("bad reference fixture objects: %d", len(doc.Nftables))
	}
	// [metainfo, table, chain, accepted4, accepted6, rules...] ->
	// [metainfo, table, accepted4, accepted6, chain, rules...].
	doc.Nftables[2], doc.Nftables[3], doc.Nftables[4] =
		doc.Nftables[3], doc.Nftables[4], doc.Nftables[2]
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestNativeReplyGuardDebian12OrderingExactOwnership(t *testing.T) {
	raw12 := nativeReplyGuardDebian12Ordering(t)
	for _, fixture := range []string{nativeReplyGuardFixtureJSON, raw12} {
		handle, digest, err := nativeReplyGuardReceipt(fixture)
		if err != nil || handle != 10 || digest != nativeAcceptedTCPFingerprint(nil) {
			t.Fatalf("refused exact owned nft order: handle=%d err=%v", handle, err)
		}
	}
	// Reordered sets or rules are still a foreign shape, even if their
	// individual contents could otherwise appear exactly legitimate.
	var doc struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(raw12), &doc); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		a, b int
	}{
		{"reversed-sets", 2, 3},
		{"interleaved-chain-and-sets", 3, 4},
		{"reordered-mark-rules", 5, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc.Nftables[tc.a], doc.Nftables[tc.b] = doc.Nftables[tc.b], doc.Nftables[tc.a]
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := nativeReplyGuardShape(string(raw)); err == nil {
				t.Fatal("unexpected nft object ordering accepted")
			}
			doc.Nftables[tc.a], doc.Nftables[tc.b] = doc.Nftables[tc.b], doc.Nftables[tc.a]
		})
	}
	for _, tc := range []struct{ name, original, replacement string }{
		{"foreign-mark", `"value":8228`, `"value":8227`},
		{"wrong-hook", `"prio":-150`, `"prio":-149`},
		{"wrong-set", `"name":"accepted4"`, `"name":"foreign4"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(raw12, tc.original) {
				t.Fatalf("bad mutation: %s", tc.original)
			}
			if err := nativeReplyGuardShape(strings.Replace(raw12, tc.original, tc.replacement, 1)); err == nil {
				t.Fatal("modified nft owner accepted")
			}
		})
	}
	ctx := context.Background()
	// Handle is an ownership RECEIPT identity, not an invariant fixture
	// constant: accept any valid new handle during creation, but never
	// adopt that replacement under the previously committed handle.
	changedHandle := &fakeReplyGuardRunner{has: true,
		nftJSON: strings.Replace(raw12, `"handle":10`, `"handle":11`, 1)}
	if err := requireNativeReplyGuardClaim(ctx, changedHandle, 10, nativeAcceptedTCPFingerprint(nil)); err == nil {
		t.Fatal("an identical replacement table with another handle was adopted")
	}
	if err := recoverNativeReplyGuard(ctx, changedHandle, 10, nativeAcceptedTCPFingerprint(nil)); err == nil || len(changedHandle.mutations) != 0 {
		t.Fatal("foreign handle was deleted or adopted")
	}
	r := &fakeReplyGuardRunner{nftJSON: raw12}
	handle, err := installNativeReplyGuardWithHandle(ctx, r, nil, nativeAcceptedTCPFingerprint(nil))
	if err != nil || handle != 10 {
		t.Fatalf("Debian12 installed early guard cannot verify its receipt: %v (%d)", err, handle)
	}
	if err := requireNativeReplyGuardClaim(ctx, r, handle, nativeAcceptedTCPFingerprint(nil)); err != nil {
		t.Fatalf("Debian12 installed guard cannot verify live ownership: %v", err)
	}
	if err := recoverNativeReplyGuard(ctx, r, handle, nativeAcceptedTCPFingerprint(nil)); err != nil {
		t.Fatalf("Debian12 installed guard cannot delete its exact owner: %v", err)
	}
	if r.has || !r.deleted || len(r.mutations) != 2 {
		t.Fatalf("Debian12 exact receipt not recovered: %+v", r)
	}
	// Debian 12's real failure left a committed accepted-socket fingerprint
	// without a table handle. That interrupted pre-start window must remain
	// safely recoverable, without silently accepting a foreign owner.
	interrupted := &fakeReplyGuardRunner{has: true, nftJSON: raw12}
	if err := recoverNativeReplyGuard(ctx, interrupted, 0, nativeAcceptedTCPFingerprint(nil)); err != nil {
		t.Fatalf("Debian12 pre-start uncommitted handle cannot recover: %v", err)
	}
	if interrupted.has || !interrupted.deleted || len(interrupted.mutations) != 1 {
		t.Fatalf("Debian12 interrupted owned guard not safely reclaimed: %+v", interrupted)
	}
}

func TestNativeReplyGuardTransactionalInstallAndExactRecovery(t *testing.T) {
	r := &fakeReplyGuardRunner{}
	ctx := context.Background()
	if err := installNativeReplyGuard(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := requireNativeReplyGuard(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := installNativeReplyGuard(ctx, r); err == nil {
		t.Fatal("second install adopted a preexisting table")
	}
	if len(r.mutations) != 1 || r.mutations[0] != "create" {
		t.Fatalf("preexisting table caused foreign mutation: %v", r.mutations)
	}
	if err := recoverNativeReplyGuard(ctx, r, 10, nativeAcceptedTCPFingerprint(nil)); err != nil {
		t.Fatal(err)
	}
	if r.has || !r.deleted || len(r.mutations) != 2 || r.mutations[1] != "delete" {
		t.Fatalf("owned cleanup did not delete exact table: %+v", r)
	}
	if err := recoverNativeReplyGuard(ctx, r, 10, nativeAcceptedTCPFingerprint(nil)); err != nil || len(r.mutations) != 2 {
		t.Fatalf("idempotent missing-table recovery: %v / %v", err, r.mutations)
	}
}

func TestNativeReplyGuardForeignCollisionCannotDeleteOrAdopt(t *testing.T) {
	ctx := context.Background()
	for _, foreign := range []string{
		"table ip sc_reply_guard\n",
		"table inet sc_reply_guard\ntable ip sc_reply_guard\n",
	} {
		t.Run(strings.ReplaceAll(strings.TrimSpace(foreign), "\n", "_"), func(t *testing.T) {
			r := &fakeReplyGuardRunner{foreign: foreign}
			if err := installNativeReplyGuard(ctx, r); err == nil {
				t.Fatal("foreign name collision accepted")
			}
			if len(r.mutations) != 0 {
				t.Fatalf("foreign kernel data changed: %+v", r)
			}
		})
	}
	r := &fakeReplyGuardRunner{has: true, foreign: strings.Replace(nativeReplyGuardFixtureJSON, `"value":8228`, `"value":8227`, 1)}
	if err := recoverNativeReplyGuard(ctx, r, 10, nativeAcceptedTCPFingerprint(nil)); err == nil || len(r.mutations) != 0 {
		t.Fatalf("foreign mark rule deleted: %v / %v", err, r.mutations)
	}
	r.foreign = strings.Replace(nativeReplyGuardFixtureJSON, `"prio":-150`, `"prio":-149`, 1)
	if err := recoverNativeReplyGuard(ctx, r, 10, nativeAcceptedTCPFingerprint(nil)); err == nil || len(r.mutations) != 0 {
		t.Fatalf("foreign hook deleted: %v / %v", err, r.mutations)
	}
}

func TestNativeReplyGuardInterruptedInstallAndRetryableRecovery(t *testing.T) {
	ctx := context.Background()
	r := &fakeReplyGuardRunner{createErr: errors.New("nft timed out after kernel accepted batch")}
	if err := installNativeReplyGuard(ctx, r); err == nil || !r.has {
		t.Fatalf("ambiguous create outcome must retain kernel resource for claim cleanup: %v %+v", err, r)
	}
	r.deleteErr = errors.New("first delete failed")
	if err := recoverNativeReplyGuard(ctx, r, 0, nativeAcceptedTCPFingerprint(nil)); err == nil || !r.has {
		t.Fatalf("failed delete cannot lose owned retry claim: %v %+v", err, r)
	}
	r.deleteErr = nil
	if err := recoverNativeReplyGuard(ctx, r, 0, nativeAcceptedTCPFingerprint(nil)); err != nil || r.has {
		t.Fatalf("verified retry must recover without altering foreign state: %v %+v", err, r)
	}
}

func TestNativeReplyGuardLostTableFailsReadOnlyHealth(t *testing.T) {
	r := &fakeReplyGuardRunner{}
	if err := requireNativeReplyGuard(context.Background(), r); err == nil {
		t.Fatal("missing reply guard declared healthy")
	}
	if len(r.mutations) != 0 {
		t.Fatalf("health check wrote kernel: %v", r.mutations)
	}
}

func TestNativeReplyGuardConcurrentNftGenerationMutationRetainsClaim(t *testing.T) {
	r := &fakeReplyGuardRunner{has: true, generationDrift: true}
	if err := recoverNativeReplyGuard(context.Background(), r, 10, nativeAcceptedTCPFingerprint(nil)); err == nil {
		t.Fatal("concurrent nftables generation change not detected")
	}
	if !r.has || len(r.mutations) != 0 {
		t.Fatalf("generation drift must never delete a table: %+v", r)
	}
	// Reconciliation is repeatable when the externally changing owner has
	// stopped and the complete table is still independently validated.
	r.generationDrift = false
	if err := recoverNativeReplyGuard(context.Background(), r, 10, nativeAcceptedTCPFingerprint(nil)); err != nil || r.has {
		t.Fatalf("later verified CAS recovery failed: %v / %+v", err, r)
	}
}

func TestNativeReplyGuardPersistedHandlePreventsIdenticalForeignReplacement(t *testing.T) {
	ctx := context.Background()
	r := &fakeReplyGuardRunner{has: true}
	// Even when the replacement rule has an identical observable shape,
	// its different table handle must not be adopted by a persisted receipt.
	if err := recoverNativeReplyGuard(ctx, r, 42, nativeAcceptedTCPFingerprint(nil)); err == nil {
		t.Fatal("foreign replacement table handle was accepted")
	}
	if !r.has || len(r.mutations) != 0 {
		t.Fatalf("an identical foreign replacement was deleted: %+v", r)
	}
}

func TestNativeReplyGuardRealKernelNamespaceLifecycle(t *testing.T) {
	if os.Getenv("SC_NATIVE_REPLY_GUARD_GUEST") != "yes" {
		t.Skip("requires explicitly selected root-owned isolated Linux network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel CAS test requires guest-only CAP_NET_ADMIN")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if self == initial {
		t.Fatal("refuse mutation in the guest host's original network namespace")
	}
	ctx := context.Background()
	r := nativeSystemRunner{}
	baseline, err := r.output(ctx, "nft", "list", "tables")
	if err != nil {
		t.Fatal(err)
	}
	present, err := inspectNativeReplyGuard(ctx, r)
	if err != nil || present {
		t.Fatalf("owned guest table must be absent before install: %v %t", err, present)
	}
	flows := []nativeAcceptedTCPFlow{
		{Local: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), 22),
			Peer: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.77"), 51430)},
		{Local: netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1"), 8443),
			Peer: netip.AddrPortFrom(netip.MustParseAddr("2001:db8::2"), 54120)},
	}
	digest := nativeAcceptedTCPFingerprint(flows)
	handle, err := installNativeReplyGuardWithHandle(ctx, r, flows, digest)
	if err != nil {
		t.Fatal(err)
	}
	if handle == 0 {
		t.Fatal("real nftables table handle not captured")
	}
	if err := requireNativeReplyGuardClaim(ctx, r, handle, digest); err != nil {
		t.Fatalf("real nftables JSON or committed handle validation failed: %v", err)
	}
	if err := recoverNativeReplyGuard(ctx, r, handle+1, digest); err == nil {
		t.Fatal("foreign replacement table handle accepted")
	}
	if err := requireNativeReplyGuardClaim(ctx, r, handle, digest); err != nil {
		t.Fatalf("refused foreign recovery must preserve installed rule: %v", err)
	}
	if err := recoverNativeReplyGuard(ctx, r, handle, digest); err != nil {
		t.Fatalf("real kernel generation-conditional nftables delete failed: %v", err)
	}
	if err := recoverNativeReplyGuard(ctx, r, handle, digest); err != nil {
		t.Fatalf("idempotent exact cleanup failed: %v", err)
	}
	restored, err := r.output(ctx, "nft", "list", "tables")
	if err != nil || restored != baseline {
		t.Fatalf("isolated kernel namespace nft baseline not restored: %v / %q / %q", err, baseline, restored)
	}
	t.Log("QA_KERNEL_GENERATION_CONDITIONAL_REPLY_GUARD_LIFECYCLE=PASS")
}

func TestNativeReplyGuardAcceptedSnapshotFingerprintCannotAdoptOtherTuple(t *testing.T) {
	ctx := context.Background()
	// The nft rule has not changed; an additional kernel set element by
	// itself must invalidate the exact precommitted tuple fingerprint.
	needle := `"handle":2,"type":["ipv4_addr","inet_service","ipv4_addr","inet_service"]`
	replacement := `"handle":2,"type":["ipv4_addr","inet_service","ipv4_addr","inet_service"],"elem":[{"concat":["203.0.113.10",22,"198.51.100.77",51430]}]`
	if !strings.Contains(nativeReplyGuardFixtureJSON, needle) {
		t.Fatal("wrong fixture")
	}
	altered := strings.Replace(nativeReplyGuardFixtureJSON, needle, replacement, 1)
	if err := nativeReplyGuardShape(altered); err != nil {
		t.Fatalf("otherwise legitimate alternate tuple set rejected structurally: %v", err)
	}
	flow := nativeAcceptedTCPFlow{
		Local: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), 22),
		Peer:  netip.AddrPortFrom(netip.MustParseAddr("198.51.100.77"), 51430),
	}
	_, digest, err := nativeReplyGuardReceipt(altered)
	if err != nil || digest != nativeAcceptedTCPFingerprint([]nativeAcceptedTCPFlow{flow}) {
		t.Fatalf("kernel tuple did not survive canonical signature: %v %s", err, digest)
	}
	r := &fakeReplyGuardRunner{has: true, foreign: altered}
	if err := requireNativeReplyGuardClaim(ctx, r, 10, nativeAcceptedTCPFingerprint(nil)); err == nil {
		t.Fatal("live health silently adopted an unsaved accepted TCP tuple")
	}
	if err := recoverNativeReplyGuard(ctx, r, 10, nativeAcceptedTCPFingerprint(nil)); err == nil {
		t.Fatal("recovery deleted table with a changed accepted TCP tuple")
	}
	if len(r.mutations) != 0 {
		t.Fatalf("foreign accepted TCP tuple triggered kernel mutation: %v", r.mutations)
	}
	// The same kernel shape may only be reconciled against its *actual*
	// prior committed intent, even if table handle and generation match.
	if err := recoverNativeReplyGuard(ctx, r, 10, nativeAcceptedTCPFingerprint([]nativeAcceptedTCPFlow{flow})); err != nil {
		t.Fatalf("valid precommitted accepted tuple could not be reclaimed: %v", err)
	}
}

func TestNativeReplyGuardRejectsWrongTupleSetTypesAndForeignSet(t *testing.T) {
	for _, tc := range []struct{ name, old, new string }{
		{"wrong-tuple-type", `"ipv4_addr","inet_service","ipv4_addr","inet_service"`, `"ipv4_addr","inet_service","ipv4_addr","ipv4_addr"`},
		{"changed-set-name", `"name":"accepted4"`, `"name":"foreign4"`},
		{"additional-set", `"handle":3,"type":["ipv6_addr","inet_service","ipv6_addr","inet_service"]`, `"handle":3,"type":["ipv6_addr","inet_service","ipv6_addr","inet_service"]}},{"set":{"family":"inet","table":"sc_reply_guard","name":"third","handle":8`},
		{"unapproved-mark-rule", `"right":"@accepted4"`, `"right":"@accepted6"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(nativeReplyGuardFixtureJSON, tc.old) {
				t.Fatalf("bad mutation fixture: %q", tc.old)
			}
			altered := strings.Replace(nativeReplyGuardFixtureJSON, tc.old, tc.new, 1)
			if err := nativeReplyGuardShape(altered); err == nil {
				t.Fatal("unowned nft shape was accepted")
			}
		})
	}
}
