//go:build linux

package sc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type nativeStartupFake struct {
	listing string
	body    string
}

func (r nativeStartupFake) output(_ context.Context, binary string, args ...string) (string, error) {
	k := binary + " " + strings.Join(args, " ")
	switch k {
	case "nft list tables":
		return r.listing, nil
	default:
		if strings.HasPrefix(k, "nft -j -a list table inet ") {
			return r.body, nil
		}
	}
	return "", fmt.Errorf("unexpected startup inspection %s", k)
}
func nativeStartupFixture(t *testing.T) (nativeStartupPlan, nativeStartupFake) {
	t.Helper()
	p := nativeStartupPlan{Version: 1, Name: "sc_pre_" + strings.Repeat("a", 32),
		UnderlayIF: "eth0", DirectPrefixes: []string{"193.111.235.0/25"}}
	rules, e := nativeStartupRules(p)
	if e != nil {
		t.Fatal(e)
	}
	rows := []any{
		map[string]any{"table": map[string]any{"family": "inet", "name": p.Name, "handle": uint64(5)}},
		map[string]any{"chain": map[string]any{"family": "inet", "table": p.Name, "name": "output",
			"handle": uint64(1), "type": "filter", "hook": "output", "prio": nativeStartupPriority, "policy": "accept"}},
	}
	for i, r := range rules {
		rows = append(rows, map[string]any{"rule": map[string]any{"family": "inet", "table": p.Name,
			"chain": "output", "handle": i + 2, "expr": r.Expr}})
	}
	body, e := json.Marshal(map[string]any{"nftables": rows})
	if e != nil {
		t.Fatal(e)
	}
	return p, nativeStartupFake{listing: "table inet " + p.Name + "\n", body: string(body)}
}
func TestNativeStartupBarrierHasEarlyOutboundRejectAndNarrowExceptions(t *testing.T) {
	p, _ := nativeStartupFixture(t)
	script, e := nativeStartupScript(p)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(script, "type filter hook output priority 200;") ||
		!strings.Contains(script, "ct direction reply accept") ||
		!strings.Contains(script, "meta mark 0x2023 accept") ||
		!strings.Contains(script, "meta mark 0x2024 accept") ||
		strings.Contains(script, "204.11.2.217") ||
		strings.Contains(script, " dport 53 accept") ||
		strings.Contains(script, "oifname \"eth0\" ip daddr 0.0.0.0/0 reject") ||
		!strings.Contains(script, "ip daddr 0.0.0.0/0 reject") ||
		!strings.Contains(script, "ip6 daddr ::/0 reject") {
		t.Fatal("pre-core barrier omitted a required outbound containment or bootstrap rule")
	}
	for _, bad := range []nativeStartupPlan{
		{Version: 1, Name: "sc_pre_$(touch /tmp/unsafe)", UnderlayIF: "eth0"},
		{Version: 1, Name: p.Name, UnderlayIF: "eth0;drop"},
		{Version: 1, Name: p.Name, UnderlayIF: "lo"},
		{Version: 1, Name: p.Name, UnderlayIF: "eth0", DirectPrefixes: []string{"0.0.0.0/0"}},
	} {
		if _, e := nativeStartupScript(bad); e == nil {
			t.Fatalf("unsafe startup barrier accepted: %+v", bad)
		}
	}
}
func TestNativeStartupKernelReceiptRefusesAlteredOrForeignObject(t *testing.T) {
	p, r := nativeStartupFixture(t)
	handle, e := nativeStartupReceipt(context.Background(), r, p)
	if e != nil || handle != 5 {
		t.Fatalf("valid kernel receipt failed: %d %v", handle, e)
	}
	if e = requireNativeStartupGuardClaim(context.Background(), r, p, 5); e != nil {
		t.Fatal(e)
	}
	if e = requireNativeStartupGuardClaim(context.Background(), r, p, 6); e == nil {
		t.Fatal("adopted replaced nft handle")
	}
	variants := []struct{ name, body string }{
		{"altered-mark", strings.Replace(r.body, `"right":8228`, `"right":8227`, 1)},
		{"changed-direct-prefix", strings.Replace(r.body, "193.111.235.0", "193.111.235.128", 1)},
		{"removed-reject", strings.Replace(r.body, `"reject":{"expr":"port-unreachable","type":"icmp"}`, `"accept":null`, 1)},
		{"extra-object", strings.Replace(r.body, "]}", `,{"table":{"family":"ip","name":"intruder"}}]}`, 1)},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			altered := r
			altered.body = v.body
			if _, e := nativeStartupReceipt(context.Background(), altered, p); e == nil {
				t.Fatal("modified kernel object accepted")
			}
		})
	}
	foreign := r
	foreign.listing += "table inet sc_pre_" + strings.Repeat("b", 32) + "\n"
	if e := requireNativeStartupGuardClaim(context.Background(), foreign, p, 5); e == nil {
		t.Fatal("foreign parallel native barrier ignored")
	}
}

// Executed by the isolated root network-namespace harness, not by ordinary
// source CI users. Genuine nftables JSON and generation-CAS behavior must
// agree with the verified script before any physical installed-host Apply.
func TestNativeStartupRealKernelNamespaceLifecycle(t *testing.T) {
	// Root inside a CI/container image is NOT authorization to mutate its
	// host network. Require an actual, separate network namespace relative
	// to the container/host PID 1, and the kernel tools needed for the test.
	if os.Geteuid() != 0 {
		t.Skip("requires root in an isolated network namespace")
	}
	self, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		t.Skipf("cannot verify network namespace isolation: %v", err)
	}
	init, err := os.Stat("/proc/1/ns/net")
	if err != nil {
		t.Skipf("cannot verify init network namespace: %v", err)
	}
	if os.SameFile(self, init) {
		t.Skip("not an isolated network namespace")
	}
	if _, err = exec.LookPath("nft"); err != nil {
		t.Skip("nft tool unavailable in isolated namespace")
	}
	if _, err = exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 unavailable in isolated namespace")
	}
	if b, e := exec.Command("ip", "link", "show", "eth0").CombinedOutput(); e == nil {
		t.Fatalf("refusing namespace with a potential real underlay: %s", b)
	}
	p, _ := nativeStartupFixture(t)
	ctx := context.Background()
	runner := nativeSystemRunner{}
	present, e := nativeStartupPresent(ctx, runner, p.Name)
	if e != nil || present {
		t.Fatalf("unexpected occupied namespace: %v %v", present, e)
	}
	handle, e := nativeStartupInstall(ctx, runner, p)
	if e != nil || handle == 0 {
		t.Fatalf("nft guard install or ownership verification failed: %d %v", handle, e)
	}
	t.Cleanup(func() {
		// Only this uniquely named test table in a disposable netns is task-owned.
		_ = exec.Command("nft", "delete", "table", "inet", p.Name).Run()
	})
	if e = requireNativeStartupGuardClaim(ctx, runner, p, handle); e != nil {
		t.Fatal(e)
	}
	if e = nativeStartupRecover(ctx, runner, p, handle, "armed"); e != nil {
		t.Fatal(e)
	}
	present, e = nativeStartupPresent(ctx, runner, p.Name)
	if e != nil || present {
		t.Fatalf("nft startup barrier remained: %v %v", present, e)
	}
	// A confirmed removed table is retryable under the durable releasing
	// receipt after an interruption, even before final receipt retirement.
	if e = nativeStartupRecover(ctx, runner, p, handle, "releasing"); e != nil {
		t.Fatal(e)
	}
	if e = nativeStartupRecover(ctx, runner, p, handle, "released"); e != nil {
		t.Fatal(e)
	}
}

// A CONNECT intent alone is not admission. Caller-visible Smart is forbidden
// until the actual startup packet gate has been installed, verified and
// committed. Historical prearm tests did not cover this unsafe interleaving.
func TestNativePrearmMustRemainDirectUntilPacketContainment(t *testing.T) {
	s := NativeSession{Selected: "qa-profile"}
	state := State{Desired: "direct", Selected: "qa-profile"}
	if err := nativePendingPrearmMatches(state, s); err != nil {
		t.Fatalf("safe prearm refused: %v", err)
	}
	for _, mutation := range []struct {
		name    string
		state   State
		session NativeSession
	}{
		{"premature-smart", State{Desired: "smart", Selected: "qa-profile"}, s},
		{"profile-swapped", State{Desired: "direct", Selected: "other"}, s},
		{"unset-profile", State{Desired: "direct"}, s},
		{"replayed-core", state, NativeSession{Selected: "qa-profile", CoreStartAttempted: true}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if err := nativePendingPrearmMatches(mutation.state, mutation.session); err == nil {
				t.Fatal("unsafe native prearm state accepted")
			}
		})
	}
}

// Model only this operation's exact nft table, without mutating the host.
// A real nft deletion may succeed just before ExecStopPost is interrupted.
type nativeStartupReleaseRunner struct {
	nativeStartupFake
	present      bool
	generation   uint32
	fails        int
	deletes      int
	beforeDelete func() error
}

func (r *nativeStartupReleaseRunner) output(ctx context.Context, binary string, args ...string) (string, error) {
	if binary == "nft" && strings.Join(args, " ") == "list tables" && !r.present {
		return "table inet unrelated_owner\n", nil
	}
	if !r.present {
		return "", fmt.Errorf("owned nft table absent")
	}
	return r.nativeStartupFake.output(ctx, binary, args...)
}

func (r *nativeStartupReleaseRunner) replyGuardGeneration() (uint32, error) {
	return r.generation, nil
}
func (r *nativeStartupReleaseRunner) deleteReplyGuardCAS(handle uint64, generation uint32) error {
	if !r.present || handle != 5 || generation != r.generation {
		return fmt.Errorf("unexpected CAS handle or generation")
	}
	if r.beforeDelete != nil {
		if err := r.beforeDelete(); err != nil {
			return err
		}
	}
	if r.fails > 0 {
		r.fails--
		return fmt.Errorf("injected nft generation-conditional deletion failure")
	}
	r.present = false
	r.generation++
	r.deletes++
	return nil
}

func nativeStartupReleaseFixture(t *testing.T) (*Manager, NativeSession, *nativeStartupReleaseRunner) {
	t.Helper()
	p, fake := nativeStartupFixture(t)
	m := New(filepath.Join(t.TempDir(), "state"), "", 0)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	session := NativeSession{Version: 1, Selected: "0123456789abcdef", InterfaceName: "sctun0",
		UnderlayIF: p.UnderlayIF, ConfigSHA256: strings.Repeat("b", 64),
		HealthOperationID: strings.Repeat("a", 32), StartupGuardName: p.Name,
		StartupGuardSHA256: hex.EncodeToString(digest[:]), StartupGuardPhase: "armed", StartupGuardHandle: 5}
	claim, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.withLock(func() error {
		if err := m.save(State{Version: 1, Desired: "direct", Port: m.Port}); err != nil {
			return err
		}
		if err := put(filepath.Join(m.Dir, nativeStartupFile), raw); err != nil {
			return err
		}
		return put(filepath.Join(m.Dir, nativeSessionFile), claim)
	}); err != nil {
		t.Fatal(err)
	}
	return m, session, &nativeStartupReleaseRunner{nativeStartupFake: fake, present: true, generation: 5}
}

func TestNativeLifetimeBarrierInterruptedRelease(t *testing.T) {
	ctx := context.Background()
	t.Run("deleted-before-finalization-recovers-idempotently", func(t *testing.T) {
		m, claim, r := nativeStartupReleaseFixture(t)
		r.beforeDelete = func() error {
			state, err := m.load()
			if err != nil || state.Desired != "direct" {
				return fmt.Errorf("Direct not durable before deletion: %v", err)
			}
			current, err := m.readNativeSession()
			if err != nil || current.StartupGuardPhase != "releasing" ||
				current.StartupGuardHandle != claim.StartupGuardHandle || current.HealthOperationID != claim.HealthOperationID {
				return fmt.Errorf("release intent not durable before deletion: %+v, %v", current, err)
			}
			return nil
		}
		if err := m.withLock(func() error {
			return m.recoverNativeStartupWithSession(ctx, r, claim)
		}); err != nil {
			t.Fatal(err)
		}
		if r.present || r.deletes != 1 {
			t.Fatal("owned nft deletion did not complete")
		}
		// Simulate SIGKILL after kernel CAS succeeded, before final receipt retirement.
		persisted, err := m.readNativeSession()
		if err != nil || persisted.StartupGuardPhase != "releasing" {
			t.Fatalf("lost durable release intent: %+v %v", persisted, err)
		}
		if err := m.withLock(func() error {
			if err := m.recoverNativeStartupWithSession(ctx, r, persisted); err != nil {
				return err
			}
			if err := m.recoverNativeStartupWithSession(ctx, r, persisted); err != nil {
				return err
			}
			return m.finalizeNativeRecoveryLocked()
		}); err != nil {
			t.Fatalf("interrupted cleanup could not complete: %v", err)
		}
		if _, err := m.readNativeSession(); !os.IsNotExist(err) {
			t.Fatalf("recovery claim not retired: %v", err)
		}
		if r.deletes != 1 {
			t.Fatalf("idempotent retry deleted twice: %d", r.deletes)
		}
	})
	t.Run("failed-delete-stays-owned-and-retries", func(t *testing.T) {
		m, claim, r := nativeStartupReleaseFixture(t)
		r.fails = 1
		if err := m.withLock(func() error { return m.recoverNativeStartupWithSession(ctx, r, claim) }); err == nil {
			t.Fatal("injected CAS failure was ignored")
		}
		persisted, err := m.readNativeSession()
		if err != nil || persisted.StartupGuardPhase != "releasing" || !r.present || r.deletes != 0 {
			t.Fatalf("failed deletion lost original guard/intent: %+v %v", persisted, err)
		}
		if err := m.withLock(func() error {
			if err := m.recoverNativeStartupWithSession(ctx, r, persisted); err != nil {
				return err
			}
			return m.finalizeNativeRecoveryLocked()
		}); err != nil {
			t.Fatalf("retry failed: %v", err)
		}
		if r.present || r.deletes != 1 {
			t.Fatal("retry did not remove exact original guard once")
		}
	})
	t.Run("changed-or-foreign-table-is-refused", func(t *testing.T) {
		m, claim, r := nativeStartupReleaseFixture(t)
		r.fails = 1
		if err := m.withLock(func() error { return m.recoverNativeStartupWithSession(ctx, r, claim) }); err == nil {
			t.Fatal("injected first delete should fail")
		}
		persisted, err := m.readNativeSession()
		if err != nil || persisted.StartupGuardPhase != "releasing" {
			t.Fatalf("lost release intent: %v", err)
		}
		original := r.body
		r.body = strings.Replace(original, `"handle":5`, `"handle":6`, 1)
		if r.body == original {
			t.Fatal("fixture did not change table handle")
		}
		if err := m.withLock(func() error { return m.recoverNativeStartupWithSession(ctx, r, persisted) }); err == nil || r.deletes != 0 {
			t.Fatalf("modified nft owner accepted: %v deletes=%d", err, r.deletes)
		}
		r.body = original
		originalListing := r.listing
		r.listing += "table inet sc_pre_" + strings.Repeat("c", 32) + "\n"
		if err := m.withLock(func() error { return m.recoverNativeStartupWithSession(ctx, r, persisted) }); err == nil || r.deletes != 0 {
			t.Fatalf("foreign parallel nft owner accepted: %v deletes=%d", err, r.deletes)
		}
		r.listing = originalListing
		if err := m.withLock(func() error {
			return put(filepath.Join(m.Dir, nativeStartupFile), []byte(`{"version":1,"name":"tampered"}`))
		}); err != nil {
			t.Fatal(err)
		}
		if err := m.withLock(func() error { return m.recoverNativeStartupWithSession(ctx, r, persisted) }); err == nil || r.deletes != 0 {
			t.Fatalf("tampered original release plan accepted: %v deletes=%d", err, r.deletes)
		}
		current, err := m.readNativeSession()
		if err != nil || current != persisted {
			t.Fatalf("foreign collision altered receipt: %+v %v", current, err)
		}
	})
	t.Run("no-premature-intent-or-absent-armed-acceptance", func(t *testing.T) {
		m, claim, r := nativeStartupReleaseFixture(t)
		if err := m.withLock(func() error { return m.save(State{Version: 1, Desired: "smart", Port: m.Port}) }); err != nil {
			t.Fatal(err)
		}
		if err := m.withLock(func() error { return m.recoverNativeStartupWithSession(ctx, r, claim) }); err == nil || !r.present {
			t.Fatalf("pre-Direct nft removal accepted: %v", err)
		}
		current, err := m.readNativeSession()
		if err != nil || current.StartupGuardPhase != "armed" {
			t.Fatalf("premature release intent: %+v %v", current, err)
		}
		if err := m.withLock(func() error { return m.save(State{Version: 1, Desired: "direct", Port: m.Port}) }); err != nil {
			t.Fatal(err)
		}
		otherOperation := claim
		otherOperation.HealthOperationID = strings.Repeat("c", 32)
		if err := m.withLock(func() error { return m.recoverNativeStartupWithSession(ctx, r, otherOperation) }); err == nil || !r.present {
			t.Fatalf("different session adopted operation: %v", err)
		}
		r.present = false
		if err := m.withLock(func() error { return m.recoverNativeStartupWithSession(ctx, r, claim) }); err == nil {
			t.Fatal("absent guard accepted without durable release intent")
		}
		current, err = m.readNativeSession()
		if err != nil || current.StartupGuardPhase != "armed" {
			t.Fatalf("missing original guard advanced state: %+v %v", current, err)
		}
	})
}
