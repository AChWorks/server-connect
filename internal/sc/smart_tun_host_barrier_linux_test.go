//go:build linux

package sc

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func hostBarrierExample() hostNetworkBarrier {
	return hostNetworkBarrier{Version: 1, OperationID: strings.Repeat("a", 32),
		BootID: "11111111-2222-3333-4444-555555555555", NamespaceDev: 1, NamespaceIno: 2,
		Name: "scq" + strings.Repeat("a", 12), Stage: "planned"}
}
func TestHostNetworkBarrierRequiresExactIdentityAndTransitions(t *testing.T) {
	b := hostBarrierExample()
	if err := validateHostNetworkBarrier(b); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*hostNetworkBarrier){
		func(b *hostNetworkBarrier) { b.Version = 0 }, func(b *hostNetworkBarrier) { b.OperationID = "short" },
		func(b *hostNetworkBarrier) { b.BootID = "" }, func(b *hostNetworkBarrier) { b.NamespaceDev = 0 },
		func(b *hostNetworkBarrier) { b.NamespaceIno = 0 }, func(b *hostNetworkBarrier) { b.Name = "lo" },
		func(b *hostNetworkBarrier) { b.Stage = "active" },
	} {
		bad := b
		change(&bad)
		if validateHostNetworkBarrier(bad) == nil {
			t.Fatalf("invalid barrier accepted: %+v", bad)
		}
	}
	called := 0
	persist := func(previous, next hostNetworkBarrier) error {
		called++
		if previous != b {
			t.Fatal("lost parent comparison")
		}
		return nil
	}
	bad := b
	bad.Stage = "closed"
	if advanceHostNetworkBarrier(&b, bad, persist) == nil || called != 0 {
		t.Fatal("uncreated barrier acquired close receipt")
	}
	next := b
	next.Stage = "create_possible"
	if err := advanceHostNetworkBarrier(&b, next, persist); err != nil || called != 1 {
		t.Fatalf("create intent: %v calls%d", err, called)
	}
	before := b
	next = b
	next.Stage = "closed"
	failure := errors.New("directory fsync failed")
	if err := advanceHostNetworkBarrier(&b, next, func(previous, next hostNetworkBarrier) error { return failure }); err != failure || b != before {
		t.Fatal("failed persistence advanced confirmed memory")
	}
	if err := advanceHostNetworkBarrier(&b, next, func(previous, next hostNetworkBarrier) error { return nil }); err != nil || b.Stage != "closed" {
		t.Fatal("durable close did not advance")
	}
	if advanceHostNetworkBarrier(&b, next, func(previous, next hostNetworkBarrier) error { return nil }) == nil {
		t.Fatal("close receipt replay was accepted")
	}
}

func TestHostNetworkBarrierNativeLifetime(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_BARRIER_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: explicit fresh isolated namespace required")
	}
	self, e1 := os.Stat("/proc/self/ns/net")
	root, e2 := os.Stat("/proc/1/ns/net")
	if os.Geteuid() != 0 || e1 != nil || e2 != nil || os.SameFile(self, root) {
		t.Fatal("root host namespace refused")
	}
	guard := func() error {
		now, err := os.Stat("/proc/self/ns/net")
		if err != nil || !os.SameFile(now, self) {
			return errors.New("test isolation changed")
		}
		return nil
	}
	// This is a helper kernel lifetime test. Namespace isolation supplies the
	// test safety boundary; no installed systemd guard or activation is claimed.
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	op, err := randomHex(16)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newHostNetworkBarrier(op)
	if err != nil {
		t.Fatal(err)
	}
	type parent struct {
		Version int                `json:"version"`
		Barrier hostNetworkBarrier `json:"barrier"`
	}
	snapshots := map[string]string{}
	for _, family := range []string{"-4", "-6"} {
		for _, kind := range []string{"route", "rule"} {
			args := []string{"-j", family, kind, "show"}
			if kind == "route" {
				args = append(args, "table", "all")
			}
			raw, err := nativeIPJSON(args...)
			if err != nil {
				t.Fatal(err)
			}
			snapshots[family+kind] = string(raw)
		}
	}
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		raw, _ := json.Marshal(parent{Version: 600, Barrier: b})
		if err := store.writeJournal(raw, nil); err != nil {
			return err
		}
		persist := func(previous, next hostNetworkBarrier) error {
			raw, id, err := store.readJournal()
			if err != nil {
				return err
			}
			var p parent
			if json.Unmarshal(raw, &p) != nil || p.Version != 600 || p.Barrier != previous {
				return errors.New("enclosing parent changed")
			}
			p.Barrier = next
			raw, _ = json.Marshal(p)
			return store.writeJournal(raw, &id)
		}
		if err := runHostNetworkBarrierLocked(store, &b, guard, persist); err != nil {
			return err
		}
		if b.Stage != "closed" {
			return errors.New("close not durably observed")
		}
		if err := verifyHostNetworkBarrierReleased(b); err != nil {
			return err
		}
		// A durable close receipt cannot become a new helper lifetime.
		if runHostNetworkBarrierLocked(store, &b, guard, persist) == nil {
			return errors.New("replayed lifetime accepted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"-4", "-6"} {
		for _, kind := range []string{"route", "rule"} {
			args := []string{"-j", family, kind, "show"}
			if kind == "route" {
				args = append(args, "table", "all")
			}
			raw, err := nativeIPJSON(args...)
			if err != nil || snapshots[family+kind] != string(raw) {
				t.Fatalf("foreign %s %s changed: %v", family, kind, err)
			}
		}
	}
	t.Log("HOST_BARRIER_FINAL_FD_RELEASE_AND_OWNED_ABSENCE=PASS")
	t.Log("HOST_BARRIER_DUAL_STACK_FIB_RPDB_PRESERVED=PASS")
}
