//go:build linux

package sc

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestNativeTUNAdvanceRequiresOneDurableParent(t *testing.T) {
	current := nativeTrialExample(false)
	next := cloneSmartTUNTrial(current)
	next.Native.LinkStage = "create_possible"
	called := 0
	accept := func(before, after smartTUNTrialJournal) error {
		called++
		if !sameSmartTUNTrial(before, current) || !sameSmartTUNTrial(after, next) {
			t.Fatal("lost a full native record during persistence")
		}
		return nil
	}
	if ErrorCode(nativeTUNAdvanceWithPersist(nil, next, accept)) != "guard_unavailable" ||
		ErrorCode(nativeTUNAdvanceWithPersist(&current, next, nil)) != "guard_unavailable" {
		t.Fatal("missing durable owner accepted")
	}
	wrong := cloneSmartTUNTrial(next)
	wrong.OperationID = strings.Repeat("f", 32)
	if ErrorCode(nativeTUNAdvanceWithPersist(&current, wrong, accept)) != "activation_journal_conflict" {
		t.Fatal("wrong operation accepted")
	}
	wrong = cloneSmartTUNTrial(next)
	wrong.BootID = "22222222-3333-4444-5555-666666666666"
	if ErrorCode(nativeTUNAdvanceWithPersist(&current, wrong, accept)) != "activation_journal_conflict" {
		t.Fatal("wrong boot accepted")
	}
	refused := errors.New("parent fsync failed")
	if !errors.Is(nativeTUNAdvanceWithPersist(&current, next, func(smartTUNTrialJournal, smartTUNTrialJournal) error { return refused }), refused) ||
		current.Native.LinkStage != "planned" || called != 0 {
		t.Fatal("failed durability advanced uncommitted record")
	}
	if err := nativeTUNAdvanceWithPersist(&current, next, accept); err != nil ||
		current.Native.LinkStage != "create_possible" || called != 1 {
		t.Fatalf("successful complete native transition rejected: %v", err)
	}
}

// A future full-host journal must write BOTH ingress and native state in one
// inode-CAS parent, never create a parallel v4 native journal.
type nativeTestEnclosingParent struct {
	Capture hostCaptureGateProgress `json:"capture"`
	TUN     smartTUNTrialJournal    `json:"tun"`
}

func TestNativeTUNPersistDetectsChangedHostCaptureParent(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	record := nativeTrialExample(false)
	parent := nativeTestEnclosingParent{Capture: hostCaptureJournalExample().Progress, TUN: record}
	if parent.Capture.Ingress.OperationID != record.OperationID || parent.Capture.Ingress.BootID != record.BootID {
		t.Fatal("cross-operation test fixture")
	}
	encode := func(p nativeTestEnclosingParent) []byte {
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := store.writeJournal(encode(parent), nil); err != nil {
			return err
		}
		persist := func(before, next smartTUNTrialJournal) error {
			raw, identity, err := store.readJournal()
			if err != nil {
				return err
			}
			var observed nativeTestEnclosingParent
			if err := json.Unmarshal(raw, &observed); err != nil {
				return err
			}
			if !reflect.DeepEqual(observed, parent) || !sameSmartTUNTrial(observed.TUN, before) {
				return Fault("activation_journal_conflict", "host/native enclosing parent changed")
			}
			updated := observed
			updated.TUN = cloneSmartTUNTrial(next)
			if err := store.writeJournal(encode(updated), &identity); err != nil {
				return err
			}
			confirmedRaw, _, err := store.readJournal()
			if err != nil {
				return err
			}
			var confirmed nativeTestEnclosingParent
			if err := json.Unmarshal(confirmedRaw, &confirmed); err != nil {
				return err
			}
			if !reflect.DeepEqual(confirmed, updated) {
				return Fault("activation_journal_conflict", "parent readback mismatch")
			}
			parent = updated
			return nil
		}
		first := cloneSmartTUNTrial(record)
		first.Native.LinkStage = "create_possible"
		if err := nativeTUNAdvanceWithPersist(&record, first, persist); err != nil {
			return err
		}
		if parent.Capture.Ingress.SysctlBefore != 1 || record.Native.LinkStage != "create_possible" {
			t.Fatal("native transition altered host ingress")
		}
		oldParent := parent
		raw, identity, err := store.readJournal()
		if err != nil || len(raw) == 0 {
			return err
		}
		foreign := parent
		foreign.Capture.Ingress.Deadline++
		if err := store.writeJournal(encode(foreign), &identity); err != nil {
			return err
		}
		second := cloneSmartTUNTrial(record)
		second.Native.LinkStage = "planned"
		if ErrorCode(nativeTUNAdvanceWithPersist(&record, second, persist)) != "activation_journal_conflict" ||
			record.Native.LinkStage != "create_possible" || !reflect.DeepEqual(parent, oldParent) {
			t.Fatal("stale native transition replaced a changed host ingress parent")
		}
		observedRaw, _, err := store.readJournal()
		if err != nil {
			return err
		}
		if string(observedRaw) != string(encode(foreign)) {
			t.Fatal("foreign parent change was erased")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
