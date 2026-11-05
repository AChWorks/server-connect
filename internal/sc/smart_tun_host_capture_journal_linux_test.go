//go:build linux

package sc

import (
	"encoding/json"
	"strings"
	"syscall"
	"testing"
)

func hostCaptureJournalExample() hostCaptureJournal {
	ingress := hostIngressStageExample()
	ingress.SysctlBefore = 1
	return hostCaptureJournal{
		Version: hostCaptureJournalVersion, Intent: hostCaptureJournalIntent,
		Progress: hostCaptureGateProgress{Ingress: ingress, Barrier: hostBarrierExample()},
	}
}

func TestHostCaptureParentStrictIdentityAndUnsupportedFields(t *testing.T) {
	example := hostCaptureJournalExample()
	data, err := json.Marshal(example)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeHostCaptureJournal(data); err != nil || got != example {
		t.Fatalf("valid enclosing journal did not roundtrip: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*hostCaptureJournal)
	}{
		{"version", func(r *hostCaptureJournal) { r.Version++ }},
		{"intent", func(r *hostCaptureJournal) { r.Intent = "" }},
		{"sysctl", func(r *hostCaptureJournal) { r.Progress.Ingress.SysctlBefore = 0 }},
		{"operation", func(r *hostCaptureJournal) {
			r.Progress.Barrier.OperationID = strings.Repeat("b", 32)
			r.Progress.Barrier.Name = "scq" + strings.Repeat("b", 12)
		}},
		{"boot", func(r *hostCaptureJournal) { r.Progress.Barrier.BootID = "22222222-3333-4444-5555-666666666666" }},
		{"namespace", func(r *hostCaptureJournal) { r.Progress.Barrier.NamespaceIno++ }},
		{"barrier too early", func(r *hostCaptureJournal) { r.Progress.Barrier.Stage = "closed" }},
		{"invalid nft stage", func(r *hostCaptureJournal) { r.Progress.Ingress.NFTStage = "observed" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := example
			tc.change(&bad)
			raw, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeHostCaptureJournal(raw); err == nil {
				t.Fatalf("unsafe parent accepted: %+v", bad)
			}
		})
	}
	for _, raw := range []string{
		strings.Replace(string(data), "\"version\":6", "\"version\":6,\"Version\":6", 1),
		strings.Replace(string(data), "\"progress\":{", "\"Progress\":{},\"progress\":{", 1),
		strings.Replace(string(data), "\"ingress\":{", "\"INGRESS\":{},\"ingress\":{", 1),
		strings.Replace(string(data), "\"barrier\":{", "\"barrier\":null,", 1),
		strings.Replace(string(data), "\"namespace_ino\":2", "\"namespace_ino\":null", 1),
		strings.Replace(string(data), "\"stage\":\"planned\"", "\"stage\":null", 1),
		string(data[:len(data)-1]) + ",\"extra\":true}",
		string(data) + " {}",
	} {
		if _, err := decodeHostCaptureJournal([]byte(raw)); err == nil {
			t.Fatalf("ambiguous privileged recovery journal accepted: %s", raw)
		}
	}
}

func TestHostCaptureParentProgressCASAndRecoverySelectionShareLock(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	record := hostCaptureJournalExample()
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostCaptureJournal(store, record, nil); err != nil {
			return err
		}
		persist := hostCaptureJournalPersist(store, &record)
		previous := record.Progress
		next := previous
		next.Ingress.SysctlStage = "effect_possible"
		if err := persist(previous, next); err != nil || record.Progress != next {
			t.Fatalf("durable full-parent progress not acknowledged: %v", err)
		}
		observed, id, err := loadHostCaptureJournal(store)
		if err != nil || observed != record {
			t.Fatalf("durable host capture parent lost progress: %v", err)
		}
		if code := ErrorCode(persist(previous, next)); code != "activation_journal_conflict" {
			t.Fatalf("old parent progress replay accepted: %s", code)
		}
		tampered := observed
		tampered.Progress.Ingress.Deadline++
		if err := writeHostCaptureJournal(store, tampered, &id); err != nil {
			return err
		}
		next.Ingress.SysctlStage = "observed"
		if code := ErrorCode(persist(record.Progress, next)); code != "activation_journal_conflict" {
			t.Fatalf("foreign changed parent evaded full comparison: %s", code)
		}
		if record.Progress != observed.Progress {
			t.Fatal("readback or conflict advanced in-memory parent")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	label, err := m.pendingSmartTUNTrial()
	if err != nil || label != "host_capture_pending" {
		t.Fatalf("host capture journal invisible to concurrency gates: %s %v", label, err)
	}
	selections := 0
	_, err = m.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, selection trialRecoverySelection) (TrialReceipt, error) {
		selections++
		if selection.version != hostCaptureJournalVersion || selection.capture.Progress.Ingress.SysctlStage != "effect_possible" ||
			selection.capture.Progress.Ingress.Deadline != record.Progress.Ingress.Deadline+1 {
			t.Fatal("recovery did not select the validated full parent under the manager lock")
		}
		return TrialReceipt{Phase: "read_only_selected"}, nil
	})
	if err != nil || selections != 1 {
		t.Fatalf("locked v6 dispatch failed: %v", err)
	}
	_, err = m.recoverGuardedTrialWithHandler("after-delete", "", func(*activationJournalDir, trialRecoverySelection) (TrialReceipt, error) {
		t.Fatal("legacy injected recovery reached v6 handler")
		return TrialReceipt{}, nil
	})
	if ErrorCode(err) != "invalid_arguments" {
		t.Fatalf("legacy QA fault not refused for v6: %v", err)
	}
}

// The nonprivileged unit case verifies that a recognized v6 preparation
// cannot be abandoned before Off, even when its identity matches. Native
// tests separately prove exact terminal clearance against the actual kernel.
func TestHostCapturePreparationClearRejectsPendingAndWrongIdentity(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	record := hostCaptureJournalExample()
	id := record.Progress.Ingress.OperationID
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostCaptureJournal(store, record, nil); err != nil {
			return err
		}
		for _, tc := range []struct {
			id   string
			code string
		}{
			{"short", "invalid_arguments"},
			{strings.Repeat("f", 32), "activation_journal_conflict"},
			{id, "activation_journal_conflict"},
		} {
			if code := ErrorCode(clearRecoveredHostCapturePreparationLocked(store, tc.id)); code != tc.code {
				t.Fatalf("clear(%s) = %s, want %s", tc.id, code, tc.code)
			}
			got, _, err := loadHostCaptureJournal(store)
			if err != nil || got != record {
				t.Fatalf("refused clearance modified parent: %v", err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if code := ErrorCode(m.ClearRecoveredHostCapturePreparation(id)); code != "invalid_arguments" {
		t.Fatalf("test-local directory used installed-only clearance: %s", code)
	}
}
