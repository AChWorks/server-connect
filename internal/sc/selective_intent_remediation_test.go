package sc

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func testSelectiveInspection(string, string) (HostPreflight, error) {
	return fixtureSelectiveHost(), nil
}

func stagedSelectiveTestJournal(t *testing.T, m *Manager) activationJournal {
	t.Helper()
	receipt, err := m.stageSelectiveIntentWithInspector(fixtureSelectiveRequest(), testSelectiveInspection)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.observeActivationJournal()
	if err != nil || got.OperationID != receipt.OperationID ||
		got.Revision != receipt.Revision || got.IntentType != selectiveIntentType || got.Selective == nil {
		t.Fatalf("staged selective journal not durable and self-identifying: %+v %+v %v", got, receipt, err)
	}
	return got
}

func TestSelectiveStageReceiptSurvivesOtherManagerRemoval(t *testing.T) {
	dir := privateJournalTempDir(t)
	first := New(dir, "", 0)
	second := New(dir, "", 0)
	var operation string
	receipt, err := first.stageSelectiveIntentWithAfterCommit(fixtureSelectiveRequest(), testSelectiveInspection,
		func(a activationJournal) {
			operation = a.OperationID
			status, err := second.AbandonSelectiveIntent(a.OperationID, a.Revision)
			if err != nil || status.OperationID != a.OperationID || status.Phase != "absent" {
				t.Fatalf("other manager could not remove A: %+v %v", status, err)
			}
		})
	if err != nil || receipt.OperationID != operation || receipt.Phase != "prepared" || !receipt.Present ||
		receipt.Revision != 1 || !receipt.RequiresOperatorReview || receipt.GuardArmed || receipt.ActivationReady {
		t.Fatalf("stage receipt returned missing/unrelated operation: %+v %v", receipt, err)
	}
	actual, err := New(dir, "", 0).InspectActivationJournal()
	if err != nil || actual.Phase != "absent" || actual.Present {
		t.Fatalf("test did not create intended interleaving: %+v %v", actual, err)
	}
}

func TestSelectiveStageReceiptSurvivesReplacementOperation(t *testing.T) {
	dir := privateJournalTempDir(t)
	first, other := New(dir, "", 0), New(dir, "", 0)
	var a, b string
	receipt, err := first.stageSelectiveIntentWithAfterCommit(fixtureSelectiveRequest(), testSelectiveInspection,
		func(record activationJournal) {
			a = record.OperationID
			if _, err := other.AbandonSelectiveIntent(a, 1); err != nil {
				t.Fatal(err)
			}
			replacement, err := other.stageSelectiveIntentWithInspector(fixtureSelectiveRequest(), testSelectiveInspection)
			if err != nil {
				t.Fatal(err)
			}
			b = replacement.OperationID
		})
	if err != nil || a == "" || b == "" || a == b || receipt.OperationID != a || receipt.OperationID == b {
		t.Fatalf("stage A returned B after A was replaced: A=%s B=%s receipt=%+v err=%v", a, b, receipt, err)
	}
	live, err := New(dir, "", 0).InspectActivationJournal()
	if err != nil || live.OperationID != b || live.OperationID == receipt.OperationID {
		t.Fatalf("the interleaving did not actually replace A with B: %+v %v", live, err)
	}
}

func TestSelectiveAbandonReceiptSurvivesReplacementOperation(t *testing.T) {
	dir := privateJournalTempDir(t)
	owner, other := New(dir, "", 0), New(dir, "", 0)
	a := stagedSelectiveTestJournal(t, owner)
	var b string
	receipt, err := owner.abandonSelectiveIntentWithAfterRemove(a.OperationID, a.Revision, func() {
		replacement, err := other.stageSelectiveIntentWithInspector(fixtureSelectiveRequest(), testSelectiveInspection)
		if err != nil {
			t.Fatal(err)
		}
		b = replacement.OperationID
	})
	if err != nil || b == "" || b == a.OperationID || receipt.Phase != "absent" || receipt.Present ||
		receipt.OperationID != a.OperationID || receipt.OperationID == b || receipt.Revision != 1 ||
		receipt.GuardArmed || receipt.ActivationReady || receipt.RecoveryVerified {
		t.Fatalf("abandon A reported replacement B: A=%s B=%s receipt=%+v err=%v", a.OperationID, b, receipt, err)
	}
	live, err := other.InspectActivationJournal()
	if err != nil || live.OperationID != b || live.Phase != "prepared" {
		t.Fatalf("actual B did not persist after A removal: %+v %v", live, err)
	}
}

func TestSelectiveTwoManagersSerializeStagingUnderOneLock(t *testing.T) {
	dir := privateJournalTempDir(t)
	managers := []*Manager{New(dir, "", 0), New(dir, "", 0)}
	var start sync.WaitGroup
	start.Add(1)
	results := make([]ActivationJournalStatus, 2)
	errs := make([]error, 2)
	var done sync.WaitGroup
	done.Add(2)
	for i, m := range managers {
		go func(i int, manager *Manager) {
			defer done.Done()
			start.Wait()
			results[i], errs[i] = manager.stageSelectiveIntentWithInspector(fixtureSelectiveRequest(), testSelectiveInspection)
		}(i, m)
	}
	start.Done()
	done.Wait()
	success := 0
	var committed string
	for i, err := range errs {
		if err == nil {
			success++
			committed = results[i].OperationID
			continue
		}
		if ErrorCode(err) != "activation_journal_conflict" || results[i].OperationID != "" {
			t.Fatalf("concurrent stage returned another operation or unclassified result: %+v %v", results[i], err)
		}
	}
	if success != 1 || committed == "" {
		t.Fatalf("expected exactly one successful journal write: success=%d", success)
	}
	persisted, err := New(dir, "", 0).observeActivationJournal()
	if err != nil || persisted.OperationID != committed {
		t.Fatalf("cross-manager race lost committed operation: %+v %v", persisted, err)
	}
}

// All modifications below retain valid-looking root JSON, and many retain a
// valid generic journal schema. They must not authorize subtype-specific
// deletion or allow future guard records to masquerade as unarmed intent.
func TestSelectiveAbandonRejectsModifiedAndUnknownJournalPreservingBytes(t *testing.T) {
	cases := []struct {
		name   string
		change func(map[string]any)
	}{
		{"incomplete-single-route", func(j map[string]any) { j["changes"] = j["changes"].([]any)[:1] }},
		{"route-key-disagrees-with-destination", func(j map[string]any) {
			c := j["changes"].([]any)[0].(map[string]any)
			c["intended"].(map[string]any)["destination"] = "1.1.1.0/24"
		}},
		{"route-key-modified-only", func(j map[string]any) { j["changes"].([]any)[0].(map[string]any)["key"] = "ipv4:1.1.1.0/24:table20000" }},
		{"rule-priority-modified-only", func(j map[string]any) {
			j["changes"].([]any)[1].(map[string]any)["intended"].(map[string]any)["priority"] = float64(30005)
		}},
		{"rule-pair-removed", func(j map[string]any) { j["changes"] = j["changes"].([]any)[:1] }},
		{"route-unexpected-metadata", func(j map[string]any) {
			j["changes"].([]any)[0].(map[string]any)["intended"].(map[string]any)["operator_private_metadata"] = "hidden"
		}},
		{"route-missing-required-field", func(j map[string]any) {
			delete(j["changes"].([]any)[0].(map[string]any)["intended"].(map[string]any), "device")
		}},
		{"before-evidence-forged", func(j map[string]any) {
			j["changes"].([]any)[0].(map[string]any)["before"] = map[string]any{"route": "foreign"}
		}},
		{"plan-hash-modified", func(j map[string]any) { j["plan_sha256"] = strings.Repeat("b", 64) }},
		{"observation-hash-modified", func(j map[string]any) { j["observation_sha256"] = strings.Repeat("b", 64) }},
		{"endpoint-binding-modified", func(j map[string]any) { j["selective"].(map[string]any)["endpoint"] = "198.51.100.9" }},
		{"table-binding-modified", func(j map[string]any) { j["selective"].(map[string]any)["route_table"] = float64(20001) }},
		{"missing-subtype-marker", func(j map[string]any) { delete(j, "intent_type") }},
		{"unsupported-future-variant", func(j map[string]any) { j["intent_type"] = "guarded_selective_v2" }},
		{"unsupported-journal-version", func(j map[string]any) { j["version"] = float64(2) }},
		{"unrecognized-selective-binding", func(j map[string]any) { j["selective"].(map[string]any)["future_field"] = true }},
		{"unrelated-legacy-shape", func(j map[string]any) { delete(j, "intent_type"); delete(j, "selective") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateJournalTempDir(t)
			m := New(dir, "", 0)
			original := stagedSelectiveTestJournal(t, m)
			path := filepath.Join(dir, activationJournalFilename)
			encoded, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(encoded, &doc); err != nil {
				t.Fatal(err)
			}
			tc.change(doc)
			changed, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			changed = append(changed, '\n')
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := m.AbandonSelectiveIntent(original.OperationID, 1); err == nil ||
				(ErrorCode(err) != "activation_journal_invalid" && ErrorCode(err) != "activation_journal_conflict") {
				t.Fatalf("foreign or modified journal was deleted: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, changed) {
				t.Fatalf("rejected journal mutated or removed: %v", err)
			}
		})
	}
}

func TestSelectiveAbandonRejectsUnrelatedLegacySingleRoute(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, "", 0)
	change := fixtureJournalChanges()[:1]
	legacy, err := m.prepareActivationJournal(strings.Repeat("a", 64), strings.Repeat("b", 64), change)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, activationJournalFilename)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AbandonSelectiveIntent(legacy.OperationID, 1); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("valid generic one-route journal was adopted as selective: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("valid legacy one-route journal evidence destroyed")
	}
	observed, err := m.observeActivationJournal()
	if err != nil || !reflect.DeepEqual(observed, legacy) {
		t.Fatalf("generic record unexpectedly altered: %v", err)
	}
}

func TestSelectiveAbandonPreservesUncertainTypedJournal(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, "", 0)
	original := stagedSelectiveTestJournal(t, m)
	uncertain, err := m.markActivationJournalUncertain(original.OperationID, 1)
	if err != nil || uncertain.Phase != "uncertain" {
		t.Fatalf("typed uncertainty transition failed: %+v %v", uncertain, err)
	}
	path := filepath.Join(dir, activationJournalFilename)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, rev := range []uint64{1, 2} {
		if _, err := m.AbandonSelectiveIntent(original.OperationID, rev); ErrorCode(err) != "activation_journal_conflict" {
			t.Fatalf("uncertain revision %d was removed: %v", rev, err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("typed uncertain record changed despite refusal")
	}
}
