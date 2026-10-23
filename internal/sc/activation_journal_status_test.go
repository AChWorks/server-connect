package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestActivationJournalStatusAbsentIsNotActivationProof(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(filepath.Join(dir, "private-state"), "", 0)
	first, err := m.InspectActivationJournal()
	if err != nil {
		t.Fatal(err)
	}
	if first.Phase != "absent" || first.Present || first.OperationID != "" ||
		first.Revision != 0 || first.CreatedUnix != 0 || first.ResourceCount != 0 ||
		first.RequiresOperatorReview || first.ActivationReady || first.GuardArmed ||
		first.RecoveryVerified || first.HostNetworkInspected {
		t.Fatalf("missing intent falsely implies activation/host recovery: %+v", first)
	}
	again, err := New(m.Dir, "", 0).InspectActivationJournal()
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatalf("fresh manager changed no-journal interpretation: %+v err=%v", again, err)
	}
	if _, err := os.Lstat(filepath.Join(m.Dir, activationJournalFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("status inspection fabricated an intent journal: %v", err)
	}
}

func TestActivationJournalStatusPreparedUncertainAndRedacted(t *testing.T) {
	m := New(privateJournalTempDir(t), "", 0)
	changes := fixtureJournalChanges()
	// The PRIVATE resource evidence may contain topology or credential-like
	// bytes. The status surface must never return it.
	const secret = "opaque-internal-network-secret-do-not-export"
	changes[0].Intended = json.RawMessage(`{"destination":"8.8.8.0/24","marker":"opaque-internal-network-secret-do-not-export"}`)
	created, err := m.prepareActivationJournal(
		strings.Repeat("a", 64), strings.Repeat("b", 64), changes)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus := func(wantPhase string, wantRevision uint64) {
		t.Helper()
		report, err := New(m.Dir, "", 0).InspectActivationJournal()
		if err != nil || report.Phase != wantPhase || !report.Present ||
			report.OperationID != created.OperationID ||
			report.Revision != wantRevision || report.CreatedUnix != created.CreatedUnix ||
			report.ResourceCount != len(changes) || !report.RequiresOperatorReview ||
			report.ActivationReady || report.GuardArmed || report.RecoveryVerified ||
			report.HostNetworkInspected {
			t.Fatalf("invalid safe journal status: %+v err=%v", report, err)
		}
		raw, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{secret, "8.8.8.0/24", `"before"`, `"intended"`,
			`"observation_sha256"`, `"plan_sha256"`, `"guard_armed":true`} {
			if bytes.Contains(raw, []byte(forbidden)) {
				t.Fatalf("private evidence or unsupported safety assertion leaked: %s", raw)
			}
		}
	}
	assertStatus("prepared", 1)
	if _, err := m.markActivationJournalUncertain(created.OperationID, 1); err != nil {
		t.Fatal(err)
	}
	assertStatus("uncertain", 2)
	if err := m.abandonPreparedActivationJournal(created.OperationID, 1); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("status observation accidentally authorized uncertain cleanup: %v", err)
	}
}

func TestActivationJournalStatusCorruptRefusesFalseAbsenceAndPreservesEvidence(t *testing.T) {
	m := New(privateJournalTempDir(t), "", 0)
	if _, err := prepareFixtureJournal(m); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.Dir, activationJournalFilename)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Replace(before, []byte(`"phase":"prepared"`),
		[]byte(`"phase":"active_verified"`), 1)
	if bytes.Equal(before, corrupt) {
		t.Fatal("corrupt fixture was not constructed")
	}
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	report, err := m.InspectActivationJournal()
	if ErrorCode(err) != "activation_journal_invalid" || report.Phase != "" ||
		report.OperationID != "" || report.Present {
		t.Fatalf("untrusted intent was treated as a safe absence: %+v err=%v", report, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, corrupt) {
		t.Fatalf("status mutated corrupt journal evidence: %v", err)
	}
}
