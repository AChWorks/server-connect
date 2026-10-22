package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// The Go toolchain used on development hosts may create a TempDir with
// permissive mode. The manager deliberately requires a private state root.
func privateJournalTempDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func fixtureJournalChanges() []activationJournalChange {
	return []activationJournalChange{
		{
			Kind: "route", Key: "ipv4:8.8.8.0/24:table20000",
			Before:   json.RawMessage(`null`),
			Intended: json.RawMessage(`{"family":"ipv4","destination":"8.8.8.0/24","table":20000,"device":"scplan0"}`),
			Stage:    "intent_recorded",
		},
		{
			Kind: "rule", Key: "ipv4:30000",
			Before:   json.RawMessage(`null`),
			Intended: json.RawMessage(`{"family":"ipv4","priority":30000,"table":20000,"destination":"8.8.8.0/24"}`),
			Stage:    "intent_recorded",
		},
	}
}

func prepareFixtureJournal(m *Manager) (activationJournal, error) {
	return m.prepareActivationJournal(strings.Repeat("a", 64), strings.Repeat("b", 64), fixtureJournalChanges())
}

func TestActivationJournalDurablePrepareAndSafeAbandon(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, "", 0)
	prepared, err := prepareFixtureJournal(m)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Phase != "prepared" || prepared.Revision != 1 ||
		!journalHex32.MatchString(prepared.OperationID) ||
		len(prepared.Changes) != 2 || prepared.Changes[0].Stage != "intent_recorded" {
		t.Fatalf("journal could claim unsupported activation or omit resources: %+v", prepared)
	}
	path := filepath.Join(dir, activationJournalFilename)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("persisted journal is not private and regular: %v", info.Mode())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"guard_armed"`, `"activation_ready"`, `"pending_confirmation"`, `"active_verified"`} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("PREPARED journal claims unsupported guard state: %q", forbidden)
		}
	}
	// Fresh independent Manager simulates the next process/recovery boot.
	fresh := New(dir, "", 0)
	recovered, err := fresh.observeActivationJournal()
	if err != nil || !reflect.DeepEqual(prepared, recovered) {
		t.Fatalf("recovery lost exact prepared record: got=%+v err=%v", recovered, err)
	}
	if _, err := prepareFixtureJournal(fresh); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("second operation should never replace unfinished record: %v", err)
	}
	if err := fresh.abandonPreparedActivationJournal(strings.Repeat("0", 32)); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("wrong operation was permitted to abandon journal: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("incorrect ID damaged journal: %v", err)
	}
	if err := fresh.abandonPreparedActivationJournal(prepared.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned prepared journal was not removed safely: %v", err)
	}
	if _, err := fresh.observeActivationJournal(); ErrorCode(err) != "activation_journal_missing" {
		t.Fatalf("missing journal must be explicit, got %v", err)
	}
	if _, err := prepareFixtureJournal(fresh); err != nil {
		t.Fatalf("after safe abandonment new operation must be possible: %v", err)
	}
}

func TestActivationJournalUncertainRetainedAndReplayRefused(t *testing.T) {
	m := New(privateJournalTempDir(t), "", 0)
	prepared, err := prepareFixtureJournal(m)
	if err != nil {
		t.Fatal(err)
	}
	reopened := New(m.Dir, "", 0)
	uncertain, err := reopened.markActivationJournalUncertain(prepared.OperationID, 1)
	if err != nil || uncertain.Phase != "uncertain" || uncertain.Revision != 2 ||
		uncertain.OperationID != prepared.OperationID {
		t.Fatalf("uncertain recovery identity was not durably advanced: %+v err=%v", uncertain, err)
	}
	found, err := New(m.Dir, "", 0).observeActivationJournal()
	if err != nil || !reflect.DeepEqual(uncertain, found) {
		t.Fatalf("uncertain journal did not survive restart: %+v err=%v", found, err)
	}
	if _, err := m.markActivationJournalUncertain(prepared.OperationID, 1); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("stale revision replay accepted: %v", err)
	}
	if err := m.abandonPreparedActivationJournal(prepared.OperationID); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("unreconciled uncertain journal was erased: %v", err)
	}
	if _, err := prepareFixtureJournal(m); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("unreconciled uncertain state was overwritten: %v", err)
	}
}

func TestActivationJournalValidationFailClosed(t *testing.T) {
	tests := []struct {
		name string
		edit func(*[]activationJournalChange, *string, *string)
	}{
		{"invalid_observation_digest", func(_ *[]activationJournalChange, a, _ *string) { *a = "invalid" }},
		{"invalid_plan_digest", func(_ *[]activationJournalChange, _, b *string) { *b = "invalid" }},
		{"no_resource", func(c *[]activationJournalChange, _, _ *string) { *c = nil }},
		{"duplicate_identity", func(c *[]activationJournalChange, _, _ *string) { *c = append(*c, (*c)[0]) }},
		{"unknown_kind", func(c *[]activationJournalChange, _, _ *string) { (*c)[0].Kind = "nftables_all" }},
		{"unsafe_resource_key", func(c *[]activationJournalChange, _, _ *string) { (*c)[0].Key = "../../etc/passwd" }},
		{"missing_absence_marker", func(c *[]activationJournalChange, _, _ *string) { (*c)[0].Before = nil }},
		{"malformed_observed_state", func(c *[]activationJournalChange, _, _ *string) { (*c)[0].Before = json.RawMessage(`{broken`) }},
		{"trailing_intended_json", func(c *[]activationJournalChange, _, _ *string) { (*c)[0].Intended = json.RawMessage(`{} {}`) }},
		{"same_old_and_new", func(c *[]activationJournalChange, _, _ *string) { (*c)[0].Before = (*c)[0].Intended }},
		{"unsupported_stage", func(c *[]activationJournalChange, _, _ *string) { (*c)[0].Stage = "applied" }},
		{"large_resource", func(c *[]activationJournalChange, _, _ *string) {
			(*c)[0].Intended = json.RawMessage(`"` + strings.Repeat("x", 8193) + `"`)
		}},
		{"too_many_resources", func(c *[]activationJournalChange, _, _ *string) {
			for i := 0; i < activationJournalMaxItems; i++ {
				*c = append(*c, activationJournalChange{
					Kind: "rule", Key: "ipv4:1234", Before: json.RawMessage(`null`),
					Intended: json.RawMessage(`{"rule":1}`), Stage: "intent_recorded",
				})
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(privateJournalTempDir(t), "", 0)
			changes, a, b := fixtureJournalChanges(), strings.Repeat("a", 64), strings.Repeat("b", 64)
			tt.edit(&changes, &a, &b)
			_, err := m.prepareActivationJournal(a, b, changes)
			if ErrorCode(err) != "activation_journal_invalid" {
				t.Fatalf("expected fail-closed invalid intent: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(m.Dir, activationJournalFilename)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid intent persisted some journal content: %v", err)
			}
		})
	}
}

func TestActivationJournalCorruptAndUntrustedFilesCannotBeReplaced(t *testing.T) {
	t.Run("corrupt_record", func(t *testing.T) {
		m := New(privateJournalTempDir(t), "", 0)
		path := filepath.Join(m.Dir, activationJournalFilename)
		corrupt := []byte(`{"version":1,"phase":"active_verified","operation_id":"malformed"}`)
		if err := os.WriteFile(path, corrupt, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := prepareFixtureJournal(m); ErrorCode(err) != "activation_journal_invalid" {
			t.Fatalf("corrupt prior record was overwritten: %v", err)
		}
		check, _ := os.ReadFile(path)
		if !bytes.Equal(corrupt, check) {
			t.Fatal("invalid journal was modified")
		}
	})
	t.Run("unknown_claimed_guard_field", func(t *testing.T) {
		m := New(privateJournalTempDir(t), "", 0)
		if _, err := prepareFixtureJournal(m); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(m.Dir, activationJournalFilename)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		malicious := bytes.Replace(content, []byte(`"version":1`),
			[]byte(`"version":1,"guard_armed":true`), 1)
		if bytes.Equal(malicious, content) {
			t.Fatal("tamper fixture did not change persisted JSON")
		}
		if err := os.WriteFile(path, malicious, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := m.observeActivationJournal(); ErrorCode(err) != "activation_journal_invalid" {
			t.Fatalf("unknown activation claim was accepted: %v", err)
		}
	})
	t.Run("insecure_mode", func(t *testing.T) {
		m := New(privateJournalTempDir(t), "", 0)
		path := filepath.Join(m.Dir, activationJournalFilename)
		if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := prepareFixtureJournal(m); ErrorCode(err) != "activation_journal_invalid" {
			t.Fatalf("insecure journal mode permitted replacement: %v", err)
		}
	})
	t.Run("symlinked_journal", func(t *testing.T) {
		m := New(privateJournalTempDir(t), "", 0)
		outside := filepath.Join(privateJournalTempDir(t), "outside.json")
		if err := os.WriteFile(outside, []byte("preserve-this"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(m.Dir, activationJournalFilename)); err != nil {
			t.Fatal(err)
		}
		if _, err := prepareFixtureJournal(m); ErrorCode(err) != "activation_journal_invalid" {
			t.Fatalf("symlink journal was followed or overwritten: %v", err)
		}
		raw, _ := os.ReadFile(outside)
		if string(raw) != "preserve-this" {
			t.Fatal("outside file changed")
		}
	})
	t.Run("symlinked_state_directory", func(t *testing.T) {
		real := privateJournalTempDir(t)
		link := filepath.Join(privateJournalTempDir(t), "link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if _, err := prepareFixtureJournal(New(link, "", 0)); err == nil {
			t.Fatal("symlinked state directory accepted")
		}
	})
}

func TestActivationJournalConcurrentPrepareUsesSharedManagerLock(t *testing.T) {
	m := New(privateJournalTempDir(t), "", 0)
	const workers = 8
	var wg sync.WaitGroup
	wg.Add(workers)
	results := make(chan string, workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			_, err := prepareFixtureJournal(m)
			results <- ErrorCode(err)
		}()
	}
	wg.Wait()
	close(results)
	ok, conflict := 0, 0
	for result := range results {
		switch result {
		case "":
			ok++
		case "activation_journal_conflict":
			conflict++
		default:
			t.Fatalf("unrecognized concurrent preparation result: %s", result)
		}
	}
	if ok != 1 || conflict != workers-1 {
		t.Fatalf("journal was not serialized: success=%d conflicts=%d", ok, conflict)
	}
	record, err := New(m.Dir, "", 0).observeActivationJournal()
	if err != nil || record.Revision != 1 || record.Phase != "prepared" {
		t.Fatalf("simultaneous prepare created inconsistent state: %+v err=%v", record, err)
	}
}

func TestActivationJournalSurvivesAbruptProcessExit(t *testing.T) {
	// The subprocess calls os.Exit without defer cleanup, modelling a
	// process that disappears immediately after a durable PREPARED write.
	if os.Getenv("SC_JOURNAL_CRASH_CHILD") == "1" {
		m := New(os.Getenv("SC_JOURNAL_CRASH_DIR"), "", 0)
		if _, err := prepareFixtureJournal(m); err != nil {
			os.Exit(31)
		}
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		os.Exit(32) // unreachable if the kernel delivered SIGKILL
	}
	dir := privateJournalTempDir(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestActivationJournalSurvivesAbruptProcessExit$")
	cmd.Env = append(os.Environ(), "SC_JOURNAL_CRASH_CHILD=1", "SC_JOURNAL_CRASH_DIR="+dir)
	if err := cmd.Run(); err == nil {
		t.Fatal("crash subprocess unexpectedly did not exit")
	} else {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("subprocess did not report a signal: %v", err)
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatalf("expected SIGKILL after durable journal write, got %v", err)
		}
	}
	record, err := New(dir, "", 0).observeActivationJournal()
	if err != nil || record.Phase != "prepared" || record.Revision != 1 || len(record.Changes) != 2 {
		t.Fatalf("abruptly exited process lost prepared write-ahead identity: %+v err=%v", record, err)
	}
	if err := New(dir, "", 0).abandonPreparedActivationJournal(record.OperationID); err != nil {
		t.Fatalf("fresh process cannot safely abandon untouched operation: %v", err)
	}
}

func TestActivationJournalCallerCannotMutatePersistedSnapshot(t *testing.T) {
	m := New(privateJournalTempDir(t), "", 0)
	changes := fixtureJournalChanges()
	original := bytes.Clone(changes[0].Intended)
	prepared, err := m.prepareActivationJournal(strings.Repeat("a", 64), strings.Repeat("b", 64), changes)
	if err != nil {
		t.Fatal(err)
	}
	changes[0].Intended[0] = 'x'
	changes[0].Before[0] = 'x'
	changes[0].Key = "other"
	reopened, err := New(m.Dir, "", 0).observeActivationJournal()
	if err != nil || !bytes.Equal(reopened.Changes[0].Intended, original) ||
		!bytes.Equal(prepared.Changes[0].Intended, original) ||
		string(reopened.Changes[0].Before) != "null" {
		t.Fatalf("caller mutation altered durable validated intent: %+v err=%v", reopened, err)
	}
}

func TestActivationJournalRefusesNonPrivateStateMode(t *testing.T) {
	dir := privateJournalTempDir(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	m := New(dir, "", 0)
	if _, err := prepareFixtureJournal(m); err == nil {
		t.Fatal("world/group-accessible state directory accepted for journal")
	}
	if _, err := os.Lstat(filepath.Join(dir, activationJournalFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("untrusted state directory received a journal: %v", err)
	}
}
