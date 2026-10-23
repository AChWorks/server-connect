package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestActivationJournalFirstUseAndExistingParentSync(t *testing.T) {
	for _, fresh := range []bool{true, false} {
		name := "existing"
		if fresh {
			name = "first_use"
		}
		t.Run(name, func(t *testing.T) {
			base := privateJournalTempDir(t)
			path := filepath.Join(base, "state")
			if !fresh {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			count := 0
			syncParent := func(fd int) error {
				count++
				info, err := journalStat(fd)
				if err != nil || !journalPrivateDir(info) {
					t.Fatalf("parent of test state root was not safely pinned: %+v err=%v", info, err)
				}
				return syscall.Fsync(fd)
			}
			m := New(path, "", 0)
			created, err := m.prepareActivationJournalWithParentSync(
				strings.Repeat("a", 64), strings.Repeat("b", 64), fixtureJournalChanges(), syncParent)
			if err != nil || created.Phase != "prepared" || count != 1 {
				t.Fatalf("missing parent fsync barrier: %+v err=%v calls=%d", created, err, count)
			}
			observed, err := m.observeActivationJournal()
			if err != nil || observed.OperationID != created.OperationID {
				t.Fatalf("durable first-use journal cannot be observed: %+v err=%v", observed, err)
			}
			info, err := os.Lstat(path)
			if err != nil || info.Mode().Perm() != 0700 {
				t.Fatalf("new state directory was not private: %v %v", info, err)
			}
		})
	}
}

func TestActivationJournalParentSyncFailureRefusesAcknowledgement(t *testing.T) {
	for _, fresh := range []bool{true, false} {
		name := "existing"
		if fresh {
			name = "first_use"
		}
		t.Run(name, func(t *testing.T) {
			base := privateJournalTempDir(t)
			path := filepath.Join(base, "state")
			if !fresh {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			m := New(path, "", 0)
			called := 0
			failSync := func(int) error {
				called++
				return syscall.EIO
			}
			record, err := m.prepareActivationJournalWithParentSync(
				strings.Repeat("a", 64), strings.Repeat("b", 64), fixtureJournalChanges(), failSync)
			if ErrorCode(err) != "activation_journal_unavailable" || called != 1 ||
				record.OperationID != "" {
				t.Fatalf("fsync fault incorrectly acknowledged PREPARED: %+v err=%v calls=%d", record, err, called)
			}
			if _, err := os.Lstat(filepath.Join(path, activationJournalFilename)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed parent fsync leaked an acknowledged journal: %v", err)
			}
			// The state directory may exist in RAM after the injected fault.
			// The next operation must sync its parent again before writing.
			if _, err := prepareFixtureJournal(m); err != nil {
				t.Fatalf("retry after successful parent sync must work: %v", err)
			}
		})
	}
}

func TestActivationJournalJSONStrictInputEvidence(t *testing.T) {
	for _, variant := range []struct{ name, raw string }{
		{"duplicate_before", `{"gateway":"192.0.2.1","gateway":"192.0.2.2"}`},
		{"duplicate_before_case", `{"gateway":"192.0.2.1","Gateway":"192.0.2.2"}`},
		{"nested_duplicate", `{"one":{"two":1,"two":2}}`},
	} {
		t.Run(variant.name, func(t *testing.T) {
			m := New(privateJournalTempDir(t), "", 0)
			changes := fixtureJournalChanges()
			changes[0].Before = json.RawMessage(variant.raw)
			if _, err := m.prepareActivationJournal(strings.Repeat("a", 64),
				strings.Repeat("b", 64), changes); ErrorCode(err) != "activation_journal_invalid" {
				t.Fatalf("ambiguous input evidence accepted: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(m.Dir, activationJournalFilename)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid input evidence persisted: %v", err)
			}
		})
	}
}

func TestActivationJournalStrictDiskJSONAndIntegrity(t *testing.T) {
	tests := []struct {
		name, from, to string
	}{
		{"duplicate_phase", `"phase":"prepared"`, `"phase":"prepared","phase":"uncertain"`},
		{"duplicate_revision", `"revision":1`, `"revision":1,"revision":2`},
		{"duplicate_operation_id", `"operation_id":`, `"operation_id":"00000000000000000000000000000000","operation_id":`},
		{"duplicate_resource_key", `"kind":"route"`, `"kind":"route","kind":"rule"`},
		{"duplicate_before_object", `"before":null`, `"before":{"foo":1,"foo":2}`},
		{"duplicate_intended_nested", `"intended":{"family":"ipv4"`, `"intended":{"family":"ipv4","family":"ipv6"`},
		{"case_variant_top_schema", `"phase":"prepared"`, `"Phase":"prepared"`},
		{"case_variant_top_duplicate", `"phase":"prepared"`, `"phase":"prepared","Phase":"uncertain"`},
		{"case_variant_nested_schema", `"kind":"route"`, `"Kind":"route"`},
		{"case_variant_nested_duplicate", `"kind":"route"`, `"kind":"route","Kind":"rule"`},
		{"case_variant_resource", `"intended":{"family":"ipv4"`, `"intended":{"family":"ipv4","Family":"ipv6"`},
		{"prepared_revision_2", `"revision":1`, `"revision":2`},
		{"prepared_revision_3", `"revision":1`, `"revision":3`},
		{"prepared_revision_0", `"revision":1`, `"revision":0`},
		{"uncertain_revision_1", `"phase":"prepared","created_unix"`, `"phase":"uncertain","created_unix"`},
		{"unsupported_future_phase", `"phase":"prepared"`, `"phase":"active_verified"`},
		{"unknown_root_property", `"version":1`, `"version":1,"guard_armed":true`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(privateJournalTempDir(t), "", 0)
			record, err := prepareFixtureJournal(m)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(m.Dir, activationJournalFilename)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			replacement := bytes.Replace(before, []byte(tt.from), []byte(tt.to), 1)
			if bytes.Equal(replacement, before) {
				t.Fatalf("invalid corruption fixture was not applied: %q", tt.from)
			}
			if err := os.WriteFile(path, replacement, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := m.observeActivationJournal(); ErrorCode(err) != "activation_journal_invalid" {
				t.Fatalf("ambiguous disk journal was accepted: %v", err)
			}
			if _, err := prepareFixtureJournal(m); ErrorCode(err) != "activation_journal_invalid" {
				t.Fatalf("ambiguous journal was overwritten: %v", err)
			}
			if err := m.abandonPreparedActivationJournal(record.OperationID, 1); ErrorCode(err) != "activation_journal_invalid" {
				t.Fatalf("ambiguous journal was abandoned: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(replacement, after) {
				t.Fatalf("invalid disk evidence was destroyed: %v", err)
			}
		})
	}
}

func TestActivationJournalStrictCanonicalControlsAndPhaseRevisions(t *testing.T) {
	left, err := canonicalJournalJSON([]byte(`{"z":[{"A":1,"b":2}],"a":{"n":9999999999999999999999999}}`))
	if err != nil {
		t.Fatal(err)
	}
	right, err := canonicalJournalJSON([]byte(`{ "a" : {"n":9999999999999999999999999}, "z" : [ { "b":2, "A":1 } ] }`))
	if err != nil || !bytes.Equal(left, right) {
		t.Fatalf("equivalent canonical evidence drifted: left=%s right=%s err=%v", left, right, err)
	}
	m := New(privateJournalTempDir(t), "", 0)
	p, err := prepareFixtureJournal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.abandonPreparedActivationJournal(p.OperationID, 2); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("stale/future expected revision was allowed to abandon: %v", err)
	}
	if err := m.abandonPreparedActivationJournal(p.OperationID, 0); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("zero expected revision was allowed to abandon: %v", err)
	}
	changed, err := m.markActivationJournalUncertain(p.OperationID, 1)
	if err != nil || changed.Revision != 2 || changed.Phase != "uncertain" {
		t.Fatalf("valid uncertain transition was not accepted: %+v err=%v", changed, err)
	}
	path := filepath.Join(m.Dir, activationJournalFilename)
	original, _ := os.ReadFile(path)
	for _, rev := range []uint64{1, 2, 3} {
		if err := m.abandonPreparedActivationJournal(p.OperationID, rev); ErrorCode(err) != "activation_journal_conflict" {
			t.Fatalf("uncertain journal removed with revision %d: %v", rev, err)
		}
	}
	found, err := m.observeActivationJournal()
	after, _ := os.ReadFile(path)
	if err != nil || found.Phase != "uncertain" || !bytes.Equal(original, after) {
		t.Fatalf("uncertain evidence was lost: %+v err=%v", found, err)
	}
}

func TestActivationJournalRejectsUnsafeAncestorAndSymlinkSubstitution(t *testing.T) {
	base := privateJournalTempDir(t)
	unsafe := filepath.Join(base, "group-writable")
	if err := os.Mkdir(unsafe, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(unsafe, "private")
	if _, err := prepareFixtureJournal(New(target, "", 0)); ErrorCode(err) != "activation_journal_unavailable" {
		t.Fatalf("world/group-writable parent was accepted: %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe parent gained a state directory: %v", err)
	}
	trusted := filepath.Join(base, "trusted")
	if err := os.Mkdir(trusted, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "indirection")
	if err := os.Symlink(trusted, link); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareFixtureJournal(New(filepath.Join(link, "state"), "", 0)); ErrorCode(err) != "activation_journal_unavailable" {
		t.Fatalf("symlinked ancestor was accepted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(trusted, "state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlinked ancestor redirected a new state directory: %v", err)
	}
}

func TestActivationJournalDescriptorPinRejectsSwappedDirectoryAndLock(t *testing.T) {
	t.Run("swapped_state_directory", func(t *testing.T) {
		base := privateJournalTempDir(t)
		path := filepath.Join(base, "state")
		m := New(path, "", 0)
		prepared, err := prepareFixtureJournal(m)
		if err != nil {
			t.Fatal(err)
		}
		store, err := openActivationJournalDir(path, syscall.Fsync)
		if err != nil {
			t.Fatal(err)
		}
		defer store.close()
		if err := store.lockSharedManager(); err != nil {
			t.Fatal(err)
		}
		_, identity, err := store.readJournal()
		if err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(base, "outside")
		if err := os.Mkdir(outside, 0700); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(outside, activationJournalFilename)
		if err := os.WriteFile(sentinel, []byte("foreign-untouched"), 0600); err != nil {
			t.Fatal(err)
		}
		moved := filepath.Join(base, "moved")
		if err := os.Rename(path, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.readJournal(); ErrorCode(err) != "activation_journal_unavailable" {
			t.Fatalf("swapped directory allowed descriptor read: %v", err)
		}
		if err := store.writeJournal([]byte("unwanted"), &identity); ErrorCode(err) != "activation_journal_unavailable" {
			t.Fatalf("swapped directory allowed journal write: %v", err)
		}
		if err := store.removeJournal(identity); ErrorCode(err) != "activation_journal_unavailable" {
			t.Fatalf("swapped directory allowed journal removal: %v", err)
		}
		foreign, err := os.ReadFile(sentinel)
		if err != nil || string(foreign) != "foreign-untouched" {
			t.Fatalf("journal redirected outside pinned store: %q err=%v", foreign, err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(moved, path); err != nil {
			t.Fatal(err)
		}
		// Release the held shared lock before a second Manager opens it.
		store.close()
		recovered, err := m.observeActivationJournal()
		if err != nil || recovered.OperationID != prepared.OperationID {
			t.Fatalf("original journal was harmed by substitution: %+v err=%v", recovered, err)
		}
	})
	t.Run("shared_lock_inode_substitution", func(t *testing.T) {
		m := New(privateJournalTempDir(t), "", 0)
		if _, err := prepareFixtureJournal(m); err != nil {
			t.Fatal(err)
		}
		store, err := openActivationJournalDir(m.Dir, syscall.Fsync)
		if err != nil {
			t.Fatal(err)
		}
		defer store.close()
		if err := store.lockSharedManager(); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(m.Dir, ".lock"), filepath.Join(m.Dir, ".old-lock")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(m.Dir, ".lock"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.readJournal(); ErrorCode(err) != "activation_journal_unavailable" {
			t.Fatalf("stale lock inode was allowed to read: %v", err)
		}
	})
}

func TestActivationJournalSharesExistingManagerLock(t *testing.T) {
	m := New(privateJournalTempDir(t), "", 0)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- m.withLock(func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	acquired := make(chan error, 1)
	go func() {
		acquired <- m.withActivationJournalLock(syscall.Fsync, func(*activationJournalDir) error { return nil })
	}()
	select {
	case err := <-acquired:
		t.Fatalf("journal escaped shared lock: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("journal failed to acquire the released shared lock")
	}
}

func TestActivationJournalCrossProcessPrepareExactlyOnce(t *testing.T) {
	if os.Getenv("SC_JOURNAL_COMPETING_CHILD") == "1" {
		m := New(os.Getenv("SC_JOURNAL_COMPETING_DIR"), "", 0)
		_, err := prepareFixtureJournal(m)
		switch ErrorCode(err) {
		case "":
			os.Exit(21)
		case "activation_journal_conflict":
			os.Exit(22)
		default:
			os.Exit(23)
		}
	}
	base := privateJournalTempDir(t)
	path := filepath.Join(base, "state")
	const n = 6
	var wg sync.WaitGroup
	results := make(chan int, n)
	for i := 0; i < n; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestActivationJournalCrossProcessPrepareExactlyOnce$")
		cmd.Env = append(os.Environ(), "SC_JOURNAL_COMPETING_CHILD=1", "SC_JOURNAL_COMPETING_DIR="+path)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := cmd.Run()
			if err == nil {
				results <- 0
				return
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				results <- 99
				return
			}
			results <- exit.ExitCode()
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for code := range results {
		switch code {
		case 21:
			success++
		case 22:
			conflict++
		default:
			t.Fatalf("unexpected competing process exit: %d", code)
		}
	}
	if success != 1 || conflict != n-1 {
		t.Fatalf("cross-process journals raced: success=%d conflict=%d", success, conflict)
	}
	found, err := New(path, "", 0).observeActivationJournal()
	if err != nil || found.Revision != 1 || found.Phase != "prepared" {
		t.Fatalf("cross-process journal identity was lost: %+v err=%v", found, err)
	}
}

func TestActivationJournalRejectsIntermediateAncestorReplacement(t *testing.T) {
	base := privateJournalTempDir(t)
	intermediate := filepath.Join(base, "parent")
	if err := os.Mkdir(intermediate, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(intermediate, "state")
	m := New(state, "", 0)
	initial, err := prepareFixtureJournal(m)
	if err != nil {
		t.Fatal(err)
	}
	store, err := openActivationJournalDir(state, syscall.Fsync)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if err := store.lockSharedManager(); err != nil {
		t.Fatal(err)
	}
	_, stamp, err := store.readJournal()
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "moved-parent")
	if err := os.Rename(intermediate, moved); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, intermediate); err != nil {
		t.Fatal(err)
	}
	if err := store.writeJournal([]byte("not-an-activation-record"), &stamp); ErrorCode(err) != "activation_journal_unavailable" {
		t.Fatalf("intermediate path substitution allowed journal replacement: %v", err)
	}
	if err := store.removeJournal(stamp); ErrorCode(err) != "activation_journal_unavailable" {
		t.Fatalf("intermediate path substitution allowed journal removal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("substituted path was modified: %v", err)
	}
	if err := os.Remove(intermediate); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, intermediate); err != nil {
		t.Fatal(err)
	}
	store.close()
	recovered, err := m.observeActivationJournal()
	if err != nil || recovered.OperationID != initial.OperationID {
		t.Fatalf("intermediate path tamper damaged the original journal: %+v err=%v", recovered, err)
	}
}
