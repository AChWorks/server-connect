package sc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO open without O_NONBLOCK may block before file-type validation.
// Exercise every case in an independent subprocess so a future regression
// cannot indefinitely hang this test runner or the CI lifecycle lock.
func TestActivationJournalRejectsSpecialFilesWithoutBlocking(t *testing.T) {
	if name := os.Getenv("SC_JOURNAL_SPECIAL_CHILD"); name != "" {
		runActivationJournalSpecialFileCase(t, name, os.Getenv("SC_JOURNAL_SPECIAL_DIR"))
		return
	}
	for _, name := range []string{
		"fifo_at_journal_before_prepare",
		"fifo_at_journal_before_observe",
		"fifo_replaces_journal_under_lock",
		"fifo_at_manager_lock_before_acquire",
		"fifo_replaces_manager_lock_during_revalidation",
		"ordinary_private_regular_journal",
	} {
		t.Run(name, func(t *testing.T) {
			dir := privateJournalTempDir(t)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestActivationJournalRejectsSpecialFilesWithoutBlocking$")
			cmd.Env = append(os.Environ(),
				"SC_JOURNAL_SPECIAL_CHILD="+name,
				"SC_JOURNAL_SPECIAL_DIR="+dir)
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("journal special-file operation blocked past test deadline: case=%s err=%v output=%s", name, ctx.Err(), output)
			}
			if err != nil || !bytes.Contains(output, []byte("SPECIAL_FILE_CASE_PASS")) {
				t.Fatalf("journal special-file operation rejected incorrectly: case=%s err=%v output=%s", name, err, output)
			}
		})
	}
}

func runActivationJournalSpecialFileCase(t *testing.T, name, base string) {
	t.Helper()
	if base == "" {
		t.Fatal("missing subprocess state root")
	}
	m := New(filepath.Join(base, "state"), "", 0)
	journalPath := filepath.Join(m.Dir, activationJournalFilename)
	lockPath := filepath.Join(m.Dir, ".lock")
	mkdirPrivate := func() {
		t.Helper()
		if err := os.Mkdir(m.Dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	makeFIFO := func(path string) {
		t.Helper()
		if err := syscall.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("special-file fixture is not FIFO: %s %v", path, err)
		}
	}
	mustErrorCode := func(err error, want string) {
		t.Helper()
		if ErrorCode(err) != want {
			t.Fatalf("unexpected special-file error: want=%s got=%s err=%v", want, ErrorCode(err), err)
		}
	}
	ensureFreshLifecycle := func() {
		t.Helper()
		// The only shared Manager lock is released after the rejected
		// operation; a new Manager must acquire it and complete promptly.
		if err := New(m.Dir, "", 0).withLock(func() error { return nil }); err != nil {
			t.Fatalf("Manager lifecycle lock leaked or became unavailable: %v", err)
		}
	}
	preserveFIFO := func(path string) {
		t.Helper()
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("rejected special-file entry was replaced or destroyed: %s %v", path, err)
		}
	}

	switch name {
	case "fifo_at_journal_before_prepare", "fifo_at_journal_before_observe":
		mkdirPrivate()
		makeFIFO(journalPath)
		if name == "fifo_at_journal_before_prepare" {
			_, err := prepareFixtureJournal(m)
			mustErrorCode(err, "activation_journal_invalid")
		} else {
			_, err := m.observeActivationJournal()
			mustErrorCode(err, "activation_journal_invalid")
		}
		preserveFIFO(journalPath)
		ensureFreshLifecycle()
	case "fifo_replaces_journal_under_lock":
		original, err := prepareFixtureJournal(m)
		if err != nil {
			t.Fatal(err)
		}
		store, err := openActivationJournalDir(m.Dir, syscall.Fsync)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.lockSharedManager(); err != nil {
			store.close()
			t.Fatal(err)
		}
		unchanged, id, err := store.readJournal()
		if err != nil {
			store.close()
			t.Fatal(err)
		}
		backup := filepath.Join(m.Dir, ".saved-journal")
		if err := os.Rename(journalPath, backup); err != nil {
			store.close()
			t.Fatal(err)
		}
		makeFIFO(journalPath)
		_, _, err = store.readJournal()
		mustErrorCode(err, "activation_journal_invalid")
		mustErrorCode(store.checkTarget(&id), "activation_journal_invalid")
		mustErrorCode(store.writeJournal([]byte("unexpected journal overwrite"), &id), "activation_journal_invalid")
		preserveFIFO(journalPath)
		backupBytes, err := os.ReadFile(backup)
		if err != nil || !bytes.Equal(unchanged, backupBytes) {
			t.Fatalf("original prepared journal overwritten by failing operation: %v", err)
		}
		if err := os.Remove(journalPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(backup, journalPath); err != nil {
			t.Fatal(err)
		}
		store.close()
		reloaded, err := m.observeActivationJournal()
		if err != nil || reloaded.OperationID != original.OperationID {
			t.Fatalf("original identity not recoverable after special-file substitution: %+v err=%v", reloaded, err)
		}
		ensureFreshLifecycle()
	case "fifo_at_manager_lock_before_acquire":
		mkdirPrivate()
		makeFIFO(lockPath)
		_, err := m.observeActivationJournal()
		mustErrorCode(err, "activation_journal_unavailable")
		_, err = prepareFixtureJournal(m)
		mustErrorCode(err, "activation_journal_unavailable")
		preserveFIFO(lockPath)
		if _, err := os.Lstat(journalPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("operation with invalid manager lock modified journal: %v", err)
		}
		if err := os.Remove(lockPath); err != nil {
			t.Fatal(err)
		}
		ensureFreshLifecycle()
		if _, err := prepareFixtureJournal(m); err != nil {
			t.Fatalf("manager could not recover after removing untrusted lock: %v", err)
		}
	case "fifo_replaces_manager_lock_during_revalidation":
		original, err := prepareFixtureJournal(m)
		if err != nil {
			t.Fatal(err)
		}
		store, err := openActivationJournalDir(m.Dir, syscall.Fsync)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.lockSharedManager(); err != nil {
			store.close()
			t.Fatal(err)
		}
		oldLock := filepath.Join(m.Dir, ".saved-lock")
		if err := os.Rename(lockPath, oldLock); err != nil {
			store.close()
			t.Fatal(err)
		}
		makeFIFO(lockPath)
		mustErrorCode(store.ensureLockIdentity(), "activation_journal_unavailable")
		_, _, err = store.readJournal()
		mustErrorCode(err, "activation_journal_unavailable")
		mustErrorCode(store.writeJournal([]byte("should not publish"), nil), "activation_journal_unavailable")
		preserveFIFO(lockPath)
		if err := os.Remove(lockPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(oldLock, lockPath); err != nil {
			t.Fatal(err)
		}
		store.close()
		reloaded, err := m.observeActivationJournal()
		if err != nil || reloaded.OperationID != original.OperationID {
			t.Fatalf("prepared journal damaged by lock substitution: %+v err=%v", reloaded, err)
		}
		ensureFreshLifecycle()
	case "ordinary_private_regular_journal":
		original, err := prepareFixtureJournal(m)
		if err != nil {
			t.Fatal(err)
		}
		store, err := openActivationJournalDir(m.Dir, syscall.Fsync)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.lockSharedManager(); err != nil {
			store.close()
			t.Fatal(err)
		}
		raw, id, err := store.readJournal()
		if err != nil || len(raw) == 0 || id.ino == 0 {
			store.close()
			t.Fatalf("regular journal could not be read: id=%+v err=%v", id, err)
		}
		if err := store.checkTarget(&id); err != nil {
			store.close()
			t.Fatal(err)
		}
		store.close()
		reloaded, err := New(m.Dir, "", 0).observeActivationJournal()
		if err != nil || reloaded.OperationID != original.OperationID {
			t.Fatalf("normal journal identity or state changed: %+v err=%v", reloaded, err)
		}
		ensureFreshLifecycle()
	default:
		t.Fatal(fmt.Sprintf("unknown special-file test case %q", name))
	}
	// Child output is a positive completion marker, never a background run.
	fmt.Println("SPECIAL_FILE_CASE_PASS", strings.ReplaceAll(name, "\n", ""))
}
