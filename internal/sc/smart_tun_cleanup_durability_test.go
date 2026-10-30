package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestSmartTUNCleanupRetryRequiresDirectoryDurabilityBeforeUnlink(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, DefaultCore, DefaultPort)
	credential := []byte("credential retained until cleanup intent is durable")
	record := trialV4Example()
	record.CoreStartAttempted, record.ConfigSHA256 = true, sha256Hex(credential)
	record.Phase, record.Revision = "trial_recovered", 3
	var journalIdentity, credentialIdentity activationJournalFileIdentity

	// Exercise the real temp-file sync and rename, failing only the following
	// containing-directory sync. The new cleanup entry must already be visible.
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, credential, nil); err != nil {
			return err
		}
		_, identity, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
		if err != nil {
			return err
		}
		credentialIdentity = identity
		if err := writeSmartTUNTrialLocked(store, record, nil); err != nil {
			return err
		}
		oldIdentity, err := reloadSmartTUNTrialLocked(store, record)
		if err != nil {
			return err
		}
		record.Phase, record.Revision = "trial_cleanup_pending", 4
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		calls := 0
		err = store.writeJournalWithDirSync(append(raw, '\n'), &oldIdentity, func(fd int) error {
			calls++
			visible, identity, err := loadSmartTUNTrialLocked(store)
			if fd != int(store.dir.Fd()) || err != nil || visible != record || identity == oldIdentity {
				t.Fatalf("fault did not follow actual cleanup publication in the state directory: %+v %v", visible, err)
			}
			journalIdentity = identity
			return syscall.EIO
		})
		if ErrorCode(err) != "activation_journal_unavailable" || calls != 1 {
			t.Fatalf("post-rename sync failure was acknowledged: %v calls=%d", err, calls)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	checkJournal := func(store *activationJournalDir) {
		t.Helper()
		visible, identity, err := loadSmartTUNTrialLocked(store)
		if err != nil || visible != record || identity != journalIdentity {
			t.Fatalf("cleanup retry changed operation or journal evidence: %+v %v", visible, err)
		}
	}
	checkCredential := func(store *activationJournalDir) {
		t.Helper()
		data, identity, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
		if err != nil || identity != credentialIdentity || !bytes.Equal(data, credential) {
			t.Fatalf("credential was removed or replaced before successful cleanup barrier: %v", err)
		}
	}

	// Reopen under the shared lock as an independent recovery/explicit retry
	// would. Syncing the parent while opening does not satisfy this barrier.
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		checkJournal(store)
		checkCredential(store)
		calls := 0
		err := store.removeSmartTUNCredential(journalIdentity, record, &credentialIdentity, func(fd int) error {
			calls++
			if fd != int(store.dir.Fd()) {
				t.Fatal("cleanup barrier did not sync the credential's containing directory")
			}
			checkJournal(store)
			checkCredential(store)
			return syscall.EIO
		})
		if ErrorCode(err) != "activation_journal_unavailable" || calls != 1 {
			t.Fatalf("failed cleanup prerequisite did not return uncertainty: %v calls=%d", err, calls)
		}
		checkJournal(store)
		checkCredential(store)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A successful prerequisite now permits unlink of that same credential.
	// Fail its subsequent directory sync to exercise the already-absent retry
	// as well; it must retain the exact cleanup journal and return uncertainty.
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		calls := 0
		err := store.removeSmartTUNCredential(journalIdentity, record, &credentialIdentity, func(fd int) error {
			calls++
			checkJournal(store)
			if fd != int(store.dir.Fd()) {
				t.Fatal("cleanup retry synced a different directory")
			}
			if calls == 1 {
				checkCredential(store)
				return syscall.Fsync(fd)
			}
			if _, _, err := store.readSmartTUNFile(smartTUNTrialConfigFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("post-unlink sync did not follow credential removal: %v", err)
			}
			return syscall.EIO
		})
		if ErrorCode(err) != "activation_journal_unavailable" || calls != 2 {
			t.Fatalf("unlink durability failure was acknowledged: %v calls=%d", err, calls)
		}
		checkJournal(store)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for _, fail := range []bool{true, false} {
		if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
			checkJournal(store)
			absent, err := smartTUNCredentialForCleanupLocked(store, record)
			if err != nil || absent != nil {
				t.Fatalf("same cleanup operation did not permit already removed credential: %v", err)
			}
			calls := 0
			err = store.removeSmartTUNCredential(journalIdentity, record, absent, func(fd int) error {
				calls++
				if fd != int(store.dir.Fd()) {
					t.Fatal("absent credential retry did not sync the state directory")
				}
				if fail {
					return syscall.EIO
				}
				return syscall.Fsync(fd)
			})
			if calls != 1 || (fail && ErrorCode(err) != "activation_journal_unavailable") || (!fail && err != nil) {
				t.Fatalf("absent credential retry returned wrong durability result: fail=%v err=%v calls=%d", fail, err, calls)
			}
			checkJournal(store)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSmartTUNCleanupBarrierRejectsChangedJournal(t *testing.T) {
	for _, tc := range []struct {
		name        string
		duringSync  bool
		replaceNode bool
	}{
		{"same-bytes-replacement-before-sync", false, true},
		{"same-inode-changed-operation-before-sync", false, false},
		{"same-bytes-replacement-during-sync", true, true},
		{"same-inode-changed-operation-during-sync", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateJournalTempDir(t)
			m := New(dir, DefaultCore, DefaultPort)
			if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				credential := []byte("credential bound to original cleanup operation")
				record := trialV4Example()
				record.CoreStartAttempted, record.ConfigSHA256 = true, sha256Hex(credential)
				record.Phase, record.Revision = "trial_cleanup_pending", 4
				if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, credential, nil); err != nil {
					return err
				}
				_, credentialIdentity, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
				if err != nil {
					return err
				}
				if err := writeSmartTUNTrialLocked(store, record, nil); err != nil {
					return err
				}
				journalIdentity, err := reloadSmartTUNTrialLocked(store, record)
				if err != nil {
					return err
				}
				changed := record
				if !tc.replaceNode {
					changed.OperationID = strings.Repeat("b", 32)
				}
				changedBytes, _ := json.Marshal(changed)
				changedBytes = append(changedBytes, '\n')
				path := filepath.Join(dir, activationJournalFilename)
				changeJournal := func() error {
					if !tc.replaceNode {
						return os.WriteFile(path, changedBytes, 0600)
					}
					replacement := filepath.Join(dir, "replacement-journal")
					if err := os.WriteFile(replacement, changedBytes, 0600); err != nil {
						return err
					}
					return os.Rename(replacement, path)
				}
				if !tc.duringSync {
					if err := changeJournal(); err != nil {
						return err
					}
				}
				calls := 0
				err = store.removeSmartTUNCredential(journalIdentity, record, &credentialIdentity, func(fd int) error {
					calls++
					if !tc.duringSync {
						t.Fatal("a stale cleanup record reached the durability barrier")
					}
					if err := changeJournal(); err != nil {
						return err
					}
					return syscall.Fsync(fd)
				})
				if ErrorCode(err) != "activation_journal_conflict" || (tc.duringSync && calls != 1) || (!tc.duringSync && calls != 0) {
					t.Fatalf("cleanup adopted changed journal: %v calls=%d", err, calls)
				}
				after, _, err := store.readJournal()
				if err != nil || !bytes.Equal(after, changedBytes) {
					t.Fatalf("changed journal evidence was discarded: %v", err)
				}
				secret, identity, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
				if err != nil || identity != credentialIdentity || !bytes.Equal(secret, credential) {
					t.Fatalf("changed cleanup journal permitted credential deletion: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
