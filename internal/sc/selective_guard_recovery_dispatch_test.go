package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Exercise the production dispatch wrapper without systemd or kernel policy.
// The competing writer uses a separate open-file description for the actual
// manager flock. It must not publish v4 between an absent selection and its
// no-op handler; the next invocation must select that new v4 intact.
func TestGuardedRecoveryDispatchKeepsLockAcrossAbsentAndNewApply(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, DefaultCore, DefaultPort)
	newRecord := nativeTrialExample(false)
	attempted := make(chan error, 1)
	written := make(chan error, 1)
	writerStarted := false
	receipt, recoveryErr := m.recoverGuardedTrialWithHandler("", "",
		func(store *activationJournalDir, selected trialRecoverySelection) (TrialReceipt, error) {
			if selected.version != 0 {
				return TrialReceipt{}, fmt.Errorf("initial absence selected version %d", selected.version)
			}
			writerStarted = true
			go func() {
				file, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR, 0)
				if err != nil {
					attempted <- err
					written <- err
					return
				}
				err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
				if err == nil {
					_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				}
				_ = file.Close()
				attempted <- err
				if !errors.Is(err, syscall.EWOULDBLOCK) {
					written <- fmt.Errorf("writer was not excluded after selection: %v", err)
					return
				}
				other := New(dir, DefaultCore, DefaultPort)
				written <- other.withActivationJournalLock(syscall.Fsync, func(otherStore *activationJournalDir) error {
					return writeSmartTUNTrialLocked(otherStore, newRecord, nil)
				})
			}()
			select {
			case err := <-attempted:
				if !errors.Is(err, syscall.EWOULDBLOCK) {
					return TrialReceipt{}, fmt.Errorf("dispatch released the lock before its handler: %v", err)
				}
			case <-time.After(3 * time.Second):
				return TrialReceipt{}, errors.New("competing flock attempt did not complete")
			}
			if _, _, err := store.readJournal(); !errors.Is(err, os.ErrNotExist) {
				return TrialReceipt{}, fmt.Errorf("new Apply appeared inside the absent dispatch: %v", err)
			}
			return TrialReceipt{Phase: "absent", ExperimentOnly: true}, nil
		})
	if !writerStarted {
		t.Fatalf("absent dispatch did not reach the locked handler: %v", recoveryErr)
	}
	select {
	case err := <-written:
		if err != nil {
			t.Fatalf("competing publication failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("writer did not acquire the lock after recovery returned")
	}
	if recoveryErr != nil || receipt.Phase != "absent" || !receipt.ExperimentOnly {
		t.Fatalf("absent invocation adopted the new operation: %+v %v", receipt, recoveryErr)
	}
	want, err := json.Marshal(newRecord)
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	called := 0
	_, err = m.recoverGuardedTrialWithHandler("", "",
		func(store *activationJournalDir, selected trialRecoverySelection) (TrialReceipt, error) {
			called++
			if selected.version != smartTUNTrialVersion || !sameSmartTUNTrial(selected.tun, newRecord) {
				return TrialReceipt{}, errors.New("new v4 was sent to legacy recovery or lost its full binding")
			}
			raw, identity, err := store.readJournal()
			if err != nil || identity != selected.identity || !bytes.Equal(raw, want) {
				return TrialReceipt{}, fmt.Errorf("new v4 evidence changed during selection: %v", err)
			}
			return TrialReceipt{OperationID: selected.tun.OperationID, Phase: selected.tun.Phase}, nil
		})
	if err != nil || called != 1 {
		t.Fatalf("next invocation did not select new v4 exactly once: %v calls=%d", err, called)
	}
	after, err := os.ReadFile(filepath.Join(dir, activationJournalFilename))
	if err != nil || !bytes.Equal(after, want) {
		t.Fatalf("no-native dispatch changed the new journal: %v", err)
	}
}

func TestGuardedRecoveryDispatchValidatesSelectionBeforeHandler(t *testing.T) {
	v2 := stagedTrialRecord(t)
	v1 := v2.activationJournal
	v1.Version, v1.Revision, v1.Phase, v1.IntentType = 1, 1, "prepared", selectiveIntentType
	v3 := v2
	v3.Version, v3.IntentType, v3.RouteDevice = 3, trialRouteIntentType, "lo"
	v3Recovered := v3
	v3Recovered.Phase, v3Recovered.Revision = "trial_recovered", 3
	v1Uncertain := v1
	v1Uncertain.Phase, v1Uncertain.Revision = "uncertain", 2
	marshal := func(value any) []byte {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	v1Raw, v2Raw, v3Raw := marshal(v1), marshal(v2), marshal(v3)
	v4Raw, nativeRaw := marshal(trialV4Example()), marshal(nativeTrialExample(false))
	for _, tc := range []struct {
		name, crash, fault string
		raw                []byte
		version            int
		code               string
	}{
		{name: "absent", version: 0},
		{name: "prepared-v1", raw: v1Raw, version: 1},
		{name: "pending-v2", raw: v2Raw, version: 2},
		{name: "pending-v3", raw: v3Raw, version: 3},
		{name: "recovered-v3", raw: marshal(v3Recovered), version: 3},
		{name: "legacy-v4", raw: v4Raw, version: 4},
		{name: "native-v4", raw: nativeRaw, version: 4},
		{name: "absent-crash-noop", crash: "after-delete", version: 0},
		{name: "prepared-crash-noop", raw: v1Raw, crash: "after-route-delete", version: 1},
		{name: "v3-route-crash", raw: v3Raw, crash: "after-route-delete", version: 3},
		{name: "v3-route-fault", raw: v3Raw, fault: "route-delete", version: 3},
		{name: "absent-fault", fault: "route-delete", code: "invalid_arguments"},
		{name: "prepared-fault", raw: v1Raw, fault: "route-delete", code: "invalid_arguments"},
		{name: "v2-fault", raw: v2Raw, fault: "route-delete", code: "invalid_arguments"},
		{name: "v2-route-crash", raw: v2Raw, crash: "after-route-delete", code: "invalid_arguments"},
		{name: "recovered-v3-fault", raw: marshal(v3Recovered), fault: "route-delete", code: "invalid_arguments"},
		{name: "v4-crash-not-legacy", raw: v4Raw, crash: "after-delete", code: "activation_journal_invalid"},
		{name: "v4-fault-not-legacy", raw: nativeRaw, fault: "route-delete", code: "activation_journal_invalid"},
		{name: "uncertain-v1", raw: marshal(v1Uncertain), code: "activation_journal_invalid"},
		{name: "future-version", raw: bytes.Replace(v4Raw, []byte(`"version":4`), []byte(`"version":5`), 1), code: "activation_journal_invalid"},
		{name: "duplicate-version", raw: bytes.Replace(v4Raw, []byte(`"version":4`), []byte(`"version":4,"version":4`), 1), code: "activation_journal_invalid"},
		{name: "case-variant-version", raw: bytes.Replace(v4Raw, []byte(`"version":4`), []byte(`"VERSION":4`), 1), code: "activation_journal_invalid"},
		{name: "unknown-v4-field", raw: bytes.Replace(v4Raw, []byte(`"version":4`), []byte(`"version":4,"unknown":true`), 1), code: "activation_journal_invalid"},
		{name: "unknown-native-field", raw: bytes.Replace(nativeRaw, []byte(`"native":{`), []byte(`"native":{"unknown":true,`), 1), code: "activation_journal_invalid"},
		{name: "v2-extra-route-field", raw: bytes.Replace(v2Raw, []byte(`"version":2`), []byte(`"version":2,"trial_route_device":"lo"`), 1), code: "activation_journal_invalid"},
		{name: "truncated", raw: []byte(`{"version":4`), code: "activation_journal_invalid"},
		{name: "trailing-document", raw: append(append([]byte{}, v4Raw...), []byte(`{}`)...), code: "activation_journal_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateJournalTempDir(t)
			m := New(dir, DefaultCore, DefaultPort)
			credential := []byte("unchanged-dispatch-test-credential")
			if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, credential, nil); err != nil {
					return err
				}
				if tc.raw != nil {
					return store.writeJournal(tc.raw, nil)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			called := 0
			_, err := m.recoverGuardedTrialWithHandler(tc.crash, tc.fault,
				func(store *activationJournalDir, selected trialRecoverySelection) (TrialReceipt, error) {
					called++
					if selected.version != tc.version {
						return TrialReceipt{}, fmt.Errorf("selected version %d, want %d", selected.version, tc.version)
					}
					if tc.raw != nil {
						raw, identity, err := store.readJournal()
						if err != nil || identity != selected.identity || !bytes.Equal(raw, tc.raw) {
							return TrialReceipt{}, fmt.Errorf("selected journal evidence changed: %v", err)
						}
					}
					return TrialReceipt{Phase: "source-test-selection"}, nil
				})
			if tc.code == "" {
				if err != nil || called != 1 {
					t.Fatalf("valid selection failed: %v handler calls=%d", err, called)
				}
			} else if ErrorCode(err) != tc.code || called != 0 {
				t.Fatalf("invalid selection reached handler or changed error: %v calls=%d", err, called)
			}
			after, readErr := os.ReadFile(filepath.Join(dir, activationJournalFilename))
			if tc.raw == nil {
				if !errors.Is(readErr, os.ErrNotExist) {
					t.Fatalf("absent dispatch created a journal: %v", readErr)
				}
			} else if readErr != nil || !bytes.Equal(after, tc.raw) {
				t.Fatalf("dispatch changed journal evidence: %v", readErr)
			}
			secret, readErr := os.ReadFile(filepath.Join(dir, smartTUNTrialConfigFile))
			if readErr != nil || !bytes.Equal(secret, credential) {
				t.Fatalf("dispatch changed credential evidence: %v", readErr)
			}
		})
	}
}

func TestGuardedRecoveryDispatchPublicAdmissionStillPrecedesStateAccess(t *testing.T) {
	installed := New(DefaultDir, DefaultCore, DefaultPort)
	for _, points := range [][2]string{{"unknown", ""}, {"", "unknown"}, {"after-delete", "route-delete"}} {
		if _, err := installed.RecoverGuardedRuleTrial(points[0], points[1]); ErrorCode(err) != "invalid_arguments" {
			t.Fatalf("invalid QA options reached state/recovery: %v", err)
		}
	}
	custom := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	if _, err := custom.RecoverGuardedRuleTrial("unknown", "unknown"); ErrorCode(err) != "trial_unsupported" {
		t.Fatalf("unsupported state path changed admission order: %v", err)
	}
	if _, err := os.Stat(filepath.Join(custom.Dir, ".lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported path acquired a journal lock: %v", err)
	}
}
