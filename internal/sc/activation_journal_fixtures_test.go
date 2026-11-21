package sc

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"os"
	"syscall"
	"time"
)

// Historical v1 journal writes are test fixtures only: the installed product
// can still read/validate/abandon or recover existing operations, but no
// longer offers any new v1 creation or generic journal rewrite entrypoint.
// Only PREPARED intent is written. Parent-directory fsync is required even
// for the first creation of a custom private state root. This does not prove
// physical power-loss recovery (SIGKILL and fsync checks are lesser evidence).
func (m *Manager) prepareActivationJournal(observationSHA, planSHA string, changes []activationJournalChange) (activationJournal, error) {
	return m.prepareActivationJournalWithParentSync(observationSHA, planSHA, changes, syscall.Fsync)
}

// Test-only injectable sync distinguishes failure before the acknowledgment
// from a completed journal write. Production always uses syscall.Fsync.
func (m *Manager) prepareActivationJournalWithParentSync(observationSHA, planSHA string, changes []activationJournalChange, parentSync func(int) error) (activationJournal, error) {
	return m.prepareActivationJournalWithOptions(observationSHA, planSHA, changes, nil, parentSync)
}

// The same descriptor-pinned write path and Manager lock own generic and
// selective journal writes. A selective binding is copied before acquisition;
// there is no unprotected follow-up mutation of an already committed record.
func (m *Manager) prepareActivationJournalWithOptions(observationSHA, planSHA string, changes []activationJournalChange, binding *selectiveJournalBinding, parentSync func(int) error) (activationJournal, error) {
	id, err := randomHex(16)
	if err != nil {
		return activationJournal{}, journalFSUnavailable("cannot generate operation identity")
	}
	// Do not retain caller-owned JSON slices across lock acquisition.
	copied := make([]activationJournalChange, len(changes))
	for i, change := range changes {
		copied[i] = change
		copied[i].Before = bytes.Clone(change.Before)
		copied[i].Intended = bytes.Clone(change.Intended)
	}
	record := activationJournal{
		Version: activationJournalVersion, Revision: 1, OperationID: id,
		Phase: "prepared", CreatedUnix: time.Now().UTC().Unix(),
		ObservationSHA256: observationSHA, PlanSHA256: planSHA,
		Changes: copied,
	}
	if binding != nil {
		copiedBinding := *binding
		record.IntentType, record.Selective = selectiveIntentType, &copiedBinding
	}
	if err := validateActivationJournal(record); err != nil {
		return activationJournal{}, err
	}
	err = m.withActivationJournalLock(parentSync, func(store *activationJournalDir) error {
		if _, _, readErr := loadActivationJournalLocked(store); readErr == nil {
			return Fault("activation_journal_conflict", "an activation journal already exists; recover or abandon safely first")
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return readErr // Invalid, corrupt or foreign state blocks replacement.
		}
		data, err := json.Marshal(record)
		if err != nil {
			return activationJournalError("cannot serialize prepared activation journal")
		}
		return store.writeJournal(append(data, '\n'), nil)
	})
	if err != nil {
		return activationJournal{}, err
	}
	return record, nil
}

func (m *Manager) markActivationJournalUncertain(operationID string, expectedRevision uint64) (activationJournal, error) {
	var result activationJournal
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record, identity, err := loadActivationJournalLocked(store)
		if err != nil {
			return err
		}
		if !journalHex32.MatchString(operationID) ||
			subtle.ConstantTimeCompare([]byte(record.OperationID), []byte(operationID)) != 1 ||
			record.Revision != expectedRevision || record.Phase != "prepared" {
			return Fault("activation_journal_conflict", "operation identity, revision or phase no longer matches")
		}
		record.Phase, record.Revision = "uncertain", 2
		if err := validateActivationJournal(record); err != nil {
			return err
		}
		data, err := json.Marshal(record)
		if err != nil {
			return activationJournalError("cannot serialize uncertain activation journal")
		}
		if err := store.writeJournal(append(data, '\n'), &identity); err != nil {
			return err
		}
		result = record
		return nil
	})
	return result, err
}

// Abandonment is only for an untouched PREPARED@rev1 operation. UNCERTAIN
// survives every attempted cleanup, including matching IDs and stale
// revisions. No route or policy is removed by this function.
func (m *Manager) abandonPreparedActivationJournal(operationID string, expectedRevision uint64) error {
	return m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record, identity, err := loadActivationJournalLocked(store)
		if err != nil {
			return err
		}
		if !journalHex32.MatchString(operationID) ||
			subtle.ConstantTimeCompare([]byte(record.OperationID), []byte(operationID)) != 1 ||
			record.Phase != "prepared" || record.Revision != 1 ||
			expectedRevision != record.Revision {
			return Fault("activation_journal_conflict", "only the exact untouched prepared revision may be abandoned")
		}
		return store.removeJournal(identity)
	})
}
