package sc

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// The route-activation journal is an INTERNAL persistence primitive, not
// authorization to activate a network or proof that a guard is armed.
// Version 1 has exactly two phases: PREPARED@revision=1, meaning no network
// mutation occurred, and UNCERTAIN@revision=2, which cannot be abandoned by
// this API. Future PENDING/ACTIVE/rollback transitions are not implemented.
const (
	activationJournalFilename = "route-activation-journal.json"
	activationJournalVersion  = 1
	activationJournalMaxBytes = 1 << 20
	activationJournalMaxItems = 64
)

var (
	journalHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
	journalHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	journalKey   = regexp.MustCompile(`^[A-Za-z0-9:._/@=-]{1,192}$`)
)

// Before=null means prior absence. Intended is ONLY the proposed state,
// not a verified kernel resource. Future reconciliation must re-observe the
// exact ownership and refuse conflicts before touching any host network.
type activationJournalChange struct {
	Kind     string          `json:"kind"`
	Key      string          `json:"key"`
	Before   json.RawMessage `json:"before"`
	Intended json.RawMessage `json:"intended"`
	Stage    string          `json:"stage"`
}

type activationJournal struct {
	Version           int                       `json:"version"`
	Revision          uint64                    `json:"revision"`
	OperationID       string                    `json:"operation_id"`
	Phase             string                    `json:"phase"`
	CreatedUnix       int64                     `json:"created_unix"`
	ObservationSHA256 string                    `json:"observation_sha256"`
	PlanSHA256        string                    `json:"plan_sha256"`
	Changes           []activationJournalChange `json:"changes"`
}

func activationJournalError(message string) error {
	return Fault("activation_journal_invalid", message)
}

func canonicalJournalJSON(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 8192 {
		return nil, activationJournalError("owned resource evidence is missing or too large")
	}
	return canonicalJournalJSONStrict(raw)
}

func canonicalJournalJSONStrict(raw json.RawMessage) ([]byte, error) {
	if err := rejectAmbiguousJournalJSON(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, activationJournalError("owned resource evidence must be valid JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, activationJournalError("owned resource evidence has trailing data")
	}
	result, err := json.Marshal(value)
	if err != nil {
		return nil, activationJournalError("owned resource evidence cannot be serialized")
	}
	return result, nil
}

func validateActivationJournal(j activationJournal) error {
	if j.Version != activationJournalVersion ||
		!journalHex32.MatchString(j.OperationID) || j.CreatedUnix <= 0 ||
		!journalHex64.MatchString(j.ObservationSHA256) ||
		!journalHex64.MatchString(j.PlanSHA256) ||
		len(j.Changes) == 0 || len(j.Changes) > activationJournalMaxItems {
		return activationJournalError("unsupported activation journal version, identity or scope")
	}
	if (j.Phase != "prepared" || j.Revision != 1) &&
		(j.Phase != "uncertain" || j.Revision != 2) {
		return activationJournalError("unsupported activation journal phase/revision combination")
	}
	seen := make(map[string]bool, len(j.Changes))
	for _, change := range j.Changes {
		if (change.Kind != "route" && change.Kind != "rule" && change.Kind != "interface") ||
			!journalKey.MatchString(change.Key) || strings.Contains(change.Key, "..") ||
			change.Stage != "intent_recorded" {
			return activationJournalError("journal resource identity or progress is unsupported")
		}
		key := change.Kind + ":" + change.Key
		if seen[key] {
			return activationJournalError("journal contains duplicate resource identity")
		}
		seen[key] = true
		before, err := canonicalJournalJSON(change.Before)
		if err != nil {
			return err
		}
		intended, err := canonicalJournalJSON(change.Intended)
		if err != nil {
			return err
		}
		if bytes.Equal(before, intended) {
			return activationJournalError("journal resource has no distinct prior and intended states")
		}
	}
	return nil
}

// All read/write/delete operations use one private descriptor-pinned store,
// held under the existing Manager .lock inode. The journal is never opened,
// replaced or deleted by a standalone path-based filesystem operation.
func loadActivationJournalLocked(store *activationJournalDir) (activationJournal, activationJournalFileIdentity, error) {
	data, identity, err := store.readJournal()
	if err != nil {
		return activationJournal{}, identity, err
	}
	if err := strictActivationJournalJSON(data); err != nil {
		return activationJournal{}, identity, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record activationJournal
	if err := decoder.Decode(&record); err != nil {
		return activationJournal{}, identity, activationJournalError("activation journal schema is unsupported")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return activationJournal{}, identity, activationJournalError("activation journal has trailing content")
	}
	if err := validateActivationJournal(record); err != nil {
		return activationJournal{}, identity, err
	}
	return record, identity, nil
}

func (m *Manager) observeActivationJournal() (activationJournal, error) {
	var observed activationJournal
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		var readErr error
		observed, _, readErr = loadActivationJournalLocked(store)
		if errors.Is(readErr, os.ErrNotExist) {
			return Fault("activation_journal_missing", "no prepared activation journal exists")
		}
		return readErr
	})
	return observed, err
}

// Only PREPARED intent is written. Parent-directory fsync is required even
// for the first creation of a custom private state root. This does not prove
// physical power-loss recovery (SIGKILL and fsync checks are lesser evidence).
func (m *Manager) prepareActivationJournal(observationSHA, planSHA string, changes []activationJournalChange) (activationJournal, error) {
	return m.prepareActivationJournalWithParentSync(observationSHA, planSHA, changes, syscall.Fsync)
}

// Test-only injectable sync distinguishes failure before the acknowledgment
// from a completed journal write. Production always uses syscall.Fsync.
func (m *Manager) prepareActivationJournalWithParentSync(observationSHA, planSHA string, changes []activationJournalChange, parentSync func(int) error) (activationJournal, error) {
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
