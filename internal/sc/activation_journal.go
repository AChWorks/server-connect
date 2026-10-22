package sc

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// The route-activation journal is an internal persistence primitive, not an
// activation mechanism. No caller may equate its presence with an armed guard,
// a reserved resource, or a safe route. The only implemented states are
// PREPARED (no host effect) and UNCERTAIN (manual/guard reconciliation needed).
// PENDING_CONFIRMATION and ACTIVE_VERIFIED remain deliberately unsupported
// until an independently armed guard and owned-route reconciler exist.
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

// Each change records the *intended* exact delta before any possible future
// mutation. Before=null encodes prior absence. Intended is an observed
// comparison target, not proof that the resource has ever been installed.
// A future reconciler must compare current kernel identity before undoing
// anything, including objects that look like these proposed identities.
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
	if j.Version != activationJournalVersion || j.Revision == 0 || !journalHex32.MatchString(j.OperationID) ||
		(j.Phase != "prepared" && j.Phase != "uncertain") || j.CreatedUnix <= 0 ||
		!journalHex64.MatchString(j.ObservationSHA256) || !journalHex64.MatchString(j.PlanSHA256) ||
		len(j.Changes) == 0 || len(j.Changes) > activationJournalMaxItems {
		return activationJournalError("unsupported activation journal version, identity, phase or scope")
	}
	seen := make(map[string]bool, len(j.Changes))
	for _, change := range j.Changes {
		if (change.Kind != "route" && change.Kind != "rule" && change.Kind != "interface") ||
			(!journalKey.MatchString(change.Key) || strings.Contains(change.Key, "..")) || change.Stage != "intent_recorded" {
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
			return activationJournalError("journal resource change has no distinct prior and intended states")
		}
	}
	return nil
}

// Only the process owner may supply a private state root or durable journal.
// In a root-run manager this means root-owned state; do not adopt an
// operator-created 0700 directory or foreign-owned file for recovery.
func (m *Manager) verifyActivationJournalStoreLocked() error {
	info, err := os.Lstat(m.Dir)
	if err != nil {
		return Fault("activation_journal_unavailable", "private activation state directory is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 ||
		int(stat.Uid) != os.Geteuid() {
		return Fault("activation_journal_unavailable", "private activation state directory ownership or permissions are untrusted")
	}
	return nil
}

// loadActivationJournalLocked is called only while holding the shared
// Manager.withLock lifecycle lock; the lock spans all future routing changes.
func (m *Manager) loadActivationJournalLocked() (activationJournal, error) {
	if err := m.verifyActivationJournalStoreLocked(); err != nil {
		return activationJournal{}, err
	}
	path := filepath.Join(m.Dir, activationJournalFilename)
	info, err := os.Lstat(path)
	if err != nil {
		return activationJournal{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		int(stat.Uid) != os.Geteuid() || info.Size() <= 0 ||
		info.Size() > activationJournalMaxBytes {
		return activationJournal{}, activationJournalError("private activation journal ownership, mode or size is invalid")
	}
	data, err := readRegular(path)
	if err != nil {
		return activationJournal{}, activationJournalError("activation journal cannot be read safely")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record activationJournal
	if err := decoder.Decode(&record); err != nil {
		return activationJournal{}, activationJournalError("activation journal is corrupt or unsupported")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return activationJournal{}, activationJournalError("activation journal has trailing content")
	}
	if err := validateActivationJournal(record); err != nil {
		return activationJournal{}, err
	}
	return record, nil
}

// observeActivationJournal never claims readiness. It obtains the same lock
// used for manager lifecycle so a separate recovery process can observe the
// durable record only at a consistent record boundary.
func (m *Manager) observeActivationJournal() (activationJournal, error) {
	var found activationJournal
	err := m.withLock(func() error {
		var err error
		found, err = m.loadActivationJournalLocked()
		if os.IsNotExist(err) {
			return Fault("activation_journal_missing", "no prepared activation journal exists")
		}
		return err
	})
	return found, err
}

// prepareActivationJournal durably records the desired before/after objects
// (including absence) under the manager lock. It never invokes ip, sing-box,
// systemd, or any other networking operation. An existing or corrupt journal
// blocks replacement, preventing loss of unfinished/uncertain recovery state.
func (m *Manager) prepareActivationJournal(observationSHA, planSHA string, changes []activationJournalChange) (activationJournal, error) {
	id, err := randomHex(16)
	if err != nil {
		return activationJournal{}, Fault("activation_journal_unavailable", "cannot generate operation identity")
	}
	// Capture input bytes independently. The caller must not be able to
	// alter a validated intended resource while the durable write waits
	// for the shared lifecycle lock.
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
	err = m.withLock(func() error {
		if _, err := m.loadActivationJournalLocked(); err == nil {
			return Fault("activation_journal_conflict", "an activation journal already exists; recovery or safe abandonment is required")
		} else if !os.IsNotExist(err) {
			// A corrupt or insecure journal must never be overwritten.
			return err
		}
		data, err := json.Marshal(record)
		if err != nil || len(data) > activationJournalMaxBytes {
			return activationJournalError("activation journal cannot be serialized within its size bound")
		}
		// Manager.put fsyncs the new private temporary file, atomically
		// renames it and fsyncs its containing directory. A sync failure
		// stops the operation; no host/network effect can follow.
		return put(filepath.Join(m.Dir, activationJournalFilename), append(data, '\n'))
	})
	if err != nil {
		return activationJournal{}, err
	}
	return record, nil
}

// markActivationJournalUncertain preserves an unresolved identity for later
// manual/independent recovery. It is not a route rollback or an approval.
func (m *Manager) markActivationJournalUncertain(operationID string, expectedRevision uint64) (activationJournal, error) {
	var changed activationJournal
	err := m.withLock(func() error {
		record, err := m.loadActivationJournalLocked()
		if err != nil {
			return err
		}
		if !journalHex32.MatchString(operationID) ||
			subtle.ConstantTimeCompare([]byte(record.OperationID), []byte(operationID)) != 1 ||
			record.Revision != expectedRevision || record.Phase != "prepared" {
			return Fault("activation_journal_conflict", "operation identity, revision or phase no longer matches")
		}
		record.Revision++
		record.Phase = "uncertain"
		if err := validateActivationJournal(record); err != nil {
			return err
		}
		data, err := json.Marshal(record)
		if err != nil || len(data) > activationJournalMaxBytes {
			return activationJournalError("activation journal cannot be serialized within its size bound")
		}
		if err := put(filepath.Join(m.Dir, activationJournalFilename), append(data, '\n')); err != nil {
			return err
		}
		changed = record
		return nil
	})
	return changed, err
}

// abandonPreparedActivationJournal only removes a never-applied intent.
// Anything UNCERTAIN or beyond PREPARED requires a separate identity-safe
// recovery implementation; deleting it here would destroy recovery evidence.
func (m *Manager) abandonPreparedActivationJournal(operationID string) error {
	return m.withLock(func() error {
		record, err := m.loadActivationJournalLocked()
		if err != nil {
			return err
		}
		if !journalHex32.MatchString(operationID) ||
			subtle.ConstantTimeCompare([]byte(record.OperationID), []byte(operationID)) != 1 ||
			record.Phase != "prepared" {
			return Fault("activation_journal_conflict", "only this exact untouched prepared operation may be abandoned")
		}
		if err := os.Remove(filepath.Join(m.Dir, activationJournalFilename)); err != nil {
			return err
		}
		dir, err := os.Open(m.Dir)
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	})
}
