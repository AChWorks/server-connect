package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
)

// The route-activation journal is an INTERNAL persistence primitive, not
// authorization to activate a network or proof that a guard is armed.
// Version 1 has exactly two phases: PREPARED@revision=1, meaning no network
// mutation occurred, and UNCERTAIN@revision=2, which cannot be abandoned.
// New v1 creation is retired. Historical v2/v3 recovery uses separate
// persisted formats; retired v4/unknown records are never silently adopted
// or interpreted as this unarmed journal.
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
	Version           int    `json:"version"`
	Revision          uint64 `json:"revision"`
	OperationID       string `json:"operation_id"`
	Phase             string `json:"phase"`
	CreatedUnix       int64  `json:"created_unix"`
	ObservationSHA256 string `json:"observation_sha256"`
	PlanSHA256        string `json:"plan_sha256"`
	// Optional v1 subtype: legacy generic records remain readable, but only
	// explicitly bound unarmed Selective intents can use Selective abandonment.
	IntentType string                    `json:"intent_type,omitempty"`
	Selective  *selectiveJournalBinding  `json:"selective,omitempty"`
	Changes    []activationJournalChange `json:"changes"`
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
	if (j.IntentType == "" && j.Selective != nil) ||
		(j.IntentType != "" && (j.IntentType != selectiveIntentType || j.Selective == nil)) {
		return activationJournalError("unsupported journal intent subtype or missing selective binding")
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
	if j.IntentType == selectiveIntentType {
		return validateSelectiveJournalRecord(j)
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
