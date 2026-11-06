//go:build linux

package sc

// v8 is the next *preparation* subtype. An enclosing full-parent journal
// owns Host-Capture, Barrier, the persistent TUN link, and a bounded core
// unit/credential. It explicitly does not own FIB/RPDB/nft egress capture,
// DNS redirection, general-host activation, or active Runtime Health.
// v7 link-only operations remain strictly unchanged and independently readable.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
)

const (
	hostCoreJournalVersion = 8
	hostCoreJournalIntent  = "host_native_core_preparation_v1"
)

type hostCoreLedger struct {
	ProfileID      string `json:"profile_id"`
	ConfigSHA256   string `json:"config_sha256"`
	PinnedEndpoint string `json:"pinned_endpoint"`
	Stage          string `json:"stage"`
	StartAttempted bool   `json:"start_attempted"`
}

type hostCoreJournal struct {
	hostNativeJournal
	Core hostCoreLedger `json:"core"`
}

func (r hostCoreJournal) nativeBase() hostNativeJournal {
	base := r.hostNativeJournal
	base.Version, base.Intent = hostNativeJournalVersion, hostNativeJournalIntent
	return base
}

func validateHostCoreJournal(r hostCoreJournal) error {
	bad := func() error {
		return activationJournalError("host native core preparation has invalid identity, stage, or resource ownership")
	}
	if r.Version != hostCoreJournalVersion || r.Intent != hostCoreJournalIntent ||
		validateHostNativeJournal(r.nativeBase()) != nil || !idPattern.MatchString(r.Core.ProfileID) ||
		!journalHex64.MatchString(r.Core.ConfigSHA256) {
		return bad()
	}
	if _, ok := hostHealthPublicIP(r.Core.PinnedEndpoint, 4); !ok {
		return bad()
	}
	switch r.Core.Stage {
	case "planned", "credential_possible", "credential_staged":
		if r.Core.StartAttempted {
			return bad()
		}
	case "start_requested", "active_observed", "stop_requested":
		if !r.Core.StartAttempted {
			return bad()
		}
	case "credential_remove_requested", "stopped":
		// A verified quiescent unit permits owned credential retirement even
		// if no systemd start was ever authorized.
	default:
		return bad()
	}
	// All core stages that could have started a service require a previously
	// receipted link in the same namespace and operation (or its proven removal).
	if r.Core.StartAttempted && r.Native.LinkStage != "observed" && r.Native.LinkStage != "remove_requested" && r.Native.LinkStage != "removed" {
		return bad()
	}
	if r.Core.Stage == "credential_remove_requested" && r.Core.StartAttempted && r.Native.LinkStage == "planned" {
		return bad()
	}
	if r.Core.Stage == "active_observed" && (r.Native.LinkStage != "observed" ||
		r.Progress.Ingress.Phase != "pending" || r.Progress.Barrier.Stage != "closed") {
		return bad()
	}
	if r.Progress.Ingress.Phase == "recovered" && r.Core.Stage != "stopped" {
		return bad()
	}
	return nil
}

func decodeHostCoreJournal(raw []byte) (hostCoreJournal, error) {
	var r hostCoreJournal
	if err := rejectAmbiguousJournalJSON(raw); err != nil {
		return r, err
	}
	if err := requireExactJournalKeys(raw, map[string]bool{
		"version": true, "intent_type": true, "progress": true, "tunnel_interface": true, "native": true, "core": true,
	}); err != nil {
		return r, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return r, activationJournalError("host core parent JSON invalid")
	}
	for _, v := range obj {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return r, activationJournalError("null core parent member")
		}
	}
	if err := requireExactJournalKeys(obj["core"], map[string]bool{
		"profile_id": true, "config_sha256": true, "pinned_endpoint": true, "stage": true, "start_attempted": true,
	}); err != nil {
		return r, err
	}
	var coreFields map[string]json.RawMessage
	if err := json.Unmarshal(obj["core"], &coreFields); err != nil || coreFields == nil {
		return r, activationJournalError("host core member must be a non-null object")
	}
	for key, value := range coreFields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return r, activationJournalError("host core member cannot be null: " + key)
		}
	}
	if string(coreFields["start_attempted"]) != "true" && string(coreFields["start_attempted"]) != "false" {
		return r, activationJournalError("host core start authority must be boolean")
	}
	// Prove that the embedded legacy native+ingress record remains exactly the
	// already-reviewed v7 subtype, not an alternative journal interpretation.
	clone := make(map[string]json.RawMessage, len(obj))
	for key, value := range obj {
		if key != "core" {
			clone[key] = value
		}
	}
	clone["version"] = json.RawMessage("7")
	clone["intent_type"] = json.RawMessage(`"host_native_link_preparation_v1"`)
	nativeRaw, err := json.Marshal(clone)
	if err != nil {
		return r, activationJournalError("cannot normalize core native parent")
	}
	native, err := decodeHostNativeJournal(nativeRaw)
	if err != nil {
		return r, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return hostCoreJournal{}, activationJournalError("host core parent schema invalid")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return hostCoreJournal{}, activationJournalError("host core parent trailing content")
	}
	if r.nativeBase() != native {
		return hostCoreJournal{}, activationJournalError("core parent changed embedded native identity")
	}
	return r, validateHostCoreJournal(r)
}

func loadHostCoreJournal(store *activationJournalDir) (hostCoreJournal, activationJournalFileIdentity, error) {
	raw, id, err := store.readJournal()
	if err != nil {
		return hostCoreJournal{}, id, err
	}
	r, err := decodeHostCoreJournal(raw)
	return r, id, err
}
func writeHostCoreJournal(store *activationJournalDir, r hostCoreJournal, old *activationJournalFileIdentity) error {
	if err := validateHostCoreJournal(r); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return activationJournalError("cannot encode host native core parent")
	}
	return store.writeJournal(append(raw, '\n'), old)
}
func persistHostCoreParent(store *activationJournalDir, r *hostCoreJournal, next hostCoreJournal) error {
	if store == nil || r == nil {
		return Fault("guard_unavailable", "missing host native core enclosing journal")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	actual, id, err := loadHostCoreJournal(store)
	if err != nil {
		return err
	}
	if actual != *r {
		return Fault("activation_journal_conflict", "host core parent changed")
	}
	if err := writeHostCoreJournal(store, next, &id); err != nil {
		return err
	}
	verified, _, err := loadHostCoreJournal(store)
	if err != nil {
		return err
	}
	if verified != next {
		return Fault("activation_journal_conflict", "host core parent readback differs")
	}
	*r = next
	return nil
}

func hostCoreCapturePersist(store *activationJournalDir, r *hostCoreJournal) hostCaptureGatePersist {
	return func(before, after hostCaptureGateProgress) error {
		if r == nil || r.Progress != before {
			return Fault("activation_journal_conflict", "host core ingress parent changed")
		}
		next := *r
		next.Progress = after
		return persistHostCoreParent(store, r, next)
	}
}
func hostCoreNativePersist(store *activationJournalDir, r *hostCoreJournal) nativeTUNRecordPersist {
	return func(before, after smartTUNTrialJournal) error {
		if r == nil || !sameSmartTUNTrial(r.nativeBase().nativeView(), before) {
			return Fault("activation_journal_conflict", "host core native record changed")
		}
		fixed := r.nativeBase().nativeView()
		fixed.Native = nil
		changed := cloneSmartTUNTrial(after)
		changed.Native = nil
		if fixed != changed || after.Native == nil {
			return Fault("activation_journal_conflict", "host core operation metadata changed")
		}
		next := *r
		next.Native = *after.Native
		return persistHostCoreParent(store, r, next)
	}
}

// The parent must durably publish a core start-intent BEFORE invoking systemd.
// No later after-the-fact unit observation can manufacture start authority.
func hostCoreAdvance(store *activationJournalDir, r *hostCoreJournal, stage string) error {
	if r == nil {
		return Fault("guard_unavailable", "host core parent missing")
	}
	transitions := map[string][]string{
		"planned":                     {"credential_possible", "credential_remove_requested"},
		"credential_possible":         {"credential_staged", "credential_remove_requested"},
		"credential_staged":           {"start_requested", "credential_remove_requested"},
		"start_requested":             {"active_observed", "stop_requested"},
		"active_observed":             {"stop_requested"},
		"stop_requested":              {"credential_remove_requested"},
		"credential_remove_requested": {"stopped"},
	}
	approved := false
	for _, next := range transitions[r.Core.Stage] {
		if next == stage {
			approved = true
		}
	}
	if !approved {
		return Fault("activation_journal_conflict", "unsupported host core parent stage transition")
	}
	next := *r
	next.Core.Stage = stage
	if stage == "start_requested" {
		next.Core.StartAttempted = true
	}
	return persistHostCoreParent(store, r, next)
}

func hostCoreCredentialState(store *activationJournalDir, r hostCoreJournal) (bool, activationJournalFileIdentity, error) {
	return hostCoreCredentialMatch(store, r.Core.ConfigSHA256)
}

func hostCoreCredentialMatch(store *activationJournalDir, digest string) (bool, activationJournalFileIdentity, error) {
	data, id, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
	if errors.Is(err, os.ErrNotExist) {
		return false, id, nil
	}
	if err != nil {
		return false, id, err
	}
	if sha256Hex(data) != digest {
		return false, id, Fault("trial_resource_conflict", "host core credential no longer matches owning operation")
	}
	return true, id, nil
}

// Only the exact operation's matching private credential may be unlinked.
// An ambiguous in-flight write must be recorded before touching its bytes.
func hostCoreRemoveCredential(store *activationJournalDir, r hostCoreJournal) error {
	return hostCoreRemoveCredentialDigest(store, r.Core.ConfigSHA256)
}

func hostCoreRemoveCredentialDigest(store *activationJournalDir, digest string) error {
	present, id, err := hostCoreCredentialMatch(store, digest)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if err := store.checkSmartTUNFile(smartTUNTrialConfigFile, &id); err != nil {
		return err
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	if err := syscall.Unlinkat(int(store.dir.Fd()), smartTUNTrialConfigFile); err != nil {
		return Fault("trial_recovery_uncertain", "cannot remove exact host core credential")
	}
	if err := store.dir.Sync(); err != nil {
		return Fault("trial_recovery_uncertain", "host core credential removal durability unknown")
	}
	return nil
}
