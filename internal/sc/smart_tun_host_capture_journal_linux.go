//go:build linux

package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// This is the first durable, independently selectable parent for the two
// host-capture prerequisites. It deliberately has NO TUN/core routing ledger
// and MUST NOT be interpreted as general-host Smart Routing admission.
// A later complete host operation will need a native policy, core, health and
// recovery owner in the same journal before exposing any Apply command.
const (
	hostCaptureJournalVersion = 6
	hostCaptureJournalIntent  = "host_capture_preparation_v1"
)

type hostCaptureJournal struct {
	Version  int                     `json:"version"`
	Intent   string                  `json:"intent_type"`
	Progress hostCaptureGateProgress `json:"progress"`
}

func validateHostCaptureJournal(r hostCaptureJournal) error {
	if r.Version != hostCaptureJournalVersion || r.Intent != hostCaptureJournalIntent ||
		r.Progress.Ingress.SysctlBefore != 1 {
		return activationJournalError("invalid host capture parent identity or unowned sysctl")
	}
	if err := validateHostCaptureGatePair(r.Progress.Ingress, r.Progress.Barrier); err != nil {
		return err
	}
	if r.Progress.Ingress.Phase == "pending" && r.Progress.Barrier.Stage != "planned" &&
		r.Progress.Ingress.NFTStage != "observed" {
		return activationJournalError("kernel grace barrier precedes owned ingress")
	}
	return nil
}

func decodeHostNetworkBarrier(raw []byte) (hostNetworkBarrier, error) {
	var b hostNetworkBarrier
	if err := rejectAmbiguousJournalJSON(raw); err != nil {
		return b, err
	}
	fields := map[string]bool{
		"version": true, "operation_id": true, "boot_id": true,
		"namespace_dev": true, "namespace_ino": true, "name": true, "stage": true,
	}
	if err := requireExactJournalKeys(raw, fields); err != nil {
		return b, err
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return b, activationJournalError("invalid network grace JSON")
	}
	for _, value := range values {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return b, activationJournalError("null network grace member")
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&b) != nil {
		return b, activationJournalError("network grace schema invalid")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return b, activationJournalError("network grace JSON has trailing data")
	}
	return b, validateHostNetworkBarrier(b)
}

func decodeHostCaptureJournal(raw []byte) (hostCaptureJournal, error) {
	var r hostCaptureJournal
	if err := rejectAmbiguousJournalJSON(raw); err != nil {
		return r, err
	}
	if err := requireExactJournalKeys(raw, map[string]bool{
		"version": true, "intent_type": true, "progress": true,
	}); err != nil {
		return r, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return r, activationJournalError("host capture journal JSON invalid")
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return r, activationJournalError("null host capture journal member")
		}
	}
	if err := requireExactJournalKeys(fields["progress"], map[string]bool{
		"ingress": true, "barrier": true,
	}); err != nil {
		return r, err
	}
	var nested map[string]json.RawMessage
	if json.Unmarshal(fields["progress"], &nested) != nil {
		return r, activationJournalError("host capture parent progress invalid")
	}
	ingress, err := decodeHostIngressStage(nested["ingress"])
	if err != nil {
		return r, err
	}
	barrier, err := decodeHostNetworkBarrier(nested["barrier"])
	if err != nil {
		return r, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil {
		return hostCaptureJournal{}, activationJournalError("host capture parent schema invalid")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return hostCaptureJournal{}, activationJournalError("host capture parent has trailing data")
	}
	if r.Progress.Ingress != ingress || r.Progress.Barrier != barrier {
		return hostCaptureJournal{}, activationJournalError("host capture parent decoded inconsistent members")
	}
	return r, validateHostCaptureJournal(r)
}

func loadHostCaptureJournal(store *activationJournalDir) (hostCaptureJournal, activationJournalFileIdentity, error) {
	raw, identity, err := store.readJournal()
	if err != nil {
		return hostCaptureJournal{}, identity, err
	}
	record, err := decodeHostCaptureJournal(raw)
	return record, identity, err
}

func writeHostCaptureJournal(store *activationJournalDir, r hostCaptureJournal, old *activationJournalFileIdentity) error {
	if err := validateHostCaptureJournal(r); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return activationJournalError("cannot serialize host capture parent")
	}
	return store.writeJournal(append(raw, byte(10)), old)
}

// hostCaptureJournalPersist is the ONLY adapter used by the installed v6
// parent: it refuses a changed complete record, and requires a successfully
// durable replacement + exact readback before advancing in-memory progress.
// Do not reacquire the manager lock or write a second independent journal.
func hostCaptureJournalPersist(store *activationJournalDir, current *hostCaptureJournal) hostCaptureGatePersist {
	return func(previous, next hostCaptureGateProgress) error {
		if store == nil || current == nil {
			return Fault("guard_unavailable", "host capture enclosing journal unavailable")
		}
		if err := store.ensureLockIdentity(); err != nil {
			return err
		}
		if current.Progress != previous {
			return Fault("activation_journal_conflict", "host capture parent progress changed")
		}
		observed, identity, err := loadHostCaptureJournal(store)
		if err != nil {
			return err
		}
		if observed != *current {
			return Fault("activation_journal_conflict", "host capture parent contents changed")
		}
		updated := *current
		updated.Progress = next
		if err := writeHostCaptureJournal(store, updated, &identity); err != nil {
			return err
		}
		confirmed, _, err := loadHostCaptureJournal(store)
		if err != nil {
			return err
		}
		if confirmed != updated {
			return Fault("activation_journal_conflict", "host capture parent durable readback disagreed")
		}
		*current = updated
		return nil
	}
}
