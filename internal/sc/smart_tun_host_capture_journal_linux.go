//go:build linux

package sc

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
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

// verifyHostCapturePreparationOff checks that a recovered v6 operation has
// no native effect left. The v6 schema owns ONLY preexisting mark inheritance,
// one exact ingress nft table and the short-lived barrier interface. Do not
// reuse this clearance for a later general-host journal with TUN/FIB/RPDB
// effects. A prior boot's namespace or nft handle is never delete authority.
func verifyHostCapturePreparationOff(record hostCaptureJournal) error {
	if err := validateHostCaptureJournal(record); err != nil {
		return err
	}
	if record.Progress.Ingress.Phase != "recovered" ||
		record.Progress.Ingress.SysctlStage != "removed" ||
		record.Progress.Ingress.NFTStage != "removed" {
		return Fault("activation_journal_conflict", "host capture preparation is not durably recovered")
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return err
	}
	if boot == record.Progress.Ingress.BootID {
		// On the same boot a different netns could still contain the
		// original effect, even if this namespace observes its absence.
		if err := hostIngressNamespace(record.Progress.Ingress); err != nil {
			return err
		}
	}
	if err := verifyHostNetworkBarrierReleased(record.Progress.Barrier); err != nil {
		return err
	}
	observed, err := observeHostIngressNFT(record.Progress.Ingress)
	if err != nil {
		return err
	}
	if observed.Present {
		return ingressFault("host capture ingress name is occupied or retained")
	}
	value, err := readHostIngressSysctl()
	if err != nil {
		return err
	}
	if value != record.Progress.Ingress.SysctlBefore {
		return ingressFault("preexisting host mark inheritance changed")
	}
	return nil
}

// clearRecoveredHostCapturePreparationLocked is the only terminal v6
// clearance. Hold the same uninterrupted activation lock as independent
// Recovery, require the exact operation ID and fsynced recovered state, and
// reobserve the kernel before deleting the CAS-matched parent. This is
// journal-only cleanup: it never modifies nft, sysctls, links or routes.
func clearRecoveredHostCapturePreparationLocked(store *activationJournalDir, operationID string) error {
	if store == nil || !journalHex32.MatchString(operationID) {
		return Fault("invalid_arguments", "exact host capture preparation operation required")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	record, identity, err := loadHostCaptureJournal(store)
	if errors.Is(err, os.ErrNotExist) {
		return Fault("activation_journal_conflict", "host capture preparation is absent")
	}
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(record.Progress.Ingress.OperationID), []byte(operationID)) != 1 {
		return Fault("activation_journal_conflict", "host capture preparation operation does not match")
	}
	if err := verifyHostCapturePreparationOff(record); err != nil {
		return err
	}
	// A second independent read prevents a changed complete parent or
	// inode from being silently cleared after a long native observation.
	latest, latestIdentity, err := loadHostCaptureJournal(store)
	if err != nil {
		return err
	}
	if latest != record || latestIdentity != identity {
		return Fault("activation_journal_conflict", "host capture parent changed during clearance")
	}
	if err := verifyHostCapturePreparationOff(latest); err != nil {
		return err
	}
	return store.removeJournal(identity)
}

// ClearRecoveredHostCapturePreparation is an explicit installed-only
// recovery terminal; it does not create or admit general-host Smart TUN.
func (m *Manager) ClearRecoveredHostCapturePreparation(operationID string) error {
	if m.Dir != DefaultDir || !journalHex32.MatchString(operationID) {
		return Fault("invalid_arguments", "installed exact host capture operation required")
	}
	if os.Geteuid() != 0 {
		return Fault("ownership_required", "root required to clear host capture preparation")
	}
	return m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		return clearRecoveredHostCapturePreparationLocked(store, operationID)
	})
}
