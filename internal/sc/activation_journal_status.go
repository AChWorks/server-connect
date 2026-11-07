package sc

import (
	"encoding/json"
	"errors"
	"os"
	"syscall"
)

// ActivationJournalStatus reports only the bounded control metadata of the
// internal intent journal. Before/intended host-resource snapshots are private
// and MUST NOT be returned by this operator diagnostic. The journal v1 only
// supports prepared/uncertain intent: it does not prove any host route has
// been applied, recovered, or owned by Server Connect.
type ActivationJournalStatus struct {
	Phase                  string `json:"phase"`
	Present                bool   `json:"present"`
	OperationID            string `json:"operation_id,omitempty"`
	Revision               uint64 `json:"revision,omitempty"`
	CreatedUnix            int64  `json:"created_unix,omitempty"`
	ResourceCount          int    `json:"resource_count"`
	RequiresOperatorReview bool   `json:"requires_operator_review"`
	ActivationReady        bool   `json:"activation_ready"`
	GuardArmed             bool   `json:"guard_armed"`
	RecoveryVerified       bool   `json:"recovery_verified"`
	HostNetworkInspected   bool   `json:"host_network_inspected"`
}

// InspectActivationJournal reports only strictly validated journal metadata.
// A missing record is not proof of safe host networking, so all safety
// assertions remain false. Invalid/untrusted records fail closed with NO data.
// No route/firewall/DNS operation or host-network inspection occurs. Like other
// Manager state operations, this may initialize a private state directory and
// lifecycle lock on first inspection; it is not filesystem-side-effect-free.
func (m *Manager) InspectActivationJournal() (ActivationJournalStatus, error) {
	var report ActivationJournalStatus
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		raw, _, err := store.readJournal()
		if errors.Is(err, os.ErrNotExist) {
			report.Phase = "absent"
			return nil
		}
		if err != nil {
			return err
		}
		if err := rejectAmbiguousJournalJSON(raw); err != nil {
			return err
		}
		var discriminator struct {
			Version int `json:"version"`
		}
		if json.Unmarshal(raw, &discriminator) != nil {
			return activationJournalError("activation journal version is invalid")
		}
		if discriminator.Version == hostRouteJournalVersion {
			r, err := decodeHostRouteJournal(raw)
			if err != nil {
				return err
			}
			phase := r.Route.State
			if hostRouteSupervised(r) {
				phase = r.Supervision.State
			}
			report = ActivationJournalStatus{Phase: "host_route_" + phase,
				Present: true, OperationID: r.Progress.Ingress.OperationID, RequiresOperatorReview: true}
			return nil
		}
		if discriminator.Version == hostCoreJournalVersion {
			r, err := decodeHostCoreJournal(raw)
			if err != nil {
				return err
			}
			report = ActivationJournalStatus{Phase: "host_core_" + r.Progress.Ingress.Phase,
				Present: true, OperationID: r.Progress.Ingress.OperationID, RequiresOperatorReview: true}
			return nil
		}
		if discriminator.Version == hostNativeJournalVersion {
			r, err := decodeHostNativeJournal(raw)
			if err != nil {
				return err
			}
			report = ActivationJournalStatus{
				Phase:   "host_native_" + r.Progress.Ingress.Phase,
				Present: true, OperationID: r.Progress.Ingress.OperationID,
				RequiresOperatorReview: true,
			}
			return nil
		}
		if discriminator.Version == hostCaptureJournalVersion {
			// Strict v6 selection only, under the same manager lock as its
			// independent Recovery. The pending/stop/recovered phase is
			// *journal metadata*, never a kernel or timer-health proof.
			r, err := decodeHostCaptureJournal(raw)
			if err != nil {
				return err
			}
			report = ActivationJournalStatus{
				Phase:                  "host_capture_" + r.Progress.Ingress.Phase,
				Present:                true,
				OperationID:            r.Progress.Ingress.OperationID,
				RequiresOperatorReview: true,
			}
			return nil
		}
		// Preserve exact historical v1 generic/selective intent semantics.
		// An unrelated future/invalid subtype must never become "absent".
		legacy, _, err := loadActivationJournalLocked(store)
		if err != nil {
			return err
		}
		report = activationJournalStatusFromRecord(legacy)
		return nil
	})
	if err != nil {
		return ActivationJournalStatus{}, err
	}
	return report, nil
}

// A bounded status built from an EXACT journal record. Used both by live
// inspection and by stage receipts, which must never re-read an unrelated
// operation after the acknowledged filesystem lock has been released.
func activationJournalStatusFromRecord(journal activationJournal) ActivationJournalStatus {
	return ActivationJournalStatus{
		Phase:                  journal.Phase,
		Present:                true,
		OperationID:            journal.OperationID,
		Revision:               journal.Revision,
		CreatedUnix:            journal.CreatedUnix,
		ResourceCount:          len(journal.Changes),
		RequiresOperatorReview: true,
		// All unsupported activation and recovery claims remain false.
	}
}
