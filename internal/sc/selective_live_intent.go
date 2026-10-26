package sc

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"os"
	"syscall"
)

// SelectiveIntentLiveCheck is an operation-specific read receipt. It is NOT a
// route reservation, a recoverable activation, an ownership attestation or a
// safe-to-apply token. Foreign kernel writers are not covered by Manager flock.
type SelectiveIntentLiveCheck struct {
	OperationID                   string `json:"operation_id"`
	Revision                      uint64 `json:"revision"`
	Phase                         string `json:"phase"`
	ReadOnly                      bool   `json:"read_only"`
	SnapshotAtomic                bool   `json:"snapshot_atomic"`
	ObservationsMatchStoredIntent bool   `json:"observations_match_stored_intent"`
	ActivationReady               bool   `json:"activation_ready"`
	GuardArmed                    bool   `json:"guard_armed"`
	OwnershipVerified             bool   `json:"ownership_verified"`
	RecoveryVerified              bool   `json:"recovery_verified"`
}

// VerifySelectiveIntentLive compares TWO new, non-atomic native observations
// against the exact private PREPARED selective operation while holding the
// existing Manager lifecycle lock. It does not write journal or kernel state.
// A later guarded activator MUST re-observe independently after prearming the
// actual rollback mechanism, with its own exclusive transaction.
func (m *Manager) VerifySelectiveIntentLive(operationID string, revision uint64) (SelectiveIntentLiveCheck, error) {
	return m.verifySelectiveIntentLiveWithInspector(operationID, revision, InspectHostRoutes)
}

func selectiveRequestFromValidatedJournal(record activationJournal) (SelectivePlanRequest, error) {
	if record.IntentType != selectiveIntentType || record.Selective == nil ||
		record.Phase != "prepared" || record.Revision != 1 {
		return SelectivePlanRequest{}, Fault("activation_journal_conflict", "only a valid unarmed selective PREPARED intent can be reobserved")
	}
	if err := validateSelectiveJournalRecord(record); err != nil {
		return SelectivePlanRequest{}, err
	}
	req := SelectivePlanRequest{
		EndpointIP: record.Selective.Endpoint, ManagementPeerIP: record.Selective.ManagementPeer,
		TunnelInterface: record.Selective.TunnelInterface,
		Destinations:    make([]string, 0, len(record.Changes)/2),
	}
	for i := 0; i < len(record.Changes); i += 2 {
		var route PlannedRoute
		if err := json.Unmarshal(record.Changes[i].Intended, &route); err != nil {
			return SelectivePlanRequest{}, activationJournalError("validated selective resource cannot be reconstructed")
		}
		req.Destinations = append(req.Destinations, route.Destination)
	}
	return req, nil
}

// inspect is an internal read-only test seam. The public method pins native
// /usr/bin/ip and never permits caller-selected subprocesses or network edits.
func (m *Manager) verifySelectiveIntentLiveWithInspector(operationID string, revision uint64,
	inspect func(endpointIP, managementPeerIP string) (HostPreflight, error)) (SelectiveIntentLiveCheck, error) {
	if !journalHex32.MatchString(operationID) || revision != 1 {
		return SelectiveIntentLiveCheck{}, Fault("invalid_arguments", "an exact PREPARED operation ID and revision 1 are required")
	}
	if inspect == nil {
		return SelectiveIntentLiveCheck{}, Fault("route_plan_uncertain", "native observation provider is unavailable")
	}
	var receipt SelectiveIntentLiveCheck
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record, _, err := loadActivationJournalLocked(store)
		if errors.Is(err, os.ErrNotExist) {
			return Fault("activation_journal_missing", "no staged selective intent exists")
		}
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(operationID), []byte(record.OperationID)) != 1 ||
			revision != record.Revision {
			return Fault("activation_journal_conflict", "staged intent operation ID or revision no longer matches")
		}
		req, err := selectiveRequestFromValidatedJournal(record)
		if err != nil {
			return err
		}
		intent, err := validateSelectiveRequest(req)
		if err != nil {
			return activationJournalError("validated selective intent has unsupported request identity")
		}
		previousPlan := ""
		previousObservation := ""
		for i := 0; i < 2; i++ {
			host, inspectErr := inspect(intent.endpoint.String(), intent.peer.String())
			if inspectErr != nil {
				return Fault("route_plan_uncertain", "native host observation is unavailable for reinspection")
			}
			plan, planErr := buildSelectivePlan(intent, host)
			if planErr != nil {
				return Fault("route_plan_changed", "live host state cannot reproduce the staged selective intent")
			}
			if plan.PlanSHA256 != record.PlanSHA256 ||
				plan.ObservationSHA256 != record.ObservationSHA256 ||
				plan.RouteTable != record.Selective.RouteTable {
				return Fault("route_plan_changed", "live host state differs from the exact staged operation")
			}
			if i > 0 && (previousPlan != plan.PlanSHA256 ||
				previousObservation != plan.ObservationSHA256) {
				return Fault("route_plan_changed", "live host state changed across reinspection")
			}
			previousPlan, previousObservation = plan.PlanSHA256, plan.ObservationSHA256
		}
		receipt = SelectiveIntentLiveCheck{
			OperationID: record.OperationID, Revision: record.Revision, Phase: record.Phase,
			ReadOnly: true, ObservationsMatchStoredIntent: true,
			// No claim of atomicity, kernel ownership, guard, or recovery.
		}
		return nil
	})
	if err != nil {
		return SelectiveIntentLiveCheck{}, err
	}
	return receipt, nil
}
