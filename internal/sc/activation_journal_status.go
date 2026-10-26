package sc

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
	journal, err := m.observeActivationJournal()
	if err != nil {
		if ErrorCode(err) == "activation_journal_missing" {
			return ActivationJournalStatus{Phase: "absent"}, nil
		}
		return ActivationJournalStatus{}, err
	}
	return activationJournalStatusFromRecord(journal), nil
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
