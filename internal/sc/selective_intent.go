package sc

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Each kernel object is linked by identity to the SAME deterministic plan
// and observation digests. Before=null records verified absence in advisory
// evidence; no kernel owner is acquired, and future activation may not trust
// this field without its own fresh exclusive transaction observation.
func selectiveJournalChanges(p SelectiveRoutePlan) ([]activationJournalChange, error) {
	bad := func() ([]activationJournalChange, error) {
		return nil, Fault("route_plan_uncertain", "selective preview cannot form a complete and bounded journal intent")
	}
	if p.Mode != "selective_preview" || !p.ReadOnly || p.SnapshotAtomic ||
		p.ActivationReady || p.GuardArmed || p.OwnershipVerified ||
		!journalHex64.MatchString(p.ObservationSHA256) || !journalHex64.MatchString(p.PlanSHA256) ||
		p.RouteTable < selectiveFirstTable || p.RouteTable > selectiveLastTable ||
		!selectiveInterfacePattern.MatchString(p.TunnelInterface) ||
		len(p.Routes) == 0 || len(p.Routes) > selectiveMaxDestinations ||
		len(p.Rules) != len(p.Routes) {
		return bad()
	}
	recomputed, err := selectivePlanDigest(p)
	if err != nil || recomputed != p.PlanSHA256 {
		return bad()
	}
	changes := make([]activationJournalChange, 0, len(p.Routes)*2)
	used := make(map[string]bool)
	usedPriorities := make(map[int]bool)
	for i, route := range p.Routes {
		rule := p.Rules[i]
		if (route.Family != "ipv4" && route.Family != "ipv6") ||
			route.Family != rule.Family || route.Destination != rule.Destination ||
			route.Device != p.TunnelInterface || route.Table != p.RouteTable ||
			rule.Table != p.RouteTable || rule.Priority < selectiveFirstPriority ||
			rule.Priority > selectiveLastPriority {
			return bad()
		}
		routeKey := fmt.Sprintf("%s:%s:table%d", route.Family, route.Destination, route.Table)
		ruleKey := fmt.Sprintf("%s:%d", rule.Family, rule.Priority)
		if used["route:"+routeKey] || used["rule:"+ruleKey] || usedPriorities[rule.Priority] {
			return bad()
		}
		used["route:"+routeKey], used["rule:"+ruleKey] = true, true
		usedPriorities[rule.Priority] = true
		routeJSON, err1 := json.Marshal(route)
		ruleJSON, err2 := json.Marshal(rule)
		if err1 != nil || err2 != nil {
			return bad()
		}
		changes = append(changes,
			activationJournalChange{Kind: "route", Key: routeKey, Before: json.RawMessage("null"), Intended: routeJSON, Stage: "intent_recorded"},
			activationJournalChange{Kind: "rule", Key: ruleKey, Before: json.RawMessage("null"), Intended: ruleJSON, Stage: "intent_recorded"})
	}
	// Same strict bounded schema used by the durable store; reject any
	// unsupported key or JSON shape BEFORE creating a persistent record.
	example := activationJournal{Version: activationJournalVersion, Revision: 1, Phase: "prepared",
		OperationID: "00000000000000000000000000000000", CreatedUnix: 1,
		ObservationSHA256: p.ObservationSHA256, PlanSHA256: p.PlanSHA256, Changes: changes}
	if err := validateActivationJournal(example); err != nil {
		return nil, err
	}
	return changes, nil
}

// Abandon only the exact untouched PREPARED revision. UNCERTAIN and all future
// post-mutation phases cannot be removed through this method. This never
// executes systemctl, iproute2, or any other network command.
func (m *Manager) AbandonSelectiveIntent(operationID string, revision uint64) (ActivationJournalStatus, error) {
	return m.abandonSelectiveIntentWithAfterRemove(operationID, revision, nil)
}

// afterRemove is a private test seam for a competing authorized manager's
// operation after this exact deletion commits, before its receipt is returned.
func (m *Manager) abandonSelectiveIntentWithAfterRemove(operationID string, revision uint64,
	afterRemove func()) (ActivationJournalStatus, error) {
	var receipt ActivationJournalStatus
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record, identity, err := loadActivationJournalLocked(store)
		if errors.Is(err, os.ErrNotExist) {
			return Fault("activation_journal_missing", "no prepared activation journal exists")
		}
		if err != nil {
			return err
		}
		if !journalHex32.MatchString(operationID) ||
			subtle.ConstantTimeCompare([]byte(record.OperationID), []byte(operationID)) != 1 ||
			record.Phase != "prepared" || record.Revision != 1 || revision != record.Revision {
			return Fault("activation_journal_conflict", "only the exact untouched prepared revision may be abandoned")
		}
		if record.IntentType != selectiveIntentType || record.Selective == nil {
			return Fault("activation_journal_conflict", "journal is not an unarmed selective intent")
		}
		// Loading already checks every resource, digest and binding for typed
		// records. Explicitly revalidate before the inode-pinned deletion.
		if err := validateSelectiveJournalRecord(record); err != nil {
			return err
		}
		if err := store.removeJournal(identity); err != nil {
			return err
		}
		// This is an operation-specific deletion RECEIPT, not a live global
		// assertion that no other manager created B after we released the lock.
		receipt = ActivationJournalStatus{Phase: "absent", OperationID: record.OperationID,
			Revision: record.Revision}
		return nil
	})
	if err != nil {
		return ActivationJournalStatus{}, err
	}
	if afterRemove != nil {
		afterRemove()
	}
	return receipt, nil
}
