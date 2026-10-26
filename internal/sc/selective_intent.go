package sc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Staging is a durable RECORD of advisory intent, not a route reservation,
// guard arming, ownership proof, or permission to mutate the kernel. No host
// network, firewall, service or DNS operation occurs on this path.
// A future activator MUST independently re-observe all exact native kernel
// identities, verify its own armed recovery service and apply with a separate
// crash-safe, guarded state transition. A stable double observation here is
// deliberately not advertised as an atomic snapshot.
func (m *Manager) StageSelectiveIntent(req SelectivePlanRequest) (ActivationJournalStatus, error) {
	return m.stageSelectiveIntentWithInspector(req, InspectHostRoutes)
}

// inspect is a read-only test seam. Production always uses native iproute2.
func (m *Manager) stageSelectiveIntentWithInspector(req SelectivePlanRequest,
	inspect func(endpointIP, managementPeerIP string) (HostPreflight, error)) (ActivationJournalStatus, error) {
	intent, err := validateSelectiveRequest(req)
	if err != nil {
		return ActivationJournalStatus{}, err
	}
	if inspect == nil {
		return ActivationJournalStatus{}, Fault("route_plan_uncertain", "host inventory provider is unavailable")
	}

	// Re-observe after plan construction. Neither this comparison nor the
	// Manager's private filesystem lock can lock unrelated kernel writers.
	// An inconsistent pair must never leave a newly prepared journal.
	var plan SelectiveRoutePlan
	for i := 0; i < 2; i++ {
		host, err := inspect(intent.endpoint.String(), intent.peer.String())
		if err != nil {
			return ActivationJournalStatus{}, Fault("route_plan_uncertain", "native host inventory is unavailable for staging")
		}
		current, err := buildSelectivePlan(intent, host)
		if err != nil {
			return ActivationJournalStatus{}, err
		}
		if i > 0 && (plan.PlanSHA256 != current.PlanSHA256 ||
			plan.ObservationSHA256 != current.ObservationSHA256) {
			return ActivationJournalStatus{}, Fault("route_plan_changed", "kernel observation changed during selective intent staging")
		}
		plan = current
	}
	changes, err := selectiveJournalChanges(plan)
	if err != nil {
		return ActivationJournalStatus{}, err
	}
	if _, err := m.prepareActivationJournal(plan.ObservationSHA256, plan.PlanSHA256, changes); err != nil {
		return ActivationJournalStatus{}, err
	}
	// Re-read through the verified private journal lock and strict schema.
	// This can fail closed if a concurrent administrator changes the record.
	return m.InspectActivationJournal()
}

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
	if err := m.abandonPreparedActivationJournal(operationID, revision); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ActivationJournalStatus{}, Fault("activation_journal_missing", "no prepared activation journal exists")
		}
		return ActivationJournalStatus{}, err
	}
	return m.InspectActivationJournal()
}
