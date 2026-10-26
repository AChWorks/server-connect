package sc

import (
	"bytes"
	"encoding/json"
)

// This is a contract for ONE private, unarmed v1 selective intent, not
// authenticity against an administrator with control of the private store.
// The explicit subtype and complete plan binding distinguish it from legacy
// generic journals and from every unsupported future activation variant.
const selectiveIntentType = "unarmed_selective_v1"

type selectiveJournalBinding struct {
	Endpoint        string `json:"endpoint"`
	ManagementPeer  string `json:"management_peer"`
	TunnelInterface string `json:"tunnel_interface"`
	RouteTable      int    `json:"route_table"`
}

var selectiveRouteEvidenceFields = map[string]bool{
	"family": true, "destination": true, "table": true, "device": true,
}
var selectiveRuleEvidenceFields = map[string]bool{
	"family": true, "destination": true, "priority": true, "table": true,
}

// Unknown fields, omitted required fields, nulls, aliases and changed
// numeric types cannot be treated as a supported exact resource identity.
func exactSelectiveEvidence(raw json.RawMessage, allowed map[string]bool, value any) error {
	if err := requireExactJournalKeys(raw, allowed); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, value); err != nil {
		return activationJournalError("selective resource evidence has unsupported types")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return activationJournalError("selective resource evidence cannot be serialized")
	}
	original, err1 := canonicalJournalJSON(raw)
	rebuilt, err2 := canonicalJournalJSON(encoded)
	if err1 != nil || err2 != nil || !bytes.Equal(original, rebuilt) {
		return activationJournalError("selective resource evidence is incomplete or inconsistent")
	}
	return nil
}

// Validate ALL route/rule pairs against their keys, binding, before=absence,
// and deterministic preview digest before any selective-specific deletion.
// Also used when reading a typed selective journal: malformed stored evidence
// is never an innocuous generic PREPARED record.
func validateSelectiveJournalRecord(record activationJournal) error {
	bad := func() error {
		return activationJournalError("selective intent provenance or resource binding is inconsistent")
	}
	if record.IntentType != selectiveIntentType || record.Selective == nil ||
		len(record.Changes) == 0 || len(record.Changes)%2 != 0 ||
		len(record.Changes) > 2*selectiveMaxDestinations {
		return bad()
	}
	binding := record.Selective
	plan := SelectiveRoutePlan{
		Mode: "selective_preview", ReadOnly: true,
		Endpoint: binding.Endpoint, ManagementPeer: binding.ManagementPeer,
		TunnelInterface: binding.TunnelInterface, RouteTable: binding.RouteTable,
		ObservationSHA256: record.ObservationSHA256, PlanSHA256: record.PlanSHA256,
		Routes: make([]PlannedRoute, 0, len(record.Changes)/2),
		Rules:  make([]PlannedRule, 0, len(record.Changes)/2),
	}
	request := SelectivePlanRequest{
		EndpointIP: binding.Endpoint, ManagementPeerIP: binding.ManagementPeer,
		TunnelInterface: binding.TunnelInterface,
		Destinations:    make([]string, 0, len(record.Changes)/2),
	}
	for index := 0; index < len(record.Changes); index += 2 {
		routeEntry := record.Changes[index]
		ruleEntry := record.Changes[index+1]
		if routeEntry.Kind != "route" || ruleEntry.Kind != "rule" {
			return bad()
		}
		var route PlannedRoute
		var rule PlannedRule
		if err := exactSelectiveEvidence(routeEntry.Intended, selectiveRouteEvidenceFields, &route); err != nil {
			return err
		}
		if err := exactSelectiveEvidence(ruleEntry.Intended, selectiveRuleEvidenceFields, &rule); err != nil {
			return err
		}
		plan.Routes = append(plan.Routes, route)
		plan.Rules = append(plan.Rules, rule)
		request.Destinations = append(request.Destinations, route.Destination)
	}
	validated, err := validateSelectiveRequest(request)
	if err != nil || len(validated.prefixes) != len(plan.Routes) {
		return bad()
	}
	for i, prefix := range validated.prefixes {
		if plan.Routes[i].Destination != prefix.String() {
			return bad()
		}
	}
	// Rebuild the exact deterministic resource identities and hash from the
	// persisted binding. This cannot validate who wrote privileged state,
	// but detects mistaken/foreign/semantically edited journal records.
	expected, err := selectiveJournalChanges(plan)
	if err != nil || len(expected) != len(record.Changes) {
		return bad()
	}
	for index, wanted := range expected {
		found := record.Changes[index]
		if found.Kind != wanted.Kind || found.Key != wanted.Key || found.Stage != wanted.Stage {
			return bad()
		}
		before, err1 := canonicalJournalJSON(found.Before)
		wantBefore, err2 := canonicalJournalJSON(wanted.Before)
		intended, err3 := canonicalJournalJSON(found.Intended)
		wantIntended, err4 := canonicalJournalJSON(wanted.Intended)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil ||
			!bytes.Equal(before, wantBefore) || !bytes.Equal(intended, wantIntended) {
			return bad()
		}
	}
	return nil
}
