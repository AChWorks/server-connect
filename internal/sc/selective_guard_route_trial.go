package sc

import (
	"encoding/json"
	"net/netip"
	"strconv"
)

// Route-bearing trial v3 is ONLY a loopback-route laboratory transaction in
// the already enforced disconnected Docker systemd namespace. The staged
// Selective intent binds the exact CIDR/table, but its proposed TUN device is
// deliberately NOT created: the single native route uses existing lo instead.
// Never infer that this exercise proves VPN traffic, route ownership against
// arbitrary privileged writers, a usable TUN or production routing safety.
func trialSingleRoute(record trialJournal) (PlannedRoute, error) {
	var route PlannedRoute
	if record.Version != 3 || record.IntentType != trialRouteIntentType || record.RouteDevice != "lo" {
		return route, Fault("trial_unsupported", "route-bearing operation requires v3 laboratory journal")
	}
	if err := exactSelectiveEvidence(record.Changes[0].Intended, selectiveRouteEvidenceFields, &route); err != nil {
		return route, err
	}
	if route.Family != "ipv4" || route.Destination == "" || route.Table != record.Selective.RouteTable {
		return route, activationJournalError("route-bearing trial intent inconsistent")
	}
	return route, nil
}

func trialRouteCommand(route PlannedRoute, verb string) []string {
	return []string{"-4", "route", verb, route.Destination, "dev", "lo", "table", strconv.Itoa(route.Table),
		"proto", trialProtocol, "scope", "link"}
}

// Inspect the WHOLE trial table, not just its intended destination. Another
// route in this previously empty table invalidates exclusive ownership; no
// broad flush, replace or adoption is permitted. -N is required for numeric
// protocol/table/scope representations, including user-defined aliases.
func trialNativeRoutePresence(route PlannedRoute) (bool, error) {
	raw, err := nativeIPJSON("-N", "-j", "-4", "route", "show", "table", strconv.Itoa(route.Table))
	if err != nil {
		return false, Fault("trial_observation_uncertain", "native laboratory route inventory unavailable")
	}
	rows, err := selectiveRows(raw)
	if err != nil {
		return false, Fault("trial_observation_uncertain", "native laboratory route inventory unsupported")
	}
	return trialRoutePresence(rows, route)
}

func trialRoutePresence(rows []map[string]json.RawMessage, route PlannedRoute) (bool, error) {
	if len(rows) == 0 {
		return false, nil
	}
	if len(rows) != 1 {
		return false, Fault("trial_resource_conflict", "route trial table contains foreign or duplicate routes")
	}
	row := rows[0]
	dst := selectiveText(row["dst"])
	prefix, err := netip.ParsePrefix(dst)
	if err != nil || prefix.String() != route.Destination || selectiveText(row["dev"]) != "lo" ||
		!trialProtocolMatches(row["protocol"]) || selectiveText(row["scope"]) != "253" {
		return false, Fault("trial_resource_conflict", "route trial table contains foreign destination or identity")
	}
	table, err := selectiveTable(row["table"], false)
	if err != nil || table != route.Table {
		return false, Fault("trial_resource_conflict", "route trial table cannot be proven owned")
	}
	for name, raw := range row {
		switch name {
		case "dst", "dev", "table", "scope", "protocol":
		case "flags":
			var flags []any
			if json.Unmarshal(raw, &flags) != nil || len(flags) != 0 {
				return false, Fault("trial_resource_conflict", "route trial has foreign flags")
			}
		default:
			return false, Fault("trial_resource_conflict", "route trial has unsupported native attributes")
		}
	}
	return true, nil
}

// One unrelated policy rule referencing the same table can make a route
// useful to foreign traffic. In that case, refuse even a seemingly exact
// owned route deletion. This is a conservative lab check, not cross-process
// proof of table ownership: external writers remain outside Manager .lock.
func trialNoForeignTableRules(rows []map[string]json.RawMessage, trialRule PlannedRule) error {
	for _, row := range rows {
		priority, ok := selectiveInt(row["priority"])
		if !ok {
			return Fault("trial_observation_uncertain", "native rule priority unsupported")
		}
		if priority == trialRule.Priority {
			continue
		} // inspected separately by trialRulePresence
		table, err := selectiveTable(row["table"], false)
		if err != nil {
			return Fault("trial_observation_uncertain", "other native policy table unsupported")
		}
		if table == trialRule.Table {
			return Fault("trial_resource_conflict", "foreign policy rule references the route trial table")
		}
	}
	return nil
}

// Called only after the trial RPDB rule was safely removed and reobserved
// absent. A crash between the two deletions is reconciled on the next timer
// tick; an unrecognized or foreign route must remain untouched with journal.
func trialRecoverRoute(record trialJournal, qaPoint string) error {
	route, err := trialSingleRoute(record)
	if err != nil {
		return err
	}
	present, err := trialNativeRoutePresence(route)
	if err != nil {
		return err
	}
	if present {
		if err := trialRunIP(trialRouteCommand(route, "del")...); err != nil {
			return err
		}
		if err := trialQAKillAt("after-route-delete", qaPoint); err != nil {
			return err
		}
	}
	remains, err := trialNativeRoutePresence(route)
	if err != nil {
		return err
	}
	if remains {
		return Fault("trial_recovery_uncertain", "route persists after laboratory recovery")
	}
	return nil
}
