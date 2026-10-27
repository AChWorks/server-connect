package sc

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestGuardedRouteTrialV3JournalAndReceipt(t *testing.T) {
	record := stagedTrialRecord(t)
	record.Version, record.IntentType, record.RouteDevice = 3, trialRouteIntentType, "lo"
	if err := validateTrialJournal(record); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeTrialJournal(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.OperationID != record.OperationID || got.PlanSHA256 != record.PlanSHA256 || got.Version != 3 {
		t.Fatal("route trial lost exact planned identity")
	}
	if _, err := trialSingleRoute(got); err != nil {
		t.Fatal(err)
	}
	pending := trialReceipt(got, true, false)
	if pending.ActivationReady || pending.VPNVerified || pending.RecoveryVerified ||
		pending.TrialRouteRecovered || !pending.ExperimentOnly || !pending.GuardScheduled {
		t.Fatalf("unsafe route-trial claims: %+v", pending)
	}
	got.Phase, got.Revision = "trial_recovered", 3
	recovered := trialReceipt(got, false, true)
	if !recovered.TrialRuleRecovered || !recovered.TrialRouteRecovered || recovered.RecoveryVerified || recovered.ActivationReady || recovered.VPNVerified {
		t.Fatalf("route receipt implies product activation safety: %+v", recovered)
	}
	private, _ := json.Marshal(recovered)
	for _, s := range []string{record.Selective.Endpoint, record.Selective.ManagementPeer, record.Changes[0].Key, `"changes"`} {
		if bytes.Contains(private, []byte(s)) {
			t.Fatalf("private plan leaked into receipt: %s", s)
		}
	}
	for name, mutated := range map[string]func(*trialJournal){
		"wrong_type":           func(r *trialJournal) { r.IntentType = trialIntentType },
		"missing_route_device": func(r *trialJournal) { r.RouteDevice = "" },
		"foreign_route_device": func(r *trialJournal) { r.RouteDevice = "eth0" },
		"unknown_version":      func(r *trialJournal) { r.Version = 4 },
		"bad_phase":            func(r *trialJournal) { r.Phase = "active" },
		"unpaired_rule": func(r *trialJournal) {
			r.Changes = append([]activationJournalChange(nil), r.Changes...)
			r.Changes[1].Key = "ipv4:30003"
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := record
			mutated(&copy)
			data, _ := json.Marshal(copy)
			if _, err := decodeTrialJournal(data); err == nil {
				t.Fatal("unsafe v3 journal accepted")
			}
		})
	}
	if err := trialValidateQACrashPoint("route-apply", "after-route"); err != nil {
		t.Fatal(err)
	}
	if ErrorCode(trialValidateQACrashPoint("apply", "after-route")) != "invalid_arguments" {
		t.Fatal("v2 route interruption accepted")
	}
	if ErrorCode(trialValidateQACrashPoint("route-apply", "after-route-delete")) != "invalid_arguments" {
		t.Fatal("recovery point accepted during route apply")
	}
}

func TestGuardedRouteTrialNativeIdentityAndForeignTableRules(t *testing.T) {
	route := PlannedRoute{Family: "ipv4", Destination: "8.8.8.0/24", Table: 20000, Device: "scguard0"}
	rows := func(s string) []map[string]json.RawMessage {
		t.Helper()
		var rows []map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s), &rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	real := `[{"dst":"8.8.8.0/24","dev":"lo","table":"20000","protocol":"247","scope":"253","flags":[]}]`
	if present, err := trialRoutePresence(rows(real), route); err != nil || !present {
		t.Fatalf("exact route refused: %v,%v", present, err)
	}
	if present, err := trialRoutePresence(rows(`[]`), route); err != nil || present {
		t.Fatalf("absent route accepted: %v,%v", present, err)
	}
	for name, mutated := range map[string]string{
		"foreign_proto":           strings.Replace(real, `"247"`, `"248"`, 1),
		"alias_not_authenticated": strings.Replace(real, `"247"`, `"myprotocol"`, 1),
		"foreign_table":           strings.Replace(real, `"20000"`, `"20001"`, 1),
		"foreign_destination":     strings.Replace(real, "8.8.8.0/24", "8.8.9.0/24", 1),
		"foreign_device":          strings.Replace(real, `"lo"`, `"eth0"`, 1),
		"foreign_scope":           strings.Replace(real, `"253"`, `"254"`, 1),
		"foreign_metric":          strings.Replace(real, `"flags":[]`, `"flags":[],"metric":42`, 1),
		"foreign_flags":           strings.Replace(real, `"flags":[]`, `"flags":["offload"]`, 1),
		"missing_protocol":        strings.Replace(real, `,"protocol":"247"`, "", 1),
		"duplicate_route":         strings.TrimSuffix(real, "]") + `,{"dst":"8.8.9.0/24","dev":"lo"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			if present, err := trialRoutePresence(rows(mutated), route); err == nil || present {
				t.Fatalf("foreign route trusted: %v,%v", present, err)
			}
		})
	}
	rule := PlannedRule{Family: "ipv4", Destination: "8.8.8.0/24", Priority: 30000, Table: 20000}
	normal := `[{"priority":0,"src":"all","table":"local"},{"priority":30000,"dst":"8.8.8.0/24","table":"20000","protocol":"247"},{"priority":32766,"src":"all","table":"main"}]`
	if err := trialNoForeignTableRules(rows(normal), rule); err != nil {
		t.Fatal(err)
	}
	withForeign := strings.Replace(normal, `{"priority":32766`, `{"priority":30200,"dst":"8.8.8.0/24","table":"20000","protocol":"249"},{"priority":32766`, 1)
	if ErrorCode(trialNoForeignTableRules(rows(withForeign), rule)) != "trial_resource_conflict" {
		t.Fatal("foreign rule referencing our table accepted")
	}
}
