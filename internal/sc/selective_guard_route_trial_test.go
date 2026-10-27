package sc

import (
	"bytes"
	"encoding/json"
	"os"
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
	allTables := rows(`[{"dst":"127.0.0.0/8","dev":"lo","table":"local"}, {"dst":"0.0.0.0/0","dev":"lo","table":"main"}]`)
	if selected, err := trialRoutesInTable(allTables, route); err != nil || len(selected) != 0 {
		t.Fatalf("empty selected table not proved by valid all-table observation: %d,%v", len(selected), err)
	}
	if selected, err := trialRoutesInTable(rows(`[{"dst":"8.8.8.0/24","table":"foo"}]`), route); err == nil || selected != nil {
		t.Fatal("unknown table alias falsely proved selected table absence")
	}
	moved := strings.Replace(real, `"table":"20000"`, `"table":"20001"`, 1)
	if selected, err := trialRoutesInTable(rows(moved), route); ErrorCode(err) != "trial_resource_conflict" || selected != nil {
		t.Fatal("moved tagged route in foreign table was treated as recovered")
	}
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

// QA error injection is an opt-in guest-only control, not a production
// alternate executable or a public tunnel activation path.
func TestGuardedRouteTrialV3QAFaultAdmission(t *testing.T) {
	for _, tc := range []struct {
		phase, point string
		allowed      bool
	}{
		{"route-apply", "", true},
		{"route-apply", "route-add", true},
		{"route-apply", "rule-add", true},
		{"recover", "route-delete", true},
		{"recover", "recovered-journal-write", true},
		{"apply", "route-add", false},
		{"apply", "rule-add", false},
		{"recover", "route-add", false},
		{"recover", "rule-add", false},
		{"route-apply", "route-delete", false},
		{"recover", "missing", false},
	} {
		err := trialValidateQAFaultPoint(tc.phase, tc.point)
		if tc.allowed && err != nil {
			t.Errorf("refused %s/%s: %v", tc.phase, tc.point, err)
		}
		if !tc.allowed && ErrorCode(err) != "invalid_arguments" {
			t.Errorf("accepted %s/%s: %v", tc.phase, tc.point, err)
		}
	}
	if err := trialQAFailRecoveredJournal(""); err != nil {
		t.Fatal(err)
	}
	if code := ErrorCode(trialQAFailRecoveredJournal("recovered-journal-write")); code != "activation_journal_unavailable" {
		t.Fatalf("simulated persistence error code %s", code)
	}
}

func TestGuardedRouteTrialQANativeCommandError(t *testing.T) {
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("native iproute2 unavailable")
	}
	// Even when the caller supplies a would-be route mutation, the named QA
	// boundary executes ONLY a deliberately invalid, non-mutating ip command.
	if code := ErrorCode(trialRunIPWithQAFault("route-add", "route-add", "-4", "route", "add", "9.9.9.0/24", "dev", "lo")); code != "trial_kernel_error" {
		t.Fatalf("QA native command failure incorrectly accepted: %s", code)
	}
}
