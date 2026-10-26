package sc

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stagedTrialRecord(t *testing.T) trialJournal {
	t.Helper()
	m := New(privateJournalTempDir(t), "", 0)
	req := fixtureSelectiveRequest()
	req.Destinations = []string{"8.8.8.0/24"}
	_, err := m.stageSelectiveIntentWithInspector(req, func(string, string) (HostPreflight, error) { return fixtureSelectiveHost(), nil })
	if err != nil {
		t.Fatal(err)
	}
	staged, err := m.observeActivationJournal()
	if err != nil {
		t.Fatal(err)
	}
	record := trialJournal{activationJournal: staged, BootID: "01234567-89ab-cdef-0123-456789abcdef", DeadlineUptimeSec: 1000}
	record.Version, record.Revision, record.Phase, record.IntentType = 2, 2, "trial_pending", trialIntentType
	if err := validateTrialJournal(record); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestGuardedRuleTrialJournalSchemaAndNoProductionClaims(t *testing.T) {
	original := stagedTrialRecord(t)
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeTrialJournal(data)
	if err != nil || got.OperationID != original.OperationID || got.PlanSHA256 != original.PlanSHA256 {
		t.Fatalf("valid trial lost binding: %v", err)
	}
	receipt := trialReceipt(got, true, false)
	if receipt.ActivationReady || receipt.VPNVerified || receipt.RecoveryVerified || receipt.TrialRuleRecovered || !receipt.ExperimentOnly || !receipt.GuardScheduled {
		t.Fatalf("trial incorrectly advertised production safety: %+v", receipt)
	}
	for _, private := range []string{original.Selective.Endpoint, original.Selective.ManagementPeer, "8.8.8.0/24", `"changes"`, `"plan_sha256"`} {
		encoded, _ := json.Marshal(receipt)
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatalf("private evidence leaked: %s", private)
		}
	}
	tests := []struct {
		name   string
		change func(*trialJournal)
	}{
		{"unknown_revision", func(r *trialJournal) { r.Revision = 4 }},
		{"wrong_phase", func(r *trialJournal) { r.Phase = "active" }},
		{"bad_boot", func(r *trialJournal) { r.BootID = "not-a-boot-id" }},
		{"missing_deadline", func(r *trialJournal) { r.DeadlineUptimeSec = 0 }},
		{"foreign_intent", func(r *trialJournal) { r.IntentType = "unarmed_selective_v1" }},
		{"foreign_rule", func(r *trialJournal) { r.Changes[1].Key = "ipv4:30017" }},
		{"malformed_protocol", func(r *trialJournal) { r.Changes[1].Stage = "applied" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			copy := original
			copy.Changes = append([]activationJournalChange(nil), original.Changes...)
			tc.change(&copy)
			mutated, err := json.Marshal(copy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeTrialJournal(mutated); err == nil {
				t.Fatal("unsupported journal accepted")
			}
		})
	}
	mutated := bytes.Replace(data, []byte(`"version":2`), []byte(`"VERSION":2`), 1)
	if _, err := decodeTrialJournal(mutated); err == nil {
		t.Fatal("case-variant field accepted")
	}
	duplicate := bytes.Replace(data, []byte(`"version":2`), []byte(`"version":2,"version":2`), 1)
	if _, err := decodeTrialJournal(duplicate); err == nil {
		t.Fatal("duplicate journal key accepted")
	}
	extra := bytes.Replace(data, []byte(`"boot_id":`), []byte(`"external_override":true,"boot_id":`), 1)
	if _, err := decodeTrialJournal(extra); err == nil {
		t.Fatal("future unknown field accepted")
	}
	for _, bad := range [][]byte{append(data, []byte(`{}`)...), []byte(`[]`), []byte(`{"version":2}`)} {
		if _, err := decodeTrialJournal(bad); err == nil {
			t.Fatal("malformed journal accepted")
		}
	}
	original.Phase, original.Revision = "trial_recovered", 3
	if err := validateTrialJournal(original); err != nil {
		t.Fatalf("valid recovered receipt rejected: %v", err)
	}
	if !trialReceipt(original, false, true).TrialRuleRecovered || trialReceipt(original, false, true).RecoveryVerified {
		t.Fatal("rule recovery confused with production host safety")
	}
}

func TestGuardedRuleTrialNativeIdentityRefusesForeignAndReplay(t *testing.T) {
	rule := PlannedRule{Family: "ipv4", Destination: "8.8.8.0/24", Priority: 30000, Table: 20000}
	rows := func(s string) []map[string]json.RawMessage {
		t.Helper()
		var result []map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	native := `[{"priority":0,"src":"all","table":"local"},{"priority":30000,"dst":"8.8.8.0/24","src":"all","table":20000,"protocol":247},{"priority":32766,"src":"all","table":"main"}]`
	present, err := trialRulePresence(rows(native), rule)
	if err != nil || !present {
		t.Fatalf("realistic native owned priority refused: present=%v err=%v", present, err)
	}
	// ip -N -j renders even built-in and custom identities as JSON strings.
	numeric := strings.Replace(strings.Replace(native, `"protocol":247`, `"protocol":"247"`, 1),
		`"table":20000`, `"table":"20000"`, 1)
	if present, err := trialRulePresence(rows(numeric), rule); err != nil || !present {
		t.Fatalf("numeric native identity refused: present=%v err=%v", present, err)
	}
	missing, err := trialRulePresence(rows(`[{"priority":0,"src":"all","table":"local"}]`), rule)
	if err != nil || missing {
		t.Fatal("unrelated kernel policy mistaken for owned priority")
	}
	for name, mutated := range map[string]string{
		"wrong_protocol":          strings.Replace(native, `"protocol":247`, `"protocol":249`, 1),
		"alias_not_authenticated": strings.Replace(native, `"protocol":247`, `"protocol":"ospf"`, 1),
		"missing_protocol":        strings.Replace(native, `,"protocol":247`, ``, 1),
		"foreign_table":           strings.Replace(native, `"table":20000`, `"table":20001`, 1),
		"unexpected_fwmark":       strings.Replace(native, `"protocol":247`, `"protocol":247,"fwmark":"0x1"`, 1),
		"wrong_destination":       strings.Replace(native, `8.8.8.0/24`, `8.8.9.0/24`, 1),
		"moved_tagged_priority":   strings.Replace(native, `"priority":30000`, `"priority":30003`, 1),
		"same_priority_duplicate": strings.Replace(native, `{"priority":32766`, `{"priority":30000,"dst":"8.8.8.0/24","table":20000,"protocol":247},{"priority":32766`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if owned, err := trialRulePresence(rows(mutated), rule); err == nil || owned {
				t.Fatalf("foreign rule accepted/deleted: %v, %v", owned, err)
			}
		})
	}
}

// The fixed independent systemd unit always reads DefaultDir; accepting
// custom state at trial start would create an irrecoverable rule after crash.
func TestGuardedRuleTrialRejectsUnwatchedCustomState(t *testing.T) {
	m := New(privateJournalTempDir(t), "", 0)
	if _, err := m.BeginGuardedRuleTrial(strings.Repeat("a", 32), 1, 8, ""); ErrorCode(err) != "trial_unsupported" {
		t.Fatalf("custom state trial could strand an RPDB rule: %v", err)
	}
	if _, err := m.RecoverGuardedRuleTrial(""); ErrorCode(err) != "trial_unsupported" {
		t.Fatalf("unwatched recovery dir accepted: %v", err)
	}
	if _, err := m.InspectGuardedRuleTrial(); ErrorCode(err) != "trial_unsupported" {
		t.Fatalf("unwatched inspection dir accepted: %v", err)
	}
	if err := m.ClearRecoveredRuleTrial(strings.Repeat("a", 32), 3); ErrorCode(err) != "trial_unsupported" {
		t.Fatalf("unwatched clear dir accepted: %v", err)
	}
}

// Only explicitly supported boundaries may terminate the disposable guest
// controller. Recovery-only points must never be accepted during apply.
func TestGuardedRuleTrialQACrashBoundaryAdmission(t *testing.T) {
	for _, phase := range []string{"apply", "recover"} {
		for _, point := range []string{"", "before-journal", "after-journal", "after-add", "after-delete", "before-recovered-journal", "unknown"} {
			accepted := point == "" || (phase == "apply" && (point == "before-journal" || point == "after-journal" || point == "after-add")) || (phase == "recover" && (point == "after-delete" || point == "before-recovered-journal"))
			err := trialValidateQACrashPoint(phase, point)
			if accepted && err != nil {
				t.Fatalf("%s/%s unexpectedly rejected: %v", phase, point, err)
			}
			if !accepted && ErrorCode(err) != "invalid_arguments" {
				t.Fatalf("%s/%s not rejected: %v", phase, point, err)
			}
		}
	}
	if ErrorCode(trialValidateQACrashPoint("other", "after-add")) != "invalid_arguments" {
		t.Fatal("unknown QA phase unexpectedly accepted")
	}
}

// Systemd can cache loaded/static after a runtime mask has replaced the unit.
// The actual runtime filesystem is a separate observation boundary.
func TestGuardedRuleTrialRuntimeMaskRefusesCachedUnitState(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{trialRecoveryUnit, trialRecoveryTimer} {
		if err := trialNoRuntimeUnitOverride(dir, name); err != nil {
			t.Fatalf("absent override refused for %s: %v", name, err)
		}
		path := filepath.Join(dir, name)
		if err := os.Symlink("/dev/null", path); err != nil {
			t.Fatal(err)
		}
		if err := trialNoRuntimeUnitOverride(dir, name); ErrorCode(err) != "guard_unavailable" {
			t.Fatalf("runtime mask accepted: %s, %v", name, err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("foreign runtime override"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := trialNoRuntimeUnitOverride(dir, name); ErrorCode(err) != "guard_unavailable" {
			t.Fatalf("runtime override accepted: %s, %v", name, err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}
