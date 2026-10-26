package sc

import (
	"bytes"
	"encoding/json"
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
	native := `[{"priority":0,"src":"all","table":"local"},{"priority":30000,"dst":"8.8.8.0/24","src":"all","table":20000,"protocol":188},{"priority":32766,"src":"all","table":"main"}]`
	present, err := trialRulePresence(rows(native), rule)
	if err != nil || !present {
		t.Fatalf("realistic native owned priority refused: present=%v err=%v", present, err)
	}
	missing, err := trialRulePresence(rows(`[{"priority":0,"src":"all","table":"local"}]`), rule)
	if err != nil || missing {
		t.Fatal("unrelated kernel policy mistaken for owned priority")
	}
	for name, mutated := range map[string]string{
		"wrong_protocol":          strings.Replace(native, `"protocol":188`, `"protocol":191`, 1),
		"missing_protocol":        strings.Replace(native, `,"protocol":188`, ``, 1),
		"foreign_table":           strings.Replace(native, `"table":20000`, `"table":20001`, 1),
		"unexpected_fwmark":       strings.Replace(native, `"protocol":188`, `"protocol":188,"fwmark":"0x1"`, 1),
		"wrong_destination":       strings.Replace(native, `8.8.8.0/24`, `8.8.9.0/24`, 1),
		"same_priority_duplicate": strings.Replace(native, `{"priority":32766`, `{"priority":30000,"dst":"8.8.8.0/24","table":20000,"protocol":188},{"priority":32766`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if owned, err := trialRulePresence(rows(mutated), rule); err == nil || owned {
				t.Fatalf("foreign rule accepted/deleted: %v, %v", owned, err)
			}
		})
	}
}
