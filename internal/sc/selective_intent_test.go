package sc

import (
	"reflect"
	"strings"
	"testing"
)

func TestSelectiveIntentJournalShapeRefusesUnverifiedOrForgedPlan(t *testing.T) {
	original, err := planFromFixture(t, fixtureSelectiveRequest())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*SelectiveRoutePlan)
	}{
		{"claims-guard-armed", func(p *SelectiveRoutePlan) { p.GuardArmed = true }},
		{"claims-activation-ready", func(p *SelectiveRoutePlan) { p.ActivationReady = true }},
		{"claims-ownership", func(p *SelectiveRoutePlan) { p.OwnershipVerified = true }},
		{"claims-atomic-snapshot", func(p *SelectiveRoutePlan) { p.SnapshotAtomic = true }},
		{"bad-observation-hash", func(p *SelectiveRoutePlan) { p.ObservationSHA256 = "not-a-sha" }},
		{"valid-looking-forged-plan-hash", func(p *SelectiveRoutePlan) { p.PlanSHA256 = strings.Repeat("a", 64) }},
		{"valid-looking-observation-hash-drift", func(p *SelectiveRoutePlan) { p.ObservationSHA256 = strings.Repeat("b", 64) }},
		{"incorrect-rule-identity", func(p *SelectiveRoutePlan) { p.Rules[0].Priority = 1 }},
		{"mismatched-destination", func(p *SelectiveRoutePlan) { p.Routes[0].Destination = "1.1.1.0/24" }},
		{"mismatched-table", func(p *SelectiveRoutePlan) { p.Routes[0].Table = 20200 }},
		{"mismatched-family", func(p *SelectiveRoutePlan) { p.Routes[0].Family = "ipv4" }},
		{"invalid-device", func(p *SelectiveRoutePlan) { p.TunnelInterface = "invalid device" }},
		{"incomplete", func(p *SelectiveRoutePlan) { p.Rules = nil }},
		{"duplicate-priority", func(p *SelectiveRoutePlan) { p.Rules[1].Priority = p.Rules[0].Priority }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := original
			p.Routes = append([]PlannedRoute(nil), original.Routes...)
			p.Rules = append([]PlannedRule(nil), original.Rules...)
			tc.change(&p)
			if _, err := selectiveJournalChanges(p); err == nil {
				t.Fatal("unsupported or forged advisory plan staged as exact ownership")
			}
		})
	}
}

func TestSelectiveIntentUncertainJournalCannotBeAbandoned(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, "", 0)
	prepared, err := prepareFixtureJournal(m)
	if err != nil {
		t.Fatal(err)
	}
	uncertain, err := m.markActivationJournalUncertain(prepared.OperationID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AbandonSelectiveIntent(uncertain.OperationID, uncertain.Revision); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("UNCERTAIN state was discarded: %v", err)
	}
	actual, err := m.observeActivationJournal()
	if err != nil || !reflect.DeepEqual(uncertain, actual) {
		t.Fatal("uncertain journal was modified by abandonment")
	}
}
