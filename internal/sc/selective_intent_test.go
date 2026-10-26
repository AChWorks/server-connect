package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSelectiveIntentStageBindsNativePlanAndPrivateJournal(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, "", 0)
	req, h := fixtureSelectiveRequest(), fixtureSelectiveHost()
	plan, err := planFromFixture(t, req, h)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	status, err := m.stageSelectiveIntentWithInspector(req, func(endpoint, peer string) (HostPreflight, error) {
		calls++
		if endpoint != req.EndpointIP || peer != req.ManagementPeerIP {
			t.Fatalf("wrong protected paths: %s %s", endpoint, peer)
		}
		return fixtureSelectiveHost(), nil
	})
	if err != nil || calls != 2 || !status.Present || status.Phase != "prepared" ||
		status.Revision != 1 || !journalHex32.MatchString(status.OperationID) ||
		status.ResourceCount != 4 || !status.RequiresOperatorReview || status.GuardArmed ||
		status.ActivationReady || status.HostNetworkInspected || status.RecoveryVerified {
		t.Fatalf("staged intent overstated safety: status=%+v observations=%d err=%v", status, calls, err)
	}
	fresh := New(dir, "", 0)
	saved, err := fresh.observeActivationJournal()
	if err != nil || saved.PlanSHA256 != plan.PlanSHA256 || saved.ObservationSHA256 != plan.ObservationSHA256 {
		t.Fatalf("durable journal differs from exact read-only plan: %+v err=%v", saved, err)
	}
	expected, err := selectiveJournalChanges(plan)
	if err != nil || !reflect.DeepEqual(saved.Changes, expected) {
		t.Fatalf("staged resource identities are not deterministic and exact: %+v expected=%+v err=%v", saved.Changes, expected, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "runtime.json")); !os.IsNotExist(err) {
		t.Fatal("staging changed persistent runtime")
	}
	if _, err := os.Stat(filepath.Join(dir, "proxy-auth")); !os.IsNotExist(err) {
		t.Fatal("staging persisted credentials")
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); !os.IsNotExist(err) {
		t.Fatal("staging changed desired state")
	}
	info, err := os.Lstat(filepath.Join(dir, activationJournalFilename))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("journal insecure: %v %v", info, err)
	}
	summary, _ := json.Marshal(status)
	for _, private := range []string{`"before"`, `"intended"`, req.EndpointIP, req.ManagementPeerIP, "8.8.8.0/24", plan.PlanSHA256} {
		if bytes.Contains(summary, []byte(private)) {
			t.Fatalf("private network evidence was exposed in public result: %s", private)
		}
	}
	if _, err := fresh.stageSelectiveIntentWithInspector(req, func(string, string) (HostPreflight, error) { return fixtureSelectiveHost(), nil }); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("unacknowledged intent overwritten: %v", err)
	}
	if err := fresh.abandonPreparedActivationJournal(status.OperationID, 0); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("stale revision abandoned intent: %v", err)
	}
	if err := fresh.abandonPreparedActivationJournal(strings.Repeat("0", 32), 1); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("wrong operation abandoned intent: %v", err)
	}
	after, err := fresh.observeActivationJournal()
	if err != nil || !reflect.DeepEqual(saved, after) {
		t.Fatalf("failed abandon modified journal: %v", err)
	}
	absent, err := fresh.AbandonSelectiveIntent(status.OperationID, 1)
	if err != nil || absent.Phase != "absent" || absent.Present || absent.GuardArmed || absent.ActivationReady {
		t.Fatalf("untouched intent not safely abandoned: %+v %v", absent, err)
	}
	if _, err := os.Stat(filepath.Join(dir, activationJournalFilename)); !os.IsNotExist(err) {
		t.Fatal("prepared intent file retained after exact abandonment")
	}
}

func TestSelectiveIntentStageRefusesDriftAndUntrustedObservations(t *testing.T) {
	for _, tc := range []struct {
		name       string
		request    func() SelectivePlanRequest
		inspect    func(calls int) (HostPreflight, error)
		expected   string
		totalCalls int
	}{
		{"host-drift", fixtureSelectiveRequest, func(n int) (HostPreflight, error) {
			h := fixtureSelectiveHost()
			if n == 2 {
				h.IPv4Routes = json.RawMessage(`[{"dst":"default","dev":"eth0","metric":777},{"dst":"192.0.2.0/24","dev":"eth0"}]`)
			}
			return h, nil
		}, "route_plan_changed", 2},
		{"first-inspection-error", fixtureSelectiveRequest, func(int) (HostPreflight, error) { return HostPreflight{}, errors.New("private-host-path-secret") }, "route_plan_uncertain", 1},
		{"second-inspection-error", fixtureSelectiveRequest, func(n int) (HostPreflight, error) {
			if n == 2 {
				return HostPreflight{}, errors.New("private-host-path-secret")
			}
			return fixtureSelectiveHost(), nil
		}, "route_plan_uncertain", 2},
		{"foreign-device", fixtureSelectiveRequest, func(int) (HostPreflight, error) {
			h := fixtureSelectiveHost()
			h.Links = json.RawMessage(`[{"ifname":"lo"},{"ifname":"scplan0"}]`)
			return h, nil
		}, "route_plan_uncertain", 1},
		{"invalid-input", func() SelectivePlanRequest {
			r := fixtureSelectiveRequest()
			r.Destinations = []string{"0.0.0.0/0"}
			return r
		}, func(int) (HostPreflight, error) { return fixtureSelectiveHost(), nil }, "invalid_arguments", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateJournalTempDir(t)
			m := New(dir, "", 0)
			calls := 0
			_, err := m.stageSelectiveIntentWithInspector(tc.request(), func(string, string) (HostPreflight, error) { calls++; return tc.inspect(calls) })
			if ErrorCode(err) != tc.expected || strings.Contains(err.Error(), "private-host-path-secret") ||
				calls != tc.totalCalls {
				t.Fatalf("staging did not fail closed: calls=%d err=%v", calls, err)
			}
			if _, err := os.Lstat(filepath.Join(dir, activationJournalFilename)); !os.IsNotExist(err) {
				t.Fatalf("failed staging persisted unauthorized journal: %v", err)
			}
		})
	}
}

func TestSelectiveIntentJournalShapeRefusesUnverifiedOrForgedPlan(t *testing.T) {
	original, err := planFromFixture(t, fixtureSelectiveRequest(), fixtureSelectiveHost())
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
