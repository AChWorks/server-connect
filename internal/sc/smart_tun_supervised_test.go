package sc

import (
	"encoding/json"
	"strings"
	"syscall"
	"testing"
	"time"
)

func supervisedExample(t *testing.T, confirmed bool) smartTUNTrialJournal {
	t.Helper()
	r := nativeTrialExample(true)
	_, nft := nativeNFTFixture(t, r)
	bindNativeNFTReceipt(&r, nft)
	r.IntentType = smartTUNSupervisedIntent
	r.DeadlineUptimeSec = 200
	id := smartTUNHealthUnitIdentity{UnitDev: 1, UnitIno: 2, DigestDev: 1, DigestIno: 3, SHA256: strings.Repeat("a", 64)}
	r.Supervised = &smartTUNSupervision{Version: smartTUNSupervisionVersion, Generation: 1, State: "awaiting_confirmation", Options: SmartTUNHealthOptions{5, 0, 1, 2, 10}, Roles: [2]smartTUNHealthUnitIdentity{id, id}, ReadyAfterMS: 100000, HeartbeatMS: 100000, LeaseDeadlineMS: 135000, CorePID: 100, CoreStartTicks: 20, ReconnectStage: "none"}
	r.Supervised.ChallengeSHA256 = smartTUNChallengeDigest(r, strings.Repeat("b", 64))
	if confirmed {
		s := r.Supervised
		s.Confirmed = true
		s.ChallengeSHA256 = ""
		s.SessionSHA256 = strings.Repeat("c", 64)
		s.SessionStartedMS = 100010
		s.State = "healthy"
		s.Rounds = 1
		s.LastProbeMS = 100100
		s.HeartbeatMS = 100100
		s.LeaseDeadlineMS = 135100
		s.NextProbeMS = 105100
		s.Evidence = healthySupervisedEvidence()
	}
	if err := validateSmartTUNTrial(r); err != nil {
		t.Fatalf("invalid fixture: %v", err)
	}
	return r
}

func healthySupervisedEvidence() SmartTUNHealthEvidence {
	return SmartTUNHealthEvidence{UnderlayHealthy: true, VPNHealthy: true, IPv4TCP: true, IPv4UDP: true, IPv4DNS: true, IPv6TCP: true, IPv6UDP: true, IPv6DNS: true, IPv4HTTPS: true, IPv6HTTPS: true, HTTPSResults: [4]SmartTUNHTTPSResult{{Result: "pass", StatusCode: 200}, {Result: "pass", StatusCode: 200}, {Result: "pass", StatusCode: 200}, {Result: "pass", StatusCode: 200}}, ProbeCount: 17, ElapsedMS: 20, Reason: "healthy"}
}

func TestSupervisedJournalStrictSubtypeAndFullValueComparison(t *testing.T) {
	r := supervisedExample(t, false)
	raw, _ := json.Marshal(r)
	decoded, err := decodeSmartTUNTrial(raw)
	if err != nil || !sameSmartTUNTrial(r, decoded) {
		t.Fatalf("roundtrip: %v", err)
	}
	for _, bad := range []string{
		strings.Replace(string(raw), `"supervised":{`, `"supervised":{"unknown":1,`, 1),
		strings.Replace(string(raw), `"confirmed":false`, `"confirmed":null`, 1),
		strings.Replace(string(raw), `"confirmed":false`, `"Confirmed":false`, 1),
		strings.Replace(string(raw), `"confirmed":false`, `"confirmed":false,"confirmed":true`, 1),
		strings.Replace(string(raw), `"options":{`, `"options":{"unknown":1,`, 1),
		strings.Replace(string(raw), `"evidence":{`, `"evidence":{"unknown":1,`, 1),
		strings.Replace(string(raw), `"core_pid":100`, `"core_pid":null`, 1),
		strings.Replace(string(raw), smartTUNSupervisedIntent, smartTUNNativeIntent, 1),
	} {
		if _, err := decodeSmartTUNTrial([]byte(bad)); err == nil {
			t.Fatal("ambiguous supervision accepted")
		}
	}
	for _, mutate := range []func(*smartTUNSupervision){
		func(s *smartTUNSupervision) { s.Generation++ }, func(s *smartTUNSupervision) { s.Roles[0].UnitIno++ },
		func(s *smartTUNSupervision) { s.Attempts++ }, func(s *smartTUNSupervision) { s.CoreStartTicks++ },
	} {
		next := cloneSmartTUNTrial(r)
		mutate(next.Supervised)
		if sameSmartTUNTrial(r, next) || r.Supervised.Generation != 1 {
			t.Fatal("supervision identity mutation hidden or clone aliased")
		}
	}
	legacy := nativeTrialExample(false)
	legacy.Supervised = r.Supervised
	if validateSmartTUNTrial(legacy) == nil {
		t.Fatal("legacy intent acquired supervised authority")
	}
}

func TestSupervisedChallengeBoundToOperationBootConfigRevisionAndFreshness(t *testing.T) {
	r := supervisedExample(t, false)
	challenge := strings.Repeat("b", 64)
	if !smartTUNConfirmMatches(r, r.OperationID, 1, challenge, r.BootID, 100050) {
		t.Fatal("exact fresh challenge rejected")
	}
	for _, mutate := range []func(*smartTUNTrialJournal){
		func(r *smartTUNTrialJournal) { r.ConfigSHA256 = strings.Repeat("d", 64) },
		func(r *smartTUNTrialJournal) { r.Supervised.ReadyAfterMS++ },
		func(r *smartTUNTrialJournal) { r.OperationID = strings.Repeat("e", 32) },
		func(r *smartTUNTrialJournal) { r.BootID = "10000000-0000-0000-0000-000000000001" },
		func(r *smartTUNTrialJournal) { r.Revision = 2 },
		func(r *smartTUNTrialJournal) { r.Supervised.Confirmed = true; r.Supervised.ChallengeSHA256 = "" },
	} {
		next := cloneSmartTUNTrial(r)
		mutate(&next)
		if smartTUNConfirmMatches(next, r.OperationID, 1, challenge, r.BootID, 100050) {
			t.Fatal("changed/replayed confirmation accepted")
		}
	}
	for _, now := range []int64{99999, 100000, 135000, 200000, 200001} {
		if smartTUNConfirmMatches(r, r.OperationID, 1, challenge, r.BootID, now) {
			t.Fatal("old or expired challenge/lease accepted")
		}
	}
	// Isolate activation expiry while the supervisor lease is still valid.
	activationBound := cloneSmartTUNTrial(r)
	activationBound.DeadlineUptimeSec = 110
	if !smartTUNConfirmMatches(activationBound, r.OperationID, 1, challenge, r.BootID, 109999) {
		t.Fatal("valid confirmation immediately before activation expiry rejected")
	}
	for _, now := range []int64{110000, 110001} {
		if smartTUNConfirmMatches(activationBound, r.OperationID, 1, challenge, r.BootID, now) {
			t.Fatal("expired activation accepted while supervisor lease remained valid")
		}
	}
	// Isolate lease expiry while the original activation deadline is later.
	if !smartTUNConfirmMatches(r, r.OperationID, 1, challenge, r.BootID, 134999) {
		t.Fatal("valid confirmation immediately before supervisor lease expiry rejected")
	}
	if smartTUNConfirmMatches(r, r.OperationID, 1, challenge, r.BootID, 135000) {
		t.Fatal("expired supervisor lease accepted while activation remained valid")
	}
	receipt := smartTUNReceipt(r, true, false)
	wire, _ := json.Marshal(receipt)
	if strings.Contains(string(wire), challenge) || strings.Contains(string(wire), r.Supervised.ChallengeSHA256) || receipt.VPNVerified || receipt.ActivationReady {
		t.Fatal("status exposed challenge or promoted synthetic acceptance")
	}
}

func TestSupervisedFiniteLifetimeRetryAndLateSuccess(t *testing.T) {
	r := supervisedExample(t, true)
	failed := healthySupervisedEvidence()
	failed.VPNHealthy = false
	failed.IPv4TCP = false
	failed.Reason = "vpn_ipv4_tcp_failed"
	next, stop, reconnect := advanceSupervisedHealth(r, failed, 106000)
	if stop != "" || !reconnect || next.Supervised.RecoveryDeadlineMS != 116000 {
		t.Fatalf("first incident: %s %v", stop, reconnect)
	}
	next.Supervised.Attempts = 1
	healthy, stop, reconnect := advanceSupervisedHealth(next, healthySupervisedEvidence(), 110000)
	if stop != "" || reconnect || healthy.Supervised.Attempts != 1 || healthy.Supervised.RecoveryDeadlineMS != 0 {
		t.Fatal("transient recovery reset lifetime attempt budget")
	}
	healthy.Supervised.Attempts = 2
	_, stop, reconnect = advanceSupervisedHealth(healthy, failed, 115000)
	if stop != "reconnect_exhausted" || reconnect {
		t.Fatal("flapping escaped finite operation budget")
	}
	_, stop, reconnect = advanceSupervisedHealth(next, healthySupervisedEvidence(), 116000)
	if stop != "recovery_deadline_expired" || reconnect {
		t.Fatal("late success escaped absolute incident deadline")
	}
	unit := smartTUNTrialUnitObservation{activeState: "active", mainPID: 100, result: "success"}
	if got := supervisedRuntimeReason(next, unit, true, next.BootID, 116000); got != "recovery_deadline_expired" {
		t.Fatalf("independent delayed executor ignored incident deadline: %s", got)
	}
}

func TestSupervisedFalseAlarmGraceAndCriticalPathSeparation(t *testing.T) {
	r := supervisedExample(t, true)
	r.Supervised.Options.FailureThreshold = 2
	failed := healthySupervisedEvidence()
	failed.VPNHealthy = false
	failed.IPv4UDP = false
	failed.Reason = "vpn_ipv4_udp_failed"
	next, stop, reconnect := advanceSupervisedHealth(r, failed, 106000)
	if stop != "" || reconnect || next.Supervised.Failures != 1 {
		t.Fatal("single round was treated as sustained outage")
	}
	next, stop, reconnect = advanceSupervisedHealth(next, healthySupervisedEvidence(), 112000)
	if stop != "" || reconnect || next.Supervised.Failures != 0 {
		t.Fatal("healthy round did not clear false alarm")
	}
	failed.UnderlayHealthy = false
	_, stop, _ = advanceSupervisedHealth(r, failed, 106000)
	if stop != "protected_underlay_failed" {
		t.Fatal("critical protected-path loss incorrectly retried VPN")
	}
	failed = healthySupervisedEvidence()
	failed.Reason = "vpn_path_mismatch"
	_, stop, _ = advanceSupervisedHealth(r, failed, 106000)
	if stop != "vpn_path_mismatch" {
		t.Fatal("mismatched witness accepted as healthy alternate target")
	}
}

func TestSupervisedDeadlineLeaseBootAndInterruptedAttachAreIndependent(t *testing.T) {
	r := supervisedExample(t, true)
	unit := smartTUNTrialUnitObservation{activeState: "active", mainPID: 100, result: "success"}
	r.DeadlineUptimeSec = 101
	if got := supervisedRuntimeReason(r, unit, true, r.BootID, 110000); got != "" {
		t.Fatalf("valid confirmation retained activation expiry: %s", got)
	}
	for _, tc := range []struct {
		why    string
		mutate func(*smartTUNTrialJournal, *smartTUNTrialUnitObservation)
		now    int64
	}{
		{"supervisor_lease_expired", func(*smartTUNTrialJournal, *smartTUNTrialUnitObservation) {}, 135100},
		{"core_unavailable", func(_ *smartTUNTrialJournal, u *smartTUNTrialUnitObservation) { u.activeState = "failed" }, 110000},
		{"reconnect_interrupted", func(r *smartTUNTrialJournal, _ *smartTUNTrialUnitObservation) {
			r.Supervised.ReconnectStage = "start_requested"
		}, 110000},
	} {
		next := cloneSmartTUNTrial(r)
		u := unit
		tc.mutate(&next, &u)
		if got := supervisedRuntimeReason(next, u, true, r.BootID, tc.now); got != tc.why {
			t.Fatalf("%s got %s", tc.why, got)
		}
	}
	if got := supervisedRuntimeReason(r, unit, true, "different", 110000); got != "boot_changed" {
		t.Fatal("boot change ignored")
	}
}

func TestSupervisedStalePublicationCannotAdoptAChangedJournal(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, DefaultCore, DefaultPort)
	old := supervisedExample(t, true)
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeSmartTUNTrialLocked(store, old, nil); err != nil {
			return err
		}
		id, err := reloadSmartTUNTrialLocked(store, old)
		if err != nil {
			return err
		}
		next := cloneSmartTUNTrial(old)
		next.Supervised.Generation++
		next.Supervised.Attempts++
		if err := writeSmartTUNTrialLocked(store, next, &id); err != nil {
			return err
		}
		if _, err := reloadSmartTUNTrialLocked(store, old); ErrorCode(err) != "activation_journal_conflict" {
			t.Fatalf("old measured round adopted a changed ledger: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSupervisedTerminalMeasuredDecisionSurvivesDeathBeforeStop(t *testing.T) {
	r := supervisedExample(t, true)
	r.Supervised.Attempts = r.Supervised.Options.MaxAttempts
	failed := healthySupervisedEvidence()
	failed.VPNHealthy = false
	failed.IPv4TCP = false
	failed.Reason = "vpn_ipv4_tcp_failed"
	next, stop, _ := advanceSupervisedHealth(r, failed, 106000)
	if stop != "reconnect_exhausted" || next.Supervised.Reason != stop {
		t.Fatal("terminal decision was not durable in measured publication")
	}
	unit := smartTUNTrialUnitObservation{activeState: "active", mainPID: 100, result: "success"}
	if got := supervisedRuntimeReason(next, unit, true, next.BootID, 106001); got != stop {
		t.Fatalf("independent recovery lost terminal decision after publisher death: %s", got)
	}
	if err := validateSmartTUNTrial(next); err != nil {
		t.Fatalf("terminal measured record invalid: %v", err)
	}
}

func TestSupervisedEvidenceShapeRejectsUnsupportedClaims(t *testing.T) {
	r := supervisedExample(t, true)
	for _, mutate := range []func(*SmartTUNHealthEvidence){
		func(e *SmartTUNHealthEvidence) { e.ProbeCount = 14 },
		func(e *SmartTUNHealthEvidence) { e.FailedTargets = 5 },
		func(e *SmartTUNHealthEvidence) { e.IPv6DNS = false },
		func(e *SmartTUNHealthEvidence) { e.Reason = "unspecified" },
	} {
		next := cloneSmartTUNTrial(r)
		mutate(&next.Supervised.Evidence)
		if validateSmartTUNTrial(next) == nil {
			t.Fatal("unsupported probe evidence accepted")
		}
	}
}

func TestSupervisedGuardFinalReceiptRetainsDecisionAfterJournalCleanup(t *testing.T) {
	r := supervisedExample(t, true)
	r.Phase, r.Revision = "trial_cleared", 5
	r.Supervised.State, r.Supervised.Reason = "stopped", "reconnect_exhausted"
	r.Supervised.Attempts = 2
	r.Supervised.RecoveryDeadlineMS = 123000
	final := smartTUNRecoveryReceipt(smartTUNReceipt(r, false, true))
	if final.Phase != "trial_cleared" || !final.RecoveryVerified || final.HealthReason != "reconnect_exhausted" || final.ReconnectAttempts != 2 || final.HealthLastUptimeMS != 100100 || final.HealthRound != 1 || final.HealthEvidence == nil || final.SupervisionState != "stopped" {
		t.Fatalf("independent final receipt lost cause/budget/evidence: %+v", final)
	}
	wire, _ := json.Marshal(final)
	if strings.Contains(string(wire), "challenge") || strings.Contains(string(wire), "session_sha256") {
		t.Fatal("guard log exposed private confirmation material")
	}
	legacy := trialReceipt(trialJournal{}, false, false)
	wire, _ = json.Marshal(legacy)
	for _, field := range []string{"supervision_state", "management_confirmed", "health_reason", "health_evidence", "reconnect_attempts"} {
		if strings.Contains(string(wire), field) {
			t.Fatalf("legacy JSON gained %s", field)
		}
	}
}

func TestSupervisedReconnectStartAndRenewalRespectRemainingAuthority(t *testing.T) {
	r := supervisedExample(t, true)
	r.Supervised.RecoveryDeadlineMS = 110000
	for _, tc := range []struct {
		now    int64
		budget time.Duration
		reason string
	}{
		{105000, 5 * time.Second, ""}, {109999, time.Millisecond, ""}, {110000, 0, "recovery_deadline_expired"}, {110001, 0, "recovery_deadline_expired"},
	} {
		got, reason := supervisedReconnectBudget(r, tc.now)
		if got != tc.budget || reason != tc.reason {
			t.Fatalf("at %d: %v/%s expected %v/%s", tc.now, got, reason, tc.budget, tc.reason)
		}
	}
	r.Supervised.RecoveryDeadlineMS = 200000
	if budget, reason := supervisedReconnectBudget(r, 100200); reason != "" || budget != 18*time.Second {
		t.Fatal("start command escaped 18s cap")
	}
	if budget, reason := supervisedReconnectBudget(r, 135099); reason != "" || budget != time.Millisecond {
		t.Fatal("start budget ignored nearest supervisor lease")
	}
	if _, reason := supervisedReconnectBudget(r, 135100); reason != "supervisor_lease_expired" {
		t.Fatal("expired lease was renewed")
	}
	if _, reason := supervisedReconnectBudget(r, 100099); reason != "supervisor_lease_expired" {
		t.Fatal("clock reversal granted new start authority")
	}
}

func TestSupervisedExpiredUndispatchedStartRetainsKnownStoppedReceipt(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, DefaultCore, DefaultPort)
	r := supervisedExample(t, true)
	r.Supervised.State = "reconnecting"
	r.Supervised.ReconnectStage = "start_requested"
	r.Supervised.Attempts = 1
	r.Supervised.RecoveryDeadlineMS = 110000
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeSmartTUNTrialLocked(store, r, nil); err != nil {
			return err
		}
		err := abandonUnstartedSupervisedCore(store, &r, "recovery_deadline_expired")
		if ErrorCode(err) != "recovery_deadline_expired" {
			t.Fatalf("no-dispatch expiry lost its reason: %v", err)
		}
		found, _, err := loadSmartTUNTrialLocked(store)
		if err != nil {
			return err
		}
		if found.Supervised.ReconnectStage != "stopped" || !found.Native.StartupVerified || found.Supervised.HeartbeatMS != 100100 {
			t.Fatal("known unstarted core became uncertain or lease was renewed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSupervisedVerifiedAttachRemainsDurableWithoutLateLeaseRenewal(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, DefaultCore, DefaultPort)
	r := supervisedExample(t, true)
	r.Supervised.State = "reconnecting"
	r.Supervised.ReconnectStage = "start_requested"
	r.Supervised.Attempts = 1
	r.Supervised.RecoveryDeadlineMS = 110000
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeSmartTUNTrialLocked(store, r, nil); err != nil {
			return err
		}
		if err := recordSupervisedVerifiedAttach(store, &r, 101, 30); err != nil {
			return err
		}
		if _, reason := supervisedReconnectBudget(r, 110000); reason != "recovery_deadline_expired" {
			t.Fatal("verified attach extended expired recovery authority")
		}
		found, _, err := loadSmartTUNTrialLocked(store)
		if err != nil {
			return err
		}
		if found.Supervised.ReconnectStage != "none" || found.Supervised.CorePID != 101 || found.Supervised.CoreStartTicks != 30 || found.Supervised.HeartbeatMS != 100100 || found.Supervised.LeaseDeadlineMS != 135100 || found.Supervised.LastProbeMS != 100100 || found.Supervised.State != "degraded" {
			t.Fatal("positive attach receipt was lost or promoted to fresh healthy authority")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
