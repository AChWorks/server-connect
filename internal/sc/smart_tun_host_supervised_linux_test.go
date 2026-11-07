//go:build linux

package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"syscall"
	"testing"
)

func hostSupervisorExample(t *testing.T, active bool) hostRouteJournal {
	t.Helper()
	r := hostRouteExample(t)
	r.Intent = hostRouteSupervisedIntent
	r.Supervision = hostRouteSupervision{
		Generation: 1, State: "initializing", ManagementPeer: "10.20.0.1",
		Options:     SmartTUNHealthOptions{IntervalSeconds: 15, FailureThreshold: 2, MaxAttempts: 3, RecoverySeconds: 120},
		HeartbeatMS: 20000, LeaseDeadlineMS: 20000 + smartTUNHealthLeaseMS, ReconnectStage: "none",
	}
	for i := range r.Supervision.Roles {
		r.Supervision.Roles[i] = smartTUNHealthUnitIdentity{UnitDev: 1, UnitIno: uint64(i + 2), DigestDev: 1, DigestIno: uint64(i + 4), SHA256: strings.Repeat("c", 64)}
	}
	p := hostHealthPlanFixture(false)
	p.OperationID, p.BootID, p.ConfigSHA256 = r.Progress.Ingress.OperationID, r.Progress.Ingress.BootID, r.Core.ConfigSHA256
	p.TunnelInterface, p.UnderlayInterface, p.EndpointIP = r.TunnelInterface, r.Progress.Ingress.Underlay, r.Core.PinnedEndpoint
	p.Domestic = HostHealthTraceTarget{}
	r.Supervision.Plans = [2]HostHealthPlan{p, p}
	r.Supervision.Plans[1].IPv4.Trace = HostHealthTraceTarget{Address: "1.0.0.1", Port: 443, ServerName: "cloudflare.com", Path: "/cdn-cgi/trace"}
	if active {
		r.Route.State = "observed"
		r.Core.Stage, r.Core.StartAttempted = "active_observed", true
		r.Native.StartupVerified = true
		for _, kind := range []string{"rule", "route", "fallback"} {
			*nativeTUNResource(&r.Native, 4, kind) = smartTUNNativeObject{Stage: "observed", SHA256: strings.Repeat("b", 64)}
		}
		r.Native.NFT = smartTUNNativeObject{Stage: "observed", SHA256: strings.Repeat("b", 64)}
		r.Native.NFTHandle = 100
		objects := nativeNFTObjects(r.nativeView())
		r.Native.NFTCount = len(objects)
		for i, obj := range objects {
			for kind, value := range obj {
				fields := value.(map[string]any)
				name, _ := fields["name"].(string)
				if kind == "rule" {
					name, _ = fields["chain"].(string)
				}
				digest, err := nativeNFTObjectHash([]map[string]any{obj}, true)
				if err != nil {
					t.Fatal(err)
				}
				r.Native.NFTObjects[i] = smartTUNNativeNFTIdentity{Kind: kind, Name: name, Handle: uint64(100 + i), SHA256: digest}
			}
		}
		r.Supervision.State = "awaiting_confirmation"
		r.Supervision.ReadyAfterMS = 10000
		r.Supervision.CorePID, r.Supervision.CoreStartTicks = 77, 88
		r.Supervision.ChallengeSHA256 = hostRouteChallengeDigest(r, strings.Repeat("d", 64))
	}
	if err := validateHostRouteJournal(r); err != nil {
		t.Fatalf("supervisor fixture: %v", err)
	}
	return r
}

func hostSupervisorEvidence(r hostRouteJournal, now int64, alter func(int, hostHealthProbe) HostHealthResult) [2]HostHealthEvidence {
	var results [2]HostHealthEvidence
	for i, p := range hostRouteHealthPlans(r, r.Supervision.Rounds+1) {
		var samples []hostHealthSample
		for _, probe := range hostHealthProbes(p) {
			response := HostHealthResult{Result: "pass"}
			if probe.role != "dns" && probe.role != "endpoint" {
				response.HTTPStatus, response.ObservedIP = 200, probe.expected
			}
			if alter != nil {
				response = alter(i, probe)
			}
			samples = append(samples, hostHealthSample{probe: probe, result: response})
		}
		results[i] = summarizeHostHealth(p, samples, false)
		results[i].StartedUptimeMS, results[i].CompletedUptimeMS, results[i].ElapsedMS = now-20, now-10, 10
	}
	return results
}
func hostSupervisorPassingResult(p hostHealthProbe) HostHealthResult {
	r := HostHealthResult{Result: "pass"}
	if p.role != "dns" && p.role != "endpoint" {
		r.HTTPStatus, r.ObservedIP = 200, p.expected
	}
	return r
}
func hostSupervisorConfirmed(t *testing.T) hostRouteJournal {
	t.Helper()
	r := hostSupervisorExample(t, true)
	next, action, err := advanceHostRouteHealth(r, hostSupervisorEvidence(r, 21000, nil), 21000)
	if err != nil || action != "" {
		t.Fatalf("health before confirmation: %v %s", err, action)
	}
	next.Supervision.Confirmed, next.Supervision.ChallengeSHA256, next.Supervision.State = true, "", "healthy"
	next.Supervision.SessionSHA256, next.Supervision.SessionStartedMS = strings.Repeat("e", 64), 12000
	if err := validateHostRouteJournal(next); err != nil {
		t.Fatal(err)
	}
	return next
}

func TestHostSupervisorStrictIntentAndNestedSchema(t *testing.T) {
	for _, active := range []bool{false, true} {
		r := hostSupervisorExample(t, active)
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeHostRouteJournal(raw)
		if err != nil || decoded != r {
			t.Fatalf("supervised v9 roundtrip: %v", err)
		}
		for name, changed := range map[string]string{
			"duplicate supervisor":          strings.Replace(string(raw), "\"supervision\":{", "\"supervision\":{},\"supervision\":{", 1),
			"null supervisor":               strings.Replace(string(raw), "\"supervision\":{", "\"supervision\":null,\"ignored\":{", 1),
			"unknown supervisor":            strings.Replace(string(raw), "\"supervision\":{", "\"supervision\":{\"extra\":1,", 1),
			"aliased generation":            strings.Replace(string(raw), "\"generation\":1", "\"Generation\":1", 1),
			"null option":                   strings.Replace(string(raw), "\"interval_seconds\":15", "\"interval_seconds\":null", 1),
			"plan option":                   strings.Replace(string(raw), "\"expected_vpn_ip\":", "\"unknown\":true,\"expected_vpn_ip\":", 1),
			"plan duplicate":                strings.Replace(string(raw), "\"expected_vpn_ip\":", "\"expected_vpn_ip\":\"9.9.9.9\",\"expected_vpn_ip\":", 1),
			"evidence alias":                strings.Replace(string(raw), "\"elapsed_ms\":0", "\"Elapsed_ms\":0", 1),
			"result null":                   strings.Replace(string(raw), "\"http_status\":0", "\"http_status\":null", 1),
			"trailing":                      string(raw) + " {}",
			"legacy intent with supervisor": strings.Replace(string(raw), hostRouteSupervisedIntent, hostRouteJournalIntent, 1),
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := decodeHostRouteJournal([]byte(changed)); err == nil {
					t.Fatal("ambiguous/unsupported supervisor accepted")
				}
			})
		}
	}
	legacy := hostRouteExample(t)
	raw, _ := json.Marshal(legacy)
	if bytes.Contains(raw, []byte("\"supervision\"")) {
		t.Fatal("legacy v9 shape changed")
	}
	if restored, err := decodeHostRouteJournal(raw); err != nil || restored != legacy {
		t.Fatal("legacy v9 no longer recoverable")
	}
}

func TestHostSupervisorRejectsCrossOperationAndInventedAuthority(t *testing.T) {
	for name, change := range map[string]func(*hostRouteJournal){
		"plan operation":               func(r *hostRouteJournal) { r.Supervision.Plans[0].OperationID = strings.Repeat("b", 32) },
		"plan boot":                    func(r *hostRouteJournal) { r.Supervision.Plans[0].BootID = "22222222-2222-3333-4444-555555555555" },
		"plan config":                  func(r *hostRouteJournal) { r.Supervision.Plans[0].ConfigSHA256 = strings.Repeat("b", 64) },
		"plan endpoint":                func(r *hostRouteJournal) { r.Supervision.Plans[0].EndpointIP = "9.9.9.10" },
		"same trace":                   func(r *hostRouteJournal) { r.Supervision.Plans[1].IPv4.Trace = r.Supervision.Plans[0].IPv4.Trace },
		"unprotected ipv6":             func(r *hostRouteJournal) { r.Supervision.Plans[1].IPv6 = hostHealthPlanFixture(true).IPv6 },
		"role hash":                    func(r *hostRouteJournal) { r.Supervision.Roles[0].SHA256 = "bad" },
		"management special":           func(r *hostRouteJournal) { r.Supervision.ManagementPeer = "127.0.0.1" },
		"bad lease":                    func(r *hostRouteJournal) { r.Supervision.LeaseDeadlineMS++ },
		"deadline overflow":            func(r *hostRouteJournal) { r.Progress.Ingress.Deadline = 1 << 62 },
		"fake confirmed":               func(r *hostRouteJournal) { r.Supervision.Confirmed = true },
		"healthy without confirmation": func(r *hostRouteJournal) { r.Supervision.State = "healthy" },
		"unknown reason":               func(r *hostRouteJournal) { r.Supervision.Reason = "arbitrary-secret" },
		"fake round":                   func(r *hostRouteJournal) { r.Supervision.Rounds = 1 },
		"expired readiness":            func(r *hostRouteJournal) { r.Supervision.ReadyAfterMS = r.Progress.Ingress.Deadline * 1000 },
		"restart without budget": func(r *hostRouteJournal) {
			r.Supervision.ReconnectStage = "start_requested"
			r.Supervision.State = "reconnecting"
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := hostSupervisorExample(t, true)
			change(&r)
			if validateHostRouteJournal(r) == nil {
				t.Fatal("invented host authority accepted")
			}
		})
	}
}

func TestHostSupervisorTwoWitnessesAndFatalWrongPath(t *testing.T) {
	base := hostSupervisorExample(t, true)
	for _, badIndex := range []int{0, 1} {
		e := hostSupervisorEvidence(base, 21000, func(i int, p hostHealthProbe) HostHealthResult {
			if i == badIndex && (p.role == "selected" || p.role == "direct") {
				return HostHealthResult{Result: "http_status", HTTPStatus: 503}
			}
			return hostSupervisorPassingResult(p)
		})
		next, action, err := advanceHostRouteHealth(base, e, 21000)
		if err != nil || action != "" || next.Supervision.Reason != "selected_path_healthy" {
			t.Fatalf("one trace outage became VPN outage: %v %s", err, action)
		}
		e = hostSupervisorEvidence(base, 21000, func(i int, p hostHealthProbe) HostHealthResult {
			if i == badIndex && p.role == "selected" {
				return HostHealthResult{Result: "path_mismatch", HTTPStatus: 200, ObservedIP: "8.8.8.8"}
			}
			return hostSupervisorPassingResult(p)
		})
		next, action, err = advanceHostRouteHealth(base, e, 21000)
		if err != nil || action != "stop" || next.Supervision.Reason != "path_mismatch" {
			t.Fatalf("secondary success hid wrong path: %v %s", err, action)
		}
	}
}

func TestHostSupervisorRejectsStaleOrForgedMeasurementBeforeRenewal(t *testing.T) {
	r := hostSupervisorExample(t, true)
	for name, change := range map[string]func(*[2]HostHealthEvidence){
		"old round":            func(e *[2]HostHealthEvidence) { e[0].Round = 0 },
		"other configuration":  func(e *[2]HostHealthEvidence) { e[0].ConfigSHA256 = strings.Repeat("f", 64) },
		"older than heartbeat": func(e *[2]HostHealthEvidence) { e[0].StartedUptimeMS = 19000 },
		"future completion":    func(e *[2]HostHealthEvidence) { e[0].CompletedUptimeMS = 22000 },
		"no completion":        func(e *[2]HostHealthEvidence) { e[0].CompletedUptimeMS = 0 },
		"excessive elapsed":    func(e *[2]HostHealthEvidence) { e[0].ElapsedMS = 10000 },
		"invented dns":         func(e *[2]HostHealthEvidence) { e[0].IPv4.DNS = "not_run" },
		"mismatched exit":      func(e *[2]HostHealthEvidence) { e[0].IPv4.SelectedHTTPS.ObservedIP = "8.8.8.8" },
	} {
		t.Run(name, func(t *testing.T) {
			e := hostSupervisorEvidence(r, 21000, nil)
			change(&e)
			next, _, err := advanceHostRouteHealth(r, e, 21000)
			if err == nil || next != r {
				t.Fatal("invalid result changed lease or evidence")
			}
		})
	}
	if _, _, err := advanceHostRouteHealth(r, hostSupervisorEvidence(r, 21000, nil), 27000); err == nil {
		t.Fatal("aged completed result renewed lease")
	}
}

func TestHostSupervisorFiniteFailuresRecoveryAndFlappingBudget(t *testing.T) {
	r := hostSupervisorConfirmed(t)
	fail := func(_ int, p hostHealthProbe) HostHealthResult {
		if p.role == "selected" {
			return HostHealthResult{Result: "timeout"}
		}
		return hostSupervisorPassingResult(p)
	}
	next, action, err := advanceHostRouteHealth(r, hostSupervisorEvidence(r, 22000, fail), 22000)
	if err != nil || action != "" || next.Supervision.Failures != 1 {
		t.Fatalf("first outage %v %s", err, action)
	}
	r = next
	next, action, err = advanceHostRouteHealth(r, hostSupervisorEvidence(r, 23000, fail), 23000)
	if err != nil || action != "reconnect" || next.Supervision.RecoveryDeadlineMS != 143000 {
		t.Fatalf("bounded incident %v %s", err, action)
	}
	// A later good round may clear the incident deadline, but cannot refund
	// already consumed attempts into an unbounded flapping retry loop.
	next.Supervision.Attempts = next.Supervision.Options.MaxAttempts
	r = next
	next, action, err = advanceHostRouteHealth(r, hostSupervisorEvidence(r, 24000, nil), 24000)
	if err != nil || action != "" || next.Supervision.Attempts != 3 || next.Supervision.RecoveryDeadlineMS != 0 {
		t.Fatalf("flap reset budget: %v %s", err, action)
	}
	r = next
	r, _, err = advanceHostRouteHealth(r, hostSupervisorEvidence(r, 25000, fail), 25000)
	if err != nil {
		t.Fatal(err)
	}
	next, action, err = advanceHostRouteHealth(r, hostSupervisorEvidence(r, 26000, fail), 26000)
	if err != nil || action != "stop" || next.Supervision.Reason != "reconnect_exhausted" {
		t.Fatalf("exhausted retry resumed: %v %s", err, action)
	}
	if err := validateHostRouteJournal(next); err != nil {
		t.Fatal(err)
	}
	pending := hostSupervisorExample(t, true)
	pending.Supervision.Options.FailureThreshold = 1
	next, action, err = advanceHostRouteHealth(pending, hostSupervisorEvidence(pending, 21000, fail), 21000)
	if err != nil || action != "stop" || next.Supervision.Reason != "unconfirmed_path_failed" {
		t.Fatalf("unconfirmed outage reconnected: %v %s", err, action)
	}
}

func TestHostSupervisorChallengeFreshnessAndIndependentLease(t *testing.T) {
	r := hostSupervisorExample(t, true)
	op, challenge, boot := r.Progress.Ingress.OperationID, strings.Repeat("d", 64), r.Progress.Ingress.BootID
	if !hostRouteConfirmMatches(r, op, challenge, boot, 21000) {
		t.Fatal("valid challenge refused")
	}
	for _, test := range []struct {
		op, challenge, boot string
		now                 int64
	}{
		{strings.Repeat("b", 32), challenge, boot, 21000},
		{op, strings.Repeat("e", 64), boot, 21000},
		{op, challenge, "22222222-2222-3333-4444-555555555555", 21000},
		{op, challenge, boot, r.Supervision.ReadyAfterMS},
		{op, challenge, boot, r.Supervision.LeaseDeadlineMS},
		{op, challenge, boot, r.Progress.Ingress.Deadline * 1000},
	} {
		if hostRouteConfirmMatches(r, test.op, test.challenge, test.boot, test.now) {
			t.Fatal("stale/replayed authority accepted")
		}
	}
	r = hostSupervisorConfirmed(t)
	if hostRouteConfirmMatches(r, op, challenge, boot, 22000) {
		t.Fatal("consumed challenge replayed")
	}
	for name, test := range map[string]struct {
		boot   string
		now    int64
		reason string
	}{
		"boot changed":   {"22222222-2222-3333-4444-555555555555", 22000, "boot_changed"},
		"clock rollback": {boot, 20000, "supervisor_lease_expired"},
		"dead executor":  {boot, r.Supervision.LeaseDeadlineMS, "supervisor_lease_expired"},
	} {
		t.Run(name, func(t *testing.T) {
			if reason := hostRouteRuntimeDeadline(r, test.boot, test.now); reason != test.reason {
				t.Fatalf("%s", reason)
			}
		})
	}
	r.Progress.Ingress.Deadline = 21
	if reason := hostRouteRuntimeDeadline(r, boot, 22000); reason != "" {
		t.Fatal("confirmed state treated as a renewed preparation deadline")
	}
	r.Supervision.State, r.Supervision.ReconnectStage = "reconnecting", "stop_requested"
	r.Supervision.Attempts, r.Supervision.RecoveryDeadlineMS = 1, 50000
	if reason := hostRouteRuntimeDeadline(r, boot, 22000); reason != "reconnect_interrupted" {
		t.Fatalf("interrupted restart survived: %s", reason)
	}
}

func TestHostSupervisorFullParentCASAndNoLegacyPromotion(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	r := hostSupervisorExample(t, true)
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostRouteJournal(store, r, nil); err != nil {
			return err
		}
		selected, err := selectTrialRecoveryLocked(store, "", "")
		if err != nil || selected.version != 9 || selected.hostRoute != r {
			return errors.New("installed selector lost supervised parent")
		}
		before := r
		next := r
		next.Supervision.Generation++
		next.Supervision.HeartbeatMS, next.Supervision.LeaseDeadlineMS = 21000, 21000+smartTUNHealthLeaseMS
		if err := persistHostRouteParent(store, &r, next); err != nil {
			return err
		}
		stale := before
		stale.Supervision.Generation++
		stale.Supervision.Reason = "selected_path_failed"
		if ErrorCode(persistHostRouteParent(store, &before, stale)) != "activation_journal_conflict" {
			return errors.New("stale health overwrote parent")
		}
		if err := hostRoutePhasePersist(store, &r, "off_pending"); err != nil {
			return err
		}
		if r.Supervision.State != "stopped" || r.Supervision.ReconnectStage != "none" || r.Native.StopReason != "guard" {
			return errors.New("Off did not retire lease atomically")
		}
		after, _, err := loadHostRouteJournal(store)
		if err != nil || after != r {
			return errors.New("Off lost complete parent")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy := hostRouteExample(t)
	m = New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostRouteJournal(store, legacy, nil); err != nil {
			return err
		}
		next := hostSupervisorExample(t, false)
		if ErrorCode(persistHostRouteParent(store, &legacy, next)) != "activation_journal_conflict" {
			return errors.New("legacy preparation acquired supervision")
		}
		stored, _, err := loadHostRouteJournal(store)
		if err != nil || stored != legacy {
			return errors.New("legacy record changed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHostSupervisorConfirmationRestartsOnlyForHealthyConcurrentRound(t *testing.T) {
	before := hostSupervisorExample(t, true)
	after, action, err := advanceHostRouteHealth(before, hostSupervisorEvidence(before, 21000, nil), 21000)
	if err != nil || action != "" || !hostRouteConfirmHealthOnlyRefresh(before, after) {
		t.Fatal("safe entire-confirmation restart refused")
	}
	for _, change := range []func(*hostRouteJournal){
		func(r *hostRouteJournal) { r.Supervision.ChallengeSHA256 = strings.Repeat("f", 64) },
		func(r *hostRouteJournal) { r.Supervision.CorePID++ },
		func(r *hostRouteJournal) { r.Supervision.Roles[0].UnitIno++ },
		func(r *hostRouteJournal) { r.Supervision.Attempts++ },
		func(r *hostRouteJournal) { r.Supervision.Options.MaxAttempts++ },
		func(r *hostRouteJournal) { r.Native.LinkIndex++ },
		func(r *hostRouteJournal) { r.Core.ConfigSHA256 = strings.Repeat("f", 64) },
		func(r *hostRouteJournal) { r.Supervision.Confirmed = true },
		func(r *hostRouteJournal) { r.Supervision.State = "degraded" },
	} {
		changed := after
		change(&changed)
		if hostRouteConfirmHealthOnlyRefresh(before, changed) {
			t.Fatal("unsafe change authorized stale confirmation retry")
		}
	}
}

func TestHostSupervisorTransitionsCannotRewritePlanConfirmationOrBudget(t *testing.T) {
	before := hostSupervisorConfirmed(t)
	for name, change := range map[string]func(*hostRouteJournal){
		"witness":             func(r *hostRouteJournal) { r.Supervision.Plans[0].IPv4.Trace.Path = "/other" },
		"role":                func(r *hostRouteJournal) { r.Supervision.Roles[0].UnitIno++ },
		"options":             func(r *hostRouteJournal) { r.Supervision.Options.MaxAttempts++ },
		"management":          func(r *hostRouteJournal) { r.Supervision.ManagementPeer = "10.20.0.3" },
		"reopen challenge":    func(r *hostRouteJournal) { r.Supervision.Confirmed = false },
		"replace session":     func(r *hostRouteJournal) { r.Supervision.SessionSHA256 = strings.Repeat("f", 64) },
		"replace readiness":   func(r *hostRouteJournal) { r.Supervision.ReadyAfterMS++ },
		"refund attempt":      func(r *hostRouteJournal) { r.Supervision.Attempts = -1 },
		"unreceipted attempt": func(r *hostRouteJournal) { r.Supervision.Attempts++ },
		"rewrite result":      func(r *hostRouteJournal) { r.Supervision.Evidence[0].Reason = "selected_path_failed" },
		"rollback clock":      func(r *hostRouteJournal) { r.Supervision.HeartbeatMS-- },
	} {
		t.Run(name, func(t *testing.T) {
			next := before
			next.Supervision.Generation++
			change(&next)
			if hostRouteSupervisionTransition(before, next) {
				t.Fatal("privileged authority changed without new operation")
			}
		})
	}
}

func TestHostSupervisorCredentialRequiresExactSelectedEndpointAndBytes(t *testing.T) {
	r := hostSupervisorExample(t, true)
	raw := []byte("{\"outbounds\":[{\"tag\":\"upstream\",\"type\":\"vless\",\"server\":\"8.8.8.8\",\"server_port\":443}]}")
	r.Core.ConfigSHA256 = sha256Hex(raw)
	if !hostRouteCredentialPlanMatches(raw, r) {
		t.Fatal("exact endpoint refused")
	}
	if hostRouteCredentialPlanMatches(append(raw, ' '), r) {
		t.Fatal("changed credential accepted")
	}
	r.Supervision.Plans[0].EndpointPort = 8443
	if hostRouteCredentialPlanMatches(raw, r) {
		t.Fatal("health endpoint differs from selected core")
	}
}

func TestHostSupervisorFreshConstructorCannotAdoptOrGuessAuthority(t *testing.T) {
	native, profile := hostNativeExample(), testHostCoreWSProfile()
	policy, err := compileHostCoreAttachConfig(profile, "8.8.8.8", native.Progress.Ingress.Underlay, native.TunnelInterface)
	if err != nil {
		t.Fatal(err)
	}
	a := hostCoreQAAdmission{Native: native, Profile: profile, Policy: policy}
	fixture := hostSupervisorExample(t, false).Supervision
	plans := fixture.Plans
	for i := range plans {
		plans[i].OperationID, plans[i].BootID, plans[i].ConfigSHA256 = native.Progress.Ingress.OperationID, native.Progress.Ingress.BootID, sha256Hex(policy)
	}
	construct := func(a hostCoreQAAdmission, plans [2]HostHealthPlan, boot string, now int64) (hostRouteJournal, error) {
		return newHostRouteSupervisorPlan(a, fixture.ManagementPeer, plans, fixture.Options, fixture.Roles, boot, now)
	}
	r, err := construct(a, plans, native.Progress.Ingress.BootID, 20000)
	if err != nil {
		t.Fatal(err)
	}
	if !hostRouteSupervised(r) || r.Route.State != "planned" || r.Core.StartAttempted || r.Core.Stage != "planned" ||
		r.Supervision.State != "initializing" || r.Supervision.ReadyAfterMS != 0 || r.Supervision.ChallengeSHA256 != "" || r.Supervision.Confirmed {
		t.Fatal("initialization invented effect/readiness/confirmation")
	}
	for name, change := range map[string]func(*hostCoreQAAdmission, *[2]HostHealthPlan){
		"adopt observed link": func(a *hostCoreQAAdmission, _ *[2]HostHealthPlan) { a.Native.Native.LinkStage = "observed" },
		"prior ingress effect": func(a *hostCoreQAAdmission, _ *[2]HostHealthPlan) {
			a.Native.Progress.Ingress.NFTStage = "effect_possible"
		},
		"changed compiled config": func(a *hostCoreQAAdmission, _ *[2]HostHealthPlan) {
			a.Policy = append(append([]byte(nil), a.Policy...), ' ')
		},
		"different profile":     func(a *hostCoreQAAdmission, _ *[2]HostHealthPlan) { a.Profile.Outbound = []byte(`{"type":"direct"}`) },
		"guessed endpoint port": func(_ *hostCoreQAAdmission, p *[2]HostHealthPlan) { p[0].EndpointPort = 8443; p[1].EndpointPort = 8443 },
		"unbounded preparation": func(a *hostCoreQAAdmission, _ *[2]HostHealthPlan) { a.Native.Progress.Ingress.Deadline = 1 << 62 },
		"foreign operation":     func(_ *hostCoreQAAdmission, p *[2]HostHealthPlan) { p[0].OperationID = strings.Repeat("e", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			bad, ps := a, plans
			change(&bad, &ps)
			if _, err := construct(bad, ps, native.Progress.Ingress.BootID, 20000); err == nil {
				t.Fatal("unproven initialization accepted")
			}
		})
	}
	for _, observation := range []struct {
		boot string
		now  int64
	}{
		{"22222222-2222-3333-4444-555555555555", 20000},
		{native.Progress.Ingress.BootID, 0},
		{native.Progress.Ingress.BootID, native.Progress.Ingress.Deadline * 1000},
	} {
		if _, err := construct(a, plans, observation.boot, observation.now); err == nil {
			t.Fatal("stale/unknown time authority accepted")
		}
	}
}

func TestHostSupervisorCanceledOrLateWitnessNeverGrantsHealth(t *testing.T) {
	r := hostSupervisorExample(t, true)
	plans := hostRouteHealthPlans(r, 1)
	for bad := 0; bad < 2; bad++ {
		for _, late := range []bool{false, true} {
			e := hostSupervisorEvidence(r, 21000, func(i int, p hostHealthProbe) HostHealthResult {
				if i != bad && p.role == "selected" {
					return HostHealthResult{Result: "timeout"}
				}
				return hostSupervisorPassingResult(p)
			})
			var samples []hostHealthSample
			for _, p := range hostHealthProbes(plans[bad]) {
				samples = append(samples, hostHealthSample{probe: p, result: hostSupervisorPassingResult(p)})
			}
			e[bad] = summarizeHostHealth(plans[bad], samples, true)
			e[bad].StartedUptimeMS, e[bad].CompletedUptimeMS, e[bad].ElapsedMS = 20980, 20990, 10
			if late {
				e[bad].ElapsedMS = 5000
			}
			if err := ValidateHostHealthEvidence(plans[bad], e[bad]); err != nil {
				t.Fatal(err)
			}
			if healthy, _ := hostRouteHealthSummary(plans, e); healthy {
				t.Fatal("canceled/late positive hid selected outage")
			}
			next, _, err := advanceHostRouteHealth(r, e, 21000)
			if err != nil || next.Supervision.Reason != "selected_path_failed" {
				t.Fatalf("cancellation handling %v %s", err, next.Supervision.Reason)
			}
			// A fatal authenticated wrong path remains fatal even when its
			// enclosing deadline expired and the other witness succeeded.
			e = hostSupervisorEvidence(r, 21000, func(i int, p hostHealthProbe) HostHealthResult {
				if i == bad && p.role == "selected" {
					return HostHealthResult{Result: "path_mismatch", HTTPStatus: 200, ObservedIP: "8.8.8.8"}
				}
				return hostSupervisorPassingResult(p)
			})
			e[bad].ElapsedMS = 5000
			if healthy, reason := hostRouteHealthSummary(plans, e); healthy || reason != "path_mismatch" {
				t.Fatal("late fatal path was suppressed")
			}
		}
	}
}

func TestHostSupervisorHealthDispatchDistinguishesAbsenceAndLegacy(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	if version, found, err := m.hostRouteHealthDispatch(); err != nil || version != 0 || found {
		t.Fatalf("absent dispatch %d %t %v", version, found, err)
	}
	for _, supervised := range []bool{false, true} {
		m = New(privateJournalTempDir(t), DefaultCore, DefaultPort)
		r := hostRouteExample(t)
		if supervised {
			r = hostSupervisorExample(t, false)
		}
		if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error { return writeHostRouteJournal(store, r, nil) }); err != nil {
			t.Fatal(err)
		}
		version, found, err := m.hostRouteHealthDispatch()
		if err != nil || version != 9 || found != supervised {
			t.Fatalf("explicit intent dispatch %d %t %v", version, found, err)
		}
	}
}

func TestHostSupervisorReconnectCannotStartBeyondFiniteBudget(t *testing.T) {
	r := hostSupervisorConfirmed(t)
	r.Supervision.Attempts = r.Supervision.Options.MaxAttempts
	if ErrorCode(reconnectHostRouteCore(nil, &r)) != "trial_recovery_uncertain" {
		t.Fatal("exhausted reconnect reached installed effects")
	}
	if ErrorCode(reconnectHostRouteCore(nil, nil)) != "trial_recovery_uncertain" {
		t.Fatal("absent reconnect authority reached installed effects")
	}
}

func TestHostSupervisorPendingExpiryAndReceiptNeverInventDirect(t *testing.T) {
	r := hostSupervisorExample(t, true)
	if reason := hostRouteRuntimeDeadline(r, r.Progress.Ingress.BootID, r.Progress.Ingress.Deadline*1000); reason != "activation_expired" {
		t.Fatalf("pending operation survived deadline: %s", reason)
	}
	r = hostSupervisorConfirmed(t)
	if hostRouteSupervisionReceipt(r).IPv4SelectedVerified {
		t.Fatal("historical journal alone claimed a current path")
	}
	if !hostRouteCurrentReceipt(r, r.Supervision.HeartbeatMS).IPv4SelectedVerified {
		t.Fatal("fresh independently checked paths lost positive evidence")
	}
	if hostRouteCurrentReceipt(r, r.Supervision.LastProbeMS+31000).IPv4SelectedVerified {
		t.Fatal("stale path evidence advertised")
	}
	r.Route.State, r.Supervision.State, r.Native.StopReason = "off_pending", "stopped", "guard"
	if hostRouteCurrentReceipt(r, r.Supervision.HeartbeatMS).IPv4SelectedVerified {
		t.Fatal("stopped operation advertised selected traffic")
	}
}

func TestHostSupervisorStoredRoundCannotForgeFreshness(t *testing.T) {
	for name, change := range map[string]func(*hostRouteJournal){
		"invent later completion": func(r *hostRouteJournal) { r.Supervision.LastProbeMS++ },
		"no completion":           func(r *hostRouteJournal) { r.Supervision.Evidence[1].CompletedUptimeMS = 0 },
		"before readiness":        func(r *hostRouteJournal) { r.Supervision.Evidence[1].StartedUptimeMS = r.Supervision.ReadyAfterMS - 1 },
	} {
		t.Run(name, func(t *testing.T) {
			r := hostSupervisorConfirmed(t)
			change(&r)
			if validateHostRouteJournal(r) == nil {
				t.Fatal("forged stored round freshness accepted")
			}
		})
	}
}
