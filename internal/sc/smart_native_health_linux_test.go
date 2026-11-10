//go:build linux

package sc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nativeHealthTestState() NativeHealthState {
	return NativeHealthState{Version: 1, OperationID: strings.Repeat("a", 32), ConfigSHA256: strings.Repeat("b", 64), BootID: "11111111-1111-4111-8111-111111111111", StartedMS: 1000, HeartbeatMS: 1000, FailureThreshold: 3, Phase: "starting", Reason: "awaiting_selected_probe", ProbeScope: "synthetic_https"}
}
func TestNativeSelectedProofCannotOutliveCoreOrMode(t *testing.T) {
	h := nativeHealthTestState()
	h.Phase = "healthy"
	h.ProbeScope = "synthetic_https"
	h.LastProbeMS = 21000
	cases := []struct {
		name, desired, observed string
		now                     int64
		want                    string
	}{
		{"valid", "smart", "active", 22000, "recent_synthetic_https"},
		{"core-stopped", "smart", "inactive", 22000, "not_run"},
		{"core-failed", "smart", "failed", 22000, "not_run"},
		{"saved-direct", "direct", "active", 22000, "not_run"},
		{"expired", "smart", "active", 21000 + nativeHealthLeaseMS + 1, "not_run"},
		{"clock-rewind", "smart", "active", 20000, "not_run"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeSelectedHTTPSProof(h, tc.desired, tc.observed, tc.now); got != tc.want {
				t.Fatalf("proof got %q want %q", got, tc.want)
			}
		})
	}
	h.Phase = "degraded"
	if got := nativeSelectedHTTPSProof(h, "smart", "active", 22000); got != "not_run" {
		t.Fatal("degraded path inherited stale proof")
	}
}

func TestNativeStartupGraceOnlyBeforeCoreActivity(t *testing.T) {
	scenarios := []struct {
		name, phase                string
		elapsed                    int64
		activity                   string
		uncertain, resampled, want bool
	}{
		{"prearmed-inactive", "starting", 0, "inactive", false, false, true},
		{"inconclusive-then-activating", "starting", 0, "unknown", true, true, true},
		{"inconclusive-then-active", "starting", 1000, "unknown", true, true, true},
		{"active-first-read", "starting", 0, "active", false, true, false},
		{"active-at-12secs", "starting", 12000, "active", false, true, false},
		{"failed-core", "starting", 1000, "failed", false, false, false},
		{"unknown-not-confirmed", "starting", 1000, "unknown", true, false, false},
		{"past-grace", "starting", nativeHealthGraceMS, "inactive", false, false, false},
		{"negative-time", "starting", -1, "inactive", false, false, false},
		{"healthy-not-startup", "healthy", 0, "inactive", false, false, false},
		{"degraded-not-startup", "degraded", 0, "inactive", false, false, false},
	}
	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			got := nativeStartupGraceDecision(tc.phase, tc.elapsed, tc.activity, tc.uncertain, tc.resampled)
			if got != tc.want {
				t.Fatalf("startup grace got %t, want %t", got, tc.want)
			}
		})
	}
}

func TestNativeStartupTransitionCannotFalseStopOnActiveResample(t *testing.T) {
	for _, state := range []string{"activating", "active"} {
		if !nativeStartupTransientState(state) {
			t.Fatalf("first unknown then %s must honor bounded startup grace", state)
		}
	}
	for _, state := range []string{"", "failed", "inactive", "deactivating", "unknown"} {
		if nativeStartupTransientState(state) {
			t.Fatalf("unverified core state %q was allowed as startup transition", state)
		}
	}
}

func TestNativeHealthInvalidPolicyRejectedBeforePrivilegedAdmission(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "health-admission")
	m := New(dir, "", 0)
	for _, n := range []int{-1, 11, 100} {
		_, err := m.ConnectNativeSmartRouting(NativePolicyOptions{HealthFailureThreshold: n})
		if ErrorCode(err) != "invalid_arguments" {
			t.Fatalf("invalid threshold %d got %v", n, err)
		}
		if _, e := os.Stat(dir); !os.IsNotExist(e) {
			t.Fatalf("invalid threshold %d touched private host state: %v", n, e)
		}
	}
}

func TestNativeHealthSustainedAndFlappingFailureBound(t *testing.T) {
	s := nativeHealthTestState()
	negative := nativeHealthOutcome{Reason: "selected_tcp_unreachable"}
	var stop bool
	s, stop = nativeHealthAdvance(s, negative, 2000)
	if stop || s.Phase != "starting" || s.Failures != 0 {
		t.Fatalf("unexpected startup phase: %+v", s)
	}
	for i := 0; i < 2; i++ {
		s, stop = nativeHealthAdvance(s, negative, 21000+int64(i)*1000)
		if stop || s.Phase != "degraded" {
			t.Fatalf("early stop: %+v", s)
		}
	}
	s, stop = nativeHealthAdvance(s, nativeHealthOutcome{OK: true}, 24000)
	if stop || s.Failures != 0 || s.UnhealthyRounds != 2 || s.Phase != "healthy" {
		t.Fatalf("recovery erased budget: %+v", s)
	}
	for i := 0; i < 6; i++ {
		s, stop = nativeHealthAdvance(s, negative, 25000+int64(i)*2000)
		if (i == 2) != stop {
			if i != 2 {
				break
			}
			t.Fatalf("failed to stop on sustained outage: %+v", s)
		}
		if stop {
			break
		}
	}
	if !stop || s.Phase != "stopping" || s.Failures != 3 {
		t.Fatalf("sustained exhaustion not detected: %+v", s)
	}
	s = nativeHealthTestState()
	s.Phase = "healthy"
	for i := 0; i < 8; i++ {
		s, stop = nativeHealthAdvance(s, negative, 22000+int64(i)*2000)
		if stop {
			t.Fatalf("stopped before cumulative budget: %+v", s)
		}
		s, stop = nativeHealthAdvance(s, nativeHealthOutcome{OK: true}, 23000+int64(i)*2000)
		if stop || s.UnhealthyRounds != i+1 {
			t.Fatalf("flap incorrectly replenished budget: %+v", s)
		}
	}
	s, stop = nativeHealthAdvance(s, negative, 40000)
	if !stop || s.UnhealthyRounds != 9 {
		t.Fatalf("unlimited flapping admitted: %+v", s)
	}
}
func TestNativeHealthTargetsExcludeDirectIPRules(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		scope string
		want  int
		fail  bool
	}{
		{`{"route":{"final":"upstream","rules":[]}}`, "internet_https", 2, false},
		{`{"route":{"final":"upstream","rules":[{"ip_cidr":["1.0.0.0/8"],"outbound":"direct"}]}}`, "internet_https", 1, false},
		{`{"route":{"final":"upstream","rules":[{"ip_cidr":["0.0.0.0/0"],"outbound":"direct"}]}}`, "internet_https", 0, true},
		{`{"route":{"final":"direct","rules":[]}}`, "synthetic_https", 0, true},
		{`{"route":{"final":"upstream","rules":[{"ip_cidr":["invalid"],"outbound":"direct"}]}}`, "synthetic_https", 0, true},
	} {
		got, err := nativeHealthTargets([]byte(tc.raw), tc.scope)
		if len(got) != tc.want || (err != nil) != tc.fail {
			t.Fatalf("scope=%s policy=%s targets=%v err=%v", tc.scope, tc.raw, got, err)
		}
	}
}
func TestNativeHealthStrictReceiptAndIdleDispatch(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "state"), "", 0)
	if e := m.prepare(); e != nil {
		t.Fatal(e)
	}
	if mode, e := m.NativeHealthGuardMode(); e != nil || mode != "legacy" {
		t.Fatalf("absent journal: %s %v", mode, e)
	}
	s := nativeHealthTestState()
	s.Phase = "off"
	if e := m.saveNativeHealth(s); e != nil {
		t.Fatal(e)
	}
	if got, e := m.readNativeHealth(); e != nil || got != s {
		t.Fatalf("roundtrip: %+v %v", got, e)
	}
	if mode, e := m.NativeHealthGuardMode(); e != nil || mode != "native_off" {
		t.Fatalf("off dispatch %q %v", mode, e)
	}
	base, _ := json.Marshal(s)
	for _, raw := range []string{
		string(base) + "{}",
		strings.Replace(string(base), `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(string(base), `"failure_threshold":3`, `"failure_threshold":99`, 1),
		strings.Replace(string(base), `"phase":"off"`, `"phase":"unknown"`, 1),
	} {
		if e := put(filepath.Join(m.Dir, nativeHealthFile), []byte(raw)); e != nil {
			t.Fatal(e)
		}
		if _, e := m.readNativeHealth(); e == nil {
			t.Fatalf("invalid receipt admitted: %s", raw)
		}
	}
	if e := put(filepath.Join(m.Dir, nativeHealthFile), base); e != nil {
		t.Fatal(e)
	}
	if e := put(filepath.Join(m.Dir, nativeSessionFile), []byte("not-a-valid-session")); e != nil {
		t.Fatal(e)
	}
	if _, e := m.NativeHealthGuardMode(); e == nil {
		t.Fatal("untrusted native claim silently selected")
	}
	if e := os.Remove(filepath.Join(m.Dir, nativeSessionFile)); e != nil {
		t.Fatal(e)
	}
}
func TestNativeHealthRoundIdentityIsFullStateValue(t *testing.T) {
	previous := nativeHealthTestState()
	changed := previous
	for _, mutation := range []func(*NativeHealthState){
		func(s *NativeHealthState) { s.Rounds++ },
		func(s *NativeHealthState) { s.Failures++ },
		func(s *NativeHealthState) { s.UnhealthyRounds++ },
		func(s *NativeHealthState) { s.HeartbeatMS++ },
		func(s *NativeHealthState) { s.Phase = "degraded" },
		func(s *NativeHealthState) { s.Reason = "selected_tcp_unreachable" },
		func(s *NativeHealthState) { s.OperationID = strings.Repeat("c", 32) },
	} {
		changed = previous
		mutation(&changed)
		if changed == previous {
			t.Fatal("health publication did not detect a superseding round")
		}
	}
}

func TestNativeHealthProbeAggregationAndCanceledRound(t *testing.T) {
	targets := []nativeProbeTarget{{"1.0.0.1", "a", 443}, {"8.8.8.8", "b", 443}}
	healthy := runNativeHealthProbes(context.Background(), "sctun0", "synthetic_https", targets, func(_ context.Context, iface string, t nativeProbeTarget, synthetic bool) nativeHealthOutcome {
		if iface != "sctun0" || !synthetic {
			return nativeHealthOutcome{Reason: "incorrect_probe_scope"}
		}
		return nativeHealthOutcome{OK: t.IP == "1.0.0.1", Reason: "selected_https_verified"}
	})
	if !healthy.OK {
		t.Fatalf("one of two selected targets must suffice: %+v", healthy)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := runNativeHealthProbes(ctx, "sctun0", "internet_https", targets, func(_ context.Context, _ string, _ nativeProbeTarget, _ bool) nativeHealthOutcome {
		return nativeHealthOutcome{OK: true}
	})
	if canceled.OK {
		t.Fatalf("canceled health round accepted: %+v", canceled)
	}
	// A real dialer obeys the round deadline; no blocking goroutine is left in
	// this mock because all probes explicitly obey cancellation.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	deadline := runNativeHealthProbes(ctx2, "sctun0", "internet_https", targets, func(ctx context.Context, _ string, _ nativeProbeTarget, _ bool) nativeHealthOutcome {
		<-ctx.Done()
		return nativeHealthOutcome{Reason: "canceled"}
	})
	if deadline.OK {
		t.Fatalf("timed-out round accepted: %+v", deadline)
	}
}

// A healthy selected endpoint must not inherit the other endpoint's timeout.
func TestNativeHealthProbeFastPositiveDoesNotWaitForSlowPeer(t *testing.T) {
	targets := []nativeProbeTarget{{"1.0.0.1", "good", 443}, {"8.8.8.8", "slow", 443}}
	start := time.Now()
	result := runNativeHealthProbes(context.Background(), "sctun0", "synthetic_https", targets,
		func(ctx context.Context, _ string, target nativeProbeTarget, _ bool) nativeHealthOutcome {
			if target.IP == "1.0.0.1" {
				return nativeHealthOutcome{OK: true, Reason: "selected_https_verified"}
			}
			<-ctx.Done()
			return nativeHealthOutcome{Reason: "selected_tls_unavailable"}
		})
	if !result.OK || result.Reason != "selected_https_verified" {
		t.Fatalf("other endpoint erased valid selected-path evidence: %+v", result)
	}
	if time.Since(start) > time.Second {
		t.Fatal("positive selected-path probe waited for a stalled peer")
	}
}
func TestNativeHealthProbeCanceledRoundNeverAcceptsLatePositive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := runNativeHealthProbes(ctx, "sctun0", "synthetic_https",
		[]nativeProbeTarget{{"1.0.0.1", "a", 443}}, func(context.Context, string, nativeProbeTarget, bool) nativeHealthOutcome {
			return nativeHealthOutcome{OK: true, Reason: "selected_https_verified"}
		})
	if got.OK || got.Reason != "selected_probe_timeout" {
		t.Fatalf("canceled round accepted stale positive: %+v", got)
	}
}
func TestNativeGuardQuiescentWaitIsBounded(t *testing.T) {
	calls := 0
	err := awaitNativeGuardExecutors(time.Second, func() error {
		calls++
		if calls < 3 {
			return Fault("guard_unavailable", "old recovery oneshot still running")
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("settled executor rejected: calls=%d err=%v", calls, err)
	}
	start := time.Now()
	err = awaitNativeGuardExecutors(1*time.Millisecond, func() error {
		return Fault("guard_unavailable", "executor never idle")
	})
	if ErrorCode(err) != "guard_unavailable" || time.Since(start) > time.Second {
		t.Fatalf("hung or foreign executor admitted or wait unbounded: %v", err)
	}
}
