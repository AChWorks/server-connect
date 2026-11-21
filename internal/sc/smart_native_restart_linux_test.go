//go:build linux

package sc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestRetiredNativePlanMatchesExactOffReceipt(t *testing.T) {
	raw := []byte(`{"inbounds":[{"type":"tun","interface_name":"sctun0"}],"outbounds":[{"type":"direct","tag":"direct"}]}`)
	hash := sha256.Sum256(raw)
	receipt := nativeHealthTestState()
	receipt.Phase = "off"
	receipt.ConfigSHA256 = hex.EncodeToString(hash[:])
	if got, err := nativeOffConfigTunnel(raw, receipt); err != nil || got != "sctun0" {
		t.Fatalf("valid native plan refused: %q %v", got, err)
	}
	for _, tc := range []struct {
		name string
		data []byte
		mod  func(*NativeHealthState)
	}{
		{"wrong-digest", append(append([]byte(nil), raw...), ' '), nil},
		{"no-complete-off", raw, func(h *NativeHealthState) { h.Phase = "healthy" }},
		{"bad-digest-record", raw, func(h *NativeHealthState) { h.ConfigSHA256 = "0" }},
		{"duplicate-object-key", []byte(`{"inbounds":[],"inbounds":[]}`), nil},
		{"invalid-inbound", []byte(`{"inbounds":[{"type":"mixed","interface_name":"sctun0"}]}`), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := receipt
			if tc.mod != nil {
				tc.mod(&h)
			}
			if tc.name == "duplicate-object-key" || tc.name == "invalid-inbound" {
				sum := sha256.Sum256(tc.data)
				h.ConfigSHA256 = hex.EncodeToString(sum[:])
			}
			if _, err := nativeOffConfigTunnel(tc.data, h); ErrorCode(err) != "guard_pending" {
				t.Fatalf("untrusted native plan accepted: %v", err)
			}
		})
	}
}

func TestOffReconcileRejectsLeftoverStartupBarrierButPreflightAdmitsOwn(t *testing.T) {
	for _, tc := range []struct {
		tables  string
		allowed bool
	}{
		{"table inet foreign\n", true},
		{"table inet sc_pre_0123456789abcdef0123456789abcdef\n", false},
		{"table ip sc_pre_0123456789abcdef0123456789abcdef\n", false},
		{"table inet foreign\ntable inet sc_pre_fedcba9876543210fedcba9876543210\n", false},
	} {
		err := nativeOffStartupTablesEmpty(tc.tables)
		if (err == nil) != tc.allowed {
			t.Fatalf("off startup owner admission: %q err=%v", tc.tables, err)
		}
	}
	// This exact positive case protects the Native ExecStartPre sequence:
	// unlike Off reconciliation, the already installed startup nft barrier
	// is an expected, committed resource during the same operation.
	fixture := nativeAdmissionFixture()
	fixture.outputs["nft list tables"] = "table inet foreign\ntable inet sc_pre_0123456789abcdef0123456789abcdef\n"
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "eth0", Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	if err := inspectNativeAdmission(context.Background(), fixture, scope); err != nil {
		t.Fatalf("normal native preflight incorrectly rejected its startup barrier: %v", err)
	}
}

func TestRetiredPlanReconciliationRequiresTwoIndependentOffChecks(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failFirst   bool
		failRemove  bool
		failAfter   bool
		wantChecks  int
		wantRemoved bool
	}{
		{"clean-after-reboot", false, false, false, 2, true},
		{"foreign-resource-before", true, false, false, 1, false},
		{"file-delete-failed", false, true, false, 1, false},
		{"resource-changed-after", false, false, true, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checks, removed := 0, false
			err := reconcileRetiredNativePlan(func() error {
				checks++
				if checks == 1 && tc.failFirst || checks == 2 && tc.failAfter {
					return Fault("guard_pending", "unverified owner or operation")
				}
				return nil
			}, func() error {
				if tc.failRemove {
					return errors.New("delete failed")
				}
				removed = true
				return nil
			})
			if (err == nil) != (tc.name == "clean-after-reboot") ||
				checks != tc.wantChecks || removed != tc.wantRemoved {
				t.Fatalf("reconciliation error=%v checks=%d removed=%t", err, checks, removed)
			}
		})
	}
	// An already-absent plan is a safe idempotent no-op in the manager.
}

func TestNativeCompletedCoreReplacementDefersUntilFreshReleasedClaim(t *testing.T) {
	// A real selected-peer outage left the new Core alive with a changed
	// PID, phase recovering, and a newly released startup receipt. Continuing
	// in the same invocation used its stale armed claim, made Health exit 1
	// with "recovery backoff ownership changed", and induced false Off.
	base := nativeHealthTestState()
	base.RestartLimit = 3
	base.RestartAttempts = 1
	base.RestartDeadlineMS = 60000
	base.RestartBackoffMS = 1000
	base.RestartIncidentMS = 5000
	base.RestartNextMS = 14000
	base.Phase = "recovering"
	base.RestartResult = "fresh_core_selected_path_unavailable"
	base.RestartFromPID = 13650
	base.RestartToPID = 15059
	failCalls := 0
	fail := func(s NativeHealthState, reason string) (NativeHealthState, error) {
		failCalls++
		s.Phase, s.Reason = "off", reason
		return s, nil
	}
	got, err := nativeFinishCoreReplacementRound(base, fail)
	if err != nil || got != base || failCalls != 0 {
		t.Fatalf("a fresh, still-guarded Core was incorrectly retired: result=%+v error=%v calls=%d", got, err, failCalls)
	}
	for _, tc := range []struct {
		name       string
		state      NativeHealthState
		failReason string
	}{
		{"last-attempt-exhausted", func() NativeHealthState { x := base; x.RestartAttempts = 3; return x }(), "core_restart_attempts_exhausted"},
		{"untrusted-phase", func() NativeHealthState { x := base; x.Phase = "off"; return x }(), "core_restart_result_unverified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := failCalls
			got, err := nativeFinishCoreReplacementRound(tc.state, fail)
			if err != nil || got.Phase != "off" || got.Reason != tc.failReason || failCalls != before+1 {
				t.Fatalf("invalid replacement result did not stop: %+v err=%v calls=%d", got, err, failCalls)
			}
		})
	}
	for _, phase := range []string{"healthy", "recovering"} {
		state := base
		state.Phase = phase
		state.RestartInFlight = true
		before := failCalls
		if got, err := nativeFinishCoreReplacementRound(state, fail); err != nil || got != state || failCalls != before {
			t.Fatalf("live or healthy replacement result incorrectly terminated: %+v err=%v", got, err)
		}
	}
}

func TestNativeRestartBudgetBackoffAndFlapNoReset(t *testing.T) {
	base := nativeHealthTestState()
	base.RestartLimit = 3
	base.RestartBackoffMS = 1000
	base.RestartDeadlineMS = 60000
	base.Phase = "stopping"
	initial, permitted := nativeEnterCoreRecovery(base, 5000)
	if !permitted || initial.Phase != "recovering" || initial.RestartIncidentMS != 5000 ||
		initial.RestartNextMS != 5000 || !nativeRestartCanTry(initial, 5000) {
		t.Fatalf("first incident not properly bounded: %+v", initial)
	}
	for i, expectedBackoff := range []int64{1000, 2000, 4000} {
		initial.RestartAttempts = i + 1
		if got := nativeRestartDelay(initial); got != expectedBackoff {
			t.Fatalf("attempt %d delay=%d want %d", i+1, got, expectedBackoff)
		}
		if i < 2 && !nativeRestartCanTry(initial, 5000) {
			t.Fatalf("remaining budget unexpectedly exhausted: %+v", initial)
		}
	}
	if nativeRestartCanTry(initial, 5000) {
		t.Fatal("attempt budget replenished after three tries")
	}
	initial.RestartIncidentMS = 0 // selected path recovered; a later flap is a new incident
	if _, allowed := nativeEnterCoreRecovery(initial, 100000); allowed {
		t.Fatal("flapping replenished the operation-wide exhausted attempt counter")
	}
	atDeadline := base
	atDeadline.RestartAttempts = 1
	atDeadline.RestartIncidentMS = 5000
	atDeadline.RestartNextMS = 5000
	if nativeRestartCanTry(atDeadline, 65000) {
		t.Fatal("deadline allowed additional retry")
	}
	if _, allowed := nativeEnterCoreRecovery(atDeadline, 65000); allowed {
		t.Fatal("expired incident rearmed")
	}
	base.RestartLimit = 0
	if _, allowed := nativeEnterCoreRecovery(base, 5000); allowed {
		t.Fatal("operator-disabled restarts were ignored")
	}
}

// Linux checks /proc/PID/exe with PTRACE_MODE_READ_FSCREDS. Recovery is a
// separate systemd unit: it must have the bounded capability superset of
// its inspected Core, or a legitimate child is misclassified as missing.
func TestIndependentRecoveryServiceCanAttestCoreExe(t *testing.T) {
	unit, err := os.ReadFile("../../bundle/server-connect-activation-recover.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW",
		"AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW",
		"NoNewPrivileges=yes",
	} {
		if !strings.Contains(string(unit), line+"\n") {
			t.Fatalf("independent Recovery lost required, bounded Core identity capability: %s", line)
		}
	}
	if strings.Contains(string(unit), "CAP_SYS_PTRACE") {
		for _, line := range strings.Split(string(unit), "\n") {
			if strings.HasPrefix(line, "CapabilityBoundingSet=") || strings.HasPrefix(line, "AmbientCapabilities=") {
				if strings.Contains(line, "CAP_SYS_PTRACE") {
					t.Fatal("Recovery must not require global ptrace authority")
				}
			}
		}
	}
}

func TestNativeSupervisorStartupRequiresCommittedSmartPrearm(t *testing.T) {
	claim := NativeSession{Selected: "0123456789abcdef", ConfigSHA256: strings.Repeat("b", 64),
		HealthOperationID: strings.Repeat("a", 32), CoreStartAttempted: true,
		StartupGuardPhase: "armed"}
	h := nativeHealthTestState()
	state := State{Version: 1, Desired: "smart", Selected: claim.Selected}
	if err := nativeSupervisorJustConsumedPrearm(state, claim, h); err != nil {
		t.Fatalf("first real Core startup rejected after successful ExecStartPre: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*State, *NativeSession, *NativeHealthState)
	}{
		{"not-yet-smart", func(s *State, _ *NativeSession, _ *NativeHealthState) { s.Desired = "direct" }},
		{"no-consumed-claim", func(_ *State, c *NativeSession, _ *NativeHealthState) { c.CoreStartAttempted = false }},
		{"wrong-selected", func(s *State, _ *NativeSession, _ *NativeHealthState) { s.Selected = "fedcba9876543210" }},
		{"wrong-guard-phase", func(_ *State, c *NativeSession, _ *NativeHealthState) { c.StartupGuardPhase = "released" }},
		{"replayed-health", func(_ *State, _ *NativeSession, h *NativeHealthState) { h.Phase = "healthy" }},
		{"other-operation", func(_ *State, _ *NativeSession, h *NativeHealthState) { h.OperationID = strings.Repeat("c", 32) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, c, h2 := state, claim, h
			tc.mutate(&s, &c, &h2)
			if err := nativeSupervisorJustConsumedPrearm(s, c, h2); ErrorCode(err) != "guard_pending" {
				t.Fatalf("unsafe initial Core startup admitted: %v", err)
			}
		})
	}
}

func TestNativeChildStatRejectsSpoofAndZombie(t *testing.T) {
	pid, parent := 3210, 3000
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[1] = strconv.Itoa(parent)
	fields[19] = "987654"
	valid := []byte(fmt.Sprintf("%d (sing-box core) %s\n", pid, strings.Join(fields, " ")))
	id, err := parseNativeChildStat(valid, pid, parent)
	if err != nil || id != (nativeCoreIdentity{PID: pid, Started: 987654}) {
		t.Fatalf("valid stat rejected: %+v %v", id, err)
	}
	for _, tc := range []struct {
		name   string
		raw    []byte
		pid    int
		parent int
	}{
		{"parent-spoof", valid, pid, parent + 1},
		{"PID-spoof", valid, pid + 1, parent},
		{"truncated", []byte("3221 (bad) S 3000"), pid, parent},
		{"zombie", []byte(strings.Replace(string(valid), ") S ", ") Z ", 1)), pid, parent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseNativeChildStat(tc.raw, tc.pid, tc.parent); err == nil {
				t.Fatal("untrusted process identity accepted")
			}
		})
	}
}

// Execute actual OS child processes; the parent supervisor itself remains
// inside the Go test process, with injected signal channels. PID change is a
// real kernel observation; no privileged network, systemd, or production host.
func TestNativeCoreSupervisorRealProcessRestartAndFailClosedExit(t *testing.T) {
	if testing.Short() {
		t.Skip("real child-process lifecycle")
	}
	makeCore := func(t *testing.T) (string, string) {
		t.Helper()
		dir := t.TempDir()
		core, log := filepath.Join(dir, "core.sh"), filepath.Join(dir, "pids")
		script := "#!/bin/sh\nprintf '%s\\n' \"$$\" >> " + strconv.Quote(log) + "\ntrap 'exit 0' TERM INT\nwhile :; do sleep 0.05; done\n"
		if err := os.WriteFile(core, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		return core, log
	}
	waitPIDs := func(t *testing.T, log string, count int) []int {
		t.Helper()
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			raw, _ := os.ReadFile(log)
			var pids []int
			for _, line := range strings.Fields(string(raw)) {
				v, e := strconv.Atoi(line)
				if e == nil {
					pids = append(pids, v)
				}
			}
			if len(pids) >= count {
				return pids
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("expected %d actual Core processes in log %s", count, log)
		return nil
	}
	t.Run("guarded-new-PID-and-stale-signal", func(t *testing.T) {
		core, log := makeCore(t)
		stops, restarts := make(chan os.Signal, 2), make(chan os.Signal, 2)
		var allow atomic.Bool
		ready := make(chan error, 1)
		go func() {
			ready <- superviseNativeCoreWithSignals(core, "irrelevant",
				func(pid int) error {
					if !allow.Load() {
						return errors.New("not-authorized")
					}
					return nil
				},
				stops, restarts)
		}()
		defer func() {
			select {
			case stops <- syscall.SIGTERM:
			default:
			}
		}()
		first := waitPIDs(t, log, 1)
		restarts <- syscall.SIGUSR1 // no authority; must NOT terminate child
		time.Sleep(120 * time.Millisecond)
		raw, _ := os.ReadFile(log)
		if len(strings.Fields(string(raw))) != 1 {
			t.Fatalf("untrusted restart changed PID: %s", raw)
		}
		allow.Store(true)
		restarts <- syscall.SIGUSR1
		second := waitPIDs(t, log, 2)
		if first[0] == second[1] {
			t.Fatal("restart reused the original PID")
		}
		stops <- syscall.SIGTERM
		select {
		case err := <-ready:
			if err != nil {
				t.Fatalf("stop failed: %v", err)
			}
		case <-time.After(4 * time.Second):
			t.Fatal("Core supervisor did not stop")
		}
	})
	t.Run("unexpected-core-SIGKILL-is-fatal", func(t *testing.T) {
		core, log := makeCore(t)
		stops, restarts := make(chan os.Signal, 2), make(chan os.Signal, 2)
		ready := make(chan error, 1)
		go func() {
			ready <- superviseNativeCoreWithSignals(core, "irrelevant",
				func(int) error { return nil }, stops, restarts)
		}()
		defer func() {
			select {
			case stops <- syscall.SIGTERM:
			default:
			}
		}()
		ids := waitPIDs(t, log, 1)
		if err := syscall.Kill(ids[0], syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-ready:
			if err == nil {
				t.Fatal("unexpected Core exit was treated as healthy")
			}
		case <-time.After(4 * time.Second):
			t.Fatal("Core SIGKILL did not terminate supervisor")
		}
		raw, _ := os.ReadFile(log)
		if len(strings.Fields(string(raw))) != 1 {
			t.Fatalf("fatal Core crash spawned unsafe replacement: %s", raw)
		}
	})
}
