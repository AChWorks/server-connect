package sc

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// All identity substitutions are injected and never touch installed systemd
// or actual host routing. Selected transport is pinned by DiagnosePath itself.
func TestPathDiagnosticsRejectsContradictorySampleStatuses(t *testing.T) {
	targets := []string{"https://first.example/private-secret", "https://second.example"}
	healthy := ProbeResult{Path: "proxy", Code: 204, Result: "reachable"}
	for _, tt := range []struct {
		name   string
		second ProbeResult
		err    error
		status string
		code   string
	}{
		{"wrong_path_200", ProbeResult{Path: "direct", Code: 200, Result: "reachable"}, nil, "unverified", "diagnostic_inconsistent"},
		{"contradictory_502", ProbeResult{Path: "proxy", Code: 502, Result: "reachable"}, nil, "unverified", "diagnostic_inconsistent"},
		{"reachable_with_dns_error", ProbeResult{Path: "proxy", Code: 200, Result: "reachable"}, Fault("probe_dns", "private-secret"), "failed", "probe_dns"},
		{"failed_http_502", ProbeResult{Path: "proxy", Code: 502, Result: "http_error"}, Fault("probe_http", "secret"), "http_error", "probe_http"},
		{"redirect_unverified", ProbeResult{Path: "proxy", Code: 302, Result: "reachable"}, nil, "redirect_unverified", "probe_redirect_unverified"},
		{"unavailable", ProbeResult{Path: "proxy", Result: "unavailable"}, Fault("proxy_unavailable", "secret"), "unavailable", "proxy_unavailable"},
		{"unknown_raw_status", ProbeResult{Path: "proxy", Code: 200, Result: "secret_raw_status"}, nil, "unverified", "diagnostic_inconsistent"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			index := 0
			report, err := runPathDiagnostics("proxy", targets, func(string) (ProbeResult, error) {
				index++
				if index == 1 {
					return healthy, nil
				}
				return tt.second, tt.err
			})
			if ErrorCode(err) != "probe_set_partial" || index != len(targets) ||
				report.ReachableCount != 1 || report.FailedCount != 1 ||
				report.Assessment != "mixed_results" || report.Samples[0].Status != "reachable" ||
				report.Samples[1].Status != tt.status || report.Samples[1].ErrorCode != tt.code {
				t.Fatalf("inconsistent sample was not normalized: %+v err=%v", report, err)
			}
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"private-secret", "second.example", "secret_raw_status"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatalf("raw probe/destination leaked into JSON: %s", secret)
				}
			}
		})
	}
	both, err := runPathDiagnostics("proxy", targets, func(string) (ProbeResult, error) {
		return healthy, nil
	})
	if err != nil || both.Assessment != "all_targets_reachable" || both.ReachableCount != 2 ||
		both.Samples[0].Status != "reachable" || both.Samples[1].Status != "reachable" {
		t.Fatalf("valid 2xx selected profile result was lost: %+v err=%v", both, err)
	}
}

func TestParseDiagnosticServiceInstanceRejectsAmbiguity(t *testing.T) {
	valid := "MainPID=4321\nInvocationID=abcdef0123456789abcdef0123456789\nActiveState=active\n"
	instance, err := parseDiagnosticServiceInstance([]byte(valid))
	if err != nil || instance.PID != 4321 || instance.Invocation != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("valid service generation rejected: %+v %v", instance, err)
	}
	for _, input := range []string{
		"", "ActiveState=active\nMainPID=4321\n",
		"ActiveState=inactive\nMainPID=4321\nInvocationID=abcdef0123456789abcdef0123456789",
		"ActiveState=active\nMainPID=0\nInvocationID=abcdef0123456789abcdef0123456789",
		"ActiveState=active\nMainPID=4321\nInvocationID=not-an-invocation-id",
		valid + "MainPID=4321\n", valid + "Unknown=other\n",
	} {
		if _, err := parseDiagnosticServiceInstance([]byte(input)); err == nil {
			t.Fatalf("ambiguous service instance was accepted: %q", input)
		}
	}
}

func TestPathDiagnosticsRequiresOneStableSelectedProxy(t *testing.T) {
	targets := []string{"https://one.example", "https://two.example"}
	base := diagnosticProxyIdentity{
		SelectedID: "1111111111111111", Port: 20807,
		Service: diagnosticServiceInstance{PID: 1234, Invocation: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	base.RuntimeHash[0] = 1
	base.AuthHash[0] = 2
	for _, tt := range []struct {
		name          string
		mutate        func(*diagnosticProxyIdentity)
		changeAtCheck int
		wantProbes    int
	}{
		{"stable", nil, 0, 2},
		{"new_profile_between_targets", func(v *diagnosticProxyIdentity) { v.SelectedID = "2222222222222222" }, 3, 1},
		{"service_restart_same_pid", func(v *diagnosticProxyIdentity) { v.Service.Invocation = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }, 3, 1},
		{"service_pid_changed", func(v *diagnosticProxyIdentity) { v.Service.PID++ }, 3, 1},
		{"runtime_replaced", func(v *diagnosticProxyIdentity) { v.RuntimeHash[0]++ }, 3, 1},
		{"credentials_rotated", func(v *diagnosticProxyIdentity) { v.AuthHash[0]++ }, 3, 1},
		{"profile_changes_in_first_request", func(v *diagnosticProxyIdentity) { v.SelectedID = "2222222222222222" }, 2, 1},
		{"selected_proxy_unavailable", func(v *diagnosticProxyIdentity) { v.Service = diagnosticServiceInstance{} }, 1, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := base
			checks := 0
			probes := 0
			report, err := runPathDiagnosticsChecked("proxy", targets,
				func(string) (ProbeResult, error) {
					probes++
					return ProbeResult{Path: "proxy", Code: 200, Result: "reachable"}, nil
				},
				func() bool {
					checks++
					if checks == tt.changeAtCheck && tt.mutate != nil {
						tt.mutate(&now)
					}
					return now == base
				},
			)
			if probes != tt.wantProbes {
				t.Fatalf("unexpected probes after drift: %d", probes)
			}
			if tt.mutate == nil {
				if err != nil || report.Assessment != "all_targets_reachable" || report.ReachableCount != 2 {
					t.Fatalf("stable selected profile should pass: %+v err=%v", report, err)
				}
				return
			}
			if ErrorCode(err) != "diagnostic_path_changed" ||
				report.Assessment != "path_changed_unverified" || report.ReachableCount != 0 ||
				report.FailedCount != len(targets) || len(report.Samples) != len(targets) {
				t.Fatalf("selected profile drift was not fail-closed: %+v err=%v", report, err)
			}
			for _, sample := range report.Samples {
				if sample.Status != "unverified" || sample.ErrorCode != "diagnostic_path_changed" {
					t.Fatalf("prior or future target misattributed to mixed profile: %+v", report.Samples)
				}
			}
		})
	}
}

func TestDiagnosticNeverKeepsLifecycleLockAcrossProbe(t *testing.T) {
	m := New(t.TempDir(), "", 0)
	if err := os.Chmod(m.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	report, err := runPathDiagnosticsChecked("proxy",
		[]string{"https://one.example", "https://two.example"},
		func(string) (ProbeResult, error) {
			// A disconnect or recovery operation must be able to acquire the
			// same Manager lock while a simulated remote probe is in flight.
			done := make(chan error, 1)
			go func() { done <- m.withLock(func() error { return nil }) }()
			select {
			case lockErr := <-done:
				if lockErr != nil {
					t.Fatalf("manager lifecycle lock failed: %v", lockErr)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("probe held lifecycle lock across remote operation")
			}
			return ProbeResult{Path: "proxy", Code: 204, Result: "reachable"}, nil
		},
		func() bool {
			err := m.withLock(func() error { return nil })
			if err != nil {
				t.Logf("diagnostic lock guard failed: %v", err)
			}
			return err == nil
		})
	if err != nil || report.ReachableCount != 2 || report.Assessment != "all_targets_reachable" {
		t.Fatalf("short lock scope changed healthy aggregation: %+v err=%v", report, err)
	}
}

func TestCheckedPathDiagnosticsStillRejectsPreflightBeforeGuard(t *testing.T) {
	called := false
	report, err := runPathDiagnosticsChecked("proxy", []string{"http://one.example"},
		func(string) (ProbeResult, error) { called = true; return ProbeResult{}, nil },
		func() bool { called = true; return false })
	if called || ErrorCode(err) != "invalid_arguments" || report.Assessment != "not_tested" {
		t.Fatalf("preflight unexpectedly inspected runtime or network: %+v %v", report, err)
	}
}

func TestPathDiagnosticsRetainsSafeFailureCategory(t *testing.T) {
	r, err := runPathDiagnostics("proxy", []string{"https://one.example", "https://two.example"},
		func(string) (ProbeResult, error) {
			return ProbeResult{Path: "proxy", Code: 200, Result: "reachable"}, errors.New("unclassified private auth")
		})
	if ErrorCode(err) != "probe_set_unreachable" || r.ReachableCount != 0 {
		t.Fatalf("error-bearing HTTP 200 became successful: %+v %v", r, err)
	}
	for _, sample := range r.Samples {
		if sample.Status == "reachable" || sample.ErrorCode == "" {
			t.Fatalf("error-bearing result was marked reachable: %+v", sample)
		}
	}
}
