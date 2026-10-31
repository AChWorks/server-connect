package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

func TestModeOverviewHonestServiceAndTrialStates(t *testing.T) {
	for _, tc := range []struct {
		name, desired, observed, health, wantMode, wantTrial, wantError string
	}{
		{"direct-inactive", "direct", "inactive", "not_tested", "unknown", "", ""},
		{"proxy-active", "proxy", "active", "not_tested", "proxy_only", "", ""},
		{"proxy-failed", "proxy", "failed", "core_unavailable", "unknown", "", ""},
		{"proxy-inactive", "proxy", "inactive", "core_unavailable", "unknown", "", ""},
		{"unexpected-active", "direct", "active", "unexpected_active_service", "unknown", "", ""},
		{"historical-failed", "direct", "failed", "historical_proxy_failure_direct_unaffected", "unknown", "", ""},
		{"unavailable", "direct", "unknown", "service_state_unavailable", "unknown", "", "service_state_unavailable"},
		{"foreign-active-owner", "proxy", "active", "service_ownership_conflict", "unknown", "", "service_conflict"},
		{"smart-tun-pending", "direct", "smart_tun_trial_pending", "guarded_trial_unconfirmed", "unknown", "trial_pending", "guard_pending"},
		{"smart-tun-supervised", "direct", "smart_tun_supervised_healthy", "supervised_record_not_freshly_verified", "unknown", "supervised_healthy", "guard_pending"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var statusErr error
			if tc.wantError != "" {
				statusErr = sc.Fault(tc.wantError, "safe status observation unavailable")
			}
			reads := 0
			code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
				return runModeOverview(true, func() (sc.Status, error) {
					reads++
					return sc.Status{Desired: tc.desired, Observed: tc.observed,
						Health: tc.health, Selected: "0123456789abcdef", Port: 20807}, statusErr
				})
			})
			var reply struct {
				OK    bool         `json:"ok"`
				Data  modeOverview `json:"data"`
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(stdout), &reply); err != nil {
				t.Fatalf("bad JSON: %v %s", err, stdout)
			}
			if reads != 1 || stderr != "" || reply.Data.DesiredMode != map[string]string{"direct": "direct", "proxy": "proxy_only"}[tc.desired] ||
				reply.Data.ObservedMode != tc.wantMode || reply.Data.TrialPhase != tc.wantTrial ||
				reply.Data.SelectedProfileID != "0123456789abcdef" ||
				reply.Data.VPNPathProof != "not_run" || reply.Data.HostDirectPathProof != "not_run" ||
				len(reply.Data.Modes) != 3 || reply.Data.Modes[2].ID != "smart_routing" ||
				reply.Data.Modes[2].Availability != "disposable_guest_only" ||
				reply.Data.Modes[2].GeneralHostActivation || reply.Data.Modes[0].ID != "direct" ||
				reply.Data.Modes[1].ID != "proxy_only" {
				t.Fatalf("dishonest or divergent mode overview, reads=%d: %+v", reads, reply)
			}
			if tc.wantError != "" {
				if code != 1 || reply.OK || reply.Error.Code != tc.wantError {
					t.Fatalf("failed status was treated as healthy: exit=%d %+v", code, reply)
				}
			} else if code != 0 || !reply.OK {
				t.Fatalf("unexpected mode overview failure: exit=%d %+v", code, reply)
			}
			if tc.wantMode == "unknown" && reply.Data.ActiveRouteVerified {
				t.Fatalf("uncertain state claimed route proof: %+v", reply.Data)
			}
		})
	}
}

func TestModeOverviewFailureRedactsInvalidState(t *testing.T) {
	const secret = "vless://private-token@endpoint.example:443"
	for _, tc := range []struct {
		name     string
		status   sc.Status
		err      error
		wantCode string
		partial  bool
	}{
		{"missing-state", sc.Status{}, sc.Fault("invalid_state", "private state unavailable"), "invalid_state", false},
		{"untrusted-selected", sc.Status{Desired: "direct", Observed: "inactive", Selected: secret}, nil, "invalid_state", true},
		{"malformed-mode", sc.Status{Desired: secret, Observed: "inactive", Selected: "0123456789abcdef"}, nil, "invalid_state", false},
		{"malformed-observed", sc.Status{Desired: "direct", Observed: secret}, nil, "invalid_state", true},
		{"malformed-health", sc.Status{Desired: "proxy", Observed: "active", Health: secret}, nil, "invalid_state", true},
		{"unsupported-state", sc.Status{Desired: "direct", Observed: "unknown"}, nil, "invalid_state", true},
		{"contradictory-service-health", sc.Status{Desired: "proxy", Observed: "active", Health: "service_ownership_conflict"}, nil, "invalid_state", true},
		{"forged-trial-without-guard", sc.Status{Desired: "direct", Observed: "smart_tun_trial_pending"}, nil, "invalid_state", true},
		{"garbled-trial-phase", sc.Status{Desired: "direct", Observed: "smart_tun_123secret"}, sc.Fault("guard_pending", "guarded trial"), "invalid_state", true},
	} {
		for _, jsonMode := range []bool{true, false} {
			t.Run(tc.name+map[bool]string{true: "-json", false: "-text"}[jsonMode], func(t *testing.T) {
				code, out, errOut := hostDriftCapturedOutput(t, func() int {
					return runModeOverview(jsonMode, func() (sc.Status, error) { return tc.status, tc.err })
				})
				if code != 1 || strings.Contains(out+errOut, secret) || strings.Contains(out+errOut, "private-token") {
					t.Fatalf("secret leaked or failure swallowed: exit=%d output=%s stderr=%s", code, out, errOut)
				}
				if jsonMode {
					var response struct {
						OK    bool          `json:"ok"`
						Data  *modeOverview `json:"data"`
						Error struct {
							Code string `json:"code"`
						} `json:"error"`
					}
					if err := json.Unmarshal([]byte(out), &response); err != nil || response.OK || response.Error.Code != tc.wantCode ||
						(response.Data != nil) != tc.partial {
						t.Fatalf("wrong safe error envelope: %v %+v", err, response)
					}
					if response.Data != nil && response.Data.ObservedMode != "unknown" {
						t.Fatalf("malformed state fabricated a known mode: %+v", response.Data)
					}
				} else if !strings.Contains(errOut, "Error:") && !strings.Contains(errOut, "Error [invalid_state]") {
					t.Fatalf("missing safe classified error: %s", errOut)
				}
			})
		}
	}
}

func TestModeOverviewCLIAndMenuShareReadOnlySurface(t *testing.T) {
	m := sc.New(filepath.Join(t.TempDir(), "isolated-manager"), "", 0)
	for _, args := range [][]string{{"mode-overview", "--unexpected"}, {"mode-overview", "extra"}} {
		code, out, stderr := hostDriftCapturedOutput(t, func() int { return run(true, m, args) })
		if code == 0 || stderr != "" || !strings.Contains(out, "invalid_arguments") {
			t.Fatalf("invalid option accepted: exit=%d %s %s", code, out, stderr)
		}
		if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
			t.Fatal("argument refusal initialized the manager")
		}
	}
	// Installed systemctl activity may be unavailable in source-test hosts.
	// Both paths must use the same bounded status observation, and must not
	// claim the experimental TUN is supported by a general host.
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err = writer.Write([]byte("18\n0\n")); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	old := os.Stdin
	os.Stdin = input
	code, menuOut, menuErr := hostDriftCapturedOutput(t, func() int { return menu(m) })
	os.Stdin = old
	if code != 0 || !strings.Contains(menuOut, "18 Mode Overview") ||
		!strings.Contains(menuOut, `"general_host_activation": false`) ||
		!strings.Contains(menuOut, `"vpn_path_proof": "not_run"`) ||
		strings.Contains(menuOut, `"observed_mode": "smart_routing"`) {
		t.Fatalf("menu cannot explain non-admitted mode: exit=%d out=%s err=%s", code, menuOut, menuErr)
	}
	_, cliOut, _ := hostDriftCapturedOutput(t, func() int { return run(false, m, []string{"mode-overview"}) })
	for _, part := range []string{`"availability": "disposable_guest_only"`, `"host_direct_path_proof": "not_run"`, `"observed_mode": "unknown"`} {
		if !strings.Contains(menuOut, part) || !strings.Contains(cliOut, part) {
			t.Fatalf("CLI/menu mode drift: %s\nmenu=%s\nCLI=%s", part, menuOut, cliOut)
		}
	}
}
