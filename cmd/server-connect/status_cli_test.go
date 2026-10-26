package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

func TestStatusCommandKeepsSafeDiagnosticsOnFailure(t *testing.T) {
	const secret = "vless://private-operator-token@server.invalid:443"
	for _, tc := range []struct {
		name, code, desired, observed, health, message string
	}{
		{"untrusted-native-controller", "service_binary_untrusted", "direct", "unknown", "service_state_unavailable", "native systemd controller missing or unsafe"},
		{"service-read-failure", "service_state_unavailable", "proxy", "unknown", "service_state_unavailable", "native systemd service state cannot be verified"},
		{"unverifiable-active-service", "service_conflict", "proxy", "active", "service_ownership_conflict", "active systemd unit ownership is unverified"},
	} {
		for _, jsonMode := range []bool{true, false} {
			t.Run(tc.name+map[bool]string{true: "-json", false: "-text"}[jsonMode], func(t *testing.T) {
				report := sc.Status{Desired: tc.desired, Observed: tc.observed, Health: tc.health,
					Selected: "abcdef1234567890", Port: 20807, CoreVersion: sc.CoreVersion}
				readCalls := 0
				code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
					return runStatus(jsonMode, func() (sc.Status, error) {
						readCalls++
						return report, sc.Fault(tc.code, tc.message)
					})
				})
				if code != 1 || readCalls != 1 || strings.Contains(stdout+stderr, secret) ||
					strings.Contains(stdout+stderr, "secret://") {
					t.Fatalf("status output unsafe or succeeded: exit=%d reads=%d out=%s err=%s", code, readCalls, stdout, stderr)
				}
				if jsonMode {
					if stderr != "" {
						t.Fatalf("JSON status emitted stderr: %s", stderr)
					}
					var response struct {
						OK    bool      `json:"ok"`
						Data  sc.Status `json:"data"`
						Error struct {
							Code string `json:"code"`
						} `json:"error"`
					}
					if err := json.Unmarshal([]byte(stdout), &response); err != nil || response.OK ||
						response.Error.Code != tc.code || response.Data != report {
						t.Fatalf("lost machine diagnostics: response=%+v err=%v", response, err)
					}
				} else {
					for _, part := range []string{`"desired": "` + tc.desired + `"`,
						`"observed": "` + tc.observed + `"`, `"health": "` + tc.health + `"`} {
						if !strings.Contains(stdout, part) {
							t.Fatalf("text status lost %s: %s", part, stdout)
						}
					}
					if !strings.Contains(stderr, "Error ["+tc.code+"]") || !strings.Contains(stderr, tc.message) {
						t.Fatalf("status omitted safe error classification: %s", stderr)
					}
				}
			})
		}
	}
}

func TestStatusCommandDoesNotFabricatePartialState(t *testing.T) {
	for _, jsonMode := range []bool{true, false} {
		code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
			return runStatus(jsonMode, func() (sc.Status, error) {
				return sc.Status{}, sc.Fault("invalid_state", "private state could not be loaded")
			})
		})
		if code != 1 || strings.Contains(stdout, `"desired"`) || strings.Contains(stdout, `"observed"`) ||
			strings.Contains(stdout, `"health"`) {
			t.Fatalf("fabricated status: %d %s %s", code, stdout, stderr)
		}
		if jsonMode && (!strings.Contains(stdout, "invalid_state") || stderr != "") {
			t.Fatalf("missing JSON error classification: %s %s", stdout, stderr)
		}
		if !jsonMode && !strings.Contains(stderr, "private state could not be loaded") {
			t.Fatalf("missing text status error: %s", stderr)
		}
	}
}
