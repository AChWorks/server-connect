package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

// This is the same JSON formatter and typed action invoked by the actual
// smart-tun-trial-reconcile-idle-guard CLI branch, with only its privileged
// action substituted. No systemd, kernel or product-state mutation is needed.
func TestIdleGuardReconcileCommandJSONPartialResults(t *testing.T) {
	tests := []struct {
		name     string
		report   sc.SmartTUNIdleGuardReconcileResult
		failure  error
		wantCode int
		wantOK   bool
		wantErr  string
	}{
		{
			name:     "verified Health only before Recovery reset fails",
			report:   sc.SmartTUNIdleGuardReconcileResult{HealthReconciled: true},
			failure:  sc.Fault("guard_unavailable", "recovery reset outcome unavailable"),
			wantCode: 1, wantErr: "guard_unavailable",
		},
		{
			name:     "verified both before final native validation fails",
			report:   sc.SmartTUNIdleGuardReconcileResult{Reconciled: true, HealthReconciled: true},
			failure:  sc.Fault("trial_observation_uncertain", "native generation changed"),
			wantCode: 1, wantErr: "trial_observation_uncertain",
		},
		{
			name:     "unverified failed Health reset never claimed",
			report:   sc.SmartTUNIdleGuardReconcileResult{},
			failure:  sc.Fault("guard_unavailable", "health reset outcome unknown"),
			wantCode: 1, wantErr: "guard_unavailable",
		},
		{
			name:     "verified success of both reset roles",
			report:   sc.SmartTUNIdleGuardReconcileResult{Reconciled: true, HealthReconciled: true, GuardIdleVerified: true},
			wantCode: 0, wantOK: true,
		},
		{
			name:     "idempotent no-op retains truthful all false with idle verified",
			report:   sc.SmartTUNIdleGuardReconcileResult{GuardIdleVerified: true},
			wantCode: 0, wantOK: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			exit, stdout, stderr := hostDriftCapturedOutput(t, func() int {
				return runIdleGuardReconcile(true, func() (sc.SmartTUNIdleGuardReconcileResult, error) {
					calls++
					return tc.report, tc.failure
				})
			})
			if calls != 1 || exit != tc.wantCode || stderr != "" || strings.Contains(stdout, "secret://") {
				t.Fatalf("CLI action count, exit, stderr or sanitization invalid: calls=%d exit=%d stderr=%q output=%q", calls, exit, stderr, stdout)
			}
			var got struct {
				OK    bool                                `json:"ok"`
				Data  sc.SmartTUNIdleGuardReconcileResult `json:"data"`
				Error *struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatalf("CLI JSON not decodable: %v (body=%q)", err, stdout)
			}
			if got.OK != tc.wantOK || got.Data != tc.report {
				t.Fatalf("CLI misrepresented known partial effects or overall success: got=%+v want=%+v", got, tc.report)
			}
			if tc.wantErr == "" && got.Error != nil {
				t.Fatalf("spurious CLI error: %+v", got.Error)
			}
			if tc.wantErr != "" && (got.Error == nil || got.Error.Code != tc.wantErr) {
				t.Fatalf("missing precise CLI error code %s: %+v", tc.wantErr, got.Error)
			}
			if !got.OK && (got.Data.GuardIdleVerified || got.Data.ActivationReady) {
				t.Fatalf("CLI claimed idle-guard acceptance on failed reconciliation: %+v", got.Data)
			}
		})
	}
}
