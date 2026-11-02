package sc

import (
	"reflect"
	"testing"
)

// The exact VM-only operator command may leave verified bookkeeping progress
// after a later failure. Exercise the real sequencing with inert observations
// and reset callbacks; no test gains systemd or network mutation authority.
func TestReconcileIdleSmartTUNServicesPartialFailureTruth(t *testing.T) {
	tests := []struct {
		name           string
		healthFailed   bool
		recoveryFailed bool
		fail           string
		wantHealth     bool
		wantRecovery   bool
		wantVerified   bool
		wantCode       string
		wantCalls      []string
	}{
		{
			name:         "both failed both reset",
			healthFailed: true, recoveryFailed: true,
			wantHealth: true, wantRecovery: true, wantVerified: true,
			wantCalls: []string{"health-observe", "recovery-observe", "native-preflight", "health-reset", "health-observe", "recovery-reset", "recovery-observe", "final-check"},
		},
		{
			name:         "health reset verified recovery reset failed",
			healthFailed: true, recoveryFailed: true, fail: "recovery-reset",
			wantHealth: true, wantCode: "guard_unavailable",
			wantCalls: []string{"health-observe", "recovery-observe", "native-preflight", "health-reset", "health-observe", "recovery-reset"},
		},
		{
			name:         "health reset verified recovery observation failed",
			healthFailed: true, recoveryFailed: true, fail: "recovery-post-observe",
			wantHealth: true, wantCode: "guard_unavailable",
			wantCalls: []string{"health-observe", "recovery-observe", "native-preflight", "health-reset", "health-observe", "recovery-reset", "recovery-observe"},
		},
		{
			name:         "health reset verified recovery identity changed",
			healthFailed: true, recoveryFailed: true, fail: "recovery-identity-drift",
			wantHealth: true, wantCode: "guard_unavailable",
			wantCalls: []string{"health-observe", "recovery-observe", "native-preflight", "health-reset", "health-observe", "recovery-reset", "recovery-observe"},
		},
		{
			name:         "both reset verified final native check failed",
			healthFailed: true, recoveryFailed: true, fail: "final-native",
			wantHealth: true, wantRecovery: true, wantCode: "trial_observation_uncertain",
			wantCalls: []string{"health-observe", "recovery-observe", "native-preflight", "health-reset", "health-observe", "recovery-reset", "recovery-observe", "final-check"},
		},
		{
			name:           "health healthy recovery reset",
			recoveryFailed: true, wantRecovery: true, wantVerified: true,
			wantCalls: []string{"health-observe", "recovery-observe", "native-preflight", "health-observe", "recovery-reset", "recovery-observe", "final-check"},
		},
		{
			name:         "recovery healthy health reset",
			healthFailed: true, wantHealth: true, wantVerified: true,
			wantCalls: []string{"health-observe", "recovery-observe", "native-preflight", "health-reset", "health-observe", "recovery-observe", "final-check"},
		},
		{
			name:         "both healthy no-op",
			wantVerified: true,
			wantCalls:    []string{"health-observe", "recovery-observe", "native-preflight", "health-observe", "recovery-observe", "final-check"},
		},
		{
			name:         "unsafe recovery preflight no reset",
			healthFailed: true, recoveryFailed: true, fail: "recovery-pre-observe",
			wantCode:  "guard_unavailable",
			wantCalls: []string{"health-observe", "recovery-observe"},
		},
		{
			name:         "unsafe health preflight no reset",
			healthFailed: true, recoveryFailed: true, fail: "health-pre-observe",
			wantCode:  "guard_unavailable",
			wantCalls: []string{"health-observe"},
		},
		{
			name:         "unsafe native preflight no reset",
			healthFailed: true, recoveryFailed: true, fail: "native-preflight",
			wantCode:  "trial_observation_uncertain",
			wantCalls: []string{"health-observe", "recovery-observe", "native-preflight"},
		},
		{
			name:         "failed health reset unknown outcome not counted",
			healthFailed: true, recoveryFailed: true, fail: "health-reset",
			wantCode:  "guard_unavailable",
			wantCalls: []string{"health-observe", "recovery-observe", "native-preflight", "health-reset"},
		},
		{
			name:         "failed health post reset observation unknown not counted",
			healthFailed: true, recoveryFailed: true, fail: "health-post-observe",
			wantCode:  "guard_unavailable",
			wantCalls: []string{"health-observe", "recovery-observe", "native-preflight", "health-reset", "health-observe"},
		},
		{
			name:         "health post reset identity changed not counted",
			healthFailed: true, recoveryFailed: true, fail: "health-identity-drift",
			wantCode:  "guard_unavailable",
			wantCalls: []string{"health-observe", "recovery-observe", "native-preflight", "health-reset", "health-observe"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			healthID := smartTUNHealthUnitIdentity{UnitIno: 101, SHA256: "owned-health"}
			recoveryID := smartTUNHealthUnitIdentity{UnitIno: 202, SHA256: "owned-recovery"}
			var calls []string
			var hObserved, rObserved int
			var hReset, rReset bool
			ops := smartTUNIdleReconcileOperations{
				observeHealth: func() (smartTUNHealthUnitIdentity, bool, error) {
					calls = append(calls, "health-observe")
					hObserved++
					if (hObserved == 1 && tc.fail == "health-pre-observe") ||
						(hObserved == 2 && tc.fail == "health-post-observe") {
						return smartTUNHealthUnitIdentity{}, false, Fault("guard_unavailable", "health observation unavailable")
					}
					if hObserved == 2 && tc.fail == "health-identity-drift" {
						return smartTUNHealthUnitIdentity{UnitIno: 303, SHA256: "foreign"}, false, nil
					}
					return healthID, tc.healthFailed && !hReset, nil
				},
				observeRecovery: func() (smartTUNHealthUnitIdentity, bool, error) {
					calls = append(calls, "recovery-observe")
					rObserved++
					if (rObserved == 1 && tc.fail == "recovery-pre-observe") ||
						(rObserved == 2 && tc.fail == "recovery-post-observe") {
						return smartTUNHealthUnitIdentity{}, false, Fault("guard_unavailable", "recovery observation unavailable")
					}
					if rObserved == 2 && tc.fail == "recovery-identity-drift" {
						return smartTUNHealthUnitIdentity{UnitIno: 404, SHA256: "foreign"}, false, nil
					}
					return recoveryID, tc.recoveryFailed && !rReset, nil
				},
				inspectNative: func() error {
					calls = append(calls, "native-preflight")
					if tc.fail == "native-preflight" {
						return Fault("trial_observation_uncertain", "native ownership cannot be verified")
					}
					return nil
				},
				resetFailed: func(name string) error {
					switch name {
					case smartTUNHealthUnit:
						calls = append(calls, "health-reset")
						if tc.fail == "health-reset" {
							return Fault("guard_unavailable", "health reset outcome unknown")
						}
						hReset = true
					case trialRecoveryUnit:
						calls = append(calls, "recovery-reset")
						if tc.fail == "recovery-reset" {
							return Fault("guard_unavailable", "recovery reset outcome unknown")
						}
						rReset = true
					default:
						t.Fatalf("untrusted systemd role reset: %q", name)
					}
					return nil
				},
				verifyFinal: func() error {
					calls = append(calls, "final-check")
					if tc.fail == "final-native" {
						return Fault("trial_observation_uncertain", "native generation changed")
					}
					return nil
				},
			}
			got, err := reconcileIdleSmartTUNServices(ops)
			if ErrorCode(err) != tc.wantCode {
				// ErrorCode(nil) is empty in the current error contract.
				t.Fatalf("unexpected result error code %q: %v", ErrorCode(err), err)
			}
			if got.HealthReconciled != tc.wantHealth ||
				got.Reconciled != tc.wantRecovery ||
				got.GuardIdleVerified != tc.wantVerified || got.ActivationReady {
				t.Fatalf("incorrect confirmed partial progress: %+v (err=%v)", got, err)
			}
			if !reflect.DeepEqual(calls, tc.wantCalls) {
				t.Fatalf("unexpected attempted effect/observation sequence:\n got: %q\nwant: %q", calls, tc.wantCalls)
			}
		})
	}
}
