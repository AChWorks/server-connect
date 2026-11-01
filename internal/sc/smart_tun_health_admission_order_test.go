package sc

import (
	"errors"
	"reflect"
	"testing"
)

// REQUIRED-04: an invalid topology must not normalize a stale FAILED health
// unit, even though its owned unit and journal are otherwise quiescent.
func TestSmartTUNHealthBookkeepingOnlyAfterSuccessfulAdmission(t *testing.T) {
	invalid := errors.New("trial_unsupported")
	normalizationFailed := errors.New("guard_unavailable")
	fixture := smartTUNTrialAdmission{endpoint: "10.0.2.2", baseline: "already-read"}

	for _, tc := range []struct {
		name               string
		admissionError     error
		normalizationError error
		normalize          bool
		wantCalls          []string
		wantError          error
		wantReceipt        bool
	}{
		{"rejected-topology-preserves-failed-health", invalid, nil, true, []string{"admit"}, invalid, false},
		{"valid-topology-resets-idle-health", nil, nil, true, []string{"admit", "normalize"}, nil, true},
		{"valid-topology-normalizer-refusal", nil, normalizationFailed, true, []string{"admit", "normalize"}, normalizationFailed, false},
		{"unsupervised-does-not-normalize", nil, nil, false, []string{"admit"}, nil, true},
		{"unsupervised-invalid", invalid, nil, false, []string{"admit"}, invalid, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := []string{}
			admit := func() (smartTUNTrialAdmission, error) {
				calls = append(calls, "admit")
				if tc.admissionError != nil {
					return smartTUNTrialAdmission{}, tc.admissionError
				}
				return fixture, nil
			}
			var normalize func() error
			if tc.normalize {
				normalize = func() error {
					calls = append(calls, "normalize")
					return tc.normalizationError
				}
			}
			receipt, err := smartTUNAdmitBeforeHealthBookkeeping(admit, normalize)
			if !reflect.DeepEqual(calls, tc.wantCalls) || !errors.Is(err, tc.wantError) {
				t.Fatalf("incorrect pre-mutation ordering: calls=%q err=%v", calls, err)
			}
			if tc.wantReceipt {
				if receipt.endpoint != fixture.endpoint || receipt.baseline != fixture.baseline {
					t.Fatalf("successful read-only admission lost: %+v", receipt)
				}
			} else if receipt.endpoint != "" || receipt.baseline != "" {
				t.Fatalf("failed admission escaped into prearm path: %+v", receipt)
			}
		})
	}
}
