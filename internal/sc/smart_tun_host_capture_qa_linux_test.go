//go:build linux

package sc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A prearm callback is the only entry into systemd. Unsupported/invalid
// invocation must refuse before even creating a private activation lock.
func TestHostCaptureQAInvalidOrUninstalledNeverPrearms(t *testing.T) {
	for _, tc := range []struct {
		name           string
		manager        *Manager
		peer, underlay string
		seconds        int
	}{
		{"nil_manager", nil, "8.8.8.8", "ens3", 120},
		{"uninstalled", New(filepath.Join(t.TempDir(), "uncreated"), DefaultCore, DefaultPort), "8.8.8.8", "ens3", 120},
		{"uninstalled_core", New(filepath.Join(t.TempDir(), "uncreated"), filepath.Join(t.TempDir(), "core"), DefaultPort), "8.8.8.8", "ens3", 120},
		{"invalid_deadline", New(filepath.Join(t.TempDir(), "uncreated"), DefaultCore, DefaultPort), "8.8.8.8", "ens3", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invoked := false
			var dir string
			if tc.manager != nil {
				dir = tc.manager.Dir
			}
			receipt, err := tc.manager.runHostCaptureQAWithPrearm(tc.peer, tc.underlay, tc.seconds, func() error { invoked = true; return nil })
			if ErrorCode(err) != "trial_unsupported" || invoked || receipt.ActivationReady || receipt.KernelBarrierClosed || receipt.GuardScheduled || receipt.OperationID != "" || receipt.Phase != "not_started" || !receipt.ExperimentOnly {
				t.Fatalf("false approval or prearm on %s: %+v err=%v", tc.name, receipt, err)
			}
			if dir != "" {
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Fatalf("unsupported invocation wrote state: %v", err)
				}
			}
		})
	}
}

func TestHostCaptureQAReceiptCannotClaimActivation(t *testing.T) {
	receipt := HostCapturePreparationQAReceipt{OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: "prepared_pending_independent_recovery", ExperimentOnly: true, GuardScheduled: true, KernelBarrierClosed: true}
	wire, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		ActivationReady  bool `json:"activation_ready"`
		ExperimentOnly   bool `json:"experiment_only"`
		RecoveryVerified bool `json:"recovery_verified"`
	}
	if err := json.Unmarshal(wire, &parsed); err != nil || parsed.ActivationReady || !parsed.ExperimentOnly || parsed.RecoveryVerified {
		t.Fatalf("preparation masqueraded as activation/recovery: %s, %v", wire, err)
	}
}
