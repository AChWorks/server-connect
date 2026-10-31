package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/AChWorks/server-connect/internal/sc"
)

// This overview reports only the existing Manager service observation. A
// native TUN trial is not equivalent to production Smart Routing admission,
// and a local Proxy Only service is not proof of selected VPN egress.
type modeAvailability struct {
	ID                    string `json:"id"`
	Availability          string `json:"availability"`
	GeneralHostActivation bool   `json:"general_host_activation"`
}

type modeOverview struct {
	DesiredMode         string             `json:"desired_mode"`
	ObservedMode        string             `json:"observed_mode"`
	ProxyServiceState   string             `json:"proxy_service_state"`
	StatusHealth        string             `json:"status_health"`
	SelectedProfileID   string             `json:"selected_profile_id,omitempty"`
	TrialPhase          string             `json:"trial_phase,omitempty"`
	EvidenceScope       string             `json:"evidence_scope"`
	VPNPathProof        string             `json:"vpn_path_proof"`
	HostDirectPathProof string             `json:"host_direct_path_proof"`
	ActiveRouteVerified bool               `json:"active_route_verified"`
	Modes               []modeAvailability `json:"modes"`
}

func validModeProfileID(id string) bool {
	if len(id) != 16 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func modeOverviewFromStatus(status sc.Status, observationErr error) (modeOverview, error) {
	if status.Desired != "direct" && status.Desired != "proxy" {
		return modeOverview{}, sc.Fault("invalid_state", "desired mode cannot be verified")
	}
	desired := "direct"
	if status.Desired == "proxy" {
		desired = "proxy_only"
	}
	overview := modeOverview{
		DesiredMode: desired, ObservedMode: "unknown",
		ProxyServiceState: "unknown", StatusHealth: "not_verified",
		EvidenceScope: "unverified",
		VPNPathProof:  "not_run", HostDirectPathProof: "not_run",
		Modes: []modeAvailability{
			{ID: "direct", Availability: "implemented", GeneralHostActivation: true},
			{ID: "proxy_only", Availability: "implemented", GeneralHostActivation: true},
			{ID: "smart_routing", Availability: "disposable_guest_only", GeneralHostActivation: false},
		},
	}
	if status.Selected != "" {
		// The historical state decoder accepts an unvalidated Selected field.
		// Never turn unexpected private bytes into a displayed profile value.
		if !validModeProfileID(status.Selected) {
			return overview, sc.Fault("invalid_state", "selected profile identity cannot be verified")
		}
		overview.SelectedProfileID = status.Selected
	}
	switch status.Health {
	case "not_tested", "core_unavailable", "unexpected_active_service",
		"historical_proxy_failure_direct_unaffected", "service_state_unavailable",
		"service_ownership_conflict", "guarded_trial_unconfirmed",
		"supervised_record_not_freshly_verified":
		overview.StatusHealth = status.Health
	default:
		if status.Health != "" {
			return overview, sc.Fault("invalid_state", "service health classification cannot be verified")
		}
	}
	switch status.Observed {
	case "active", "inactive", "failed", "unknown":
		overview.ProxyServiceState = status.Observed
		if observationErr == nil {
			if status.Observed == "unknown" {
				return overview, sc.Fault("invalid_state", "service observation cannot be verified")
			}
			if ((status.Desired == "direct" && status.Observed == "inactive") ||
				(status.Desired == "proxy" && status.Observed == "active")) &&
				status.Health != "not_tested" {
				return overview, sc.Fault("invalid_state", "service observation conflicts with its health classification")
			}
			overview.EvidenceScope = "local_proxy_service_only"
			// An inactive product proxy cannot prove the host route table is
			// Direct: foreign owners or stale network policy may still exist.
			// Only the active, ownership-verified Proxy Only mode is observable.
			if status.Desired == "proxy" && status.Observed == "active" {
				overview.ObservedMode = "proxy_only"
			}
		}
	default:
		if !strings.HasPrefix(status.Observed, "smart_tun_") ||
			observationErr == nil || sc.ErrorCode(observationErr) != "guard_pending" {
			return overview, sc.Fault("invalid_state", "service observation cannot be verified")
		}
		phase := strings.TrimPrefix(status.Observed, "smart_tun_")
		if phase == "" {
			return overview, sc.Fault("invalid_state", "trial phase cannot be verified")
		}
		for _, c := range phase {
			if (c < 'a' || c > 'z') && c != '_' {
				return overview, sc.Fault("invalid_state", "trial phase cannot be verified")
			}
		}
		overview.TrialPhase = phase
		overview.ProxyServiceState = "not_inspected"
		overview.EvidenceScope = "experimental_trial_record_only"
		// Neither an admitted active mode nor a real VPN path is proven.
	}
	return overview, nil
}

func runModeOverview(jsonMode bool, read func() (sc.Status, error)) int {
	status, observationErr := read()
	if status.Desired == "" {
		if observationErr == nil {
			observationErr = sc.Fault("invalid_state", "desired mode cannot be verified")
		}
		return output(jsonMode, nil, observationErr)
	}
	report, inspectErr := modeOverviewFromStatus(status, observationErr)
	if inspectErr != nil {
		// Untrusted private status fields must not inherit a weaker,
		// unrelated service/guard error as their classification.
		observationErr = inspectErr
	}
	if report.DesiredMode == "" {
		return output(jsonMode, nil, observationErr)
	}
	if jsonMode || observationErr == nil {
		return output(jsonMode, report, observationErr)
	}
	// Keep safe partial mode diagnostics visible even on an uncertain state.
	// The error remains nonzero; no unknown state is treated as Direct.
	if output(false, report, nil) != 0 {
		return 1
	}
	fmt.Fprintf(os.Stderr, "Error [%s]: %s\n", sc.ErrorCode(observationErr), observationErr)
	return 1
}
