package sc

import (
	"net/url"
	"strings"
)

const (
	pathDiagnosticsMinTargets = 2
	pathDiagnosticsMaxTargets = 4
	pathDiagnosticsMaxURLSize = 2048
)

// PathDiagnosticTarget deliberately contains no destination URL, hostname,
// query, profile details, proxy credentials or response body. A target index
// permits matching results with the operator's own private input list.
type PathDiagnosticTarget struct {
	Index      int    `json:"index"`
	Status     string `json:"status"`
	HTTPStatus int    `json:"http_status,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	ErrorCode  string `json:"error_code,omitempty"`
}

// PathDiagnostics is a bounded, read-only HOST NETWORK observation. It is not
// a Runtime Health Guard, transport ownership attestation or routing/activation
// authorization. Each target is tested using only the requested transport;
// one site's failure is not automatically a dead VPN and no recovery runs.
type PathDiagnostics struct {
	Path                 string                 `json:"path"`
	Assessment           string                 `json:"assessment"`
	TargetCount          int                    `json:"target_count"`
	ReachableCount       int                    `json:"reachable_count"`
	FailedCount          int                    `json:"failed_count"`
	Samples              []PathDiagnosticTarget `json:"samples"`
	HostNetworkReadOnly  bool                   `json:"host_network_read_only"`
	FallbackAttempted    bool                   `json:"fallback_attempted"`
	TunnelHealthVerified bool                   `json:"tunnel_health_verified"`
	ActivationReady      bool                   `json:"activation_ready"`
}

func validatePathDiagnosticTargets(path string, targets []string) error {
	if path != "direct" && path != "proxy" {
		return Fault("invalid_arguments", "diagnostic path must be direct or proxy")
	}
	if len(targets) < pathDiagnosticsMinTargets || len(targets) > pathDiagnosticsMaxTargets {
		return Fault("invalid_arguments", "path diagnostics require two to four distinct HTTP(S) hosts")
	}
	seen := make(map[string]bool, len(targets))
	for _, text := range targets {
		if text == "" || len(text) > pathDiagnosticsMaxURLSize {
			return Fault("invalid_arguments", "invalid diagnostic target length")
		}
		u, err := url.Parse(text)
		if err != nil || u.Opaque != "" || u.User != nil || u.Fragment != "" ||
			(u.Scheme != "https" && u.Scheme != "http") ||
			u.Host == "" || u.Hostname() == "" || strings.ContainsAny(text, "\r\n\t") {
			return Fault("invalid_arguments", "diagnostic target must be an HTTP(S) URL without credentials or fragment")
		}
		// Hostnames alone are only a minimum distinctness check: DNS aliases
		// can share a server. Do not claim independent foreign providers.
		hostname := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		if seen[hostname] {
			return Fault("invalid_arguments", "diagnostic targets must have different hostnames")
		}
		seen[hostname] = true
	}
	return nil
}

// runPathDiagnostics is dependency-injected solely to make aggregate decision
// policy testable without installed systemd or outbound network access.
// Production always binds each probe to Manager.Probe (no fallback).
func runPathDiagnostics(path string, targets []string, probe func(string) (ProbeResult, error)) (PathDiagnostics, error) {
	report := PathDiagnostics{
		Path: path, Assessment: "not_tested",
		HostNetworkReadOnly: true, FallbackAttempted: false,
		TunnelHealthVerified: false, ActivationReady: false,
	}
	if err := validatePathDiagnosticTargets(path, targets); err != nil {
		return report, err
	}
	if probe == nil {
		return report, Fault("diagnostic_unavailable", "diagnostic probe function is unavailable")
	}
	report.TargetCount = len(targets)
	report.Samples = make([]PathDiagnosticTarget, 0, len(targets))
	for i, destination := range targets {
		result, err := probe(destination)
		entry := PathDiagnosticTarget{
			Index: i, Status: result.Result, HTTPStatus: result.Code,
			DurationMs: result.DurationMs,
		}
		if err == nil && result.Path == path &&
			result.Result == "reachable" && result.Code >= 200 && result.Code < 300 {
			report.ReachableCount++
		} else {
			report.FailedCount++
			if err != nil {
				entry.ErrorCode = ErrorCode(err)
			} else if result.Code >= 300 && result.Code < 400 && result.Path == path {
				// Redirects/captive portals do not establish that the
				// selected destination returned its expected HTTP content.
				entry.Status = "redirect_unverified"
				entry.ErrorCode = "probe_redirect_unverified"
			} else {
				entry.ErrorCode = "diagnostic_inconsistent"
			}
			if entry.Status == "" {
				entry.Status = "failed"
			}
		}
		report.Samples = append(report.Samples, entry)
	}
	switch {
	case report.ReachableCount == report.TargetCount:
		report.Assessment = "all_targets_reachable"
		return report, nil
	case report.ReachableCount > 0:
		report.Assessment = "mixed_results"
		return report, Fault("probe_set_partial", "some selected-path targets failed; path-wide health is unverified")
	default:
		report.Assessment = "no_targets_reachable"
		return report, Fault("probe_set_unreachable", "no selected-path target succeeded; cause is not independently established")
	}
}

// DiagnosePath never uses direct probes to rescue/prove a failed proxy result;
// callers can request a separate Direct report for comparison. No timer,
// route modification, daemon, automatic fallback or state transition exists.
func (m *Manager) DiagnosePath(path string, targets []string) (PathDiagnostics, error) {
	return runPathDiagnostics(path, targets, func(target string) (ProbeResult, error) {
		return m.Probe(path, target)
	})
}
