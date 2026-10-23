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

// runPathDiagnostics isolates aggregation policy from the installed service.
// Production Direct uses Manager.Probe; Proxy uses a pinned selected transport
// and a short-lived identity check around every request (never a long lock).
func runPathDiagnostics(path string, targets []string, probe func(string) (ProbeResult, error)) (PathDiagnostics, error) {
	return runPathDiagnosticsChecked(path, targets, probe, nil)
}

// identityUnchanged verifies that all responses still belong to one selected
// outbound. Failure invalidates the WHOLE set, including prior successful
// samples. Never hold the Manager lifecycle lock while probe is executing.
func runPathDiagnosticsChecked(path string, targets []string, probe func(string) (ProbeResult, error), identityUnchanged func() bool) (PathDiagnostics, error) {
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
	pathChanged := false
	for i, destination := range targets {
		if identityUnchanged != nil && !identityUnchanged() {
			pathChanged = true
			break
		}
		result, err := probe(destination)
		if identityUnchanged != nil && !identityUnchanged() {
			// Do not report even this target as successful: it may have
			// completed on a different service or profile generation.
			pathChanged = true
			break
		}
		entry := PathDiagnosticTarget{
			Index: i, Status: "failed", HTTPStatus: result.Code,
			DurationMs: result.DurationMs,
		}
		if err == nil && result.Path == path &&
			result.Result == "reachable" && result.Code >= 200 && result.Code < 300 {
			entry.Status = "reachable"
			report.ReachableCount++
		} else {
			report.FailedCount++
			switch {
			case result.Path != path:
				// A successful Direct response never proves selected Proxy.
				entry.Status = "unverified"
				entry.ErrorCode = "diagnostic_inconsistent"
			case err != nil:
				// A conflicting raw 'reachable' result is never trusted.
				// Retain only known non-success result categories and a
				// safe classified error (not its underlying raw message).
				if result.Result == "unavailable" || result.Result == "http_error" {
					entry.Status = result.Result
				}
				entry.ErrorCode = ErrorCode(err)
			case result.Code >= 300 && result.Code < 400:
				// A redirect does not prove destination content.
				entry.Status = "redirect_unverified"
				entry.ErrorCode = "probe_redirect_unverified"
			default:
				entry.Status = "unverified"
				entry.ErrorCode = "diagnostic_inconsistent"
			}
		}
		report.Samples = append(report.Samples, entry)
	}
	if pathChanged {
		// A successful sample taken before drift is no longer evidence
		// about one stable profile. Fill untouched targets without probing
		// a newly selected outbound or exposing sensitive path details.
		for i := range report.Samples {
			if report.Samples[i].Status == "reachable" {
				report.Samples[i].Status = "unverified"
				report.Samples[i].ErrorCode = "diagnostic_path_changed"
			}
		}
		for len(report.Samples) < report.TargetCount {
			report.Samples = append(report.Samples, PathDiagnosticTarget{
				Index: len(report.Samples), Status: "unverified", ErrorCode: "diagnostic_path_changed",
			})
		}
		report.ReachableCount = 0
		report.FailedCount = report.TargetCount
		report.Assessment = "path_changed_unverified"
		return report, Fault("diagnostic_path_changed", "selected proxy identity changed; aggregate path evidence is unverified")
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
	if path != "proxy" {
		return runPathDiagnostics(path, targets, func(target string) (ProbeResult, error) {
			return m.Probe(path, target)
		})
	}
	// Validate all destinations before inspecting local profile/service state.
	if err := validatePathDiagnosticTargets(path, targets); err != nil {
		return runPathDiagnostics(path, targets, nil)
	}
	return runSelectedProxyPathDiagnostics(targets, m.captureDiagnosticProxy)
}

// A capturing function is injected only so installed-state/transport behavior
// can be tested against disposable local fixtures, not a real systemd unit.
func runSelectedProxyPathDiagnostics(targets []string, capture func() (diagnosticProxySnapshot, error)) (PathDiagnostics, error) {
	initial, err := capture()
	if err != nil {
		// An unavailable selected Proxy must never silently fall back to
		// Direct; preserve per-target unavailable results and CLI errors.
		return runPathDiagnostics("proxy", targets, func(string) (ProbeResult, error) {
			return ProbeResult{Path: "proxy", Result: "unavailable"},
				Fault("proxy_unavailable", "selected proxy path cannot be verified")
		})
	}
	return runPathDiagnosticsChecked("proxy", targets, func(target string) (ProbeResult, error) {
		return probeHTTPPath("proxy", target, initial.proxy)
	}, func() bool {
		current, err := capture()
		return err == nil && current.identity == initial.identity
	})
}
