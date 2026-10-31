package sc

import "encoding/json"

// Version1 must retain its exact accepted wire shape during owned stop and
// cleanup. Re-encoding old evidence using the Version2 fields would make the
// next strict read reject the very journal needed to finish recovery.
type smartTUNLegacyHealthEvidence struct {
	UnderlayHealthy bool   `json:"underlay_healthy"`
	VPNHealthy      bool   `json:"vpn_healthy"`
	IPv4TCP         bool   `json:"ipv4_tcp"`
	IPv4UDP         bool   `json:"ipv4_udp"`
	IPv4DNS         bool   `json:"ipv4_dns"`
	IPv6TCP         bool   `json:"ipv6_tcp"`
	IPv6UDP         bool   `json:"ipv6_udp"`
	IPv6DNS         bool   `json:"ipv6_dns"`
	FailedTargets   int    `json:"failed_targets"`
	ProbeCount      int    `json:"probe_count"`
	ElapsedMS       int64  `json:"elapsed_ms"`
	Reason          string `json:"reason"`
}

func (s smartTUNSupervision) MarshalJSON() ([]byte, error) {
	type wire smartTUNSupervision
	if s.Version == 1 {
		e := s.Evidence
		if e.IPv4HTTPS || e.IPv6HTTPS || e.HTTPSResults != ([4]SmartTUNHTTPSResult{}) {
			return nil, activationJournalError("legacy supervision cannot contain HTTPS evidence")
		}
		return json.Marshal(struct {
			wire
			Evidence smartTUNLegacyHealthEvidence `json:"evidence"`
		}{wire: wire(s), Evidence: smartTUNLegacyHealthEvidence{
			UnderlayHealthy: e.UnderlayHealthy, VPNHealthy: e.VPNHealthy,
			IPv4TCP: e.IPv4TCP, IPv4UDP: e.IPv4UDP, IPv4DNS: e.IPv4DNS,
			IPv6TCP: e.IPv6TCP, IPv6UDP: e.IPv6UDP, IPv6DNS: e.IPv6DNS,
			FailedTargets: e.FailedTargets, ProbeCount: e.ProbeCount,
			ElapsedMS: e.ElapsedMS, Reason: e.Reason,
		}})
	}
	if s.Version != smartTUNSupervisionVersion {
		return nil, activationJournalError("unsupported supervision evidence version")
	}
	return json.Marshal(wire(s))
}

func validSmartTUNHTTPSResult(r SmartTUNHTTPSResult) bool {
	switch r.Result {
	case "pass", "invalid_response", "path_mismatch":
		return r.StatusCode == 200
	case "http_status":
		return r.StatusCode >= 100 && r.StatusCode <= 599 && r.StatusCode != 200
	case "http_invalid_response", "http_oversized_response", "http_truncated_response", "canceled", "timeout":
		return r.StatusCode == 0 || r.StatusCode == 200
	case "not_run", "transport_failed", "deadline_unavailable", "nonce_unavailable", "tls_identity_failed", "tls_handshake_failed":
		return r.StatusCode == 0
	default:
		return false
	}
}

func validSmartTUNHTTPSEvidence(e SmartTUNHealthEvidence, ipv6 bool) bool {
	if e.ProbeCount == 0 {
		// The only unmeasured round is cancellation before workers start.
		zero := smartTUNHealthNotRunEvidence()
		zero.Reason, zero.ElapsedMS = "round_canceled", e.ElapsedMS
		return e == zero
	}
	targets := 2
	if ipv6 {
		targets = 4
	}
	passed := [2]bool{}
	failed, mismatch := 0, false
	for target, result := range e.HTTPSResults {
		if !validSmartTUNHTTPSResult(result) {
			return false
		}
		if target >= targets {
			if result != (SmartTUNHTTPSResult{Result: "not_run"}) {
				return false
			}
			continue
		}
		if result.Result == "not_run" {
			return false
		}
		if result.Result == "pass" {
			passed[target/2] = true
		} else {
			failed++
		}
		mismatch = mismatch || result.Result == "path_mismatch"
	}
	if e.IPv4HTTPS != passed[0] || e.IPv6HTTPS != passed[1] || e.FailedTargets < failed {
		return false
	}
	if mismatch && e.Reason != "vpn_path_mismatch" {
		return false
	}
	if e.Reason == "vpn_path_mismatch" || e.Reason == "round_canceled" {
		return !e.VPNHealthy
	}
	wantVPN := e.IPv4TCP && e.IPv4UDP && e.IPv4DNS && e.IPv4HTTPS &&
		(!ipv6 || e.IPv6TCP && e.IPv6UDP && e.IPv6DNS && e.IPv6HTTPS)
	if e.VPNHealthy != wantVPN && !(e.Reason == "protected_underlay_failed" && !e.VPNHealthy) {
		return false
	}
	wantReason := "healthy"
	switch {
	case !e.UnderlayHealthy:
		wantReason = "protected_underlay_failed"
	case !e.IPv4TCP:
		wantReason = "vpn_ipv4_tcp_failed"
	case !e.IPv4UDP:
		wantReason = "vpn_ipv4_udp_failed"
	case !e.IPv4DNS:
		wantReason = "vpn_ipv4_dns_failed"
	case !e.IPv4HTTPS:
		wantReason = "vpn_ipv4_https_failed"
	case ipv6 && !e.IPv6TCP:
		wantReason = "vpn_ipv6_tcp_failed"
	case ipv6 && !e.IPv6UDP:
		wantReason = "vpn_ipv6_udp_failed"
	case ipv6 && !e.IPv6DNS:
		wantReason = "vpn_ipv6_dns_failed"
	case ipv6 && !e.IPv6HTTPS:
		wantReason = "vpn_ipv6_https_failed"
	case e.FailedTargets > 0:
		wantReason = "healthy_partial_targets"
	}
	return e.Reason == wantReason
}
