package sc

// Pure legacy synthetic evidence validator retained as a test oracle.
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
