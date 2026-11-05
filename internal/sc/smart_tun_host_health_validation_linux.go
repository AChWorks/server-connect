//go:build linux

package sc

// ValidateHostHealthEvidence checks an already decoded value against its
// immutable requested round and recomputes coverage/health. The supervising
// journal must additionally reject ambiguous/unknown JSON members, revalidate
// its live operation/boot/native ownership and reject stale round publication.
func ValidateHostHealthEvidence(p HostHealthPlan, e HostHealthEvidence) error {
	if err := ValidateHostHealthPlan(p); err != nil {
		return err
	}
	base := hostHealthNotRun(p)
	if e.Round != base.Round || e.OperationID != base.OperationID || e.BootID != base.BootID ||
		e.ConfigSHA256 != base.ConfigSHA256 || e.PlanSHA256 != base.PlanSHA256 ||
		e.IPv4.Enabled != base.IPv4.Enabled || e.IPv6.Enabled != base.IPv6.Enabled ||
		e.IPv4.DirectUnavailable != base.IPv4.DirectUnavailable || e.IPv6.DirectUnavailable != base.IPv6.DirectUnavailable ||
		e.ElapsedMS < 0 || e.StartedUptimeMS < 0 || e.CompletedUptimeMS < 0 {
		return hostHealthFault("health evidence does not match its requested operation, plan or round")
	}
	if e.ProbeCount == 0 {
		switch e.Reason {
		case "round_canceled", "boot_identity_mismatch", "clock_unavailable":
		default:
			return hostHealthFault("unmeasured health evidence has an invalid reason")
		}
		base.Reason = e.Reason
		base.StartedUptimeMS = e.StartedUptimeMS
		base.CompletedUptimeMS = e.CompletedUptimeMS
		base.ElapsedMS = e.ElapsedMS
		if e != base {
			return hostHealthFault("unmeasured health evidence contains measured success")
		}
		return nil
	}
	probes := hostHealthProbes(p)
	if e.ProbeCount != len(probes) || e.StartedUptimeMS <= 0 || (e.CompletedUptimeMS != 0 && e.CompletedUptimeMS < e.StartedUptimeMS) {
		return hostHealthFault("health evidence probe count or monotonic timing invalid")
	}
	samples := make([]hostHealthSample, 0, len(probes))
	for _, probe := range probes {
		family := e.IPv4
		if probe.family == 6 {
			family = e.IPv6
		}
		var result HostHealthResult
		switch probe.role {
		case "selected":
			result = family.SelectedHTTPS
		case "direct":
			result = family.DirectHTTPS
		case "dns":
			result.Result = family.DNS
		case "endpoint":
			result.Result = e.EndpointTCP
		case "domestic":
			result = e.DomesticHTTPS
		}
		if !validHostHealthResult(probe, result) {
			return hostHealthFault("health evidence contains an invalid protocol result")
		}
		samples = append(samples, hostHealthSample{probe: probe, result: result})
	}
	expected := summarizeHostHealth(p, samples, e.Reason == "round_canceled")
	if e.Reason == "clock_unavailable" && expected.Reason != "path_mismatch" {
		expected.Reason = "clock_unavailable"
		expected.Healthy = false
	}
	expected.StartedUptimeMS = e.StartedUptimeMS
	expected.CompletedUptimeMS = e.CompletedUptimeMS
	expected.ElapsedMS = e.ElapsedMS
	if e != expected {
		return hostHealthFault("health evidence coverage or healthy state contradicts its results")
	}
	if e.Healthy && (e.CompletedUptimeMS == 0 || e.ElapsedMS > smartTUNHealthRoundTimeout.Milliseconds() ||
		e.CompletedUptimeMS-e.StartedUptimeMS > smartTUNHealthRoundTimeout.Milliseconds()) {
		return hostHealthFault("healthy evidence exceeded its bounded monotonic round")
	}
	return nil
}
func validHostHealthResult(p hostHealthProbe, r HostHealthResult) bool {
	if p.role == "endpoint" || p.role == "dns" {
		if r.HTTPStatus != 0 || r.ObservedIP != "" {
			return false
		}
		switch r.Result {
		case "pass", "not_run", "canceled", "timeout", "transport_failed", "deadline_unavailable", "source_binding_failed", "nonce_unavailable", "invalid_request":
			return true
		case "dns_oversized_response", "dns_invalid_response":
			return p.role == "dns"
		}
		return false
	}
	switch r.Result {
	case "pass":
		return r.HTTPStatus == 200 && r.ObservedIP == p.expected
	case "path_mismatch":
		_, valid := hostHealthPublicIP(r.ObservedIP, 0)
		return r.HTTPStatus == 200 && valid && r.ObservedIP != p.expected
	case "http_status":
		return r.HTTPStatus >= 100 && r.HTTPStatus <= 599 && r.HTTPStatus != 200 && r.ObservedIP == ""
	case "not_run", "canceled", "timeout", "transport_failed", "deadline_unavailable", "source_binding_failed", "nonce_unavailable",
		"tls_identity_failed", "tls_handshake_failed", "http_invalid_response", "http_oversized_response", "http_cache_unverified", "http_stale_response", "truncated_response":
		if r.HTTPStatus != 0 && r.HTTPStatus != 200 {
			return false
		}
		// A complete matching response may race cancellation; it remains explicit
		// canceled evidence and must never be counted as pass.
		return r.ObservedIP == "" || r.Result == "canceled" && r.HTTPStatus == 200 && r.ObservedIP == p.expected
	}
	return false
}
