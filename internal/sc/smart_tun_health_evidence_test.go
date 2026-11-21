package sc

// Verify strict selected-HTTPS result classification in live TLS/HTTP tests.
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
