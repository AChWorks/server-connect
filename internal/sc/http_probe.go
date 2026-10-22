package sc

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// probeHTTPPath is the shared no-fallback HTTP(S) transport used by the
// existing one-target probe and bounded multi-target diagnostics. The URL
// of the destination, private auth and any response content are never
// included in returned errors. A proxy request only targets the verified
// loopback listener; a missing proxy is a failure, never a Direct request.
func probeHTTPPath(via, destination string, selectedProxy *url.URL) (ProbeResult, error) {
	if via != "direct" && via != "proxy" {
		return ProbeResult{}, Fault("invalid_arguments", "probe path must be direct or proxy")
	}
	parsed, err := url.Parse(destination)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ProbeResult{}, Fault("invalid_arguments", "probe URL must be HTTP(S)")
	}
	if via == "proxy" && (selectedProxy == nil || selectedProxy.Scheme != "http" ||
		selectedProxy.Hostname() != "127.0.0.1" || selectedProxy.User == nil) {
		return ProbeResult{Path: via, Result: "unavailable"}, Fault("proxy_unavailable", "verified loopback proxy unavailable")
	}
	if via == "direct" && selectedProxy != nil {
		return ProbeResult{Path: via, Result: "unavailable"}, Fault("invalid_arguments", "Direct path cannot use a proxy")
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 6 * time.Second}).DialContext,
		TLSHandshakeTimeout: 7 * time.Second, DisableKeepAlives: true,
	}
	if via == "proxy" {
		transport.Proxy = http.ProxyURL(selectedProxy)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: 12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	start := time.Now()
	request, err := http.NewRequest(http.MethodGet, destination, nil)
	if err != nil {
		return ProbeResult{}, Fault("invalid_arguments", "invalid HTTP(S) probe request")
	}
	request.Header.Set("Cache-Control", "no-cache")
	response, err := client.Do(request)
	result := ProbeResult{Path: via, DurationMs: time.Since(start).Milliseconds(), Result: "failed"}
	if err != nil {
		var dnsErr *net.DNSError
		var authorityErr x509.UnknownAuthorityError
		var certErr x509.CertificateInvalidError
		switch {
		case errors.As(err, &dnsErr):
			return result, Fault("probe_dns", "path DNS resolution failed")
		case errors.As(err, &authorityErr) || errors.As(err, &certErr):
			return result, Fault("probe_tls", "path TLS certificate validation failed")
		case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded):
			return result, Fault("probe_timeout", "path probe timed out")
		default:
			var connectErr *net.OpError
			if errors.As(err, &connectErr) {
				return result, Fault("probe_connect", "path TCP or proxy connection failed")
			}
			return result, Fault("probe_transport", "path request failed; root cause unverified")
		}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 2048))
	result.Code = response.StatusCode
	if response.StatusCode >= 200 && response.StatusCode < 400 {
		result.Result = "reachable"
		return result, nil
	}
	result.Result = "http_error"
	return result, Fault("probe_http", "selected path returned unhealthy HTTP response")
}
