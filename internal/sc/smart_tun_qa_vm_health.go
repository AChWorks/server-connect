package sc

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// Fixed QEMU validation lane: a trusted HTTPS response on a TUN-bound socket,
// plus a separately device/mark-bound underlay transport. This proves only
// selected IPv4 TCP/TLS/HTTPS in the disposable VM. UDP, DNS and IPv6 remain
// explicitly NOT_RUN and are never promoted by these observations.
func probeSmartTUNQAVMHealth(parent context.Context) SmartTUNHealthEvidence {
	start := time.Now()
	e := smartTUNHealthNotRunEvidence()
	ctx, cancel := context.WithTimeout(parent, smartTUNHealthRoundTimeout)
	defer cancel()
	e.ProbeCount = 2
	e.UnderlayHealthy = smartTUNVMDialUnderlay(ctx)
	selected := smartTUNVMHTTPSProbe(ctx)
	e.HTTPSResults[0] = selected
	e.IPv4HTTPS = selected.Result == "pass" && selected.StatusCode == 200
	e.IPv4TCP = e.IPv4HTTPS
	e.VPNHealthy = e.UnderlayHealthy && e.IPv4HTTPS
	if !e.UnderlayHealthy {
		e.Reason = "vm_protected_underlay_failed"
	} else if !e.IPv4HTTPS {
		e.Reason = "vm_selected_https_failed"
	} else {
		e.Reason = "vm_https_only_udp_dns_not_run"
	}
	if !e.IPv4HTTPS {
		e.FailedTargets = 1
	}
	if ctx.Err() != nil {
		e.VPNHealthy = false
		e.Reason = "vm_round_canceled"
	}
	e.ElapsedMS = time.Since(start).Milliseconds()
	return e
}

func smartTUNVMControl(device string, mark bool) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			if socketErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device); socketErr != nil {
				return
			}
			if mark {
				socketErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(nativeTUNBypassMark))
			}
		}); err != nil {
			return err
		}
		return socketErr
	}
}

func smartTUNVMDialUnderlay(ctx context.Context) bool {
	dialer := net.Dialer{Timeout: 1500 * time.Millisecond, Control: smartTUNVMControl(smartTUNVMUnderlay, true)}
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(smartTUNVMEndpoint, "19182"))
	if err != nil {
		return false
	}
	return conn.Close() == nil
}

func smartTUNVMHTTPSProbe(ctx context.Context) SmartTUNHTTPSResult {
	dialer := &net.Dialer{Timeout: 2500 * time.Millisecond, Control: smartTUNVMControl(smartTUNVMInterface, false)}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "one.one.one.one"},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", "1.0.0.1:443")
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3000 * time.Millisecond, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://one.one.one.one/cdn-cgi/trace", nil)
	if err != nil {
		return SmartTUNHTTPSResult{Result: "invalid_response"}
	}
	resp, err := client.Do(req)
	if err != nil {
		var ce *tls.CertificateVerificationError
		if errors.As(err, &ce) {
			return SmartTUNHTTPSResult{Result: "tls_identity_failed"}
		}
		if ctx.Err() != nil {
			return SmartTUNHTTPSResult{Result: "canceled"}
		}
		return SmartTUNHTTPSResult{Result: "transport_failed"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SmartTUNHTTPSResult{Result: "http_status", StatusCode: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 || !strings.Contains(string(data), "ip=") || !strings.Contains(string(data), "visit_scheme=https") {
		return SmartTUNHTTPSResult{Result: "invalid_response", StatusCode: 200}
	}
	if ctx.Err() != nil {
		return SmartTUNHTTPSResult{Result: "canceled", StatusCode: 200}
	}
	return SmartTUNHTTPSResult{Result: "pass", StatusCode: 200}
}

func validSmartTUNQAVMHealthEvidence(e SmartTUNHealthEvidence) bool {
	if e.ProbeCount == 0 {
		zero := smartTUNHealthNotRunEvidence()
		zero.Reason, zero.ElapsedMS = "round_canceled", e.ElapsedMS
		return e == zero
	}
	if e.ProbeCount != 2 || e.FailedTargets < 0 || e.FailedTargets > 1 ||
		e.IPv4UDP || e.IPv4DNS || e.IPv6TCP || e.IPv6UDP || e.IPv6DNS || e.IPv6HTTPS ||
		!validSmartTUNHTTPSResult(e.HTTPSResults[0]) {
		return false
	}
	for _, r := range e.HTTPSResults[1:] {
		if r != (SmartTUNHTTPSResult{Result: "not_run"}) {
			return false
		}
	}
	passing := e.HTTPSResults[0] == (SmartTUNHTTPSResult{Result: "pass", StatusCode: 200})
	if e.IPv4HTTPS != passing || e.IPv4TCP != passing || e.FailedTargets != boolInt(!passing) {
		return false
	}
	switch e.Reason {
	case "vm_https_only_udp_dns_not_run":
		return e.UnderlayHealthy && passing && e.VPNHealthy
	case "vm_protected_underlay_failed":
		return !e.UnderlayHealthy && !e.VPNHealthy
	case "vm_selected_https_failed":
		return e.UnderlayHealthy && !passing && !e.VPNHealthy
	case "vm_round_canceled":
		return !e.VPNHealthy
	default:
		return false
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
