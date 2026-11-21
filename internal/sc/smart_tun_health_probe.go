package sc

// The current Native selected-HTTPS guard uses this bounded TLS/HTTP response
// classifier. The historical v2/v3 journal still requires the exact
// SmartTUNHealthEvidence JSON shape, but the retired v4 synthetic multi-
// protocol probe/aggregator is no longer part of production or QA.
import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
)

type SmartTUNHealthEvidence struct {
	IPv4HTTPS       bool                   `json:"ipv4_https"`
	IPv6HTTPS       bool                   `json:"ipv6_https"`
	HTTPSResults    [4]SmartTUNHTTPSResult `json:"https_results"`
	UnderlayHealthy bool                   `json:"underlay_healthy"`
	VPNHealthy      bool                   `json:"vpn_healthy"`
	IPv4TCP         bool                   `json:"ipv4_tcp"`
	IPv4UDP         bool                   `json:"ipv4_udp"`
	IPv4DNS         bool                   `json:"ipv4_dns"`
	IPv6TCP         bool                   `json:"ipv6_tcp"`
	IPv6UDP         bool                   `json:"ipv6_udp"`
	IPv6DNS         bool                   `json:"ipv6_dns"`
	FailedTargets   int                    `json:"failed_targets"`
	ProbeCount      int                    `json:"probe_count"`
	ElapsedMS       int64                  `json:"elapsed_ms"`
	Reason          string                 `json:"reason"`
}

type smartTUNHealthProbe struct {
	expectedSource string
}

func smartTUNHealthExchangeWithDeadline(ctx context.Context, connection net.Conn, probe smartTUNHealthProbe, nonce []byte) SmartTUNHTTPSResult {
	defer connection.Close()
	closed := make(chan struct{})
	stopClose := context.AfterFunc(ctx, func() {
		_ = connection.Close()
		close(closed)
	})
	defer func() {
		if !stopClose() {
			<-closed
		}
	}()
	deadline, ok := ctx.Deadline()
	if !ok || connection.SetDeadline(deadline) != nil {
		return SmartTUNHTTPSResult{Result: "deadline_unavailable"}
	}
	return exchangeSmartTUNHTTPSHealth(ctx, connection, probe, nonce)
}

func smartTUNHealthReply(reply []byte, probe smartTUNHealthProbe, nonce []byte) string {
	expected := "SCHEALTH1 " + hex.EncodeToString(nonce) + " " + probe.expectedSource + "\n"
	if string(reply) == expected {
		return "pass"
	}
	prefix := "SCHEALTH1 " + hex.EncodeToString(nonce) + " "
	if strings.HasPrefix(string(reply), prefix) && bytes.HasSuffix(reply, []byte{'\n'}) {
		source := strings.TrimSuffix(strings.TrimPrefix(string(reply), prefix), "\n")
		if _, err := netip.ParseAddr(source); err == nil {
			return "path_mismatch"
		}
	}
	return "invalid_response"
}

func smartTUNHealthTransportFailure(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return "canceled"
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return "timeout"
	}
	return "transport_failed"
}
