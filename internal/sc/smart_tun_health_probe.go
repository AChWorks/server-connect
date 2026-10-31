package sc

// These witnesses belong only to the fixed disconnected native TUN fixture.
// They are ordinary unproxied, unmarked host-origin VPN requests. The peer
// echoes a fresh nonce and the source it actually observed. That is useful
// synthetic path evidence, not geographic evidence or a configurable Internet
// health checker. Callers must revalidate the complete
// operation/native identity before publishing a round measured without locks.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	smartTUNHealthRoundTimeout = 4 * time.Second
	smartTUNHealthProbeTimeout = 2500 * time.Millisecond
)

// A value-only result can be bound to the strict operation journal. Disabled
// IPv6 fields remain false; VPNHealthy considers only the requested families.
// ElapsedMS is observed elapsed time, not a clamped deadline claim.
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
	family         int
	protocol       string
	target         int
	address        string
	expectedSource string
	underlay       bool
}

type smartTUNHealthSample struct {
	probe  smartTUNHealthProbe
	result SmartTUNHTTPSResult
}

func smartTUNHealthPlan(ipv6 bool) []smartTUNHealthProbe {
	plan := []smartTUNHealthProbe{{family: 4, protocol: "tcp", target: -1,
		address: "10.254.72.2", expectedSource: "10.254.72.1", underlay: true}}
	addresses := []string{"8.8.8.8", "198.51.100.42"}
	if ipv6 {
		addresses = append(addresses, "2606:4700:8::8", "2606:4700:5::10")
	}
	for target, address := range addresses {
		family := 4
		if target >= 2 {
			family = 6
		}
		for _, protocol := range []string{"tcp", "udp", "dns", "https"} {
			plan = append(plan, smartTUNHealthProbe{family: family, protocol: protocol,
				target: target, address: address, expectedSource: address})
		}
	}
	return plan
}

func probeSmartTUNHealth(parent context.Context, ipv6 bool) SmartTUNHealthEvidence {
	return runSmartTUNHealthProbes(parent, ipv6, probeSmartTUNHealthEndpoint)
}

// The private runner seam tests aggregation and cancellation without requiring
// native networking. The production caller has no externally supplied targets,
// dialer, proxy, resolver or callback. At most 17 workers/connections exist and
// every one is joined before returning, including cancellation/error paths.
func runSmartTUNHealthProbes(parent context.Context, ipv6 bool,
	probe func(context.Context, smartTUNHealthProbe) SmartTUNHTTPSResult) SmartTUNHealthEvidence {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, smartTUNHealthRoundTimeout)
	defer cancel()
	if ctx.Err() != nil {
		result := smartTUNHealthNotRunEvidence()
		result.Reason = "round_canceled"
		return result
	}
	plan := smartTUNHealthPlan(ipv6)
	results := make(chan smartTUNHealthSample, len(plan))
	for _, request := range plan {
		go func(p smartTUNHealthProbe) {
			results <- smartTUNHealthSample{probe: p, result: probe(ctx, p)}
		}(request)
	}
	samples := make([]smartTUNHealthSample, 0, len(plan))
	for range plan {
		samples = append(samples, <-results)
	}
	evidence := summarizeSmartTUNHealth(ipv6, samples)
	evidence.ElapsedMS = time.Since(started).Milliseconds()
	if ctx.Err() != nil {
		// A context-expired round cannot publish success from earlier samples.
		// Nor may it erase a Direct leak or protected-path failure already
		// observed before a different request consumed the remaining budget.
		evidence.VPNHealthy = false
		critical := false
		for _, sample := range samples {
			if sample.result.Result == "path_mismatch" || sample.probe.underlay &&
				sample.result.Result != "pass" && sample.result.Result != "canceled" {
				critical = true
			}
		}
		if !critical {
			evidence.Reason = "round_canceled"
		}
	}
	return evidence
}

func summarizeSmartTUNHealth(ipv6 bool, samples []smartTUNHealthSample) SmartTUNHealthEvidence {
	result := smartTUNHealthNotRunEvidence()
	result.ProbeCount = len(samples)
	failed := [4]bool{}
	pathMismatch := false
	for _, sample := range samples {
		p := sample.probe
		ok := sample.result.Result == "pass" && (p.protocol != "https" || sample.result.StatusCode == 200)
		if p.underlay {
			result.UnderlayHealthy = ok
			continue
		}
		if p.protocol == "https" && p.target >= 0 && p.target < len(result.HTTPSResults) {
			result.HTTPSResults[p.target] = sample.result
		}
		if p.target >= 0 && p.target < len(failed) && !ok {
			failed[p.target] = true
		}
		if sample.result.Result == "path_mismatch" {
			pathMismatch = true
		}
		if !ok {
			continue
		}
		switch {
		case p.family == 4 && p.protocol == "tcp":
			result.IPv4TCP = true
		case p.family == 4 && p.protocol == "udp":
			result.IPv4UDP = true
		case p.family == 4 && p.protocol == "dns":
			result.IPv4DNS = true
		case p.family == 4 && p.protocol == "https":
			result.IPv4HTTPS = true
		case p.family == 6 && p.protocol == "tcp":
			result.IPv6TCP = true
		case p.family == 6 && p.protocol == "udp":
			result.IPv6UDP = true
		case p.family == 6 && p.protocol == "dns":
			result.IPv6DNS = true
		case p.family == 6 && p.protocol == "https":
			result.IPv6HTTPS = true
		}
	}
	for _, bad := range failed {
		if bad {
			result.FailedTargets++
		}
	}
	result.VPNHealthy = result.IPv4TCP && result.IPv4UDP && result.IPv4DNS && result.IPv4HTTPS &&
		(!ipv6 || result.IPv6TCP && result.IPv6UDP && result.IPv6DNS && result.IPv6HTTPS) && !pathMismatch
	switch {
	case pathMismatch:
		result.Reason = "vpn_path_mismatch"
	case !result.UnderlayHealthy:
		result.Reason = "protected_underlay_failed"
	case !result.IPv4TCP:
		result.Reason = "vpn_ipv4_tcp_failed"
	case !result.IPv4UDP:
		result.Reason = "vpn_ipv4_udp_failed"
	case !result.IPv4DNS:
		result.Reason = "vpn_ipv4_dns_failed"
	case !result.IPv4HTTPS:
		result.Reason = "vpn_ipv4_https_failed"
	case ipv6 && !result.IPv6TCP:
		result.Reason = "vpn_ipv6_tcp_failed"
	case ipv6 && !result.IPv6UDP:
		result.Reason = "vpn_ipv6_udp_failed"
	case ipv6 && !result.IPv6DNS:
		result.Reason = "vpn_ipv6_dns_failed"
	case ipv6 && !result.IPv6HTTPS:
		result.Reason = "vpn_ipv6_https_failed"
	case result.FailedTargets > 0:
		result.Reason = "healthy_partial_targets"
	default:
		result.Reason = "healthy"
	}
	return result
}

func probeSmartTUNHealthEndpoint(ctx context.Context, probe smartTUNHealthProbe) SmartTUNHTTPSResult {
	// One failed target must finish before the aggregate round deadline, so
	// a healthy independent target can still establish the protocol result.
	ctx, cancel := context.WithTimeout(ctx, smartTUNHealthProbeTimeout)
	defer cancel()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return SmartTUNHTTPSResult{Result: "nonce_unavailable"}
	}
	port := 19220
	network := "tcp"
	if probe.protocol == "udp" || probe.protocol == "dns" {
		network, port = "udp", 19221
	}
	if probe.protocol == "dns" {
		port = 19222
	}
	if probe.protocol == "https" {
		port = smartTUNHealthHTTPSPort
	}
	network += strconv.Itoa(probe.family)
	dialer := net.Dialer{}
	if probe.underlay {
		// Omitting an HTTP proxy does not prove Direct under an active TUN.
		// Bind both source and native device, and explicitly bypass our capture
		// mark. The independent peer must still observe that exact source.
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP("10.254.72.1")}
		dialer.Control = smartTUNHealthUnderlayControl
	}
	connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(probe.address, strconv.Itoa(port)))
	if err != nil {
		return SmartTUNHTTPSResult{Result: smartTUNHealthTransportFailure(ctx, err)}
	}
	return smartTUNHealthExchangeWithDeadline(ctx, connection, probe, nonce)
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
	if probe.protocol == "https" {
		return exchangeSmartTUNHTTPSHealth(ctx, connection, probe, nonce)
	}
	return SmartTUNHTTPSResult{Result: exchangeSmartTUNHealth(ctx, connection, probe, nonce)}
}

func smartTUNHealthUnderlayControl(_, _ string, raw syscall.RawConn) error {
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		if socketErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "scqaedge0"); socketErr != nil {
			return
		}
		socketErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(nativeTUNBypassMark))
	}); err != nil {
		return err
	}
	return socketErr
}

// One small exact response is accepted; trailing bytes, stale nonce, a malformed
// DNS response or a different observed source cannot turn Direct into VPN proof.
func exchangeSmartTUNHealth(ctx context.Context, connection net.Conn, probe smartTUNHealthProbe, nonce []byte) string {
	if len(nonce) != 16 {
		return "nonce_unavailable"
	}
	request := []byte("SCHEALTH1 " + hex.EncodeToString(nonce) + "\n")
	if probe.protocol == "dns" {
		request = smartTUNHealthDNSQuery(nonce)
	}
	if count, err := connection.Write(request); err != nil || count != len(request) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return smartTUNHealthTransportFailure(ctx, err)
	}
	var reply []byte
	if probe.protocol == "tcp" {
		var err error
		reply, err = io.ReadAll(io.LimitReader(connection, 257))
		if err != nil {
			return smartTUNHealthTransportFailure(ctx, err)
		}
	} else {
		reply = make([]byte, 257)
		count, err := connection.Read(reply)
		if err != nil {
			return smartTUNHealthTransportFailure(ctx, err)
		}
		reply = reply[:count]
	}
	// A full buffer can be the limiter's synthetic EOF or a truncated
	// datagram, not a complete reply. Preserve critical source evidence only
	// after a successful bounded read, even if cancellation follows it.
	classification := "invalid_response"
	if len(reply) <= 256 {
		if probe.protocol == "dns" {
			if bytes.Equal(reply, smartTUNHealthDNSResponse(request, true)) {
				classification = "pass"
			} else if bytes.Equal(reply, smartTUNHealthDNSResponse(request, false)) {
				classification = "path_mismatch"
			}
		} else {
			classification = smartTUNHealthReply(reply, probe, nonce)
		}
	}
	if ctx.Err() != nil && classification != "path_mismatch" {
		return "canceled"
	}
	return classification
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

func smartTUNHealthDNSQuery(nonce []byte) []byte {
	query := make([]byte, 12, 96)
	copy(query[:2], nonce[:2])
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range []string{hex.EncodeToString(nonce[2:]), "scqa", "example", "test"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	return append(query, 0, 0, 1, 0, 1)
}

func smartTUNHealthDNSResponse(query []byte, vpn bool) []byte {
	response := append([]byte{}, query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	marker := byte(11)
	if vpn {
		marker = 22
	}
	return append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, marker)
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
