package sc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSmartTUNHealthFixedPlanAndEvidence(t *testing.T) {
	for _, dual := range []bool{false, true} {
		plan := smartTUNHealthPlan(dual)
		count := 9
		if dual {
			count = 17
		}
		if len(plan) != count || !plan[0].underlay || plan[0].address != "10.254.72.2" ||
			plan[0].expectedSource != "10.254.72.1" {
			t.Fatalf("wrong fixed synthetic plan: %+v", plan)
		}
		seen := map[string]bool{}
		for _, probe := range plan[1:] {
			key := probe.address + "/" + probe.protocol
			if probe.underlay || seen[key] || probe.expectedSource != probe.address {
				t.Fatalf("ambiguous VPN source/target: %+v", probe)
			}
			seen[key] = true
		}
		result := runSmartTUNHealthTestProbes(context.Background(), dual,
			func(context.Context, smartTUNHealthProbe) string { return "pass" })
		if !result.VPNHealthy || !result.UnderlayHealthy || result.ProbeCount != count ||
			result.Reason != "healthy" || result.FailedTargets != 0 || result.IPv6TCP != dual ||
			result.IPv6UDP != dual || result.IPv6DNS != dual || !result.IPv4HTTPS || result.IPv6HTTPS != dual {
			t.Fatalf("positive bounded round invalid: %+v", result)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil || len(fields) != 15 {
			t.Fatalf("journal evidence lost exact field set: %s %v", encoded, err)
		}
		for _, name := range []string{"underlay_healthy", "vpn_healthy", "ipv4_tcp", "ipv4_udp", "ipv4_dns",
			"ipv6_tcp", "ipv6_udp", "ipv6_dns", "ipv4_https", "ipv6_https", "https_results", "failed_targets", "probe_count", "elapsed_ms", "reason"} {
			if _, ok := fields[name]; !ok {
				t.Fatalf("required evidence field absent: %s", name)
			}
		}
	}
}

func TestSmartTUNHealthRequiresEachProtocolButToleratesOneFailedTarget(t *testing.T) {
	for _, tc := range []struct {
		name, reason        string
		dual, vpn, underlay bool
		failed              int
		result              func(smartTUNHealthProbe) string
	}{
		{name: "one-ipv4-site", reason: "healthy_partial_targets", vpn: true, underlay: true, failed: 1,
			result: func(p smartTUNHealthProbe) string {
				if p.target == 0 {
					return "transport_failed"
				}
				return "pass"
			}},
		{name: "one-ipv6-site", reason: "healthy_partial_targets", dual: true, vpn: true, underlay: true, failed: 1,
			result: func(p smartTUNHealthProbe) string {
				if p.target == 2 {
					return "timeout"
				}
				return "pass"
			}},
		{name: "both-dns-targets", reason: "vpn_ipv4_dns_failed", underlay: true, failed: 2,
			result: func(p smartTUNHealthProbe) string {
				if p.protocol == "dns" {
					return "timeout"
				}
				return "pass"
			}},
		{name: "all-ipv6-udp", reason: "vpn_ipv6_udp_failed", dual: true, underlay: true, failed: 2,
			result: func(p smartTUNHealthProbe) string {
				if p.family == 6 && p.protocol == "udp" {
					return "transport_failed"
				}
				return "pass"
			}},
		{name: "one-direct-leak", reason: "vpn_path_mismatch", underlay: true, failed: 1,
			result: func(p smartTUNHealthProbe) string {
				if p.target == 0 && p.protocol == "tcp" {
					return "path_mismatch"
				}
				return "pass"
			}},
		{name: "underlay-does-not-borrow-vpn", reason: "protected_underlay_failed", vpn: true,
			result: func(p smartTUNHealthProbe) string {
				if p.underlay {
					return "path_mismatch"
				}
				return "pass"
			}},
		{name: "live-underlay-dead-vpn", reason: "vpn_ipv4_tcp_failed", underlay: true, failed: 2,
			result: func(p smartTUNHealthProbe) string {
				if !p.underlay {
					return "transport_failed"
				}
				return "pass"
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runSmartTUNHealthTestProbes(context.Background(), tc.dual,
				func(_ context.Context, p smartTUNHealthProbe) string { return tc.result(p) })
			if result.Reason != tc.reason || result.VPNHealthy != tc.vpn || result.UnderlayHealthy != tc.underlay ||
				result.FailedTargets != tc.failed {
				t.Fatalf("incorrect independent/protocol aggregation: %+v", result)
			}
		})
	}
}

func TestSmartTUNHealthRoundCancellationJoinsEveryProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 17)
	var completed atomic.Int32
	finished := make(chan SmartTUNHealthEvidence, 1)
	go func() {
		finished <- runSmartTUNHealthTestProbes(ctx, true,
			func(ctx context.Context, _ smartTUNHealthProbe) string {
				entered <- struct{}{}
				<-ctx.Done()
				completed.Add(1)
				return "canceled"
			})
	}()
	// All 17 must start before any finishes: no sequential 17*timeout chain.
	for range 17 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("bounded probes were serialized or did not start")
		}
	}
	cancel()
	select {
	case result := <-finished:
		if completed.Load() != 17 || result.VPNHealthy || result.Reason != "round_canceled" || result.ProbeCount != 17 {
			t.Fatalf("cancellation leaked pending workers or passed: %+v completed=%d", result, completed.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not bound whole round")
	}
	called := false
	result := runSmartTUNHealthTestProbes(ctx, false, func(context.Context, smartTUNHealthProbe) string {
		called = true
		return "pass"
	})
	if called || result.ProbeCount != 0 || result.VPNHealthy || result.Reason != "round_canceled" {
		t.Fatalf("already-canceled round still launched work: %+v", result)
	}
	if smartTUNHealthProbeTimeout >= smartTUNHealthRoundTimeout || smartTUNHealthRoundTimeout > 4*time.Second {
		t.Fatal("per-site timeout leaves no budget for healthy alternate evidence")
	}
}

func TestSmartTUNHealthCanceledRoundRetainsObservedCriticalFailure(t *testing.T) {
	for _, underlay := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		observed := make(chan struct{})
		result := runSmartTUNHealthTestProbes(ctx, false, func(_ context.Context, p smartTUNHealthProbe) string {
			if underlay && p.underlay || !underlay && p.target == 0 && p.protocol == "tcp" {
				close(observed)
				return "path_mismatch"
			}
			if p.target == 1 && p.protocol == "dns" {
				<-observed
				cancel()
			}
			return "pass"
		})
		cancel()
		want := "vpn_path_mismatch"
		if underlay {
			want = "protected_underlay_failed"
		}
		if result.VPNHealthy || result.Reason != want || !validSmartTUNHTTPSEvidence(result, false) {
			t.Fatalf("cancellation hid observed critical failure: %+v want=%s", result, want)
		}
	}
}

func healthTestExchange(t *testing.T, protocol string, respond func([]byte, []byte) []byte) string {
	t.Helper()
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	nonce := bytes.Repeat([]byte{0xa6}, 16)
	requestSize := len("SCHEALTH1 ") + 32 + 1
	if protocol == "dns" {
		requestSize = len(smartTUNHealthDNSQuery(nonce))
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		request := make([]byte, requestSize)
		if _, err := io.ReadFull(server, request); err == nil {
			_, _ = server.Write(respond(request, nonce))
		}
	}()
	result := smartTUNHealthExchangeWithDeadline(ctx, client,
		smartTUNHealthProbe{protocol: protocol, expectedSource: "8.8.8.8"}, nonce)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("probe did not close the bounded connection")
	}
	return result.Result
}

func TestSmartTUNHealthTCPAndUDPRequireFreshExactPeerSource(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		for _, tc := range []struct {
			name, want string
			reply      func([]byte) []byte
		}{
			{name: "exact", want: "pass", reply: func(n []byte) []byte { return []byte("SCHEALTH1 " + hex.EncodeToString(n) + " 8.8.8.8\n") }},
			{name: "direct", want: "path_mismatch", reply: func(n []byte) []byte { return []byte("SCHEALTH1 " + hex.EncodeToString(n) + " 10.254.72.1\n") }},
			{name: "stale", want: "invalid_response", reply: func(n []byte) []byte { n[0] ^= 1; return []byte("SCHEALTH1 " + hex.EncodeToString(n) + " 8.8.8.8\n") }},
			{name: "trailing", want: "invalid_response", reply: func(n []byte) []byte { return []byte("SCHEALTH1 " + hex.EncodeToString(n) + " 8.8.8.8\nextra") }},
			{name: "missing-terminator", want: "invalid_response", reply: func(n []byte) []byte { return []byte("SCHEALTH1 " + hex.EncodeToString(n) + " 8.8.8.8") }},
			{name: "oversized", want: "invalid_response", reply: func([]byte) []byte { return bytes.Repeat([]byte{'a'}, 1024) }},
			{name: "untrusted-source-text", want: "invalid_response", reply: func(n []byte) []byte { return []byte("SCHEALTH1 " + hex.EncodeToString(n) + " secret.invalid\n") }},
		} {
			t.Run(protocol+"/"+tc.name, func(t *testing.T) {
				result := healthTestExchange(t, protocol, func(_ []byte, nonce []byte) []byte {
					return tc.reply(append([]byte{}, nonce...))
				})
				if result != tc.want {
					t.Fatalf("wrong source/nonce/frame result: got %q want %q", result, tc.want)
				}
			})
		}
	}
}

func TestSmartTUNHealthDNSRequiresExactNonceQuestionAndPathAnswer(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		reply      func([]byte) []byte
	}{
		{name: "vpn", want: "pass", reply: func(q []byte) []byte { return smartTUNHealthDNSResponse(q, true) }},
		{name: "direct", want: "path_mismatch", reply: func(q []byte) []byte { return smartTUNHealthDNSResponse(q, false) }},
		{name: "wrong-id", want: "invalid_response", reply: func(q []byte) []byte { r := smartTUNHealthDNSResponse(q, true); r[0] ^= 1; return r }},
		{name: "stale-question", want: "invalid_response", reply: func(q []byte) []byte { r := smartTUNHealthDNSResponse(q, true); r[14] ^= 1; return r }},
		{name: "wrong-flags", want: "invalid_response", reply: func(q []byte) []byte { r := smartTUNHealthDNSResponse(q, true); r[3] ^= 1; return r }},
		{name: "cached-ttl", want: "invalid_response", reply: func(q []byte) []byte { r := smartTUNHealthDNSResponse(q, true); r[len(r)-7] = 1; return r }},
		{name: "trailing", want: "invalid_response", reply: func(q []byte) []byte { return append(smartTUNHealthDNSResponse(q, true), 0) }},
		{name: "truncated", want: "invalid_response", reply: func(q []byte) []byte { return q[:12] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := healthTestExchange(t, "dns", func(query, _ []byte) []byte { return tc.reply(query) })
			if result != tc.want {
				t.Fatalf("invalid DNS source/nonce/frame result: got %q want %q", result, tc.want)
			}
		})
	}
}

func TestSmartTUNHealthPartialTCPDoesNotOutliveContext(t *testing.T) {
	client, server := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bounded, end := context.WithTimeout(ctx, time.Second)
	defer end()
	nonce := bytes.Repeat([]byte{7}, 16)
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		request := make([]byte, len("SCHEALTH1 ")+33)
		if _, err := io.ReadFull(server, request); err != nil {
			return
		}
		_, _ = io.WriteString(server, "SCHEALTH1 "+hex.EncodeToString(nonce)+" 8.8.8.8\n")
		close(ready)
		// Exact-looking bytes without peer EOF are not a complete TCP reply.
		<-bounded.Done()
	}()
	result := make(chan string, 1)
	go func() {
		result <- smartTUNHealthExchangeWithDeadline(bounded, client,
			smartTUNHealthProbe{protocol: "tcp", expectedSource: "8.8.8.8"}, nonce).Result
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("partial TCP fixture did not establish")
	}
	cancel()
	select {
	case status := <-result:
		if status != "canceled" {
			t.Fatalf("incomplete TCP response accepted: %s", status)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked TCP read outlived cancellation")
	}
	<-done
}

func TestSmartTUNHealthExchangeUsesActualLoopbackSocketAndIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		request := make([]byte, len("SCHEALTH1 ")+33)
		if _, err := io.ReadFull(connection, request); err != nil {
			done <- err
			return
		}
		source, _, err := net.SplitHostPort(connection.RemoteAddr().String())
		if err == nil {
			_, err = io.WriteString(connection, strings.TrimSuffix(string(request), "\n")+" "+source+"\n")
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	result := smartTUNHealthExchangeWithDeadline(ctx, connection,
		smartTUNHealthProbe{protocol: "tcp", expectedSource: "127.0.0.1"}, bytes.Repeat([]byte{9}, 16))
	if err := <-done; err != nil || result.Result != "pass" {
		t.Fatalf("real source-witness exchange failed: result=%+v err=%v", result, err)
	}
}

// Existing protocol fixtures use safe strings; this adapter adds the parsed
// status that a real HTTPS response supplies, while keeping those cases focused.
func runSmartTUNHealthTestProbes(ctx context.Context, dual bool, probe func(context.Context, smartTUNHealthProbe) string) SmartTUNHealthEvidence {
	return runSmartTUNHealthProbes(ctx, dual, func(ctx context.Context, p smartTUNHealthProbe) SmartTUNHTTPSResult {
		result := SmartTUNHTTPSResult{Result: probe(ctx, p)}
		if p.protocol == "https" && (result.Result == "pass" || result.Result == "invalid_response" || result.Result == "path_mismatch") {
			result.StatusCode = 200
		}
		return result
	})
}
