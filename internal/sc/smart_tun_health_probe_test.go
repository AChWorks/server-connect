package sc

import (
	"bytes"
	"context"
	"crypto/rand"
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

// Cancel only after the real connection has completed its final read. Stream
// replies require peer EOF; the UDP/DNS exchange consumes one datagram read.
// The optional read error is a negative control, never completed evidence.
type healthCancelAfterReadConn struct {
	net.Conn
	cancel    context.CancelFunc
	datagram  bool
	readError error
	completed bool
}

func (c *healthCancelAfterReadConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.completed && (err == io.EOF || c.datagram && n > 0 && err == nil) {
		c.completed = true
		c.cancel()
		if c.readError != nil {
			err = c.readError
		}
	}
	return n, err
}

func healthOrdinaryReadCompletion(t *testing.T, parent context.Context, protocol string,
	respond func([]byte, []byte) []byte, readError error) SmartTUNHTTPSResult {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	requestSize := len("SCHEALTH1 ") + 33
	if protocol == "dns" {
		requestSize = len(smartTUNHealthDNSQuery(nonce))
	}
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(time.Second))
		request := make([]byte, requestSize)
		if _, err := io.ReadFull(server, request); err != nil {
			done <- err
			return
		}
		_, err := server.Write(respond(request, nonce))
		done <- err
	}()
	connection := &healthCancelAfterReadConn{Conn: client, cancel: cancel, datagram: protocol != "tcp", readError: readError}
	result := smartTUNHealthExchangeWithDeadline(ctx, connection,
		smartTUNHealthProbe{protocol: protocol, expectedSource: "8.8.8.8"}, nonce)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ordinary completed-read peer did not join")
	}
	if !connection.completed || ctx.Err() != context.Canceled || parent.Err() != nil {
		t.Fatalf("cancellation did not occur at the child read boundary: completed=%v child=%v parent=%v", connection.completed, ctx.Err(), parent.Err())
	}
	return result
}

func healthOrdinaryBoundaryReply(protocol, variant string, request, nonce []byte) []byte {
	if protocol == "dns" {
		reply := smartTUNHealthDNSResponse(request, variant == "positive")
		switch variant {
		case "incomplete":
			return reply[:len(reply)-1]
		case "malformed":
			reply[3] ^= 1
		case "oversized":
			return append(reply, bytes.Repeat([]byte{0}, 257-len(reply))...)
		}
		return reply
	}
	source := "10.254.72.1"
	if variant == "positive" {
		source = "8.8.8.8"
	}
	reply := []byte("SCHEALTH1 " + hex.EncodeToString(nonce) + " " + source + "\n")
	switch variant {
	case "incomplete":
		return reply[:len(reply)-1]
	case "malformed":
		reply[10] ^= 1
	case "oversized":
		// ParseAddr accepts IPv6 zones; this exact-looking source must still
		// fail the wire bound instead of becoming a critical path witness.
		prefix := "SCHEALTH1 " + hex.EncodeToString(nonce) + " fe80::1%"
		return []byte(prefix + strings.Repeat("z", 256-len(prefix)) + "\n")
	}
	return reply
}

func TestSmartTUNHealthReadCompletionCancellation(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp", "dns"} {
		for _, variant := range []string{"mismatch", "positive", "incomplete", "malformed", "read-error"} {
			t.Run(protocol+"/"+variant, func(t *testing.T) {
				var readError error
				if variant == "read-error" {
					readError = io.ErrNoProgress
				}
				result := healthOrdinaryReadCompletion(t, context.Background(), protocol,
					func(request, nonce []byte) []byte {
						return healthOrdinaryBoundaryReply(protocol, variant, request, nonce)
					}, readError)
				want := "canceled"
				if variant == "mismatch" {
					want = "path_mismatch"
				}
				if result.Result != want {
					t.Fatalf("completed-read cancellation classification: got %+v want %s", result, want)
				}
			})
		}
		t.Run(protocol+"/oversized-critical-shaped", func(t *testing.T) {
			// TCP stops at its read bound before peer EOF. Datagram protocols
			// cancel after the bounded read, so neither can acquire proof.
			if protocol == "tcp" {
				got := healthTestExchange(t, protocol, func(request, nonce []byte) []byte {
					return healthOrdinaryBoundaryReply(protocol, "oversized", request, nonce)
				})
				if got != "invalid_response" {
					t.Fatalf("oversized source text became evidence: %s", got)
				}
				return
			}
			got := healthOrdinaryReadCompletion(t, context.Background(), protocol,
				func(request, nonce []byte) []byte {
					return healthOrdinaryBoundaryReply(protocol, "oversized", request, nonce)
				}, nil)
			if got.Result == "pass" || got.Result == "path_mismatch" {
				t.Fatalf("oversized canceled datagram became evidence: %+v", got)
			}
		})
	}
}

func TestSmartTUNHealthReadCompletionMismatchStopsSupervision(t *testing.T) {
	for _, protocol := range []string{"https", "tcp", "udp", "dns"} {
		t.Run(protocol, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), smartTUNHealthRoundTimeout)
			defer cancel()
			var observed SmartTUNHTTPSResult
			if protocol == "https" {
				observed, _ = healthTLSReadCompletion(t, parent, func(body string) []byte {
					return healthHTTPResponse(200, body)
				}, false, nil)
			} else {
				observed = healthOrdinaryReadCompletion(t, parent, protocol,
					func(request, nonce []byte) []byte {
						return healthOrdinaryBoundaryReply(protocol, "mismatch", request, nonce)
					}, nil)
			}
			evidence := runSmartTUNHealthProbes(parent, true, func(_ context.Context, probe smartTUNHealthProbe) SmartTUNHTTPSResult {
				if probe.target == 0 && probe.protocol == protocol {
					return observed
				}
				if probe.protocol == "https" {
					return SmartTUNHTTPSResult{Result: "pass", StatusCode: 200}
				}
				return SmartTUNHTTPSResult{Result: "pass"}
			})
			if parent.Err() != nil || evidence.VPNHealthy || evidence.Reason != "vpn_path_mismatch" ||
				!evidence.UnderlayHealthy || !evidence.IPv4TCP || !evidence.IPv4UDP || !evidence.IPv4DNS || !evidence.IPv4HTTPS ||
				evidence.FailedTargets != 1 || !validSmartTUNHTTPSEvidence(evidence, true) {
				t.Fatalf("live alternate masked real completed mismatch: observed=%+v evidence=%+v parent=%v", observed, evidence, parent.Err())
			}
			r := supervisedExample(t, true)
			r.Supervised.Options.FailureThreshold = 3
			next, stop, reconnect := advanceSupervisedHealth(r, evidence, 106000)
			if stop != "vpn_path_mismatch" || reconnect || next.Supervised.State != "degraded" || next.Supervised.Reason != stop ||
				next.Supervised.Evidence != evidence {
				t.Fatalf("classified critical reply did not request existing stop: stop=%s reconnect=%v supervision=%+v", stop, reconnect, next.Supervised)
			}
			unit := smartTUNTrialUnitObservation{activeState: "active", mainPID: 100, result: "success"}
			if got := supervisedRuntimeReason(next, unit, true, next.BootID, 106001); got != stop {
				t.Fatalf("independent recovery lost classified critical stop: %s", got)
			}
			if err := validateSmartTUNTrial(next); err != nil {
				t.Fatalf("critical measured record invalid: %v", err)
			}
		})
	}
}
