package sc

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUnderlayHostnameSyntaxAndCanonicalForm(t *testing.T) {
	for _, tc := range []struct{ input, expected string }{
		{"VPN.Example.NET", "vpn.example.net"},
		{"one.one.one.one.", "one.one.one.one"},
		{"xn--mnchen-3ya.example", "xn--mnchen-3ya.example"},
		{"a-b.example", "a-b.example"},
	} {
		name, err := validateEndpointHostname(tc.input)
		if err != nil || name != tc.expected {
			t.Fatalf("valid DNS input %q: got %q err=%v", tc.input, name, err)
		}
	}
	for _, bad := range []string{
		"", ".", "..", "localhost", "127.0.0.1", "::1", "http://vpn.example",
		"vpn.example/path", "user@vpn.example", "vpn.example:443",
		"a..example", ".example", "example.", "-bad.example", "bad-.example",
		"bad_.example", "*.example", "bad example.org", "bad\n.example",
		"VPN.éxample", strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 130) + "example",
	} {
		if name, err := validateEndpointHostname(bad); ErrorCode(err) != "invalid_arguments" {
			t.Fatalf("invalid hostname accepted: input=%q, output=%q, error=%v", bad, name, err)
		}
	}
}

func TestUnderlayDNSArgumentsRejectedBeforeAnyLookup(t *testing.T) {
	lookups := 0
	resolver := func(context.Context, string) ([]netip.Addr, error) {
		lookups++
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	for _, tc := range []struct {
		ip   string
		name string
		port int
	}{
		{"", "vpn.example", 443},
		{"255.255.255.255", "vpn.example", 443},
		{"fe80::1", "vpn.example", 443},
		{"127.0.0.1", "bad@@domain", 443},
		{"127.0.0.1", "vpn.example", 0},
		{"127.0.0.1", "vpn.example", 65536},
		{"127.0.0.1", "localhost", 443},
	} {
		if report, err := inspectUnderlayWithNameLookup(tc.ip, tc.name, tc.port, resolver); ErrorCode(err) != "invalid_arguments" {
			t.Fatalf("accepted invalid network argument: %+v error=%v", report, err)
		}
	}
	if lookups != 0 {
		t.Fatalf("invalid input invoked DNS lookup %d times", lookups)
	}
}

func requireNativePreflight(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("native Linux iproute2 required")
	}
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("native iproute2 absent in minimal APT CI stage")
	}
	if err := trustedHostIPExecutable(); err != nil {
		t.Fatalf("native iproute2 trust conflict: %v", err)
	}
}

func TestUnderlayDNSPinnedMatchUsesRealInterfaceBoundIPv4(t *testing.T) {
	requireNativePreflight(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	accepted := make(chan error, 1)
	go func() {
		conn, e := listener.Accept()
		if e == nil {
			_ = conn.Close()
		}
		accepted <- e
	}()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	name := "edge.EXAMPLE.test."
	report, err := inspectUnderlayWithNameLookup("127.0.0.1", name, port, func(ctx context.Context, hostname string) ([]netip.Addr, error) {
		if hostname != "edge.example.test." {
			t.Fatalf("hostname canonicalization mismatch: %q", hostname)
		}
		return []netip.Addr{
			netip.MustParseAddr("::1"),
			netip.MustParseAddr("127.0.0.1"),
			netip.MustParseAddr("127.0.0.1"),
		}, nil
	})
	if err != nil {
		t.Fatalf("pinned literal TCP rejected: %+v err=%v", report, err)
	}
	select {
	case e := <-accepted:
		if e != nil {
			t.Fatalf("local listener failure: %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pinned TCP listener did not receive the connection")
	}
	if !report.NameResolved || !report.NameMatched || report.Hostname != "edge.example.test" ||
		!report.ReadOnly || report.ActivationReady || report.DNSBootstrapVerified ||
		!report.InterfaceBound || !report.RouteStable || !report.SocketConnected ||
		report.Outcome != "tcp_connected" || report.RouteDevice != "lo" ||
		len(report.ResolvedAddresses) != 2 ||
		report.ResolvedAddresses[0] != "127.0.0.1" ||
		report.ResolvedAddresses[1] != "::1" {
		t.Fatalf("false readiness/bootstrapping assertion or DNS/TCP mismatch: %+v", report)
	}
}

func TestUnderlayDNSMismatchRefusesNetworkConnection(t *testing.T) {
	requireNativePreflight(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	report, err := inspectUnderlayWithNameLookup("127.0.0.1", "edge.example.test", port, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.2")}, nil
	})
	if ErrorCode(err) != "underlay_name_mismatch" || !report.NameResolved || report.NameMatched ||
		report.SocketConnected || report.InterfaceBound || report.RouteStable || report.DNSBootstrapVerified ||
		report.Outcome != "hostname_mismatch" || report.ActivationReady {
		t.Fatalf("mismatch attempted TCP or made unsupported claims: %+v err=%v", report, err)
	}
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(80 * time.Millisecond))
	if conn, err := listener.Accept(); err == nil {
		_ = conn.Close()
		t.Fatal("mismatched DNS name still caused a TCP connection")
	}
}

func TestUnderlayDNSRefusedPortRetainsResolutionEvidence(t *testing.T) {
	requireNativePreflight(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	report, err := inspectUnderlayWithNameLookup("127.0.0.1", "edge.example.test", port, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	if ErrorCode(err) != "underlay_unreachable" || !report.NameResolved || !report.NameMatched ||
		!report.InterfaceBound || !report.RouteStable || report.SocketConnected ||
		report.Outcome != "tcp_refused" || report.ActivationReady {
		t.Fatalf("TCP failure lost valid preceding name evidence: %+v err=%v", report, err)
	}
}

func TestUnderlayDNSUnsupportedAddressListsFailClosed(t *testing.T) {
	requireNativePreflight(t)
	for _, tc := range []struct {
		name      string
		addresses []netip.Addr
	}{
		{"empty", nil},
		{"too_many", make([]netip.Addr, maxEndpointNameAnswers+1)},
		{"multicast", []netip.Addr{netip.MustParseAddr("224.0.0.1")}},
		{"broadcast", []netip.Addr{netip.MustParseAddr("255.255.255.255")}},
		{"link_local", []netip.Addr{netip.MustParseAddr("fe80::1")}},
		{"ipv4_link_local", []netip.Addr{netip.MustParseAddr("169.254.1.2")}},
		{"v4_mapped", []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}},
		{"mixed_unsafe", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("fe80::1")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := inspectUnderlayWithNameLookup("127.0.0.1", "edge.example.test", 443, func(context.Context, string) ([]netip.Addr, error) {
				return tc.addresses, nil
			})
			if ErrorCode(err) != "underlay_name_unavailable" || report.NameMatched ||
				report.SocketConnected || report.InterfaceBound || report.DNSBootstrapVerified {
				t.Fatalf("unsafe resolver answer accepted or dialed: %+v error=%v", report, err)
			}
		})
	}
}

func TestUnderlayDNSResolverErrorAndTimeoutBound(t *testing.T) {
	requireNativePreflight(t)
	result, err := inspectUnderlayWithNameLookup("127.0.0.1", "edge.example.test", 443, func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("synthetic resolver unavailable")
	})
	if ErrorCode(err) != "underlay_name_unavailable" || result.NameResolved || result.SocketConnected ||
		result.Outcome != "name_resolution_failed" {
		t.Fatalf("DNS errors were not classified: %+v err=%v", result, err)
	}
	start := time.Now()
	result, err = inspectUnderlayWithNameLookup("127.0.0.1", "edge.example.test", 443, func(ctx context.Context, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	elapsed := time.Since(start)
	if ErrorCode(err) != "underlay_name_unavailable" || result.NameResolved ||
		result.SocketConnected || elapsed < 2500*time.Millisecond || elapsed > 5500*time.Millisecond {
		t.Fatalf("resolver timeout not bounded: elapsed=%v report=%+v err=%v", elapsed, result, err)
	}
}
