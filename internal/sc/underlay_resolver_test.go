package sc

import (
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// A local DNS responder exercises the genuine Go resolver and Linux
// SO_BINDTODEVICE path without involving a foreign provider or host DNS.
// It answers A records for node.example.test with the fixture-pinned IP.
func localExplicitResolver(t *testing.T, answer [4]byte) (int, *atomic.Int64) {
	t.Helper()
	sock, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	queries := new(atomic.Int64)
	go func() {
		buffer := make([]byte, 512)
		for {
			n, peer, e := sock.ReadFrom(buffer)
			if e != nil {
				return
			}
			if n < 17 {
				continue
			}
			// Scan the DNS question's bounded domain-label encoding. The
			// Go resolver controls the query. This decoder is test-only.
			end, name := 12, ""
			for end < n {
				size := int(buffer[end])
				end++
				if size == 0 {
					break
				}
				if size > 63 || end+size >= n {
					end = n
					break
				}
				name += string(buffer[end:end+size]) + "."
				end += size
			}
			if end+4 > n || name != "node.example.test." {
				continue
			}
			questionType := binary.BigEndian.Uint16(buffer[end : end+2])
			end += 4
			if questionType != 1 && questionType != 28 {
				continue
			}
			queries.Add(1)
			reply := make([]byte, 12)
			copy(reply[:2], buffer[:2])
			reply[2], reply[3] = 0x81, 0x80 // valid response, no error
			reply[5] = 1                    // one question
			if questionType == 1 {
				reply[7] = 1 // one A answer
			}
			reply = append(reply, buffer[12:end]...)
			if questionType == 1 {
				reply = append(reply,
					0xc0, 0x0c, // compressed response name
					0, 1, 0, 1, // type A, class IN
					0, 0, 0, 30, // TTL
					0, 4,
				)
				reply = append(reply, answer[:]...)
			}
			_, _ = sock.WriteTo(reply, peer)
		}
	}()
	return sock.LocalAddr().(*net.UDPAddr).Port, queries
}

func nativeExplicitResolverReady(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("requires native Linux socket binding and iproute2")
	}
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("native iproute2 not available in this test stage")
	}
	if err := trustedHostIPExecutable(); err != nil {
		t.Fatalf("native iproute2 trust: %v", err)
	}
}

func TestUnderlayExplicitResolverRejectsInvalidArgumentsBeforeNetwork(t *testing.T) {
	for _, tc := range []struct {
		host, endpoint, resolver string
		port                     int
	}{
		{"", "1.1.1.1", "127.0.0.1", 53},
		{"invalid@@host", "1.1.1.1", "127.0.0.1", 53},
		{"node.example.test", "", "127.0.0.1", 53},
		{"node.example.test", "host.example.test", "127.0.0.1", 53},
		{"node.example.test", "224.0.0.1", "127.0.0.1", 53},
		{"node.example.test", "1.1.1.1", "", 53},
		{"node.example.test", "1.1.1.1", "resolver.example.test", 53},
		{"node.example.test", "1.1.1.1", "fe80::1%eth0", 53},
		{"node.example.test", "1.1.1.1", "::ffff:127.0.0.1", 53},
		{"node.example.test", "1.1.1.1", "127.0.0.1", 0},
		{"node.example.test", "1.1.1.1", "127.0.0.1", 65536},
	} {
		report, err := InspectUnderlayDNS(tc.host, tc.endpoint, tc.resolver, tc.port)
		if ErrorCode(err) != "invalid_arguments" || report.ResolverDialCount != 0 {
			t.Fatalf("untrusted input accepted or network attempted: %+v err=%v", tc, err)
		}
	}
}

func TestUnderlayExplicitResolverPinsDNSAndMatchesEndpoint(t *testing.T) {
	nativeExplicitResolverReady(t)
	// An unrelated proxy environment must never change the DNS transport.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	port, queries := localExplicitResolver(t, [4]byte{198, 51, 100, 17})
	report, err := InspectUnderlayDNS("NODE.EXAMPLE.TEST.", "198.51.100.17", "127.0.0.1", port)
	if err != nil {
		t.Fatalf("real Linux bound DNS fixture failed: report=%+v err=%v", report, err)
	}
	if !report.ReadOnly || report.ActivationReady || report.DNSBootstrapVerified ||
		report.Outcome != "name_matched" || !report.NameResolved || !report.NameMatched ||
		!report.RouteStable || report.ResolverRouteDevice != "lo" ||
		!report.InterfaceBound || report.ResolverDialCount == 0 || queries.Load() == 0 {
		t.Fatalf("incorrect bound DNS path or unsafe safety claim: %+v queries=%d", report, queries.Load())
	}
	if report.Hostname != "node.example.test" || report.Resolver != "127.0.0.1" ||
		len(report.ResolvedAddresses) != 1 || report.ResolvedAddresses[0] != "198.51.100.17" {
		t.Fatalf("DNS response identity unexpected: %+v", report)
	}
	for _, sentence := range report.Limitations {
		if strings.Contains(strings.ToLower(sentence), "verified bootstrap") {
			t.Fatalf("unsafe assurance claim: %s", sentence)
		}
	}
}

func TestUnderlayExplicitResolverMismatchFailsClosed(t *testing.T) {
	nativeExplicitResolverReady(t)
	port, queries := localExplicitResolver(t, [4]byte{198, 51, 100, 17})
	report, err := InspectUnderlayDNS("node.example.test", "198.51.100.99", "127.0.0.1", port)
	if ErrorCode(err) != "underlay_dns_mismatch" || report.NameMatched ||
		!report.NameResolved || !report.InterfaceBound || report.Outcome != "pinned_endpoint_mismatch" ||
		report.ActivationReady || report.DNSBootstrapVerified || queries.Load() == 0 {
		t.Fatalf("mismatched pinned IP accepted: %+v err=%v", report, err)
	}
}

func TestUnderlayExplicitResolverUnavailableFailsClosed(t *testing.T) {
	nativeExplicitResolverReady(t)
	// A cleanly allocated then closed local UDP port yields either an
	// immediate kernel refusal or a bounded DNS error; never a success.
	sock, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := sock.LocalAddr().(*net.UDPAddr).Port
	_ = sock.Close()
	report, err := InspectUnderlayDNS("node.example.test", "198.51.100.17", "127.0.0.1", port)
	if err == nil || report.NameMatched || report.ActivationReady || report.DNSBootstrapVerified ||
		report.Outcome == "name_matched" {
		t.Fatalf("missing DNS server yielded false positive: %+v err=%v", report, err)
	}
}
