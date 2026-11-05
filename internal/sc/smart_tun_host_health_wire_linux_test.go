//go:build linux

package sc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func hostHealthTraceResponse(status int, body string, extra string) []byte {
	return []byte(fmt.Sprintf("HTTP/1.1 %d Test\r\nCache-Control: no-store\r\nContent-Length: %d\r\nConnection: close\r\n%s\r\n%s", status, len(body), extra, body))
}
func hostHealthTraceExchange(t *testing.T, leaf, expected string, response func(*http.Request) []byte) HostHealthResult {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		secure := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{healthTLSCertificate(t, leaf)}, MinVersion: tls.VersionTLS12})
		if err := secure.Handshake(); err != nil {
			done <- nil
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(io.LimitReader(secure, 8193)))
		if err != nil {
			done <- err
			return
		}
		defer request.Body.Close()
		u, err := url.ParseRequestURI(request.RequestURI)
		if err != nil {
			done <- err
			return
		}
		nonce, err := hex.DecodeString(u.Query().Get("sc_health"))
		if err != nil || len(nonce) != 16 || len(u.Query()) != 1 || u.Path != "/cdn-cgi/trace" || request.Host != smartTUNHealthHTTPSName ||
			request.Method != "GET" || request.Proto != "HTTP/1.1" || !request.Close || !strings.Contains(request.Header.Get("Cache-Control"), "no-store") {
			done <- fmt.Errorf("unexpected authenticated trace request: %s %s", request.Host, request.RequestURI)
			return
		}
		_, _ = secure.Write(response(request))
		done <- nil
	}()
	connection, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	probe := hostHealthProbe{role: "selected", family: 4, target: HostHealthTraceTarget{Address: "1.1.1.1", Port: 443, ServerName: smartTUNHealthHTTPSName, Path: "/cdn-cgi/trace"}, expected: expected}
	result := exchangeHostHealthConnection(ctx, connection, probe, smartTUNHealthTLSConfig())
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return result
}
func TestHostHealthRealTLSVerifiesIdentityAndAuthenticatedObservedExit(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	body := "ip=9.9.9.9\nvisit_scheme=https\n"
	for _, leaf := range []string{"qa-server.pem", "qa-wrong-name.pem", "qa-wrong-trust.pem", "qa-expired.pem", "qa-client-auth-only.pem"} {
		t.Run(leaf, func(t *testing.T) {
			result := hostHealthTraceExchange(t, leaf, "9.9.9.9", func(*http.Request) []byte { return hostHealthTraceResponse(200, body, "") })
			if leaf == "qa-server.pem" {
				if result.Result != "pass" || result.HTTPStatus != 200 || result.ObservedIP != "9.9.9.9" {
					t.Fatalf("%+v", result)
				}
			} else if result.Result != "tls_identity_failed" {
				t.Fatalf("ordinary TLS identity not checked: %+v", result)
			}
		})
	}
	mismatch := hostHealthTraceExchange(t, "qa-server.pem", "8.8.8.8", func(*http.Request) []byte { return hostHealthTraceResponse(200, body, "") })
	if mismatch.Result != "path_mismatch" || mismatch.ObservedIP != "9.9.9.9" || mismatch.HTTPStatus != 200 {
		t.Fatalf("%+v", mismatch)
	}
}
func TestHostHealthRealTLSBoundsCacheFramingAndBodies(t *testing.T) {
	body := "ip=9.9.9.9\nvisit_scheme=https\n"
	cases := []struct {
		name, want string
		response   []byte
	}{
		{"redirect", "http_status", hostHealthTraceResponse(302, body, "Location: https://other.example/\r\n")},
		{"stale", "http_stale_response", hostHealthTraceResponse(200, body, "Age: 3\r\n")},
		{"ambiguous age", "http_stale_response", hostHealthTraceResponse(200, body, "Age: 0\r\nAge: 3\r\n")},
		{"surplus after declared body", "http_invalid_response", append(hostHealthTraceResponse(200, body, ""), []byte("surplus")...)},
		{"unknown age", "http_stale_response", hostHealthTraceResponse(200, body, "Age: impossible\r\n")},
		{"cache forbidden unverified", "http_cache_unverified", []byte(fmt.Sprintf("HTTP/1.1 200 Test\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body))},
		{"compressed", "http_invalid_response", hostHealthTraceResponse(200, body, "Content-Encoding: gzip\r\n")},
		{"duplicate exit", "http_invalid_response", hostHealthTraceResponse(200, body+"ip=9.9.9.9\n", "")},
		{"nonpublic exit", "http_invalid_response", hostHealthTraceResponse(200, "ip=127.0.0.1\nvisit_scheme=https\n", "")},
		{"missing scheme", "http_invalid_response", hostHealthTraceResponse(200, "ip=9.9.9.9\n", "")},
		{"truncated", "truncated_response", []byte(fmt.Sprintf("HTTP/1.1 200 Test\r\nCache-Control: no-store\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body)+4, body))},
		{"oversized header", "http_oversized_response", hostHealthTraceResponse(200, body, "X-Pad: "+strings.Repeat("a", hostHealthHeaderLimit)+"\r\n")},
		{"oversized body", "http_invalid_response", hostHealthTraceResponse(200, strings.Repeat("a", hostHealthBodyLimit+1), "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hostHealthTraceExchange(t, "qa-server.pem", "9.9.9.9", func(*http.Request) []byte { return tc.response })
			if got.Result != tc.want {
				t.Fatalf("got=%+v want=%s", got, tc.want)
			}
		})
	}
	chunked := []byte(fmt.Sprintf("HTTP/1.1 200 Test\r\nCache-Control: no-store\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body))
	got := hostHealthTraceExchange(t, "qa-server.pem", "9.9.9.9", func(*http.Request) []byte { return chunked })
	if got.Result != "pass" {
		t.Fatalf("normal bounded chunked trace refused: %+v", got)
	}
}
func TestHostHealthTraceParserRejectsMalformedAndAmbiguousSources(t *testing.T) {
	for _, raw := range []string{"", "ip=9.9.9.9\n", "ip=9.9.9.9\nvisit_scheme=http\n", "ip=::ffff:9.9.9.9\nvisit_scheme=https\n",
		"ip=9.9.9.9\nvisit_scheme=https", "ip=9.9.9.9\r\nvisit_scheme=https\n", "ip=9.9.9.9\nvisit_scheme=https\nvisit_scheme=https\n",
		"not-a-key\nip=9.9.9.9\nvisit_scheme=https\n"} {
		if _, err := parseHostHealthTrace([]byte(raw)); err == nil {
			t.Fatalf("invalid trace accepted: %q", raw)
		}
	}
}
func hostHealthDNSReply(query []byte) []byte {
	response := append([]byte{}, query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8183)
	return response
}
func TestHostHealthDNSParserRequiresFreshQuestionAndCompleteBoundedMessage(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x37}, 16)
	query, question, err := hostHealthDNSQuestion(nonce, 4)
	if err != nil {
		t.Fatal(err)
	}
	id := binary.BigEndian.Uint16(query[:2])
	reply := hostHealthDNSReply(query)
	if !validHostHealthDNSResponse(reply, id, question) {
		t.Fatal("valid fresh NXDOMAIN refused")
	}
	query6, q6, err := hostHealthDNSQuestion(nonce, 6)
	if err != nil || binary.BigEndian.Uint16(query6[len(query6)-4:len(query6)-2]) != 28 || !validHostHealthDNSResponse(hostHealthDNSReply(query6), id, q6) {
		t.Fatalf("IPv6 DNS question: %v", err)
	}
	answer := append([]byte{}, reply...)
	binary.BigEndian.PutUint16(answer[2:4], 0x8180)
	binary.BigEndian.PutUint16(answer[6:8], 1)
	answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4, 9, 9, 9, 9)
	if !validHostHealthDNSResponse(answer, id, question) {
		t.Fatal("normal compressed A response refused")
	}
	soa := append([]byte{}, reply...)
	binary.BigEndian.PutUint16(soa[8:10], 1)
	soa = append(soa, 0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 0, 5, 0, 24, 0xc0, 0x0c, 0xc0, 0x0c)
	soa = append(soa, make([]byte, 20)...)
	if !validHostHealthDNSResponse(soa, id, question) {
		t.Fatal("normal negative SOA response refused")
	}
	cases := map[string][]byte{"trailing": append(append([]byte{}, reply...), 0), "short": reply[:11]}
	change := func(name string, fn func([]byte)) { raw := append([]byte{}, reply...); fn(raw); cases[name] = raw }
	change("old ID", func(raw []byte) { raw[0] ^= 1 })
	change("different nonce", func(raw []byte) { raw[15] ^= 1 })
	change("query echoed", func(raw []byte) { binary.BigEndian.PutUint16(raw[2:4], 0x0100) })
	change("truncated flag", func(raw []byte) { binary.BigEndian.PutUint16(raw[2:4], 0x8380) })
	change("unsupported opcode", func(raw []byte) { binary.BigEndian.PutUint16(raw[2:4], 0x8980) })
	change("server failure", func(raw []byte) { binary.BigEndian.PutUint16(raw[2:4], 0x8182) })
	change("extra question", func(raw []byte) { binary.BigEndian.PutUint16(raw[4:6], 2) })
	change("huge count", func(raw []byte) { binary.BigEndian.PutUint16(raw[6:8], 65535) })
	change("missing RR", func(raw []byte) { binary.BigEndian.PutUint16(raw[6:8], 1) })
	malformed := append([]byte{}, answer...)
	malformed[len(malformed)-5] = 3
	cases["bad A RDATA"] = malformed
	loop := append([]byte{}, answer...)
	loop[len(reply)+1] = byte(len(reply))
	cases["compression loop"] = loop
	for name, raw := range cases {
		if validHostHealthDNSResponse(raw, id, question) {
			t.Fatalf("invalid DNS message accepted: %s", name)
		}
	}
}
func TestHostHealthDNSUsesActualFreshUDPAndRejectsMismatch(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				server.SetReadDeadline(time.Now().Add(time.Second))
				request := make([]byte, 4097)
				n, peer, err := server.ReadFromUDP(request)
				if err != nil {
					done <- err
					return
				}
				response := hostHealthDNSReply(request[:n])
				if bad {
					response[0] ^= 1
				}
				_, err = server.WriteToUDP(response, peer)
				done <- err
			}()
			c, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got := exchangeHostHealthConnection(ctx, c, hostHealthProbe{role: "dns", family: 4}, nil)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			want := "pass"
			if bad {
				want = "dns_invalid_response"
			}
			if got.Result != want {
				t.Fatalf("actual UDP result: %+v want=%s", got, want)
			}
		})
	}
}
func TestHostHealthConnectionCancellationDeadlineAndSourceBinding(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	go func() { request := make([]byte, 512); _, _ = server.Read(request) }()
	started := time.Now()
	result := exchangeHostHealthConnection(ctx, client, hostHealthProbe{role: "dns", family: 4}, nil)
	if result.Result != "canceled" && result.Result != "timeout" {
		t.Fatalf("unbounded/canceled probe accepted: %+v", result)
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("probe did not honor cancellation")
	}
	client, server = net.Pipe()
	defer server.Close()
	result = exchangeHostHealthConnection(context.Background(), client, hostHealthProbe{role: "endpoint"}, nil)
	if result.Result != "deadline_unavailable" {
		t.Fatalf("unbounded caller accepted: %+v", result)
	}
}
