package sc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func healthTLSCertificate(t *testing.T, leaf string) tls.Certificate {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(filepath.Join("testdata", "smart-health-tls", leaf),
		filepath.Join("testdata", "smart-health-tls", "qa-server-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func healthHTTPResponse(status int, body string) []byte {
	return []byte(fmt.Sprintf("HTTP/1.1 %d Test\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, len(body), body))
}

// Exercise real ordinary TLS on a loopback socket. Only this test supplies a
// loopback connection; production retains its fixed address/identity plan.
func healthTLSExchange(t *testing.T, leaf string, respond func(string) []byte) SmartTUNHTTPSResult {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	config := &tls.Config{Certificates: []tls.Certificate{healthTLSCertificate(t, leaf)}, MinVersion: tls.VersionTLS12}
	serverName := make(chan string, 1)
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		serverName <- hello.ServerName
		return nil, nil
	}
	done := make(chan error, 1)
	nonce := bytes.Repeat([]byte{0x59}, 16)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		secure := tls.Server(connection, config)
		defer secure.Close()
		if err := secure.Handshake(); err != nil {
			// The peer must reject invalid identity before sending HTTP.
			done <- nil
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(io.LimitReader(secure, 4097)))
		if err != nil {
			done <- err
			return
		}
		defer request.Body.Close()
		if request.Method != "GET" || request.RequestURI != "/health/"+hex.EncodeToString(nonce) ||
			request.Host != smartTUNHealthHTTPSName+":19224" || request.Proto != "HTTP/1.1" || !request.Close {
			done <- fmt.Errorf("unexpected fixed HTTPS request")
			return
		}
		source, _, err := net.SplitHostPort(connection.RemoteAddr().String())
		if err != nil {
			done <- err
			return
		}
		body := "SCHEALTH1 " + hex.EncodeToString(nonce) + " " + source + "\n"
		// Oversized/invalid cases can correctly close before all bytes are sent.
		_, _ = secure.Write(respond(body))
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	result := smartTUNHealthExchangeWithDeadline(ctx, connection,
		smartTUNHealthProbe{protocol: "https", expectedSource: "127.0.0.1"}, nonce)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("HTTPS worker did not join after bounded connection close")
	}
	select {
	case name := <-serverName:
		if name != smartTUNHealthHTTPSName {
			t.Fatalf("fixed TLS identity was not requested: %q", name)
		}
	default:
		t.Fatal("ordinary TLS ClientHello was not observed")
	}
	return result
}

func TestSmartTUNHTTPSOrdinaryVerificationRejectsIdentityCauses(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	t.Setenv("SSL_CERT_FILE", filepath.Join("testdata", "smart-health-tls", "qa-wrong-root.pem"))
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	for _, leaf := range []string{"qa-server.pem", "qa-wrong-name.pem", "qa-wrong-trust.pem", "qa-expired.pem", "qa-client-auth-only.pem"} {
		t.Run(leaf, func(t *testing.T) {
			result := healthTLSExchange(t, leaf, func(body string) []byte { return healthHTTPResponse(200, body) })
			want := SmartTUNHTTPSResult{Result: "tls_identity_failed"}
			if leaf == "qa-server.pem" {
				want = SmartTUNHTTPSResult{Result: "pass", StatusCode: 200}
			}
			if result != want {
				t.Fatalf("ordinary chain/SAN/time/serverAuth validation: got %+v want %+v", result, want)
			}
		})
	}
}

func TestSmartTUNHTTPSFixturesDiscriminateNameTrustValidityAndUsage(t *testing.T) {
	read := func(filename string) *x509.Certificate {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("testdata", "smart-health-tls", filename))
		if err != nil {
			t.Fatal(err)
		}
		block, trailing := pem.Decode(data)
		if block == nil || len(bytes.TrimSpace(trailing)) != 0 || block.Type != "CERTIFICATE" {
			t.Fatal("test fixture must contain exactly one certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	root := read("qa-root.pem")
	if !root.IsCA || root.MaxPathLen != 0 || root.KeyUsage&x509.KeyUsageCertSign == 0 ||
		!root.NotBefore.Equal(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		!root.NotAfter.Equal(time.Date(2045, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("QA root lost its deliberate validity/usage boundary")
	}
	options := x509.VerifyOptions{Roots: smartTUNHealthTLSConfig().RootCAs, DNSName: smartTUNHealthHTTPSName,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, leaf := range []string{"qa-server.pem", "qa-wrong-name.pem", "qa-wrong-trust.pem", "qa-expired.pem", "qa-client-auth-only.pem"} {
		certificate := read(leaf)
		if certificate.IsCA || certificate.KeyUsage != x509.KeyUsageDigitalSignature || len(certificate.DNSNames) != 1 {
			t.Fatalf("leaf lost explicit SAN/key usage: %s", leaf)
		}
		_, err := certificate.Verify(options)
		switch leaf {
		case "qa-server.pem":
			if err != nil {
				t.Fatal(err)
			}
		case "qa-wrong-name.pem":
			var name x509.HostnameError
			if !errors.As(err, &name) {
				t.Fatalf("wrong-name fixture failed for another cause: %v", err)
			}
			corrected := options
			corrected.DNSName = "wrong-health.example.test"
			if _, err := certificate.Verify(corrected); err != nil {
				t.Fatalf("wrong-name fixture otherwise invalid: %v", err)
			}
		case "qa-wrong-trust.pem":
			var trust x509.UnknownAuthorityError
			if !errors.As(err, &trust) {
				t.Fatalf("wrong-trust fixture failed for another cause: %v", err)
			}
			corrected := options
			corrected.Roots = x509.NewCertPool()
			corrected.Roots.AddCert(read("qa-wrong-root.pem"))
			if _, err := certificate.Verify(corrected); err != nil {
				t.Fatalf("wrong-trust fixture otherwise invalid: %v", err)
			}
		default:
			var invalid x509.CertificateInvalidError
			want := x509.Expired
			if leaf == "qa-client-auth-only.pem" {
				want = x509.IncompatibleUsage
			}
			if !errors.As(err, &invalid) || invalid.Reason != want {
				t.Fatalf("fixture failed for another cause: %s %v", leaf, err)
			}
		}
	}
}

func TestSmartTUNHTTPSRequiresBoundedExactFreshHTTPResponse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		want  SmartTUNHTTPSResult
		reply func(string) []byte
	}{
		{"exact", SmartTUNHTTPSResult{"pass", 200}, func(body string) []byte { return healthHTTPResponse(200, body) }},
		{"unavailable", SmartTUNHTTPSResult{"http_status", 503}, func(string) []byte { return healthHTTPResponse(503, "private response body") }},
		{"redirect", SmartTUNHTTPSResult{"http_status", 302}, func(string) []byte {
			return []byte("HTTP/1.1 302 Found\r\nLocation: https://untrusted.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		}},
		{"malformed-header", SmartTUNHTTPSResult{"http_invalid_response", 0}, func(string) []byte { return []byte("HTTP/1.1 200 OK\r\nBad Header\r\n\r\n") }},
		{"truncated-header", SmartTUNHTTPSResult{"http_truncated_response", 0}, func(string) []byte { return []byte("HTTP/1.1 200 OK\r\nContent-Length:") }},
		{"truncated-body", SmartTUNHTTPSResult{"http_truncated_response", 200}, func(body string) []byte { return healthHTTPResponse(200, body)[:len(healthHTTPResponse(200, body))-1] }},
		{"oversized-length", SmartTUNHTTPSResult{"http_oversized_response", 200}, func(string) []byte { return healthHTTPResponse(200, strings.Repeat("x", 257)) }},
		{"oversized-close-body", SmartTUNHTTPSResult{"http_oversized_response", 200}, func(string) []byte {
			return []byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + strings.Repeat("x", 257))
		}},
		{"oversized-header", SmartTUNHTTPSResult{"http_oversized_response", 0}, func(string) []byte {
			return []byte("HTTP/1.1 200 OK\r\nX-Padding: " + strings.Repeat("x", 4096) + "\r\n\r\n")
		}},
		{"stale-nonce", SmartTUNHTTPSResult{"invalid_response", 200}, func(body string) []byte { return healthHTTPResponse(200, strings.Replace(body, "5959", "0000", 1)) }},
		{"wrong-source", SmartTUNHTTPSResult{"path_mismatch", 200}, func(body string) []byte {
			return healthHTTPResponse(200, strings.Replace(body, "127.0.0.1", "10.254.72.1", 1))
		}},
		{"trailing-body", SmartTUNHTTPSResult{"invalid_response", 200}, func(body string) []byte { return healthHTTPResponse(200, body+"trailing") }},
		{"missing-newline", SmartTUNHTTPSResult{"invalid_response", 200}, func(body string) []byte { return healthHTTPResponse(200, strings.TrimSuffix(body, "\n")) }},
		{"framing-trailing", SmartTUNHTTPSResult{"http_invalid_response", 200}, func(body string) []byte { return append(healthHTTPResponse(200, body), 'x') }},
		{"chunked", SmartTUNHTTPSResult{"http_invalid_response", 200}, func(string) []byte {
			return []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n")
		}},
		{"content-encoding", SmartTUNHTTPSResult{"http_invalid_response", 200}, func(string) []byte {
			return []byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		}},
		{"invalid-status", SmartTUNHTTPSResult{"http_invalid_response", 0}, func(string) []byte { return healthHTTPResponse(700, "") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := healthTLSExchange(t, "qa-server.pem", tc.reply)
			if got != tc.want || !validSmartTUNHTTPSResult(got) {
				t.Fatalf("unsafe or misclassified HTTPS reply: got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestSmartTUNHTTPSPartialTargetsAndProtocolIsolation(t *testing.T) {
	for _, dual := range []bool{false, true} {
		for _, failAll := range []bool{false, true} {
			result := runSmartTUNHealthProbes(context.Background(), dual,
				func(_ context.Context, p smartTUNHealthProbe) SmartTUNHTTPSResult {
					if p.protocol == "https" {
						if failAll || p.target%2 == 0 {
							return SmartTUNHTTPSResult{Result: "http_status", StatusCode: 503}
						}
						return SmartTUNHTTPSResult{Result: "pass", StatusCode: 200}
					}
					return SmartTUNHTTPSResult{Result: "pass"}
				})
			wantReason := "healthy_partial_targets"
			if failAll {
				wantReason = "vpn_ipv4_https_failed"
			}
			if result.VPNHealthy == failAll || !result.UnderlayHealthy || !result.IPv4TCP || !result.IPv4UDP || !result.IPv4DNS ||
				result.IPv6TCP != dual || result.IPv6UDP != dual || result.IPv6DNS != dual || result.Reason != wantReason ||
				!validSmartTUNHTTPSEvidence(result, dual) {
				t.Fatalf("HTTPS outage borrowed TCP health or lost alternate evidence: %+v", result)
			}
		}
	}
	result := runSmartTUNHealthTestProbes(context.Background(), true, func(_ context.Context, p smartTUNHealthProbe) string {
		if p.protocol == "https" && p.family == 6 {
			return "tls_identity_failed"
		}
		return "pass"
	})
	if result.VPNHealthy || result.Reason != "vpn_ipv6_https_failed" || !result.IPv4HTTPS || result.IPv6HTTPS ||
		!validSmartTUNHTTPSEvidence(result, true) {
		t.Fatalf("IPv4 HTTPS borrowed as IPv6 evidence: %+v", result)
	}
}

func TestSmartTUNHTTPSCancellationClosesHandshakeAndPartialResponse(t *testing.T) {
	for _, stage := range []string{"handshake", "body"} {
		t.Run(stage, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			certificate := healthTLSCertificate(t, "qa-server.pem")
			ready, done := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(done)
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
				var reader io.Reader = connection
				if stage == "body" {
					secure := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
					defer secure.Close()
					if err := secure.Handshake(); err != nil {
						return
					}
					if _, err := http.ReadRequest(bufio.NewReader(io.LimitReader(secure, 4097))); err != nil {
						return
					}
					if _, err := io.WriteString(secure, "HTTP/1.1 200 OK\r\nContent-Length: 70\r\nConnection: close\r\n\r\nSCHEALTH1 "); err != nil {
						return
					}
					reader = secure
				}
				close(ready)
				_, _ = io.Copy(io.Discard, reader)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan SmartTUNHTTPSResult, 1)
			go func() {
				result <- smartTUNHealthExchangeWithDeadline(ctx, connection, smartTUNHealthProbe{protocol: "https", expectedSource: "127.0.0.1"}, bytes.Repeat([]byte{8}, 16))
			}()
			select {
			case <-ready:
			case <-time.After(time.Second):
				t.Fatal("blocked TLS fixture did not become ready")
			}
			cancel()
			select {
			case got := <-result:
				if got.Result != "canceled" {
					t.Fatalf("partial %s accepted or cancellation lost: %+v", stage, got)
				}
			case <-time.After(time.Second):
				t.Fatal("TLS exchange outlived cancellation")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("TLS cancellation leaked its owned connection")
			}
		})
	}
}

func TestSmartTUNHTTPSMalformedHandshakeIsDistinctFromHTTP(t *testing.T) {
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 4096)
		_, _ = server.Read(buf)
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\n\r\n")
	}()
	got := smartTUNHealthExchangeWithDeadline(ctx, client, smartTUNHealthProbe{protocol: "https", expectedSource: "8.8.8.8"}, bytes.Repeat([]byte{1}, 16))
	<-done
	if got != (SmartTUNHTTPSResult{Result: "tls_handshake_failed"}) {
		t.Fatalf("plaintext TCP became TLS or HTTP proof: %+v", got)
	}
}

func TestSmartTUNHTTPSCanceledRoundRetainsCriticalSourceEvidence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := make(chan struct{})
	evidence := runSmartTUNHealthTestProbes(ctx, true, func(_ context.Context, p smartTUNHealthProbe) string {
		if p.target == 2 && p.protocol == "https" {
			close(observed)
			return "path_mismatch"
		}
		if p.target == 3 && p.protocol == "https" {
			<-observed
			cancel()
		}
		return "pass"
	})
	if evidence.VPNHealthy || evidence.Reason != "vpn_path_mismatch" ||
		evidence.HTTPSResults[2] != (SmartTUNHTTPSResult{Result: "path_mismatch", StatusCode: 200}) ||
		!validSmartTUNHTTPSEvidence(evidence, true) {
		t.Fatalf("alternate HTTPS success/cancellation hid a Direct source: %+v", evidence)
	}
}

// The peer performs an actual TLS handshake, reads the fresh HTTP request and
// writes complete TLS application records. Closing the raw stream at a record
// boundary lets the client wrapper cancel on the real EOF returned to TLS,
// before HTTP completion is classified. No classified result is injected.
func healthTLSReadCompletion(t *testing.T, parent context.Context, respond func(string) []byte,
	holdOpen bool, readError error) (SmartTUNHTTPSResult, bool) {
	t.Helper()
	certificate := healthTLSCertificate(t, "qa-server.pem")
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	exchanged := make(chan struct{})
	go func() {
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		secure := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{certificate},
			MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true})
		if err := secure.Handshake(); err != nil {
			done <- err
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(io.LimitReader(secure, 4097)))
		if err != nil {
			done <- err
			return
		}
		defer request.Body.Close()
		if request.Method != "GET" || request.RequestURI != "/health/"+hex.EncodeToString(nonce) ||
			request.Host != smartTUNHealthHTTPSName+":19224" || request.Proto != "HTTP/1.1" || !request.Close {
			done <- fmt.Errorf("unexpected completed-read HTTPS request")
			return
		}
		// This source value is a deliberate response fault, not a real leak.
		reply := respond("SCHEALTH1 " + hex.EncodeToString(nonce) + " 10.254.72.1\n")
		if n, err := secure.Write(reply); err != nil || n != len(reply) {
			if err == nil {
				err = io.ErrShortWrite
			}
			done <- err
			return
		}
		if holdOpen {
			// Complete-looking HTTP bytes without peer EOF cannot establish
			// critical evidence. Only the caller's cancellation closes it.
			cancel()
			<-exchanged
		}
		done <- nil
	}()
	connection := &healthCancelAfterReadConn{Conn: client, cancel: cancel, readError: readError}
	result := smartTUNHealthExchangeWithDeadline(ctx, connection,
		smartTUNHealthProbe{protocol: "https", expectedSource: "8.8.8.8"}, nonce)
	close(exchanged)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TLS completed-read peer did not join")
	}
	if parent.Err() != nil || (connection.completed || holdOpen) && ctx.Err() != context.Canceled {
		t.Fatalf("TLS child cancellation escaped its boundary: completed=%v child=%v parent=%v", connection.completed, ctx.Err(), parent.Err())
	}
	return result, connection.completed
}

func TestSmartTUNHTTPSReadCompletionCancellation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		respond   func(string) []byte
		want      SmartTUNHTTPSResult
		complete  bool
		holdOpen  bool
		readError error
	}{
		{name: "mismatch-content-length", respond: func(body string) []byte { return healthHTTPResponse(200, body) },
			want: SmartTUNHTTPSResult{"path_mismatch", 200}, complete: true},
		{name: "mismatch-close-delimited", respond: func(body string) []byte { return []byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body) },
			want: SmartTUNHTTPSResult{"path_mismatch", 200}, complete: true},
		{name: "positive", respond: func(body string) []byte {
			return healthHTTPResponse(200, strings.Replace(body, "10.254.72.1", "8.8.8.8", 1))
		},
			want: SmartTUNHTTPSResult{"canceled", 200}, complete: true},
		{name: "truncated-length", respond: func(body string) []byte {
			return healthHTTPResponse(200, body+"x")[:len(healthHTTPResponse(200, body+"x"))-1]
		},
			want: SmartTUNHTTPSResult{"canceled", 200}, complete: true},
		{name: "trailing-frame", respond: func(body string) []byte { return append(healthHTTPResponse(200, strings.TrimSuffix(body, "\n")), '\n') },
			want: SmartTUNHTTPSResult{"canceled", 200}, complete: true},
		{name: "malformed-body", respond: func(body string) []byte { return healthHTTPResponse(200, strings.TrimSuffix(body, "\n")) },
			want: SmartTUNHTTPSResult{"canceled", 200}, complete: true},
		{name: "stale-nonce", respond: func(body string) []byte {
			reply := []byte(body)
			reply[10] ^= 1
			return healthHTTPResponse(200, string(reply))
		}, want: SmartTUNHTTPSResult{"canceled", 200}, complete: true},
		{name: "read-error", respond: func(body string) []byte { return healthHTTPResponse(200, body) },
			want: SmartTUNHTTPSResult{"canceled", 200}, complete: true, readError: io.ErrNoProgress},
		{name: "body-without-eof", respond: func(body string) []byte { return healthHTTPResponse(200, body) },
			want: SmartTUNHTTPSResult{"canceled", 200}, holdOpen: true},
		{name: "oversized-length", respond: func(body string) []byte {
			return []byte("HTTP/1.1 200 OK\r\nContent-Length: 257\r\nConnection: close\r\n\r\n" + body)
		},
			want: SmartTUNHTTPSResult{"http_oversized_response", 200}},
		{name: "oversized-critical-shaped", respond: func(body string) []byte {
			prefix := strings.TrimSuffix(body, "10.254.72.1\n") + "fe80::1%"
			return []byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + prefix + strings.Repeat("z", 256-len(prefix)) + "\n")
		}, want: SmartTUNHTTPSResult{"http_oversized_response", 200}},
		{name: "malformed-header", respond: func(body string) []byte {
			return []byte("HTTP/1.1 200 OK\r\nContent-Length: invalid\r\nConnection: close\r\n\r\n" + body)
		},
			want: SmartTUNHTTPSResult{"http_invalid_response", 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, completed := healthTLSReadCompletion(t, context.Background(), tc.respond, tc.holdOpen, tc.readError)
			if completed != tc.complete || result != tc.want || !validSmartTUNHTTPSResult(result) {
				t.Fatalf("TLS completed-read classification: got %+v completed=%v want %+v completed=%v", result, completed, tc.want, tc.complete)
			}
		})
	}
}
