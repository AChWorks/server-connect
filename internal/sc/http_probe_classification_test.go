package sc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHTTPProbeErrorClassificationTLSHostnameAndWrappedFailures(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	cert := server.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	hostname := "127.0.0.1"
	if len(cert.DNSNames) > 0 {
		hostname = cert.DNSNames[0]
	} else if len(cert.IPAddresses) > 0 {
		hostname = cert.IPAddresses[0].String()
	}
	_, mismatch := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "deliberately-wrong-name.invalid"})
	var hostnameError x509.HostnameError
	if !errors.As(mismatch, &hostnameError) {
		t.Fatalf("test did not obtain a trusted-root hostname mismatch: %T %v", mismatch, mismatch)
	}
	_, untrusted := cert.Verify(x509.VerifyOptions{Roots: x509.NewCertPool(), DNSName: hostname})
	var authorityError x509.UnknownAuthorityError
	if !errors.As(untrusted, &authorityError) {
		t.Fatalf("test did not obtain untrusted CA error: %T %v", untrusted, untrusted)
	}
	_, expired := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: hostname, CurrentTime: cert.NotAfter.Add(time.Minute)})
	var invalidError x509.CertificateInvalidError
	if !errors.As(expired, &invalidError) {
		t.Fatalf("test did not obtain expiry error: %T %v", expired, expired)
	}
	wrapped := func(err error) error {
		return &url.Error{
			Op:  "Get",
			URL: "https://sensitive-host.invalid/?secret=private",
			Err: &tls.CertificateVerificationError{
				UnverifiedCertificates: []*x509.Certificate{cert},
				Err:                    err,
			},
		}
	}
	for _, tt := range []struct {
		name  string
		cause error
		code  string
	}{
		{"untrusted_ca", wrapped(untrusted), "probe_tls"},
		{"trusted_ca_wrong_hostname", wrapped(mismatch), "probe_tls"},
		{"expired_cert", wrapped(expired), "probe_tls"},
		{"bare_hostname_error", fmt.Errorf("wrapped: %w", mismatch), "probe_tls"},
		{"dns", &url.Error{Op: "Get", URL: "https://secret.invalid", Err: &net.DNSError{Err: "unknown", Name: "secret.invalid"}}, "probe_dns"},
		{"connection_refused", &url.Error{Op: "Get", URL: "https://secret.invalid", Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}, "probe_connect"},
		{"timeout", fmt.Errorf("private: %w", context.DeadlineExceeded), "probe_timeout"},
		{"unknown_transport", errors.New("very-private-provider-token"), "probe_transport"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			diagnostic := classifyHTTPProbeError(tt.cause)
			if ErrorCode(diagnostic) != tt.code {
				t.Fatalf("unexpected safe error classification: %s expected %s", ErrorCode(diagnostic), tt.code)
			}
			for _, secret := range []string{"private", "secret", "sensitive", "invalid"} {
				if strings.Contains(strings.ToLower(diagnostic.Error()), secret) {
					t.Fatalf("raw error or certificate content leaked: %s", diagnostic)
				}
			}
		})
	}
}
