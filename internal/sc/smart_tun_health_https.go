package sc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
)

const (
	smartTUNHealthHTTPSPort       = 19224
	smartTUNHealthHTTPSName       = "scqa-health.example.test"
	smartTUNHealthHTTPHeaderLimit = 4096
	smartTUNHealthHTTPBodyLimit   = 256
)

// Deliberately public, synthetic QA trust for the admitted disconnected fixture
// only. This exact public root is the only embedded certificate. QA leaf keys
// remain testdata and must never enter the normal installation payload.
//
//go:embed testdata/smart-health-tls/qa-root.pem
var smartTUNHealthQARootPEM []byte

// Four fixed target slots keep all evidence comparable and independently copied.
// Result is a fixed safe class; StatusCode is numeric HTTP information only.
// No response body, peer error text, URL or certificate data enters the journal.
type SmartTUNHTTPSResult struct {
	Result     string `json:"result"`
	StatusCode int    `json:"status_code"`
}

func smartTUNHealthNotRunEvidence() SmartTUNHealthEvidence {
	result := SmartTUNHealthEvidence{}
	for i := range result.HTTPSResults {
		result.HTTPSResults[i].Result = "not_run"
	}
	return result
}

func smartTUNHealthTLSConfig() *tls.Config {
	// A fresh pool contains only the exact QA root, never system or environment
	// trust. The ordinary verifier checks chain, SAN, wall time and serverAuth.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(smartTUNHealthQARootPEM)
	return &tls.Config{RootCAs: roots, ServerName: smartTUNHealthHTTPSName,
		MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
}

func exchangeSmartTUNHTTPSHealth(ctx context.Context, connection net.Conn, probe smartTUNHealthProbe, nonce []byte) SmartTUNHTTPSResult {
	if len(nonce) != 16 {
		return SmartTUNHTTPSResult{Result: "nonce_unavailable"}
	}
	// The caller owns the raw connection, cancellation callback and deadline.
	// Use it directly: no HTTP transport, ambient proxy, resolver or redirect.
	secure := tls.Client(connection, smartTUNHealthTLSConfig())
	if err := secure.HandshakeContext(ctx); err != nil {
		if ctx.Err() != nil {
			return SmartTUNHTTPSResult{Result: "canceled"}
		}
		var identity *tls.CertificateVerificationError
		if errors.As(err, &identity) {
			return SmartTUNHTTPSResult{Result: "tls_identity_failed"}
		}
		return SmartTUNHTTPSResult{Result: "tls_handshake_failed"}
	}
	request := "GET /health/" + hex.EncodeToString(nonce) + " HTTP/1.1\r\nHost: " +
		smartTUNHealthHTTPSName + ":19224\r\nConnection: close\r\n\r\n"
	if count, err := io.WriteString(secure, request); err != nil || count != len(request) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return SmartTUNHTTPSResult{Result: smartTUNHealthTransportFailure(ctx, err)}
	}
	reader := bufio.NewReaderSize(secure, 1024)
	header := make([]byte, 0, smartTUNHealthHTTPHeaderLimit)
	for !bytes.HasSuffix(header, []byte("\r\n\r\n")) {
		if len(header) == smartTUNHealthHTTPHeaderLimit {
			return SmartTUNHTTPSResult{Result: "http_oversized_response"}
		}
		b, err := reader.ReadByte()
		if err != nil {
			return smartTUNHealthHTTPReadFailure(ctx, err, 0)
		}
		header = append(header, b)
	}
	// Parsing occurs only after the entire bounded header has been collected.
	// The standard parser cannot allocate from an unbounded TLS header stream.
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(header)), &http.Request{Method: "GET"})
	if err != nil {
		return SmartTUNHTTPSResult{Result: "http_invalid_response"}
	}
	defer response.Body.Close()
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.StatusCode < 100 || response.StatusCode > 599 {
		return SmartTUNHTTPSResult{Result: "http_invalid_response"}
	}
	status := response.StatusCode
	if status != http.StatusOK {
		return SmartTUNHTTPSResult{Result: "http_status", StatusCode: status}
	}
	if len(response.TransferEncoding) != 0 || len(response.Trailer) != 0 || response.Header.Get("Content-Encoding") != "" ||
		(response.ContentLength < 0 && !response.Close) {
		return SmartTUNHTTPSResult{Result: "http_invalid_response", StatusCode: status}
	}
	if response.ContentLength > smartTUNHealthHTTPBodyLimit {
		return SmartTUNHTTPSResult{Result: "http_oversized_response", StatusCode: status}
	}
	var reply []byte
	var readErr error
	if response.ContentLength >= 0 {
		// An HTTP/1.1 length-delimited message ends at exactly these bytes;
		// waiting for TLS EOF can erase already complete source evidence.
		reply = make([]byte, int(response.ContentLength))
		_, readErr = io.ReadFull(reader, reply)
	} else {
		// Close-delimited replies still require a successful EOF.
		reply, readErr = io.ReadAll(io.LimitReader(reader, smartTUNHealthHTTPBodyLimit+1))
	}
	// Reject any immediately buffered surplus after a declared-length body.
	// Never wait for an extra byte/EOF: it is not part of this HTTP message.
	extraBuffered := response.ContentLength >= 0 && reader.Buffered() > 0
	classification := "invalid_response"
	if readErr == nil && len(reply) <= smartTUNHealthHTTPBodyLimit && !extraBuffered {
		classification = smartTUNHealthReply(reply, probe, nonce)
		// Completed critical evidence survives subsequent child cancellation;
		// canceled positive replies still cannot authorize healthy supervision.
		if classification == "path_mismatch" {
			return SmartTUNHTTPSResult{Result: classification, StatusCode: status}
		}
	}
	if ctx.Err() != nil {
		return SmartTUNHTTPSResult{Result: "canceled", StatusCode: status}
	}
	if len(reply) > smartTUNHealthHTTPBodyLimit {
		return SmartTUNHTTPSResult{Result: "http_oversized_response", StatusCode: status}
	}
	if readErr != nil {
		return smartTUNHealthHTTPReadFailure(ctx, readErr, status)
	}
	if extraBuffered {
		return SmartTUNHTTPSResult{Result: "http_invalid_response", StatusCode: status}
	}
	return SmartTUNHTTPSResult{Result: classification, StatusCode: status}
}

func smartTUNHealthHTTPReadFailure(ctx context.Context, err error, status int) SmartTUNHTTPSResult {
	result := "http_truncated_response"
	if ctx.Err() != nil {
		result = "canceled"
	} else if transport := smartTUNHealthTransportFailure(ctx, err); transport == "timeout" {
		result = transport
	}
	return SmartTUNHTTPSResult{Result: result, StatusCode: status}
}
