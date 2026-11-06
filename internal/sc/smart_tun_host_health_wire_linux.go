//go:build linux

package sc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

const (
	hostHealthHeaderLimit = 8192
	hostHealthBodyLimit   = 4096
	hostHealthWireLimit   = 16384
	hostHealthDNSLimit    = 4096
)

// The private TLS argument is a test seam, not a public trust override.
// Production always constructs normal system-root verification below.
func exchangeHostHealthConnection(ctx context.Context, c net.Conn, p hostHealthProbe, testTLS *tls.Config) HostHealthResult {
	defer c.Close()
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = c.Close(); close(joined) })
	defer func() {
		if !stop() {
			<-joined
		}
	}()
	deadline, ok := ctx.Deadline()
	if !ok {
		return HostHealthResult{Result: "deadline_unavailable"}
	}
	if err := c.SetDeadline(deadline); err != nil {
		if ctx.Err() != nil {
			return HostHealthResult{Result: "canceled"}
		}
		return HostHealthResult{Result: "deadline_unavailable"}
	}
	if p.bypass && p.source != "" {
		address, ok := c.LocalAddr().(*net.TCPAddr)
		expected, err := netip.ParseAddr(p.source)
		if !ok || err != nil {
			return HostHealthResult{Result: "source_binding_failed"}
		}
		actual, ok := netip.AddrFromSlice(address.IP)
		if !ok || actual.Unmap() != expected {
			return HostHealthResult{Result: "source_binding_failed"}
		}
	}
	if ctx.Err() != nil {
		return HostHealthResult{Result: "canceled"}
	}
	if p.role == "endpoint" {
		return HostHealthResult{Result: "pass"}
	}
	if p.role == "dns" {
		return HostHealthResult{Result: exchangeHostHealthDNS(ctx, c, p.family)}
	}
	return exchangeHostHealthTrace(ctx, c, p.target, p.expected, testTLS)
}

func exchangeHostHealthTrace(ctx context.Context, c net.Conn, t HostHealthTraceTarget, expected string, testTLS *tls.Config) HostHealthResult {
	config := &tls.Config{ServerName: t.ServerName, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if testTLS != nil {
		config = testTLS.Clone()
		// Tests can supply an explicit private root pool, never skip verification.
		if config.InsecureSkipVerify || config.ServerName != t.ServerName {
			return HostHealthResult{Result: "tls_identity_failed"}
		}
		config.MinVersion = tls.VersionTLS12
		config.NextProtos = []string{"http/1.1"}
	}
	secure := tls.Client(c, config)
	if err := secure.HandshakeContext(ctx); err != nil {
		if ctx.Err() != nil {
			return HostHealthResult{Result: "canceled"}
		}
		var identity *tls.CertificateVerificationError
		if errors.As(err, &identity) {
			return HostHealthResult{Result: "tls_identity_failed"}
		}
		return HostHealthResult{Result: "tls_handshake_failed"}
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return HostHealthResult{Result: "nonce_unavailable"}
	}
	authority := t.ServerName
	if t.Port != 443 {
		authority = net.JoinHostPort(t.ServerName, strconv.Itoa(t.Port))
	}
	request := "GET " + t.Path + "?sc_health=" + hex.EncodeToString(nonce) + " HTTP/1.1\r\nHost: " + authority +
		"\r\nConnection: close\r\nCache-Control: no-cache, no-store\r\nUser-Agent: server-connect-health/1\r\n\r\n"
	if n, err := io.WriteString(secure, request); err != nil || n != len(request) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return HostHealthResult{Result: smartTUNHealthTransportFailure(ctx, err)}
	}
	wire := &io.LimitedReader{R: secure, N: hostHealthWireLimit + 1}
	reader := bufio.NewReaderSize(wire, 1024)
	header := make([]byte, 0, hostHealthHeaderLimit)
	for !bytes.HasSuffix(header, []byte("\r\n\r\n")) {
		if len(header) >= hostHealthHeaderLimit {
			return HostHealthResult{Result: "http_oversized_response"}
		}
		value, err := reader.ReadByte()
		if err != nil {
			return HostHealthResult{Result: hostHealthReadFailure(ctx, err)}
		}
		header = append(header, value)
	}
	stream := bufio.NewReader(io.MultiReader(bytes.NewReader(header), reader))
	response, err := http.ReadResponse(stream, &http.Request{Method: "GET"})
	if err != nil {
		return HostHealthResult{Result: "http_invalid_response"}
	}
	defer response.Body.Close()
	result := HostHealthResult{HTTPStatus: response.StatusCode}
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.StatusCode < 100 || response.StatusCode > 599 {
		result.Result = "http_invalid_response"
		return result
	}
	if response.StatusCode != http.StatusOK {
		result.Result = "http_status"
		return result
	}
	if response.Header.Get("Content-Encoding") != "" || response.ContentLength > hostHealthBodyLimit ||
		(response.ContentLength < 0 && len(response.TransferEncoding) == 0 && !response.Close) {
		result.Result = "http_invalid_response"
		return result
	}
	// A dynamic trace must explicitly forbid cached representation reuse.
	// The request also uses an unpredictable query on a new verified TLS flow.
	if !hostHealthNoStore(response.Header.Get("Cache-Control")) {
		result.Result = "http_cache_unverified"
		return result
	}
	if len(response.Header.Values("Age")) > 1 {
		result.Result = "http_stale_response"
		return result
	}
	if age := response.Header.Get("Age"); age != "" {
		value, err := strconv.ParseUint(age, 10, 64)
		if err != nil || value != 0 {
			result.Result = "http_stale_response"
			return result
		}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, hostHealthBodyLimit+1))
	if err != nil {
		result.Result = hostHealthReadFailure(ctx, err)
		return result
	}
	if stream.Buffered() > 0 || reader.Buffered() > 0 {
		result.Result = "http_invalid_response"
		return result
	}
	if len(body) > hostHealthBodyLimit || wire.N == 0 {
		result.Result = "http_oversized_response"
		return result
	}
	observed, err := parseHostHealthTrace(body)
	if err != nil {
		result.Result = "http_invalid_response"
		return result
	}
	result.ObservedIP = observed
	if observed != expected {
		result.Result = "path_mismatch"
		return result
	}
	if ctx.Err() != nil {
		result.Result = "canceled"
		return result
	}
	result.Result = "pass"
	return result
}
func hostHealthNoStore(value string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "no-store") {
			return true
		}
	}
	return false
}
func parseHostHealthTrace(body []byte) (string, error) {
	if len(body) == 0 || len(body) > hostHealthBodyLimit || body[len(body)-1] != '\n' {
		return "", errors.New("invalid trace framing")
	}
	ip, scheme := "", ""
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	if len(lines) > 64 {
		return "", errors.New("trace line bound exceeded")
	}
	for _, line := range lines {
		if len(line) == 0 || len(line) > 1024 {
			return "", errors.New("invalid trace line")
		}
		for _, r := range line {
			if r < 0x20 || r > 0x7e {
				return "", errors.New("invalid trace byte")
			}
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return "", errors.New("invalid trace member")
		}
		switch key {
		case "ip":
			if ip != "" {
				return "", errors.New("duplicate observed source")
			}
			parsed, ok := hostHealthPublicIP(value, 0)
			if !ok {
				return "", errors.New("invalid observed source")
			}
			ip = parsed.String()
		case "visit_scheme":
			if scheme != "" {
				return "", errors.New("duplicate trace scheme")
			}
			scheme = value
		}
	}
	if ip == "" || scheme != "https" {
		return "", errors.New("incomplete authenticated trace")
	}
	return ip, nil
}
func hostHealthReadFailure(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return "canceled"
	}
	if result := smartTUNHealthTransportFailure(ctx, err); result == "timeout" {
		return result
	}
	return "truncated_response"
}

func hostHealthDNSQuestion(nonce []byte, family int) ([]byte, []byte, error) {
	if len(nonce) != 16 || (family != 4 && family != 6) {
		return nil, nil, errors.New("DNS nonce or family unavailable")
	}
	label := "sc-health-" + hex.EncodeToString(nonce)
	question := append([]byte{byte(len(label))}, []byte(label)...)
	question = append(question, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	if family == 6 {
		question[len(question)-3] = 28
	}
	request := make([]byte, 12, 12+len(question))
	copy(request[:2], nonce[:2])
	binary.BigEndian.PutUint16(request[2:4], 0x0100)
	binary.BigEndian.PutUint16(request[4:6], 1)
	return append(request, question...), question, nil
}
func exchangeHostHealthDNS(ctx context.Context, c net.Conn, family int) string {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "nonce_unavailable"
	}
	query, question, err := hostHealthDNSQuestion(nonce, family)
	if err != nil {
		return "invalid_request"
	}
	n, err := c.Write(query)
	if err != nil || n != len(query) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return smartTUNHealthTransportFailure(ctx, err)
	}
	reply := make([]byte, hostHealthDNSLimit+1)
	n, err = c.Read(reply)
	if err != nil {
		return smartTUNHealthTransportFailure(ctx, err)
	}
	if n > hostHealthDNSLimit {
		return "dns_oversized_response"
	}
	if !validHostHealthDNSResponse(reply[:n], binary.BigEndian.Uint16(query[:2]), question) {
		return "dns_invalid_response"
	}
	if ctx.Err() != nil {
		return "canceled"
	}
	return "pass"
}
func validHostHealthDNSResponse(raw []byte, id uint16, question []byte) bool {
	if len(raw) < 12+len(question) || len(raw) > hostHealthDNSLimit || len(question) == 0 ||
		binary.BigEndian.Uint16(raw[:2]) != id || binary.BigEndian.Uint16(raw[4:6]) != 1 {
		return false
	}
	flags := binary.BigEndian.Uint16(raw[2:4])
	if flags&0x8000 == 0 || flags&(0x7800|0x0200|0x0040) != 0 || (flags&15 != 0 && flags&15 != 3) {
		return false
	}
	if !bytes.Equal(raw[12:12+len(question)], question) {
		return false
	}
	answers := int(binary.BigEndian.Uint16(raw[6:8]))
	authority := int(binary.BigEndian.Uint16(raw[8:10]))
	records := answers + authority + int(binary.BigEndian.Uint16(raw[10:12]))
	if records > 64 {
		return false
	}
	offset := 12 + len(question)
	for i := 0; i < records; i++ {
		start := offset
		var ok bool
		offset, ok = hostHealthSkipDNSName(raw, offset)
		if !ok || offset+10 > len(raw) {
			return false
		}
		typ := binary.BigEndian.Uint16(raw[offset : offset+2])
		class := binary.BigEndian.Uint16(raw[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(raw[offset+4 : offset+8])
		length := int(binary.BigEndian.Uint16(raw[offset+8 : offset+10]))
		offset += 10
		if length > len(raw)-offset {
			return false
		}
		if typ == 41 {
			// OPT must be root-owned, in Additional, version zero and no extended error.
			if i < answers+authority || raw[start] != 0 || ttl&0xffff0000 != 0 || class < 512 {
				return false
			}
			for pos := offset; pos < offset+length; {
				if pos+4 > offset+length {
					return false
				}
				size := int(binary.BigEndian.Uint16(raw[pos+2 : pos+4]))
				pos += 4
				if size > offset+length-pos {
					return false
				}
				pos += size
			}
		} else if class != 1 || !hostHealthDNSRData(raw, offset, offset+length, typ) {
			return false
		}
		offset += length
	}
	return offset == len(raw)
}
func hostHealthDNSRData(raw []byte, start, end int, typ uint16) bool {
	name := func(at int) (int, bool) { next, ok := hostHealthSkipDNSName(raw, at); return next, ok && next <= end }
	switch typ {
	case 1:
		return end-start == 4
	case 28:
		return end-start == 16
	case 2, 5, 12:
		next, ok := name(start)
		return ok && next == end
	case 15:
		if end-start < 3 {
			return false
		}
		next, ok := name(start + 2)
		return ok && next == end
	case 6:
		next, ok := name(start)
		if !ok {
			return false
		}
		next, ok = name(next)
		return ok && end-next == 20
	case 16:
		if start == end {
			return false
		}
		for start < end {
			n := int(raw[start])
			start++
			if n > end-start {
				return false
			}
			start += n
		}
		return true
	case 33:
		if end-start < 7 {
			return false
		}
		next, ok := name(start + 6)
		return ok && next == end
	default:
		// Unknown RR binary types retain their declared, bounded length. They
		// cannot establish an answer value; this witness is reachability only.
		return true
	}
}
func hostHealthSkipDNSName(raw []byte, offset int) (int, bool) {
	next, total := -1, 0
	for labels := 0; labels < 128; labels++ {
		if offset >= len(raw) {
			return 0, false
		}
		at := offset
		n := int(raw[offset])
		offset++
		if n == 0 {
			if next < 0 {
				next = offset
			}
			return next, total <= 255
		}
		if n&0xc0 == 0xc0 {
			if offset >= len(raw) {
				return 0, false
			}
			pointer := (n&0x3f)<<8 | int(raw[offset])
			if pointer >= at {
				return 0, false
			}
			if next < 0 {
				next = offset + 1
			}
			offset = pointer
			continue
		}
		if n > 63 || n > len(raw)-offset {
			return 0, false
		}
		total += n + 1
		if total > 255 {
			return 0, false
		}
		offset += n
	}
	return 0, false
}
