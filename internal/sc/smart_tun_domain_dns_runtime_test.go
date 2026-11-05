package sc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type domainDNSWitness struct{ Path, Destination string }
type domainDNSSOCKS struct {
	listener    net.Listener
	path        string
	dohAddress  string
	dohPort     int
	events      chan domainDNSWitness
	wg          sync.WaitGroup
	mu          sync.Mutex
	connections map[net.Conn]bool
}

func startDomainDNSSOCKS(t *testing.T, path, dohAddress string, dohPort int) *domainDNSSOCKS {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &domainDNSSOCKS{listener: ln, path: path, dohAddress: dohAddress, dohPort: dohPort, events: make(chan domainDNSWitness, 64), connections: map[net.Conn]bool{}}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.connections[c] = true
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer c.Close()
				defer func() { s.mu.Lock(); delete(s.connections, c); s.mu.Unlock() }()
				s.serve(c)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		s.mu.Lock()
		for c := range s.connections {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}
func (s *domainDNSSOCKS) port() int { return s.listener.Addr().(*net.TCPAddr).Port }
func domainDNSReadSOCKSAddress(r io.Reader, typ byte) (string, error) {
	n := 0
	switch typ {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		b := make([]byte, 1)
		if _, e := io.ReadFull(r, b); e != nil {
			return "", e
		}
		n = int(b[0])
	default:
		return "", fmt.Errorf("SOCKS address type")
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return "", e
	}
	if typ == 3 {
		return string(b), nil
	}
	ip, ok := netip.AddrFromSlice(b)
	if !ok {
		return "", fmt.Errorf("SOCKS address")
	}
	return ip.String(), nil
}
func (s *domainDNSSOCKS) serve(c net.Conn) {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	greeting := make([]byte, 2)
	if _, e := io.ReadFull(c, greeting); e != nil || greeting[0] != 5 || greeting[1] != 1 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, e := io.ReadFull(c, methods); e != nil || methods[0] != 0 {
		return
	}
	c.Write([]byte{5, 0})
	head := make([]byte, 4)
	if _, e := io.ReadFull(c, head); e != nil || head[0] != 5 || (head[1] != 1 && head[1] != 3) {
		return
	}
	address, err := domainDNSReadSOCKSAddress(c, head[3])
	if err != nil {
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(c, portBytes); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBytes))
	if head[1] == 3 {
		s.serveUDP(c)
		return
	}
	if address == "1.1.1.1" && port == s.dohPort {
		if s.path != "VPN" {
			return
		}
		conn, err := net.DialTimeout("tcp4", s.dohAddress, time.Second)
		if err != nil {
			return
		}
		defer conn.Close()
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		copyDone := make(chan struct{})
		go func() { io.Copy(conn, c); close(copyDone) }()
		io.Copy(c, conn)
		conn.Close()
		c.Close()
		<-copyDone
		return
	}
	if address != "76.76.21.21" && address != "2606:4700:1111::1" {
		c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	payload := make([]byte, 1024)
	n, err := c.Read(payload)
	if err != nil || n == 0 {
		return
	}
	s.events <- domainDNSWitness{Path: s.path, Destination: address}
	c.Write([]byte(s.path))
}
func domainDNSSOCKSDial(proxyPort int, address string, port int) (net.Conn, error) {
	c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)), time.Second)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			c.Close()
		}
	}()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	b := make([]byte, 2)
	if _, err = io.ReadFull(c, b); err != nil || b[0] != 5 || b[1] != 0 {
		return nil, fmt.Errorf("SOCKS no-auth: %v", err)
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return nil, err
	}
	req := []byte{5, 1, 0, 1}
	if ip.Is6() {
		req[3] = 4
	}
	req = append(req, ip.AsSlice()...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err = c.Write(req); err != nil {
		return nil, err
	}
	head := make([]byte, 4)
	if _, err = io.ReadFull(c, head); err != nil || head[0] != 5 || head[1] != 0 {
		return nil, fmt.Errorf("SOCKS CONNECT rejected: %v %+v", err, head)
	}
	if _, err = domainDNSReadSOCKSAddress(c, head[3]); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(c, b); err != nil {
		return nil, err
	}
	failed = false
	return c, nil
}
func domainDNSQuestionEnd(wire []byte) (int, error) {
	if len(wire) < 17 || binary.BigEndian.Uint16(wire[4:6]) != 1 {
		return 0, fmt.Errorf("DNS question count")
	}
	end := 12
	for labels := 0; labels < 128; labels++ {
		if end >= len(wire) {
			return 0, io.ErrUnexpectedEOF
		}
		n := int(wire[end])
		end++
		if n == 0 {
			if end+4 > len(wire) {
				return 0, io.ErrUnexpectedEOF
			}
			return end + 4, nil
		}
		if n > 63 || end+n > len(wire) {
			return 0, fmt.Errorf("DNS question label")
		}
		end += n
	}
	return 0, fmt.Errorf("DNS name too long")
}
func domainDNSQueryWire(name string, kind uint16) []byte {
	wire := []byte{0x4d, 0x31, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0)
	wire = binary.BigEndian.AppendUint16(wire, kind)
	return binary.BigEndian.AppendUint16(wire, 1)
}
func domainDNSRuntimeQuery(t *testing.T, port int, name string, qtype uint16) netip.Addr {
	t.Helper()
	wire := domainDNSQueryWire(name, qtype)
	c, err := domainDNSSOCKSDial(port, "8.8.8.8", 53)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)); err != nil {
		t.Fatal(err)
	}
	length := make([]byte, 2)
	if _, err = io.ReadFull(c, length); err != nil {
		t.Fatal(err)
	}
	size := int(binary.BigEndian.Uint16(length))
	if size < 12 || size > 4096 {
		t.Fatal("bad DNS reply length")
	}
	answer := make([]byte, size)
	if _, err = io.ReadFull(c, answer); err != nil {
		t.Fatal(err)
	}
	return domainDNSParseFakeReply(t, wire, answer, qtype)
}
func domainDNSParseFakeReply(t *testing.T, wire, answer []byte, qtype uint16) netip.Addr {
	t.Helper()
	qend, err := domainDNSQuestionEnd(answer)
	if err != nil || binary.BigEndian.Uint16(answer[:2]) != 0x4d31 || answer[2]&0x80 == 0 || answer[3]&15 != 0 || binary.BigEndian.Uint16(answer[6:8]) != 1 || !bytes.Equal(answer[12:qend], wire[12:]) {
		t.Fatalf("uncorrelated DNS response %x: %v", answer, err)
	}
	pos := qend
	if pos+2 <= len(answer) && answer[pos] == 0xc0 && answer[pos+1] == 12 {
		pos += 2
	} else {
		name := wire[12 : len(wire)-4]
		if pos+len(name) > len(answer) || !bytes.Equal(answer[pos:pos+len(name)], name) {
			t.Fatalf("unexpected DNS answer name: %x", answer)
		}
		pos += len(name)
	}
	if pos+10 > len(answer) || binary.BigEndian.Uint16(answer[pos:pos+2]) != qtype || binary.BigEndian.Uint16(answer[pos+2:pos+4]) != 1 {
		t.Fatal("unexpected DNS answer type")
	}
	n := int(binary.BigEndian.Uint16(answer[pos+8 : pos+10]))
	pos += 10
	if pos+n > len(answer) {
		t.Fatal("truncated DNS answer")
	}
	ip, ok := netip.AddrFromSlice(answer[pos : pos+n])
	if !ok || (qtype == 1) != ip.Is4() {
		t.Fatal("invalid fake IP answer")
	}
	return ip
}

func TestRealPinnedCoreDNSCorrelationDoesNotAuthorizeRawIPsOrUnknownFakeIPs(t *testing.T) {
	core := os.Getenv("SC_TEST_SINGBOX")
	if core == "" {
		t.Skip("NOT_RUN: real pinned sing-box not configured")
	}
	if err := EnsureCore(core); err != nil {
		t.Fatal(err)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(81), Subject: pkix.Name{CommonName: "dns.fixture.example.org"}, DNSNames: []string{"dns.fixture.example.org"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pk, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pk}))
	if err != nil {
		t.Fatal(err)
	}
	var dnsCallsMu sync.Mutex
	dnsCalls := 0
	doh := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/dns-query" {
			w.WriteHeader(400)
			return
		}
		wire, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(wire) > 4096 {
			w.WriteHeader(400)
			return
		}
		end, err := domainDNSQuestionEnd(wire)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		kind := binary.BigEndian.Uint16(wire[end-4 : end-2])
		response := append([]byte{}, wire[:end]...)
		response[2], response[3] = 0x81, 0x80
		binary.BigEndian.PutUint16(response[6:8], 1)
		binary.BigEndian.PutUint16(response[8:10], 0)
		binary.BigEndian.PutUint16(response[10:12], 0)
		var addr netip.Addr
		if kind == 1 {
			addr = netip.MustParseAddr("76.76.21.21")
		} else if kind == 28 {
			addr = netip.MustParseAddr("2606:4700:1111::1")
		} else {
			w.WriteHeader(400)
			return
		}
		response = append(response, 0xc0, 0x0c)
		response = binary.BigEndian.AppendUint16(response, kind)
		response = binary.BigEndian.AppendUint16(response, 1)
		response = binary.BigEndian.AppendUint32(response, 30)
		response = binary.BigEndian.AppendUint16(response, uint16(len(addr.AsSlice())))
		response = append(response, addr.AsSlice()...)

		data := response
		dnsCallsMu.Lock()
		dnsCalls++
		dnsCallsMu.Unlock()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(data)
	}))
	doh.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	doh.StartTLS()
	defer doh.Close()
	dohAddress := doh.Listener.Addr().String()
	_, portText, _ := net.SplitHostPort(dohAddress)
	dohPort, _ := strconv.Atoi(portText)
	direct := startDomainDNSSOCKS(t, "DIRECT", dohAddress, dohPort)
	vpn := startDomainDNSSOCKS(t, "VPN", dohAddress, dohPort)
	profile, o := dualStackTUNFixture()
	o.Exceptions = nil
	o.IPv6Exceptions = nil
	o.DomainExceptions = []SmartTUNDomainException{{Domain: "example.org", Suffix: true, Via: "direct"}, {Domain: "vpn.example.org", Via: "vpn"}, {Domain: "private.example.org", Suffix: true, Via: "vpn"}, {Domain: "direct.private.example.org", Via: "direct"}}
	config, err := SmartTUNDNSCorrelatedConfig(profile, o, SmartTUNDomainDNS{ServerIPv4: "1.1.1.1", ServerName: "dns.fixture.example.org", ServerPort: dohPort})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if json.Unmarshal(config, &cfg) != nil {
		t.Fatal("invalid compiled config")
	}
	// Only transport endpoints are projected to unprivileged test witnesses.
	// Keep the exact compiler's DNS actions/map and ordered routing policy.
	proxyPort := freePort(t)
	cfg["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "test-numeric-in", "listen": "127.0.0.1", "listen_port": proxyPort}}
	cfg["outbounds"] = []any{map[string]any{"type": "socks", "tag": "upstream", "server": "127.0.0.1", "server_port": vpn.port(), "version": "5"}, map[string]any{"type": "socks", "tag": "direct", "server": "127.0.0.1", "server_port": direct.port(), "version": "5"}}
	delete(cfg["route"].(map[string]any), "default_interface")
	cfg["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["tls"].(map[string]any)["certificate"] = string(certPEM)
	cfg["log"] = map[string]any{"level": "debug"}
	data, _ := json.Marshal(cfg)
	dir := t.TempDir()
	if err := CheckConfig(core, dir, data); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "correlated.json")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	startCore(t, core, file, proxyPort)
	t.Cleanup(func() {
		if t.Failed() {
			raw, _ := os.ReadFile(file + ".log")
			if len(raw) > 10000 {
				raw = raw[len(raw)-10000:]
			}
			t.Logf("core runtime log: %s", raw)
		}
	})
	exchange := func(address netip.Addr, want string) {
		t.Helper()
		c, err := domainDNSSOCKSDial(proxyPort, address.String(), 4443)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err = c.Write([]byte("GET / HTTP/1.1\r\nHost: direct.private.example.org\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		actual, err := io.ReadAll(io.LimitReader(c, 32))
		if err != nil || string(actual) != want {
			t.Fatalf("route %s got %q want %q: %v", address, actual, want, err)
		}
		var witness domainDNSWitness
		select {
		case witness = <-direct.events:
		case witness = <-vpn.events:
		case <-time.After(time.Second):
			t.Fatal("no independent outbound witness")
		}
		if witness.Path != want {
			t.Fatalf("wrong independent route witness %+v", witness)
		}
	}
	for _, kind := range []uint16{1, 28} {
		pool := netip.MustParsePrefix(SmartTUNDomainFakeIPv4)
		if kind == 28 {
			pool = netip.MustParsePrefix(SmartTUNDomainFakeIPv6)
		}
		for _, sample := range []struct{ name, path string }{{"direct.example.org", "DIRECT"}, {"vpn.example.org", "VPN"}, {"sub.private.example.org", "VPN"}, {"direct.private.example.org", "DIRECT"}, {"unmatched.example.net", "VPN"}} {
			fake := domainDNSRuntimeQuery(t, proxyPort, sample.name, kind)
			if !pool.Contains(fake) {
				t.Fatalf("DNS did not allocate operation fake-IP: %s", fake)
			}
			exchange(fake, sample.path)
		}
	}
	// Repeat through genuine SOCKS5 UDP transport and the core's DNS hijack.
	udpRequest := func(address netip.Addr, port int, payload []byte) ([]byte, error) {
		control, udp, relay, err := domainDNSUDPAssociate(proxyPort)
		if err != nil {
			return nil, err
		}
		defer control.Close()
		defer udp.Close()
		return domainDNSUDPRequest(udp, relay, address, port, payload)
	}
	udpExchange := func(address netip.Addr, want string) {
		t.Helper()
		reply, err := udpRequest(address, 4443, []byte("UDP-data"))
		if err != nil || string(reply) != want {
			t.Fatalf("UDP route %s got %q want %s: %v", address, reply, want, err)
		}
		var witness domainDNSWitness
		select {
		case witness = <-direct.events:
		case witness = <-vpn.events:
		case <-time.After(time.Second):
			t.Fatal("no UDP outbound witness")
		}
		if witness.Path != want {
			t.Fatalf("wrong UDP witness %+v", witness)
		}
	}
	for _, kind := range []uint16{1, 28} {
		for _, sample := range []struct{ name, path string }{{"udp.example.org", "DIRECT"}, {"vpn.example.org", "VPN"}, {"sub.private.example.org", "VPN"}, {"direct.private.example.org", "DIRECT"}} {
			query := domainDNSQueryWire(sample.name, kind)
			response, err := udpRequest(netip.MustParseAddr("8.8.8.8"), 53, query)
			if err != nil {
				t.Fatal(err)
			}
			fake := domainDNSParseFakeReply(t, query, response, kind)
			udpExchange(fake, sample.path)
		}
	}
	udpExchange(netip.MustParseAddr("76.76.21.21"), "VPN")
	udpExchange(netip.MustParseAddr("2606:4700:1111::1"), "VPN")
	// Learned names and forged Host headers must never reclassify a real IP.
	exchange(netip.MustParseAddr("76.76.21.21"), "VPN")
	exchange(netip.MustParseAddr("2606:4700:1111::1"), "VPN")
	for _, unknown := range []string{"198.19.255.254", "2001:2::ffff:ffff"} {
		if response, err := udpRequest(netip.MustParseAddr(unknown), 4443, []byte("unknown-udp")); err == nil || len(response) != 0 {
			t.Fatalf("unknown fake IP UDP returned payload: %q %v", response, err)
		}
		c, err := domainDNSSOCKSDial(proxyPort, unknown, 4443)
		if err == nil {
			c.Write([]byte("unknown"))
			data, readErr := io.ReadAll(io.LimitReader(c, 32))
			c.Close()
			if len(data) != 0 {
				t.Fatalf("unknown fake IP delivered data: %q %v", data, readErr)
			}
		}
		select {
		case e := <-direct.events:
			t.Fatalf("unknown fake IP reached Direct: %+v", e)
		case e := <-vpn.events:
			t.Fatalf("unknown fake IP reached VPN: %+v", e)
		default:
		}
	}
	// A missing authenticated DNS channel cannot fall back to an otherwise
	// permitted Direct domain. FakeIP allocation itself still needs no DoH.
	t.Run("untrusted_doh_certificate", func(t *testing.T) {
		var bad map[string]any
		if json.Unmarshal(data, &bad) != nil {
			t.Fatal("copy runtime config")
		}
		badPort := freePort(t)
		bad["inbounds"].([]any)[0].(map[string]any)["listen_port"] = badPort
		delete(bad["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["tls"].(map[string]any), "certificate")
		encoded, _ := json.Marshal(bad)
		badFile := filepath.Join(dir, "bad-trust.json")
		if err := os.WriteFile(badFile, encoded, 0600); err != nil {
			t.Fatal(err)
		}
		startCore(t, core, badFile, badPort)
		fake := domainDNSRuntimeQuery(t, badPort, "untrusted-dns.example.org", 1)
		c, err := domainDNSSOCKSDial(badPort, fake.String(), 4443)
		if err == nil {
			c.Write([]byte("must-not-deliver"))
			reply, _ := io.ReadAll(io.LimitReader(c, 32))
			c.Close()
			if len(reply) != 0 {
				t.Fatalf("TLS failure delivered payload: %q", reply)
			}
		}
		select {
		case e := <-direct.events:
			t.Fatalf("TLS failure reached Direct payload: %+v", e)
		case e := <-vpn.events:
			t.Fatalf("TLS failure reached VPN payload: %+v", e)
		default:
		}
	})
	dnsCallsMu.Lock()
	calls := dnsCalls
	dnsCallsMu.Unlock()
	if calls == 0 {
		t.Fatal("no authenticated real-core DoH request")
	}
	t.Logf("core-owned FakeIP TCP/UDP routing and TCP/UDP DNS hijack, authenticated DoH through selected detour, exact/suffix precedence, IPv4/IPv6 raw-IP isolation and unknown-map refusal PASS; DoH exchanges=%d", calls)
}
