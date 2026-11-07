package sc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	"sync"
	"testing"
	"time"
)

// This opt-in release-blocking regression intentionally FAILS the current
// invariant. Do not change it to expect Direct or skip it after opt-in.
// It uses the production compiler's DNS map and ordered policy with the same
// unprivileged numeric ingress and independent outbound witnesses as the
// ordinary DNS runtime test. It creates no TUN, routes, firewall or services.
// See docs/QA-FAKEIP-STALE-REUSE.md for replay and evidence limits.
func TestRealPinnedCoreDNSCorrelationStaleAddressReuseAfterRestart(t *testing.T) {
	if os.Getenv("SC_TEST_DNS_STALE_REUSE") != "known-defect-negative" {
		t.Skip("NOT_RUN: explicit known-defect-negative opt-in required; current stale FakeIP reuse violates fail-closed routing")
	}
	core := os.Getenv("SC_TEST_SINGBOX")
	if core == "" {
		t.Fatal("SC_TEST_SINGBOX must identify the verified official Linux amd64 sing-box 1.14.3 binary")
	}
	const expectedCoreSHA256 = "768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93"
	f, err := os.Open(core)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, f)
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || fmt.Sprintf("%x", hash.Sum(nil)) != expectedCoreSHA256 {
		t.Fatalf("official pinned Core SHA256 mismatch or unreadable binary: read=%v close=%v", readErr, closeErr)
	}
	t.Logf("CORE_VERSION=1.14.3 CORE_SHA256=%s", expectedCoreSHA256)
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
	t.Logf("COMPILER_CONFIG_SHA256=%x", sha256.Sum256(config))
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

	running := startCore(t, core, file, proxyPort)
	exchange := func(address netip.Addr) (string, string) {
		t.Helper()
		c, e := domainDNSSOCKSDial(proxyPort, address.String(), 4443)
		if e != nil {
			return "", ""
		}
		defer c.Close()
		if _, e = c.Write([]byte("GET / HTTP/1.1\r\nHost: vpn.example.org\r\n\r\n")); e != nil {
			return "", ""
		}
		body, _ := io.ReadAll(io.LimitReader(c, 32))
		if len(body) == 0 {
			// Missing reply bytes cannot hide independently observed delivery.
			select {
			case witness := <-direct.events:
				return "", witness.Path
			case witness := <-vpn.events:
				return "", witness.Path
			default:
				return "", ""
			}
		}
		var witness domainDNSWitness
		select {
		case witness = <-direct.events:
		case witness = <-vpn.events:
		case <-time.After(time.Second):
			t.Fatal("payload without independent route witness")
		}
		return string(body), witness.Path
	}
	stale := domainDNSRuntimeQuery(t, proxyPort, "vpn.example.org", 1)
	if body, path := exchange(stale); body != "VPN" || path != "VPN" {
		t.Fatalf("first generation VPN control failed: fake=%s body=%q path=%q", stale, body, path)
	}
	t.Logf("BEFORE_RESTART vpn.example.org fake=%s route=VPN independently witnessed", stale)
	if err := running.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = running.Wait()
	if running.ProcessState == nil {
		t.Fatal("old core lifetime was not reaped")
	}
	startCore(t, core, file, proxyPort)
	if body, path := exchange(stale); body != "" || path != "" {
		t.Fatalf("unknown stale address was not initially refused: body=%q path=%q", body, path)
	}
	select {
	case e := <-direct.events:
		t.Fatalf("unknown stale address reached Direct: %+v", e)
	case e := <-vpn.events:
		t.Fatalf("unknown stale address reached VPN: %+v", e)
	default:
	}
	t.Logf("AFTER_RESTART_BEFORE_ALLOCATION cached_fake=%s refused with no outbound witness", stale)
	current := domainDNSRuntimeQuery(t, proxyPort, "direct.example.org", 1)
	if current != stale {
		t.Fatalf("expected deterministic pool reset was not reproduced: old=%s current=%s", stale, current)
	}
	if body, path := exchange(current); body != "DIRECT" || path != "DIRECT" {
		t.Fatalf("new Direct generation control failed: body=%q path=%q", body, path)
	}
	t.Logf("NEW_ALLOCATION direct.example.org fake=%s route=DIRECT independently witnessed", current)
	body, path := exchange(stale)
	if body == "DIRECT" || path == "DIRECT" {
		t.Fatalf("STALE_FAKEIP_REUSE_WRONG_PATH: cached vpn.example.org address %s was reassigned to direct.example.org; old numeric destination delivered payload through DIRECT after restart (payload=%q witness=%q)", stale, body, path)
	}
	if body != "" && body != "VPN" || path != "" && path != "VPN" {
		t.Fatalf("unexpected stale route: body=%q path=%q", body, path)
	}
}
