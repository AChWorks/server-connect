package sc

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}
func startCore(t *testing.T, core, file string, port int) *exec.Cmd {
	t.Helper()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, core, "run", "-c", file)
	log, e := os.Create(filepath.Join(filepath.Dir(file), filepath.Base(file)+".log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		log.Close()
		t.Fatal(e)
	}
	log.Close()
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	for i := 0; i < 70; i++ {
		conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if e == nil {
			conn.Close()
			return cmd
		}
		if cmd.ProcessState != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("sing-box listener did not become ready")
	return nil
}
func TestRealPinnedCoreProxyOnly(t *testing.T) {
	core := os.Getenv("SC_TEST_SINGBOX")
	if core == "" {
		t.Skip("NOT_RUN: real sing-box binary not configured; set SC_TEST_SINGBOX")
	}
	if e := EnsureCore(core); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	upstreamPort := freePort(t)
	proxyPort := freePort(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-SC-Test", "local-origin")
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer server.Close()
	inbound := map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{map[string]any{"type": "vless", "tag": "vless-in", "listen": "127.0.0.1", "listen_port": upstreamPort, "users": []any{map[string]string{"uuid": testUUID}}}}, "outbounds": []any{map[string]string{"type": "direct", "tag": "direct"}}}
	sbytes, _ := json.Marshal(inbound)
	srvFile := filepath.Join(dir, "upstream.json")
	if e := os.WriteFile(srvFile, sbytes, 0600); e != nil {
		t.Fatal(e)
	}
	if e := CheckConfig(core, dir, sbytes); e != nil {
		t.Fatal(e)
	}
	source := []byte("vless://" + testUUID + "@127.0.0.1:" + strconv.Itoa(upstreamPort) + "?security=none&type=tcp#LocalOnly")
	p, e := ValidateSource(source, "")
	if e != nil {
		t.Fatal(e)
	}
	clientCfg, e := CoreConfig(p, proxyPort, "test-proxy-password")
	if e != nil {
		t.Fatal(e)
	}
	if e = CheckConfig(core, dir, clientCfg); e != nil {
		t.Fatal(e)
	}
	cliFile := filepath.Join(dir, "client.json")
	if e = os.WriteFile(cliFile, clientCfg, 0600); e != nil {
		t.Fatal(e)
	}
	upstream := startCore(t, core, srvFile, upstreamPort)
	client := startCore(t, core, cliFile, proxyPort)
	_ = client
	if e := checkLocalAuth(proxyPort, "test-proxy-password"); e != nil {
		t.Fatalf("real SOCKS5 auth readiness failed: %v", e)
	}
	if e := checkLocalAuth(proxyPort, "wrong-password"); e == nil {
		t.Fatal("incorrect local proxy password accepted")
	}
	proxyURL, _ := url.Parse("http://sc:test-proxy-password@127.0.0.1:" + strconv.Itoa(proxyPort))
	viaProxy := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 4 * time.Second}
	viaDirect := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 4 * time.Second}
	get := func(c *http.Client) (int, error) {
		resp, e := c.Get(server.URL)
		if e != nil {
			return 0, e
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == 200 && string(b) != "ok" {
			t.Fatalf("origin mismatch %q", b)
		}
		return resp.StatusCode, nil
	}
	if status, e := get(viaProxy); e != nil || status != 200 {
		t.Fatalf("real VLESS proxy failed: status=%d err=%v", status, e)
	}
	if status, e := get(viaDirect); e != nil || status != 200 {
		t.Fatalf("direct path failed: status=%d err=%v", status, e)
	}
	if e := upstream.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	upstream.Wait()
	// A broken upstream cannot silently masquerade as a working selected proxy.
	if status, e := get(viaProxy); e == nil && status >= 200 && status < 400 {
		t.Fatal("proxy unexpectedly succeeded without VLESS upstream")
	}
	if status, e := get(viaDirect); e != nil || status != 200 {
		t.Fatalf("direct access changed after upstream died: status=%d err=%v", status, e)
	}
}

// Syntax acceptance is not reachability. Verify every advertised VLESS link
// shape against the actual pinned upstream core, then separately test TCP live.
func TestPinnedCoreAcceptsSupportedVLESSConfigShapes(t *testing.T) {
	core := os.Getenv("SC_TEST_SINGBOX")
	if core == "" {
		t.Skip("NOT_RUN: pinned sing-box executable unavailable")
	}
	if err := EnsureCore(core); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"vless-tcp":     "vless://" + testUUID + "@127.0.0.1:443?type=tcp&security=none",
		"vless-tls":     "vless://" + testUUID + "@example.org:443?type=tcp&security=tls&sni=example.org",
		"vless-ws-tls":  "vless://" + testUUID + "@example.org:443?type=ws&security=tls&sni=example.org&path=%2Fws&host=example.org",
		"vless-reality": "vless://" + testUUID + "@example.org:443?type=tcp&security=reality&sni=example.org&pbk=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA&sid=1234&fp=chrome",
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			p, e := ValidateSource([]byte(source), "")
			if e != nil {
				t.Fatal(e)
			}
			cfg, e := CoreConfig(p, 20807, "test-password")
			if e != nil {
				t.Fatal(e)
			}
			if e = CheckConfig(core, t.TempDir(), cfg); e != nil {
				t.Fatal(e)
			}
		})
	}
}
