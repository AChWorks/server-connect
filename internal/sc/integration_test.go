package sc

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	if _, e := trustedAPTCommand("apt-get"); e == nil {
		t.Run("RealAPTBoundToPinnedVLESS", func(t *testing.T) {
			testAPTThroughCore(t, proxyURL)
		})
		t.Run("NativeMirrorAndPDiffBoundToPinnedVLESS", func(t *testing.T) {
			testAPTNativeMirrorAndPDiff(t, proxyURL)
		})
	} else {
		t.Log("NOT_RUN: apt-get is not installed; only live VLESS HTTP acceptance ran")
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

// testAPTThroughCore runs a real distro APT HTTP transport over the active
// pinned sing-box proxy, using an isolated unsigned *test-only* repository.
// No APT installation, system source list or global cache is ever changed.
func testAPTThroughCore(t *testing.T, proxyURL *url.URL) {
	t.Helper()
	packageIndex := []byte("Package: server-connect-ci-only\nVersion: 0.0.1\nArchitecture: amd64\nMaintainer: Disposable QA <qa@invalid.test>\nDescription: CI-only no-install package\n\n")
	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	if _, err := zw.Write(packageIndex); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zippedIndex := zipped.Bytes()
	digest := sha256.Sum256(zippedIndex)
	plainDigest := sha256.Sum256(packageIndex)
	release := fmt.Sprintf("Origin: Server Connect CI\nLabel: SC disposable test\nSuite: qa\nCodename: qa\nArchitectures: amd64\nComponents: main\nDate: %s\nSHA256:\n %x %d main/binary-amd64/Packages\n %x %d main/binary-amd64/Packages.gz\n", time.Now().UTC().Format(time.RFC1123Z), plainDigest, len(packageIndex), digest, len(zippedIndex))
	originHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dists/qa/Release":
			w.Write([]byte(release))
		case "/dists/qa/main/binary-amd64/Packages.gz":
			w.Write(zippedIndex)
		case "/dists/qa/main/binary-amd64/Packages":
			w.Write(packageIndex)
		default:
			http.NotFound(w, r)
		}
	})
	aptOrigin := httptest.NewServer(originHandler)
	defer aptOrigin.Close()
	secondary := httptest.NewServer(originHandler)
	defer secondary.Close()
	dir := t.TempDir()
	for _, name := range []string{"lists", "lists/partial", "archives"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	source := filepath.Join(dir, "sources.list")
	if err := os.WriteFile(source, []byte(
		"deb [trusted=yes] "+aptOrigin.URL+" qa main\n"+
			"deb [trusted=yes] "+secondary.URL+" qa main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	fd, err := privateAptConfig(state, proxyURL)
	if err != nil {
		t.Fatal("could not prepare anonymous APT credentials")
	}
	defer fd.Close()
	args := []string{
		"-c", "/proc/self/fd/3", "update",
		"-o", "Dir::Etc::sourcelist=" + source,
		"-o", "Dir::Etc::sourceparts=-",
		"-o", "Dir::State::lists=" + filepath.Join(dir, "lists"),
		"-o", "Dir::Cache::archives=" + filepath.Join(dir, "archives"),
		"-o", "Dir::Cache::pkgcache=/dev/null",
		"-o", "Dir::Cache::srcpkgcache=/dev/null",
		"-o", "APT::Get::List-Cleanup=0",
		"-o", "Debug::NoLocking=1",
		"-o", "Debug::Acquire::http=1",
	}
	rawNative, err := trustedAPTCommand("apt-get")
	if err != nil {
		t.Fatal("genuine native APT binary unavailable")
	}
	cmd := exec.Command(rawNative, args...)
	cmd.Env = safeAptEnv()
	cmd.ExtraFiles = []*os.File{fd}
	// Debug::Acquire may print Proxy-Authorization: never reveal raw output.
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated APT update failed (raw credential-bearing trace withheld): %v", err)
	}
	if !bytes.Contains(out, []byte("GET "+aptOrigin.URL+"/dists/qa/")) {
		t.Fatal("APT debug trace does not show proxy-style absolute URI request")
	}
	if !strings.Contains(strings.ToLower(string(out)), "proxy-authorization:") {
		t.Fatal("authenticated proxy request not observed in APT debug trace")
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 0 {
		t.Fatal("anonymous APT credentials left a file on disk")
	}
	listEntries, err := os.ReadDir(filepath.Join(dir, "lists"))
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, entry := range listEntries {
		if strings.Contains(entry.Name(), "_Packages") {
			found++
		}
	}
	if found < 2 {
		names := make([]string, 0, len(listEntries))
		for _, entry := range listEntries {
			names = append(names, entry.Name())
		}
		safeProgress := make([]string, 0)
		for _, line := range strings.Split(string(out), "\n") {
			for _, prefix := range []string{"Get:", "Ign:", "Err:", "W:", "E:", "Fetched "} {
				if strings.HasPrefix(line, prefix) {
					safeProgress = append(safeProgress, line)
					break
				}
			}
		}
		t.Fatalf("APT package indexes missing: file_names=%v safe_progress=%v", names, safeProgress)
	}
	// Exercise the SAME credential-bearing path as the public APT wrapper.
	// Both actual Debian-family clients must use trusted native paths, verify
	// effective proxy policy, and reach the fixture through pinned VLESS.
	wrappedArgs := []string{
		"update",
		"-o", "Dir::Etc::sourcelist=" + source,
		"-o", "Dir::Etc::sourceparts=-",
		"-o", "Dir::State::lists=" + filepath.Join(dir, "lists"),
		"-o", "Dir::Cache::archives=" + filepath.Join(dir, "archives"),
		"-o", "Dir::Cache::pkgcache=/dev/null",
		"-o", "Dir::Cache::srcpkgcache=/dev/null",
		"-o", "APT::Get::List-Cleanup=0",
		"-o", "Debug::NoLocking=1",
	}
	_, action, err := validateAptArgs(wrappedArgs)
	if err != nil || action != "update" {
		t.Fatalf("wrapped update not accepted: %v", err)
	}
	for _, token := range []string{"apt-get", "apt"} {
		native, e := trustedAPTCommand(token)
		if e != nil {
			t.Fatalf("native %s path untrusted: %v", token, e)
		}
		code, e := aptThroughSelectedProxy(native, wrappedArgs, t.TempDir(), proxyURL)
		if e != nil || code != 0 {
			t.Fatalf("actual native %s via VLESS failed: exit=%d err=%v", token, code, e)
		}
	}
	// Combined update is explicitly unsupported: it cannot cause a hidden
	// non-strict index refresh before install, even on the VLESS path.
	for _, flag := range []string{"-U", "--update", "-qU"} {
		if _, _, e := validateAptArgs([]string{flag, "install", "qa-only"}); e == nil {
			t.Fatal("unsupported combined APT update accepted on genuine core integration")
		}
	}
	// Close one repository AFTER indexing it. An ordinary apt-get update can
	// return success while retaining stale indexes, so require strict mode.
	// This synthetic server is entirely local; never log its auth debug trace.
	secondary.Close()
	if _, err = fd.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	strictArgs := append(append([]string{}, args...), "--error-on=any")
	strict := exec.Command(rawNative, strictArgs...)
	strict.Env = safeAptEnv()
	strict.ExtraFiles = []*os.File{fd}
	failedOutput, runErr := strict.CombinedOutput()
	if runErr == nil {
		t.Fatal("partial APT failure incorrectly reported success with cached indexes")
	}
	var exit *exec.ExitError
	if !errors.As(runErr, &exit) || exit.ExitCode() != 100 {
		t.Fatal("strict APT update did not fail with expected acquisition error")
	}
	if !bytes.Contains(failedOutput, []byte("Failed to fetch")) {
		t.Fatal("APT failure lacked a useful acquisition diagnostic")
	}
	native, e := trustedAPTCommand("apt-get")
	if e != nil {
		t.Fatal(e)
	}
	wrappedCode, wrappedErr := aptThroughSelectedProxy(native, wrappedArgs, t.TempDir(), proxyURL)
	if wrappedErr != nil || wrappedCode != 100 {
		t.Fatalf("CLI shared execution did not fail strict cached-index update: exit=%d err=%v", wrappedCode, wrappedErr)
	}
	after, err := os.ReadDir(filepath.Join(dir, "lists"))
	if err != nil {
		t.Fatal(err)
	}
	cached := 0
	for _, entry := range after {
		if strings.Contains(entry.Name(), "_Packages") {
			cached++
		}
	}
	if cached < 2 {
		t.Fatal("partial failure test did not retain original cached repository indexes")
	}
}
