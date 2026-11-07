//go:build linux

package sc

// This opt-in root-only QA uses two nested isolated network namespaces. It
// proves an actual official sing-box VLESS/WS/TLS selected outbound carries
// proxy-unaware host TCP through the v9 native RPDB/FIB/nft graph, while a
// separate private Direct path survives loss of the VLESS relay. Neither
// namespace can mutate the Test Server's initial host network namespace.
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	hostRouteQAEndpoint   = "9.9.9.10"
	hostRouteQAForeign    = "203.0.113.10:18080"
	hostRouteQAPrivate    = "10.77.0.2:18081"
	hostRouteQAForeignUDP = "203.0.113.10:18082"
	hostRouteQAPrivateUDP = "10.77.0.2:18083"
	hostRouteQARelay      = "9.9.9.10:18443"
	hostRouteQATLSName    = "front.example.org"
)

func hostRouteQATestCore(t *testing.T) string {
	t.Helper()
	core := os.Getenv("SC_TEST_SINGBOX")
	if runtime.GOARCH != "amd64" || !filepath.IsAbs(core) {
		t.Fatal("explicit pinned amd64 sing-box Core required")
	}
	f, err := os.Open(core)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	_, readErr := io.Copy(h, f)
	closeErr := f.Close()
	if readErr != nil || closeErr != nil ||
		hex.EncodeToString(h.Sum(nil)) != "768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93" {
		t.Fatal("official 1.14.3-linux-amd64 Core digest mismatch before network effects")
	}
	version, err := exec.Command(core, "version").CombinedOutput()
	if err != nil || !strings.HasPrefix(string(version), "sing-box version 1.14.3\n") {
		t.Fatal("official Core executable version mismatch")
	}
	return core
}

func hostRouteQATLSFiles(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: hostRouteQATLSName},
		DNSNames:  []string{hostRouteQATLSName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(dir, "relay-cert.pem")
	private := filepath.Join(dir, "relay-key.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(private, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0600); err != nil {
		t.Fatal(err)
	}
	return cert, private
}

func hostRouteQAWaitFile(t *testing.T, file, content string) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(file); err == nil && string(data) == content {
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatalf("isolated relay fixture did not publish expected %s state", filepath.Base(file))
}

// Both the new underlay VETH and the Docker-bridge fixture may finish IPv6
// DAD after the IPv4 Direct baseline. Wait for their own link-local identity
// and the full foreign IPv6 FIB to settle before snapshot comparison; never
// ignore unexpected IPv6 route changes as harmless traffic counters.
func hostRouteQAWaitBaselineIPv6(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	previous := ""
	stable := 0
	for time.Now().Before(deadline) {
		ready := true
		for _, dev := range []string{"scv7edge0", "docker0"} {
			addr := ingressNativeCommand(t, "/usr/sbin/ip", "-6", "-j", "addr", "show", "dev", dev)
			if !strings.Contains(addr, "fe80:") || strings.Contains(addr, "tentative") {
				ready = false
			}
		}
		routes := ingressNativeCommand(t, "/usr/sbin/ip", "-6", "-N", "-j", "route", "show", "table", "all")
		if ready && routes == previous {
			stable++
			if stable >= 3 {
				return
			}
		} else {
			stable = 0
		}
		previous = routes
		time.Sleep(85 * time.Millisecond)
	}
	t.Fatal("isolated VETH/Docker link-local DAD routes did not settle before foreign snapshot")
}

func hostRouteQAHTTP(t *testing.T, target string, timeout time.Duration) (string, error) {
	t.Helper()
	// No HTTP/SOCKS proxy setting is inherited: this is a transparent
	// kernel-controlled host request, not an opt-in app proxy.
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{
		Proxy: nil, DisableKeepAlives: true,
		DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
	}}
	defer client.CloseIdleConnections()
	response, err := client.Get("http://" + target + "/witness")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 256))
	if err != nil || response.StatusCode != 200 {
		return "", fmt.Errorf("witness response status=%d read=%v", response.StatusCode, err)
	}
	return string(body), nil
}

// A new UDP exchange uses the host's unproxied socket and a unique nonce.
// Its source is recorded by the independent remote namespace. A matching
// HTTP response cannot substitute for a real selected VPN UDP packet.
func hostRouteQAUDP(t *testing.T, destination, nonce string, timeout time.Duration) (string, error) {
	t.Helper()
	conn, err := net.DialTimeout("udp4", destination, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte(nonce)); err != nil {
		return "", err
	}
	var buf [512]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		return "", err
	}
	response := string(buf[:n])
	if !strings.HasSuffix(response, "|"+nonce) {
		return "", fmt.Errorf("unexpected UDP nonce or foreign response")
	}
	return response, nil
}

type hostRouteQAWitnessFile interface {
	io.Writer
	Sync() error
	Close() error
}

// A negative delivery witness is invalid if its record could not be fully
// written and synchronized. Always close even after write or sync failure.
func hostRouteQAWriteWitness(record string, open func() (hostRouteQAWitnessFile, error)) error {
	file, err := open()
	if err != nil {
		return err
	}
	n, writeErr := io.WriteString(file, record)
	if writeErr == nil && n != len(record) {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(writeErr, syncErr, closeErr)
}

func hostRouteQAAppendWitness(path, record string) error {
	return hostRouteQAWriteWitness(record, func() (hostRouteQAWitnessFile, error) {
		return os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	})
}

func hostRouteQAUDPReadLoop(socket net.PacketConn, prefix, logFile string, stopping *atomic.Bool, failed func(error)) {
	var buf [512]byte
	for {
		n, peer, readErr := socket.ReadFrom(buf[:])
		if readErr != nil {
			if !stopping.Load() || !errors.Is(readErr, net.ErrClosed) {
				failed(fmt.Errorf("independent UDP witness read: %w", readErr))
			}
			return
		}
		if logFile != "" {
			if err := hostRouteQAAppendWitness(logFile, fmt.Sprintf("%s|%q\n", peer.String(), string(buf[:n]))); err != nil {
				failed(fmt.Errorf("independent UDP witness record: %w", err))
				return
			}
		}
		response := []byte(prefix + peer.String() + "|" + string(buf[:n]))
		written, writeErr := socket.WriteTo(response, peer)
		if writeErr == nil && written != len(response) {
			writeErr = io.ErrShortWrite
		}
		if writeErr != nil {
			if !stopping.Load() || !errors.Is(writeErr, net.ErrClosed) {
				failed(fmt.Errorf("independent UDP witness reply: %w", writeErr))
			}
			return
		}
	}
}

// An exit before our private stop request is a failure even when its status
// is zero. A requested stop still must return a successful, bounded exit.
func hostRouteQAFixtureExit(done <-chan error, wait time.Duration, stopRequested bool) (bool, error) {
	var exit error
	if wait <= 0 {
		select {
		case exit = <-done:
		default:
			return false, nil
		}
	} else {
		select {
		case exit = <-done:
		case <-time.After(wait):
			return false, errors.New("independent witness helper exit timed out")
		}
	}
	if exit != nil {
		return true, fmt.Errorf("independent witness helper failed: %w", exit)
	}
	if !stopRequested {
		return true, errors.New("independent witness helper exited before its stop request")
	}
	return true, nil
}

// The remote helper lives in the second netns, not the test's host netns.
// Its HTTP listeners remain alive when its task-owned VLESS relay dies, so
// a public-target Direct leak could be observed independently.
func TestHostRouteV9SelectedRemoteFixtureHelper(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_ROUTE_REMOTE_HELPER") != "isolated-relay-netns" {
		t.Skip("NOT_RUN: private remote relay namespace only")
	}
	requireNativeQANetworkNamespace(t)
	dir := os.Getenv("SC_TEST_HOST_ROUTE_REMOTE_DIR")
	if dir == "" || !filepath.IsAbs(dir) {
		t.Fatal("remote helper private directory missing")
	}
	directory, err := os.Lstat(dir)
	if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0700 {
		t.Fatal("remote helper requires the task-owned private directory")
	}
	owner, ok := directory.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		t.Fatal("remote helper directory owner mismatch")
	}
	core := hostRouteQATestCore(t)
	failures := make(chan error, 1)
	reportFailure := func(err error) {
		select {
		case failures <- err:
		default:
		}
	}
	checkWitnesses := func() {
		select {
		case err := <-failures:
			t.Fatalf("independent remote witness failed: %v", err)
		default:
		}
	}
	var stopping atomic.Bool
	var witnesses sync.WaitGroup
	originLog := filepath.Join(dir, "foreign-accepts")
	recordForeign := func(conn net.Conn, state http.ConnState) {
		if state != http.StateNew {
			return
		}
		if err := hostRouteQAAppendWitness(originLog, conn.RemoteAddr().String()+"\n"); err != nil {
			reportFailure(fmt.Errorf("independent TCP accept witness: %w", err))
		}
	}
	originLn, err := net.Listen("tcp", hostRouteQAForeign)
	if err != nil {
		t.Fatal(err)
	}
	privateLn, err := net.Listen("tcp", hostRouteQAPrivate)
	if err != nil {
		t.Fatal(err)
	}
	handler := func(prefix string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			response := prefix + r.RemoteAddr
			n, err := io.WriteString(w, response)
			if err == nil && n != len(response) {
				err = io.ErrShortWrite
			}
			if err != nil {
				reportFailure(fmt.Errorf("independent HTTP witness reply: %w", err))
			}
		}
	}
	origin := &http.Server{Handler: handler("foreign-source="), ConnState: recordForeign}
	private := &http.Server{Handler: handler("private-source=")}
	var udpSockets []net.PacketConn
	defer func() {
		// Only this helper owns these descriptors. Intentional close is the
		// only context in which listener shutdown errors are expected.
		stopping.Store(true)
		if err := errors.Join(origin.Close(), private.Close()); err != nil {
			t.Errorf("independent HTTP witness close: %v", err)
		}
		for _, socket := range udpSockets {
			if err := socket.Close(); err != nil {
				t.Errorf("independent UDP witness close: %v", err)
			}
		}
		joined := make(chan struct{})
		go func() { witnesses.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(3 * time.Second):
			t.Error("independent witness shutdown did not complete")
		}
		select {
		case err := <-failures:
			t.Errorf("independent witness failed before exit: %v", err)
		default:
		}
	}()
	serveHTTP := func(server *http.Server, listener net.Listener) {
		witnesses.Add(1)
		go func() {
			defer witnesses.Done()
			err := server.Serve(listener)
			if !stopping.Load() || !errors.Is(err, http.ErrServerClosed) {
				reportFailure(fmt.Errorf("independent HTTP witness serve ended: %v", err))
			}
		}()
	}
	serveHTTP(origin, originLn)
	serveHTTP(private, privateLn)
	for _, fixture := range []struct{ address, prefix, log string }{
		{hostRouteQAForeignUDP, "foreign-udp-source=", filepath.Join(dir, "foreign-udp-accepts")},
		{hostRouteQAPrivateUDP, "private-udp-source=", ""},
	} {
		socket, err := net.ListenPacket("udp4", fixture.address)
		if err != nil {
			t.Fatal("independent UDP witness listen:", err)
		}
		udpSockets = append(udpSockets, socket)
		witnesses.Add(1)
		go func(socket net.PacketConn, prefix, log string) {
			defer witnesses.Done()
			hostRouteQAUDPReadLoop(socket, prefix, log, &stopping, reportFailure)
		}(socket, fixture.prefix, fixture.log)
	}

	var logs hostRouteCoreOutput
	relay := exec.Command(core, "run", "-c", filepath.Join(dir, "relay-config.json"))
	relay.Stdout, relay.Stderr = &logs, &logs
	relay.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := relay.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- relay.Wait() }()
	alive := true
	defer func() {
		if alive {
			_ = relay.Process.Kill()
			select {
			case <-exited:
			case <-time.After(5 * time.Second):
				t.Error("remote fixture relay did not exit")
			}
		}
	}()

	// Readiness means the official relay is actually bound to its
	// independent underlay address, not merely a test subprocess exists.
	ready := false
	for i := 0; i < 140; i++ {
		conn, e := net.DialTimeout("tcp", hostRouteQARelay, 80*time.Millisecond)
		if e == nil {
			conn.Close()
			ready = true
			break
		}
		select {
		case e := <-exited:
			alive = false
			t.Fatalf("VLESS relay exited before admission: %v: %s", e, logs.String())
		default:
		}
		time.Sleep(40 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("real VLESS listener not ready: %s", logs.String())
	}
	checkWitnesses()
	if err := os.WriteFile(filepath.Join(dir, "relay-ready"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(65 * time.Second)
	for time.Now().Before(deadline) {
		checkWitnesses()
		if _, e := os.Stat(filepath.Join(dir, "stop-relay")); e == nil && alive {
			if err := relay.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-exited:
				alive = false
			case <-time.After(5 * time.Second):
				t.Fatal("actual relay SIGKILL did not exit")
			}
			if err := os.WriteFile(filepath.Join(dir, "relay-stopped"), []byte("stopped"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, e := os.Stat(filepath.Join(dir, "stop-fixture")); e == nil {
			return
		}
		time.Sleep(35 * time.Millisecond)
	}
	t.Fatal("remote VLESS fixture exceeded time budget")
}

func TestHostRouteV9SelectedVLESSRealKernelNoDirectLeak(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_ROUTE_SELECTED_VLESS") != "isolated-netns" {
		t.Skip("NOT_RUN: explicit root nested network namespace required")
	}
	crashMode := os.Getenv("SC_TEST_HOST_ROUTE_SELECTED_VLESS_CRASH")
	if crashMode != "" && crashMode != "client-core" {
		t.Fatal("unsupported selected data-plane crash boundary")
	}
	core := hostRouteQATestCore(t)
	guard, base := prepareHostNativeKernelFixture(t)
	dir := privateJournalTempDir(t)

	// The first fresh netns is the transparent host; the second, nested one
	// is an actual on-wire VLESS/TLS/WebSocket endpoint and HTTP origin.
	holder := exec.Command("/usr/bin/unshare", "--net", "/bin/sleep", "100")
	holder.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = holder.Process.Kill()
		_ = holder.Wait()
	})
	peerPID := strconv.Itoa(holder.Process.Pid)
	parentNetns, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	// Starting unshare is asynchronous. Do not move a veth peer into the
	// holder's initial (parent) namespace before it actually entered its
	// separate network namespace: that race can lose the test link.
	separate := false
	for i := 0; i < 100; i++ {
		other, statErr := os.Stat("/proc/" + peerPID + "/ns/net")
		if statErr == nil && !os.SameFile(parentNetns, other) {
			separate = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !separate {
		t.Fatal("remote namespace holder did not establish independent network identity")
	}
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "scv7edge1", "netns", peerPID)
	remoteIP := func(args ...string) {
		t.Helper()
		ingressNativeCommand(t, "/usr/bin/nsenter", append([]string{"-t", peerPID, "-n", "/usr/sbin/ip"}, args...)...)
	}
	remoteIP("link", "set", "lo", "up")
	remoteIP("address", "add", "9.9.9.10/30", "dev", "scv7edge1")
	remoteIP("address", "add", "10.77.0.2/30", "dev", "scv7edge1")
	remoteIP("address", "add", "203.0.113.10/32", "dev", "lo")
	remoteIP("link", "set", "scv7edge1", "up")
	ingressNativeCommand(t, "/usr/sbin/ip", "address", "add", "9.9.9.9/30", "dev", "scv7edge0")
	ingressNativeCommand(t, "/usr/sbin/ip", "address", "add", "10.77.0.1/30", "dev", "scv7edge0")
	ingressNativeCommand(t, "/usr/sbin/ip", "route", "add", "default", "via", hostRouteQAEndpoint, "dev", "scv7edge0")

	cert, key := hostRouteQATLSFiles(t, dir)
	relayConfig := map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []any{map[string]any{
			"type": "vless", "tag": "relay", "listen": hostRouteQAEndpoint, "listen_port": 18443,
			"users":     []any{map[string]any{"uuid": testUUID}},
			"tls":       map[string]any{"enabled": true, "certificate_path": cert, "key_path": key},
			"transport": map[string]any{"type": "ws", "path": "/selected"},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	}
	rawServer, err := json.Marshal(relayConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckConfig(core, dir, rawServer); err != nil {
		t.Fatalf("official VLESS TLS WS server config refused: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "relay-config.json"), rawServer, 0600); err != nil {
		t.Fatal(err)
	}
	profile := testHostCoreWSProfile()
	profile.Outbound, err = json.Marshal(map[string]any{
		"type": "vless", "tag": "upstream", "server": "node.example.org",
		"server_port": 18443, "uuid": testUUID,
		"tls": map[string]any{"enabled": true, "server_name": hostRouteQATLSName},
		"transport": map[string]any{"type": "ws", "path": "/selected",
			"headers": map[string]any{"Host": hostRouteQATLSName}},
	})
	if err != nil {
		t.Fatal(err)
	}
	config, err := compileHostCoreAttachConfig(profile, hostRouteQAEndpoint, "scv7edge0", "sctunv70")
	if err != nil {
		t.Fatalf("selected VLESS attach config refused: %v", err)
	}
	if err := CheckConfig(core, dir, config); err != nil {
		t.Fatalf("official selected client config refused: %v", err)
	}

	// Only the task-owned origin logs its accepted TCP connections. No
	// privileged global traffic trace, SNAT or host-level packet filtering.
	for _, name := range []string{"foreign-accepts", "foreign-udp-accepts"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fixture := exec.Command("/usr/bin/nsenter", "-t", peerPID, "-n", os.Args[0],
		"-test.run=^TestHostRouteV9SelectedRemoteFixtureHelper$", "-test.v", "-test.timeout=80s")
	fixture.Env = append(os.Environ(),
		"SC_TEST_HOST_ROUTE_REMOTE_HELPER=isolated-relay-netns",
		"SC_TEST_HOST_ROUTE_REMOTE_DIR="+dir,
		"SC_TEST_SINGBOX="+core)
	var fixtureLog hostRouteCoreOutput
	fixture.Stdout, fixture.Stderr = &fixtureLog, &fixtureLog
	fixture.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := fixture.Start(); err != nil {
		t.Fatal(err)
	}
	fixtureExit := make(chan error, 1)
	go func() { fixtureExit <- fixture.Wait() }()
	fixtureActive := true
	finishFixture := func() error {
		ended, err := hostRouteQAFixtureExit(fixtureExit, 0, false)
		if ended {
			fixtureActive = false
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "stop-fixture"), []byte("stop"), 0600); err != nil {
			return fmt.Errorf("request independent witness shutdown: %w", err)
		}
		ended, err = hostRouteQAFixtureExit(fixtureExit, 5*time.Second, true)
		if ended {
			fixtureActive = false
		}
		return err
	}
	checkFixture := func() {
		ended, err := hostRouteQAFixtureExit(fixtureExit, 0, false)
		if ended {
			fixtureActive = false
		}
		if err != nil {
			t.Fatalf("remote witness unavailable: %v: %s", err, fixtureLog.String())
		}
	}
	t.Cleanup(func() {
		if !fixtureActive {
			return
		}
		if err := finishFixture(); err != nil {
			t.Errorf("remote witness cleanup failed: %v: %s", err, fixtureLog.String())
			if fixtureActive {
				_ = fixture.Process.Kill()
				ended, waitErr := hostRouteQAFixtureExit(fixtureExit, 3*time.Second, true)
				fixtureActive = !ended
				if waitErr != nil {
					t.Errorf("remote witness forced termination: %v", waitErr)
				}
			}
		}
	})
	hostRouteQAWaitFile(t, filepath.Join(dir, "relay-ready"), "ready")
	checkFixture()

	direct, err := hostRouteQAHTTP(t, hostRouteQAForeign, 3*time.Second)
	if err != nil || !strings.HasPrefix(direct, "foreign-source=9.9.9.9:") {
		t.Fatalf("non-VPN baseline did not reach foreign fixture Direct: %q %v", direct, err)
	}
	private, err := hostRouteQAHTTP(t, hostRouteQAPrivate, 3*time.Second)
	if err != nil || !strings.HasPrefix(private, "private-source=10.77.0.1:") {
		t.Fatalf("private baseline failed: %q %v", private, err)
	}
	baselineUDP, err := hostRouteQAUDP(t, hostRouteQAForeignUDP, "baseline-foreign", 1800*time.Millisecond)
	if err != nil || !strings.HasPrefix(baselineUDP, "foreign-udp-source=9.9.9.9:") {
		t.Fatalf("foreign UDP Direct baseline not actually on underlay: %q %v", baselineUDP, err)
	}
	privateUDP, err := hostRouteQAUDP(t, hostRouteQAPrivateUDP, "baseline-private", 1800*time.Millisecond)
	if err != nil || !strings.HasPrefix(privateUDP, "private-udp-source=10.77.0.1:") {
		t.Fatalf("private UDP Direct baseline failed: %q %v", privateUDP, err)
	}
	hostRouteQAWaitBaselineIPv6(t)
	before := hostNativeKernelSnapshot(t)

	r := hostRouteKernelExample(t)
	r.Progress, r.Native = base.Progress, base.Native
	r.Native.NFTName = "scnt_" + r.Progress.Ingress.OperationID
	r.Core.ConfigSHA256 = sha256Hex(config)
	r.Core.PinnedEndpoint = hostRouteQAEndpoint
	digest, err := hostRoutePolicyPlanSHA256(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = digest
	if err := validateHostRouteJournal(r); err != nil {
		t.Fatal(err)
	}
	manager := New(dir, core, DefaultPort)
	var client *exec.Cmd
	var clientLog hostRouteCoreOutput
	var clientExit chan error
	clientActive := false
	t.Cleanup(func() {
		if clientActive && client != nil {
			_ = client.Process.Kill()
			select {
			case <-clientExit:
			case <-time.After(5 * time.Second):
				t.Error("task-owned selected Core did not terminate")
			}
		}
	})
	err = manager.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostRouteJournal(store, r, nil); err != nil {
			return err
		}
		if err := runHostCaptureGateLocked(store, &r.Progress, guard, hostRouteCapturePersist(store, &r)); err != nil {
			return err
		}
		native := r.nativeView()
		if err := nativeTUNPrepareLinkWithPersist(store, &native, "", hostRouteNativePersist(store, &r)); err != nil {
			return err
		}
		if err := hostRouteCoreStagePersist(store, &r, "credential_possible"); err != nil {
			return err
		}
		if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, config, nil); err != nil {
			return err
		}
		if err := hostRouteCoreStagePersist(store, &r, "credential_staged"); err != nil {
			return err
		}
		watch, err := nativeTUNWatchStart(r.nativeView())
		if err != nil {
			return err
		}
		defer watch.close()
		if err := hostRouteCoreStagePersist(store, &r, "start_requested"); err != nil {
			return err
		}
		client = exec.Command(core, "run", "-c", filepath.Join(dir, smartTUNTrialConfigFile))
		client.Env = append(os.Environ(), "SSL_CERT_FILE="+cert)
		client.Stdout, client.Stderr = &clientLog, &clientLog
		client.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if err := client.Start(); err != nil {
			return err
		}
		clientActive = true
		clientExit = make(chan error, 1)
		go func() { clientExit <- client.Wait() }()
		if err := watch.verify(r.nativeView()); err != nil {
			return err
		}
		select {
		case exit := <-clientExit:
			clientActive = false
			return fmt.Errorf("selected Core unexpectedly exited after TUN attach: %v: %s", exit, clientLog.String())
		default:
		}
		if err := hostRouteCoreStagePersist(store, &r, "active_observed"); err != nil {
			return err
		}
		if err := hostRoutePhasePersist(store, &r, "effect_possible"); err != nil {
			return err
		}
		native = r.nativeView()
		if err := nativeTUNApplyGuardFirstWithObserver(store, &native, "", hostRouteNativePersist(store, &r), hostRouteNFTObserver(&r)); err != nil {
			return err
		}
		return hostRoutePhasePersist(store, &r, "observed")
	})
	if err != nil {
		t.Fatalf("selected v9 real Core+kernel policy admission failed: %v: %s", err, clientLog.String())
	}

	// The foreign origin must now see only an inner connection from its
	// local VLESS server, never an underlay socket from the client host.
	tunneled, err := hostRouteQAHTTP(t, hostRouteQAForeign, 6*time.Second)
	if err != nil || !strings.HasPrefix(tunneled, "foreign-source=203.0.113.10:") {
		t.Fatalf("foreign host HTTP did not emerge from selected VLESS relay: %q %v: %s", tunneled, err, clientLog.String())
	}
	private, err = hostRouteQAHTTP(t, hostRouteQAPrivate, 3*time.Second)
	if err != nil || !strings.HasPrefix(private, "private-source=10.77.0.1:") {
		t.Fatalf("VPN diverted protected private Direct: %q %v", private, err)
	}
	selectedUDP, err := hostRouteQAUDP(t, hostRouteQAForeignUDP, "selected-foreign", 4*time.Second)
	if err != nil || !strings.HasPrefix(selectedUDP, "foreign-udp-source=203.0.113.10:") {
		t.Fatalf("foreign UDP did not emerge from selected VLESS relay: %q %v: %s", selectedUDP, err, clientLog.String())
	}
	privateUDP, err = hostRouteQAUDP(t, hostRouteQAPrivateUDP, "selected-private", 1800*time.Millisecond)
	if err != nil || !strings.HasPrefix(privateUDP, "private-udp-source=10.77.0.1:") {
		t.Fatalf("VPN diverted private UDP Direct: %q %v", privateUDP, err)
	}
	// Do not publish success markers until the independent witness exits
	// successfully; a late observer error invalidates the entire lane.
	passes := []string{"HOST_ROUTE_V9_SELECTED_REAL_VLESS_FOREIGN_TCP_UDP_TUN_AND_PRIVATE_DIRECT=PASS"}

	checkFixture()
	// Both failures must retain the independent kernel guard and the
	// remotely controlled foreign origin. A fresh TCP accept would prove a
	// Direct leak even if the host request itself timed out.
	if crashMode == "client-core" {
		if err := client.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-clientExit:
		case <-time.After(5 * time.Second):
			t.Fatal("real selected Core did not terminate after SIGKILL")
		}
		clientActive = false
		guardState, err := hostRouteNFTObserver(&r)(r.nativeView())
		if err != nil || !guardState.Matches ||
			!nativeTUNNFTReceiptCovers(r.nativeView(), guardState, true) {
			t.Fatal("real selected Core SIGKILL lost its independent final-egress guard")
		}
	} else {
		// The remote fixture kills only its own upstream subprocess. The
		// foreign origin stays reachable Direct.
		if err := os.WriteFile(filepath.Join(dir, "stop-relay"), []byte("stop"), 0600); err != nil {
			t.Fatal(err)
		}
		hostRouteQAWaitFile(t, filepath.Join(dir, "relay-stopped"), "stopped")
	}
	acceptedBefore, err := os.ReadFile(filepath.Join(dir, "foreign-accepts"))
	if err != nil {
		t.Fatal(err)
	}
	acceptedUDPBefore, err := os.ReadFile(filepath.Join(dir, "foreign-udp-accepts"))
	if err != nil {
		t.Fatal(err)
	}
	checkFixture()
	noRoute, err := hostRouteQAHTTP(t, hostRouteQAForeign, 1700*time.Millisecond)
	if err == nil {
		t.Fatalf("foreign HTTP unexpectedly succeeded without selected upstream: %q", noRoute)
	}
	// Give delayed direct SYN/HTTP attempts a bounded opportunity to reach
	// the foreign origin before inspecting the independent accept log.
	time.Sleep(220 * time.Millisecond)
	acceptedAfter, err := os.ReadFile(filepath.Join(dir, "foreign-accepts"))
	if err != nil || string(acceptedAfter) != string(acceptedBefore) {
		t.Fatalf("selected VLESS outage leaked fresh Direct TCP to foreign origin; read=%v", err)
	}
	checkFixture()
	noUDP, err := hostRouteQAUDP(t, hostRouteQAForeignUDP, "outage-foreign", 700*time.Millisecond)
	if err == nil {
		t.Fatalf("foreign UDP unexpectedly succeeded without selected Core/relay: %q", noUDP)
	}
	// A remote UDP witness catches every attempted unproxied Direct
	// datagram even when the sender times out without a response.
	time.Sleep(170 * time.Millisecond)
	acceptedUDPAfter, err := os.ReadFile(filepath.Join(dir, "foreign-udp-accepts"))
	if err != nil || string(acceptedUDPAfter) != string(acceptedUDPBefore) {
		t.Fatalf("selected outage leaked a foreign UDP datagram to the underlay: %v", err)
	}
	checkFixture()
	privateUDP, err = hostRouteQAUDP(t, hostRouteQAPrivateUDP, "outage-private", 1600*time.Millisecond)
	if err != nil || !strings.HasPrefix(privateUDP, "private-udp-source=10.77.0.1:") {
		t.Fatalf("private UDP Direct failed during selected outage: %q %v", privateUDP, err)
	}
	private, err = hostRouteQAHTTP(t, hostRouteQAPrivate, 3*time.Second)
	if err != nil || !strings.HasPrefix(private, "private-source=10.77.0.1:") {
		t.Fatalf("private Direct did not survive relay outage: %q %v", private, err)
	}
	checkFixture()
	if crashMode == "client-core" {
		passes = append(passes, "HOST_ROUTE_V9_SELECTED_CORE_SIGKILL_GUARD_NO_DIRECT_TCP_UDP_AND_PRIVATE_ALIVE=PASS")
	} else {
		passes = append(passes, "HOST_ROUTE_V9_SELECTED_REAL_VLESS_OUTAGE_NO_DIRECT_TCP_UDP_AND_PRIVATE_ALIVE=PASS")
	}

	state := smartTUNCoreObservationExample("active")
	inactive := smartTUNCoreObservationExample("inactive")
	inactive.identity = state.identity
	stopCount := 0
	services := hostCoreRecoveryServices{
		observe: func() (smartTUNTrialUnitObservation, error) {
			if clientActive {
				return state, nil
			}
			return inactive, nil
		},
		stop: func(_ smartTUNTrialUnitObservation, started, credential bool) error {
			if !started || !credential {
				return errors.New("selected Core stop lacks exact start/credential authority")
			}
			route, _, err := nativeTUNObserveResource(r.nativeView(), 4, "rule")
			if err != nil || !route {
				return errors.New("kernel policy removed before Core-first stop")
			}
			if clientActive {
				if err := client.Process.Signal(syscall.SIGTERM); err != nil {
					return err
				}
				select {
				case <-clientExit:
				case <-time.After(5 * time.Second):
					return errors.New("selected Core did not stop before kernel rollback")
				}
				clientActive = false
			} else if crashMode != "client-core" {
				return errors.New("selected Core stopped outside its authorized crash boundary")
			}
			stopCount++
			return nil
		},
	}
	recovered, err := manager.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, s trialRecoverySelection) (TrialReceipt, error) {
		if s.version != hostRouteJournalVersion || s.hostRoute.Route.State != "observed" {
			return TrialReceipt{}, errors.New("independent selector lost selected VLESS parent")
		}
		return recoverHostRouteJournalLocked(store, &s.hostRoute, services)
	})
	if err != nil || !recovered.RecoveryVerified || stopCount != 1 {
		t.Fatalf("selected-VLESS independent Core-first Off failed: %+v %v", recovered, err)
	}
	if err := manager.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		return clearRecoveredHostRouteLocked(store, r.Progress.Ingress.OperationID, services)
	}); err != nil {
		t.Fatal(err)
	}
	beforeStructure, beforeCounters := hostRouteRealCoreKernelSnapshot(t, before)
	afterStructure, afterCounters := hostRouteRealCoreKernelSnapshot(t, hostNativeKernelSnapshot(t))
	if beforeStructure != afterStructure || len(beforeCounters) != len(afterCounters) {
		beforeParts, afterParts := strings.Split(beforeStructure, "\x00"), strings.Split(afterStructure, "\x00")
		for i := range beforeParts {
			if i < len(afterParts) && beforeParts[i] != afterParts[i] {
				a, b := beforeParts[i], afterParts[i]
				j := 0
				for j < len(a) && j < len(b) && a[j] == b[j] {
					j++
				}
				lo := j - 60
				if lo < 0 {
					lo = 0
				}
				hi := j + 160
				if hi > len(a) {
					hi = len(a)
				}
				end := j + 160
				if end > len(b) {
					end = len(b)
				}
				t.Logf("SNAPSHOT_DELTA part=%d prefix=%d before=%q after=%q", i, j, a[lo:hi], b[lo:end])
			}
		}
		t.Logf("COUNTER_LENGTH before=%d after=%d", len(beforeCounters), len(afterCounters))
		t.Fatal("selected-VLESS native Off changed foreign FIB/RPDB/nft structure")
	}
	for i, count := range beforeCounters {
		if afterCounters[i] < count {
			t.Fatal("selected-VLESS native Off reset a foreign firewall counter")
		}
	}
	afterOff, err := hostRouteQAHTTP(t, hostRouteQAForeign, 3*time.Second)
	if err != nil || !strings.HasPrefix(afterOff, "foreign-source=9.9.9.9:") {
		t.Fatalf("ordinary Direct/off was not restored after exact cleanup: %q %v", afterOff, err)
	}
	afterUDP, err := hostRouteQAUDP(t, hostRouteQAForeignUDP, "off-foreign", 1800*time.Millisecond)
	if err != nil || !strings.HasPrefix(afterUDP, "foreign-udp-source=9.9.9.9:") {
		t.Fatalf("foreign UDP ordinary Direct/off not restored: %q %v", afterUDP, err)
	}
	if err := finishFixture(); err != nil {
		t.Fatalf("independent witness did not finish successfully: %v: %s", err, fixtureLog.String())
	}
	for _, pass := range append(passes, "HOST_ROUTE_V9_SELECTED_VLESS_INDEPENDENT_OFF_RESTORES_HOST_DIRECT_TCP_UDP=PASS") {
		fmt.Println(pass)
	}
}

type hostRouteQAFaultWitnessFile struct {
	writeN            int
	writeErr, syncErr error
	closeErr          error
	calls             []string
	record            string
}

func (f *hostRouteQAFaultWitnessFile) Write(record []byte) (int, error) {
	f.calls = append(f.calls, "write")
	f.record = string(record)
	if f.writeN >= 0 {
		return f.writeN, f.writeErr
	}
	return len(record), f.writeErr
}
func (f *hostRouteQAFaultWitnessFile) Sync() error {
	f.calls = append(f.calls, "sync")
	return f.syncErr
}
func (f *hostRouteQAFaultWitnessFile) Close() error {
	f.calls = append(f.calls, "close")
	return f.closeErr
}

func TestHostRouteQAWitnessIOFailuresNeverAcknowledgeRecord(t *testing.T) {
	failure := errors.New("injected witness failure")
	for _, mode := range []string{"open", "short-write", "write", "sync", "close", "success"} {
		t.Run(mode, func(t *testing.T) {
			file := &hostRouteQAFaultWitnessFile{writeN: -1}
			expected := failure
			switch mode {
			case "short-write":
				file.writeN, expected = 1, io.ErrShortWrite
			case "write":
				file.writeN, file.writeErr = 0, failure
			case "sync":
				file.syncErr = failure
			case "close":
				file.closeErr = failure
			case "success":
				expected = nil
			}
			record := "203.0.113.10:12345|\"exact-udp-nonce\"\n"
			err := hostRouteQAWriteWitness(record, func() (hostRouteQAWitnessFile, error) {
				if mode == "open" {
					return nil, failure
				}
				return file, nil
			})
			if expected == nil && err != nil || expected != nil && !errors.Is(err, expected) {
				t.Fatalf("witness %s outcome: got=%v want=%v", mode, err, expected)
			}
			if mode == "open" {
				if len(file.calls) != 0 {
					t.Fatal("unopened witness was used")
				}
			} else if strings.Join(file.calls, ",") != "write,sync,close" || file.record != record {
				t.Fatal("witness omitted full payload, synchronization or close after I/O failure")
			}
		})
	}
}

type hostRouteQAFaultPacketConn struct {
	readErr, writeErr error
	writeN            int
	reads             int
}

func (p *hostRouteQAFaultPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	p.reads++
	if p.readErr != nil {
		return 0, nil, p.readErr
	}
	if p.reads > 1 {
		return 0, nil, errors.New("witness failed to stop after injected reply/record failure")
	}
	return copy(buffer, "probe"), &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 12345}, nil
}
func (p *hostRouteQAFaultPacketConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	if p.writeN >= 0 {
		return p.writeN, p.writeErr
	}
	return len(data), p.writeErr
}
func (*hostRouteQAFaultPacketConn) Close() error                     { return nil }
func (*hostRouteQAFaultPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*hostRouteQAFaultPacketConn) SetDeadline(time.Time) error      { return nil }
func (*hostRouteQAFaultPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*hostRouteQAFaultPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestHostRouteQAUDPFailureCannotBecomeAnEmptyDeliveryLog(t *testing.T) {
	failure := errors.New("injected UDP witness failure")
	for _, mode := range []string{"read", "unexpected-close", "reply", "short-reply", "record-open", "requested-close"} {
		t.Run(mode, func(t *testing.T) {
			packet := &hostRouteQAFaultPacketConn{writeN: -1}
			var stopping atomic.Bool
			logPath := ""
			switch mode {
			case "read":
				packet.readErr = failure
			case "unexpected-close":
				packet.readErr = net.ErrClosed
			case "reply":
				packet.writeErr = failure
			case "short-reply":
				packet.writeN = 1
			case "record-open":
				logPath = filepath.Join(t.TempDir(), "missing-parent", "witness")
			case "requested-close":
				packet.readErr = net.ErrClosed
				stopping.Store(true)
			}
			var received []error
			hostRouteQAUDPReadLoop(packet, "source=", logPath, &stopping, func(err error) {
				received = append(received, err)
			})
			if mode == "requested-close" {
				if len(received) != 0 {
					t.Fatal("requested witness shutdown became a spurious failure")
				}
			} else if len(received) != 1 || received[0] == nil {
				t.Fatal("missing UDP witness failure could falsely certify an unchanged delivery log")
			}
		})
	}
}

func TestHostRouteQAFixtureExitFailureAndTimeoutReachParent(t *testing.T) {
	failure := errors.New("remote witness process failed")
	for _, tc := range []struct {
		name                   string
		queued, requested      bool
		child                  error
		wait                   time.Duration
		wantEnded, wantFailure bool
	}{
		{"unexpected-success-exit", true, false, nil, 0, true, true},
		{"unexpected-failure-exit", true, false, failure, 0, true, true},
		{"requested-success-exit", true, true, nil, time.Millisecond, true, false},
		{"requested-failure-exit", true, true, failure, time.Millisecond, true, true},
		{"still-running", false, false, nil, 0, false, false},
		{"requested-stop-timeout", false, true, nil, time.Millisecond, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exited := make(chan error, 1)
			if tc.queued {
				exited <- tc.child
			}
			ended, err := hostRouteQAFixtureExit(exited, tc.wait, tc.requested)
			if ended != tc.wantEnded || (err != nil) != tc.wantFailure {
				t.Fatalf("remote process result lost: ended=%v err=%v", ended, err)
			}
			if tc.child != nil && !errors.Is(err, tc.child) {
				t.Fatal("parent lost the actual remote witness failure")
			}
		})
	}
}
