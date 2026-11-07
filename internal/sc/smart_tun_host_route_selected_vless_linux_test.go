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

func hostRouteQAUDPFixture(t *testing.T, address, prefix, logFile string) {
	t.Helper()
	socket, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	go func() {
		var buf [512]byte
		for {
			n, peer, readErr := socket.ReadFrom(buf[:])
			if readErr != nil {
				return
			}
			if logFile != "" {
				f, openErr := os.OpenFile(logFile, os.O_WRONLY|os.O_APPEND, 0600)
				if openErr != nil {
					return
				}
				_, writeErr := fmt.Fprintf(f, "%s|%q\n", peer.String(), string(buf[:n]))
				syncErr := f.Sync()
				closeErr := f.Close()
				if writeErr != nil || syncErr != nil || closeErr != nil {
					return
				}
			}
			_, _ = socket.WriteTo([]byte(prefix+peer.String()+"|"+string(buf[:n])), peer)
		}
	}()
}

// The remote helper lives in the second netns, not the test's host netns.
// Its HTTP listeners remain alive when its task-owned VLESS relay dies, so
// a public-target Direct leak could be observed independently.
func TestHostRouteV9SelectedRemoteFixtureHelper(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_ROUTE_REMOTE_HELPER") != "isolated-relay-netns" {
		t.Skip("NOT_RUN: private remote relay namespace only")
	}
	dir := os.Getenv("SC_TEST_HOST_ROUTE_REMOTE_DIR")
	core := os.Getenv("SC_TEST_SINGBOX")
	if dir == "" || core == "" {
		t.Fatal("remote helper admission missing")
	}
	originLog := filepath.Join(dir, "foreign-accepts")
	recordForeign := func(conn net.Conn, state http.ConnState) {
		if state != http.StateNew {
			return
		}
		f, err := os.OpenFile(originLog, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = fmt.Fprintln(f, conn.RemoteAddr().String())
		_ = f.Sync()
		_ = f.Close()
	}
	originLn, err := net.Listen("tcp", hostRouteQAForeign)
	if err != nil {
		t.Fatal(err)
	}
	privateLn, err := net.Listen("tcp", hostRouteQAPrivate)
	if err != nil {
		t.Fatal(err)
	}
	origin := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "foreign-source="+r.RemoteAddr)
	}), ConnState: recordForeign}
	private := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "private-source="+r.RemoteAddr)
	})}
	defer origin.Close()
	defer private.Close()
	go func() { _ = origin.Serve(originLn) }()
	go func() { _ = private.Serve(privateLn) }()
	hostRouteQAUDPFixture(t, hostRouteQAForeignUDP, "foreign-udp-source=", filepath.Join(dir, "foreign-udp-accepts"))
	hostRouteQAUDPFixture(t, hostRouteQAPrivateUDP, "private-udp-source=", "")

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
	if err := os.WriteFile(filepath.Join(dir, "relay-ready"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(65 * time.Second)
	for time.Now().Before(deadline) {
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
	t.Cleanup(func() {
		if !fixtureActive {
			return
		}
		_ = os.WriteFile(filepath.Join(dir, "stop-fixture"), []byte("stop"), 0600)
		select {
		case <-fixtureExit:
		case <-time.After(5 * time.Second):
			_ = fixture.Process.Kill()
			<-fixtureExit
		}
	})
	hostRouteQAWaitFile(t, filepath.Join(dir, "relay-ready"), "ready")

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
	fmt.Println("HOST_ROUTE_V9_SELECTED_REAL_VLESS_FOREIGN_TCP_UDP_TUN_AND_PRIVATE_DIRECT=PASS")

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
	privateUDP, err = hostRouteQAUDP(t, hostRouteQAPrivateUDP, "outage-private", 1600*time.Millisecond)
	if err != nil || !strings.HasPrefix(privateUDP, "private-udp-source=10.77.0.1:") {
		t.Fatalf("private UDP Direct failed during selected outage: %q %v", privateUDP, err)
	}
	private, err = hostRouteQAHTTP(t, hostRouteQAPrivate, 3*time.Second)
	if err != nil || !strings.HasPrefix(private, "private-source=10.77.0.1:") {
		t.Fatalf("private Direct did not survive relay outage: %q %v", private, err)
	}
	if crashMode == "client-core" {
		fmt.Println("HOST_ROUTE_V9_SELECTED_CORE_SIGKILL_GUARD_NO_DIRECT_TCP_UDP_AND_PRIVATE_ALIVE=PASS")
	} else {
		fmt.Println("HOST_ROUTE_V9_SELECTED_REAL_VLESS_OUTAGE_NO_DIRECT_TCP_UDP_AND_PRIVATE_ALIVE=PASS")
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
	fmt.Println("HOST_ROUTE_V9_SELECTED_VLESS_INDEPENDENT_OFF_RESTORES_HOST_DIRECT_TCP_UDP=PASS")
}
