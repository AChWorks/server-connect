//go:build linux

package sc

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Explicit root opt-in plus independent network namespace identity: running
// this binary normally never mutates a host. The subprocess watchdog proves
// kernel/journal recovery independent of the staging caller; it is NOT proof
// of installed-systemd Guard admission or general-host routing.
func requireHostIngressNative(t *testing.T) {
	t.Helper()
	if os.Getenv("SC_TEST_HOST_INGRESS_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: explicit isolated-netns ingress QA required")
	}
	self, e1 := os.Stat("/proc/self/ns/net")
	host, e2 := os.Stat("/proc/1/ns/net")
	if os.Geteuid() != 0 || e1 != nil || e2 != nil || os.SameFile(self, host) {
		t.Fatal("root host namespace refused")
	}
}
func ingressNativeCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v %s", name, args, err, out)
	}
	return string(out)
}
func ingressNativeSocketMark(t *testing.T, c *net.TCPConn) uint32 {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mark int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		mark, socketErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
	return uint32(mark)
}
func TestHostIngressNativePeerHelper(t *testing.T) {
	if os.Getenv("SC_TEST_INGRESS_ROLE") != "peer" {
		t.Skip("native child only")
	}
	requireHostIngressNative(t)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64), 256)
	var sockets []*net.TCPConn
	defer func() {
		for _, s := range sockets {
			if s != nil {
				s.Close()
			}
		}
	}()
	for scanner.Scan() {
		switch scanner.Text() {
		case "configure":
			ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "lo", "up")
			ingressNativeCommand(t, "/usr/sbin/ip", "addr", "add", "192.0.2.2/30", "dev", "scinp0")
			ingressNativeCommand(t, "/usr/sbin/ip", "-6", "addr", "add", "fd73:71::2/64", "dev", "scinp0", "nodad")
			ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "scinp0", "up")
			fmt.Println("INGRESS_PEER_READY")
		case "4", "6":
			address, network := "192.0.2.1:28993", "tcp4"
			if scanner.Text() == "6" {
				address, network = "[fd73:71::1]:28993", "tcp6"
			}
			conn, err := net.DialTimeout(network, address, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			c := conn.(*net.TCPConn)
			c.SetLinger(0)
			c.SetDeadline(time.Now().Add(4 * time.Second))
			sockets = append(sockets, c)
			if _, err := c.Write([]byte("REQUEST")); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 1)
			if _, err := io.ReadFull(c, b); err != nil || b[0] != 'R' {
				t.Fatalf("peer reply: %q %v", b, err)
			}
			c.SetDeadline(time.Time{})
			fmt.Println("INGRESS_PEER_SESSION=PASS")
		case "close-old":
			if len(sockets) == 0 || sockets[0] == nil {
				t.Fatal("old socket missing")
			}
			sockets[0].Close()
			sockets[0] = nil
			fmt.Println("INGRESS_PEER_OLD_CLOSED")
		default:
			t.Fatal("unexpected peer control input")
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}
func TestHostIngressNativeWatchdogHelper(t *testing.T) {
	if os.Getenv("SC_TEST_INGRESS_ROLE") != "watchdog" {
		t.Skip("native child only")
	}
	requireHostIngressNative(t)
	dir := os.Getenv("SC_TEST_INGRESS_DIR")
	if dir == "" {
		t.Fatal("private journal directory required")
	}
	fmt.Println("INGRESS_WATCHDOG_READY")
	// EOF models a killed/disconnected caller. No core or caller RPC is needed.
	b := make([]byte, 1)
	_, _ = os.Stdin.Read(b)
	m := New(dir, DefaultCore, DefaultPort)
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		r, _, err := loadHostIngressStage(store)
		if err != nil {
			return err
		}
		result, err := recoverHostIngressStageLocked(store, &r, true)
		if err == nil && !result.RecoveryVerified {
			return fmt.Errorf("independent recovery did not verify baseline")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("INGRESS_INDEPENDENT_PROCESS_ROLLBACK=PASS")
}
func TestHostIngressNativeStageAndIndependentRollback(t *testing.T) {
	requireHostIngressNative(t)
	links := ingressNativeCommand(t, "/usr/sbin/ip", "-j", "link", "show")
	rows, err := selectiveRows([]byte(links))
	if err != nil || len(rows) != 1 || selectiveText(rows[0]["ifname"]) != "lo" {
		t.Fatal("fresh loopback-only namespace required")
	}
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "lo", "up")
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "add", "scing0", "type", "veth", "peer", "name", "scinp0")
	ingressNativeCommand(t, "/usr/sbin/ip", "addr", "add", "192.0.2.1/30", "dev", "scing0")
	ingressNativeCommand(t, "/usr/sbin/ip", "-6", "addr", "add", "fd73:71::1/64", "dev", "scing0", "nodad")
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "scing0", "up")
	ingressNativeCommand(t, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.tcp_fwmark_accept=0", "net.ipv4.tcp_syncookies=2")
	for _, binary := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"} {
		ingressNativeCommand(t, binary, "-t", "raw", "-A", "PREROUTING", "-p", "tcp", "--dport", "28993", "-j", "NOTRACK")
		ingressNativeCommand(t, binary, "-t", "raw", "-A", "OUTPUT", "-p", "tcp", "--sport", "28993", "-j", "NOTRACK")
	}
	_, rawBefore, err := hostIngressRawSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	routesBefore := ingressNativeCommand(t, "/usr/sbin/ip", "-j", "route", "show", "table", "all")
	rulesBefore := ingressNativeCommand(t, "/usr/sbin/ip", "-j", "rule", "show")
	peer := exec.Command(os.Args[0], "-test.run=^TestHostIngressNativePeerHelper$", "-test.v")
	peer.Env = append(os.Environ(), "SC_TEST_INGRESS_ROLE=peer")
	peer.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	peerIn, err := peer.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	peerOut, err := peer.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	peer.Stderr = os.Stderr
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { peerIn.Close(); peer.Process.Kill(); peer.Wait() }()
	peerScanner := bufio.NewScanner(peerOut)
	readUntil := func(scanner *bufio.Scanner, want string) {
		for scanner.Scan() {
			line := scanner.Text()
			if line == want {
				return
			}
			if strings.Contains(line, "FAIL") {
				t.Fatalf("child failed before %s: %s", want, line)
			}
		}
		t.Fatalf("child ended before %s: %v", want, scanner.Err())
	}
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "scinp0", "netns", strconv.Itoa(peer.Process.Pid))
	fmt.Fprintln(peerIn, "configure")
	readUntil(peerScanner, "INGRESS_PEER_READY")
	listen := func(network, address string) *net.TCPListener {
		a, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			t.Fatal(err)
		}
		listener, err := net.ListenTCP(network, a)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		return listener
	}
	l4, l6 := listen("tcp4", "192.0.2.1:28993"), listen("tcp6", "[fd73:71::1]:28993")
	exchange := func(family string) *net.TCPConn {
		fmt.Fprintln(peerIn, family)
		listener := l4
		if family == "6" {
			listener = l6
		}
		listener.SetDeadline(time.Now().Add(4 * time.Second))
		conn, err := listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		conn.SetLinger(0)
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(4 * time.Second))
		b := make([]byte, 7)
		if _, err := io.ReadFull(conn, b); err != nil || string(b) != "REQUEST" {
			t.Fatalf("request: %q %v", b, err)
		}
		if _, err := conn.Write([]byte("R")); err != nil {
			t.Fatal(err)
		}
		readUntil(peerScanner, "INGRESS_PEER_SESSION=PASS")
		conn.SetDeadline(time.Time{})
		return conn
	}
	old := exchange("4")
	if ingressNativeSocketMark(t, old) != 0 {
		t.Fatal("old socket unexpectedly marked")
	}
	dir := privateJournalTempDir(t)
	m := New(dir, DefaultCore, DefaultPort)
	watchdog := exec.Command(os.Args[0], "-test.run=^TestHostIngressNativeWatchdogHelper$", "-test.v")
	watchdog.Env = append(os.Environ(), "SC_TEST_INGRESS_ROLE=watchdog", "SC_TEST_INGRESS_DIR="+dir)
	watchIn, err := watchdog.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	watchOut, err := watchdog.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	watchdog.Stderr = os.Stderr
	if err := watchdog.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { watchIn.Close(); watchdog.Process.Kill(); watchdog.Wait() }()
	watchScanner := bufio.NewScanner(watchOut)
	readUntil(watchScanner, "INGRESS_WATCHDOG_READY")
	guard := func() error { return watchdog.Process.Signal(syscall.Signal(0)) }
	r, err := newHostIngressStage("scing0", 60)
	if err != nil {
		t.Fatal(err)
	}
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error { return applyHostIngressStageLocked(store, &r, guard) })
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("INGRESS_KERNEL_STAGE_OWNED=PASS")
	if code := ErrorCode(hostIngressDrainBarrier(r, guard)); code != "host_ingress_drain_pending" {
		t.Fatalf("old unmarked socket did not refuse capture: %s", code)
	}
	n4, n6 := exchange("4"), exchange("6")
	if ingressNativeSocketMark(t, n4) != nativeTUNBypassMark || ingressNativeSocketMark(t, n6) != nativeTUNBypassMark {
		t.Fatal("SYN-cookie accepted socket did not inherit final ACK mark")
	}
	fmt.Println("INGRESS_IPV4_IPV6_SYNCOOKIE_MARKS=PASS")
	old.Close()
	fmt.Fprintln(peerIn, "close-old")
	readUntil(peerScanner, "INGRESS_PEER_OLD_CLOSED")
	if err := hostIngressDrainBarrier(r, guard); err != nil {
		t.Fatal(err)
	}
	fmt.Println("INGRESS_GENERATION_DRAIN_BARRIER=PASS")
	// A caller disconnect must not disable the independently prearmed process.
	watchIn.Close()
	readUntil(watchScanner, "INGRESS_INDEPENDENT_PROCESS_ROLLBACK=PASS")
	if err := watchdog.Wait(); err != nil {
		t.Fatal(err)
	}
	_, rawAfter, err := hostIngressRawSnapshot()
	if err != nil || rawBefore != rawAfter {
		t.Fatalf("foreign raw changed: %v", err)
	}
	value, err := readHostIngressSysctl()
	if err != nil || value != 0 {
		t.Fatalf("sysctl not restored: %d %v", value, err)
	}
	observed, err := observeHostIngressNFT(r)
	if err != nil || observed.Present {
		t.Fatalf("owned nft remains: %+v %v", observed, err)
	}
	if routesBefore != ingressNativeCommand(t, "/usr/sbin/ip", "-j", "route", "show", "table", "all") || rulesBefore != ingressNativeCommand(t, "/usr/sbin/ip", "-j", "rule", "show") {
		t.Fatal("stage modified FIB/RPDB")
	}
	fmt.Println("INGRESS_FOREIGN_RAW_FIB_RPDB_PRESERVED=PASS")
}
