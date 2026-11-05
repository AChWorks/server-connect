//go:build linux

package sc

import (
	"bufio"
	"encoding/json"
	"errors"
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
	requireNativeQANetworkNamespace(t)
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
			ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "scinp0", "addrgenmode", "none")
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
	links := ingressNativeCommand(t, "/usr/sbin/ip", "-d", "-j", "link", "show")
	rows, err := selectiveRows([]byte(links))
	if err != nil || len(rows) == 0 {
		t.Fatal("fresh namespace inventory unavailable")
	}
	seenLoopback := false
	for _, row := range rows {
		name := selectiveText(row["ifname"])
		if name == "lo" {
			seenLoopback = true
			continue
		}
		// Loading GRE modules on the outer runner creates inert fallback
		// devices in *each new* namespace. Verify their exact kind and
		// quiescence; never remove them or broaden root-namespace admission.
		kinds := map[string]string{"gre0": "gre", "gretap0": "gretap", "erspan0": "erspan"}
		var info struct {
			Kind string `json:"info_kind"`
		}
		var flags []string
		if json.Unmarshal(row["linkinfo"], &info) != nil || kinds[name] == "" || info.Kind != kinds[name] ||
			selectiveText(row["operstate"]) != "DOWN" || json.Unmarshal(row["flags"], &flags) != nil {
			t.Fatal("unexpected device in fresh isolated namespace")
		}
		for _, flag := range flags {
			if flag == "UP" || flag == "LOWER_UP" {
				t.Fatal("active fallback device refused")
			}
		}
		var addresses []map[string]json.RawMessage
		raw := ingressNativeCommand(t, "/usr/sbin/ip", "-j", "addr", "show", "dev", name)
		if json.Unmarshal([]byte(raw), &addresses) != nil || len(addresses) != 1 {
			t.Fatal("fallback address inventory unavailable")
		}
		var configured []json.RawMessage
		if json.Unmarshal(addresses[0]["addr_info"], &configured) != nil || len(configured) != 0 {
			t.Fatal("configured fallback device refused")
		}
		for _, family := range []string{"-4", "-6"} {
			if strings.TrimSpace(ingressNativeCommand(t, "/usr/sbin/ip", family, "route", "show", "table", "all", "dev", name)) != "" {
				t.Fatal("routed fallback device refused")
			}
		}
	}
	if !seenLoopback {
		t.Fatal("loopback missing from fresh namespace")
	}
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "lo", "up")
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "add", "scing0", "type", "veth", "peer", "name", "scinp0")
	ingressNativeCommand(t, "/usr/sbin/ip", "addr", "add", "192.0.2.1/30", "dev", "scing0")
	ingressNativeCommand(t, "/usr/sbin/ip", "-6", "addr", "add", "fd73:71::1/64", "dev", "scing0", "nodad")
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "scing0", "addrgenmode", "none")
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
	// Take the baseline only after the peer VETH is configured and live.
	// Its initial linkdown->up transition is fixture setup, not stage mutation.
	routeRulesSnapshot := func() string {
		var parts []string
		for _, family := range []string{"-4", "-6"} {
			parts = append(parts, ingressNativeCommand(t, "/usr/sbin/ip", family, "-j", "route", "show", "table", "all"))
			parts = append(parts, ingressNativeCommand(t, "/usr/sbin/ip", family, "-j", "rule", "show"))
		}
		return strings.Join(parts, "\x00")
	}
	routesBefore := routeRulesSnapshot()
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
	// The globally reserved SO_MARK bits must be free BEFORE staging; new
	// inherited bypass marks created by this operation are not foreign marks.
	if err := observeReservedHostSocketMarks(); err != nil {
		t.Fatalf("pre-staging socket mark inventory: %v", err)
	}
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error { return applyHostIngressStageLocked(store, &r, guard) })
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("INGRESS_KERNEL_STAGE_OWNED=PASS")
	if code := ErrorCode(observeHostIngressKernelQuiescence(r, guard)); code != "host_ingress_drain_pending" {
		t.Fatalf("live kernel filter omitted pre-existing unmarked generation: %s", code)
	}
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
	fmt.Println("INGRESS_GENERATION_DRAIN_SNAPSHOT=PASS")
	if err := observeHostIngressKernelQuiescence(r, guard); err != nil {
		t.Fatalf("kernel-filtered drain after old socket closed: %v", err)
	}
	fmt.Println("INGRESS_KERNEL_FILTERED_QUIESCENCE=PASS")
	listenerRaw, err := l4.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	setListenerMark := func(mark int) {
		t.Helper()
		var socketErr error
		if err := listenerRaw.Control(func(fd uintptr) {
			socketErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
		}); err != nil || socketErr != nil {
			t.Fatalf("listener mark operation: control=%v setsockopt=%v", err, socketErr)
		}
	}
	setListenerMark(0x13572468)
	if code := ErrorCode(observeHostIngressKernelQuiescence(r, guard)); code != "host_ingress_listener_mark" {
		t.Fatalf("foreign listener mark was not a capture refusal: %s", code)
	}
	setListenerMark(0)
	if err := observeHostIngressKernelQuiescence(r, guard); err != nil {
		t.Fatalf("unmarked listener did not restore kernel-filtered observation: %v", err)
	}
	fmt.Println("INGRESS_FOREIGN_LISTENER_MARK_REFUSAL=PASS")
	if code := ErrorCode(observeHostIngressKernelQuiescence(r, nil)); code != "guard_unavailable" {
		t.Fatalf("unguarded kernel observation unexpectedly permitted: %s", code)
	}
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
	if routesBefore != routeRulesSnapshot() {
		t.Log("FIB/RPDB before:", routesBefore)
		t.Log("FIB/RPDB after:", routeRulesSnapshot())
		t.Fatal("stage modified IPv4/IPv6 FIB/RPDB")
	}
	fmt.Println("INGRESS_FOREIGN_RAW_FIB_RPDB_PRESERVED=PASS")

	// These deterministic fault seams exercise kernel preservation, not guard
	// admission. The positive above separately proves a prearmed independent
	// process. Each negative owns a fresh private journal and known fixture
	// objects; explicit test cleanup is not product rollback evidence.
	runNegative := func(t *testing.T, body func(*Manager, *hostIngressStage)) {
		ingressNativeCommand(t, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.tcp_fwmark_accept=0")
		stage, err := newHostIngressStage("scing0", 60)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			observed, err := observeHostIngressNFT(stage)
			if err != nil {
				t.Errorf("negative fixture cleanup inventory: %v", err)
			} else if observed.Present {
				ingressNativeCommand(t, "/usr/sbin/nft", "delete", "table", "inet", "scin_"+stage.OperationID)
			}
			ingressNativeCommand(t, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.tcp_fwmark_accept=0")
		})
		body(New(privateJournalTempDir(t), DefaultCore, DefaultPort), &stage)
	}
	testGuard := func() error { return nil }
	apply := func(t *testing.T, m *Manager, stage *hostIngressStage) {
		t.Helper()
		if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
			return applyHostIngressStageLocked(store, stage, testGuard)
		}); err != nil {
			t.Fatal(err)
		}
	}
	recover := func(m *Manager, stage *hostIngressStage) error {
		return m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
			_, err := recoverHostIngressStageLocked(store, stage, true)
			return err
		})
	}
	t.Run("expired-before-effect", func(t *testing.T) {
		runNegative(t, func(m *Manager, stage *hostIngressStage) {
			stage.Deadline, _ = trialUptime()
			err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				return applyHostIngressStageLocked(store, stage, func() error {
					t.Fatal("expired stage reached guard")
					return nil
				})
			})
			got, sysctlErr := readHostIngressSysctl()
			observed, nftErr := observeHostIngressNFT(*stage)
			if ErrorCode(err) != "host_ingress_expired" || sysctlErr != nil || nftErr != nil || got != 0 || observed.Present {
				t.Fatalf("expired effect: %v sysctl=%d/%v nft=%+v/%v", err, got, sysctlErr, observed, nftErr)
			}
		})
	})
	t.Run("foreign-child-retained", func(t *testing.T) {
		runNegative(t, func(m *Manager, stage *hostIngressStage) {
			apply(t, m, stage)
			ingressNativeCommand(t, "/usr/sbin/nft", "add", "chain", "inet", "scin_"+stage.OperationID, "foreign")
			before, err := observeHostIngressNFT(*stage)
			if err != nil || before.Matches {
				t.Fatalf("foreign child absent: %+v %v", before, err)
			}
			if err := recover(m, stage); err == nil {
				t.Fatal("foreign child authorized product deletion")
			}
			after, err := observeHostIngressNFT(*stage)
			value, _ := readHostIngressSysctl()
			if err != nil || after != before || value != 1 {
				t.Fatalf("foreign graph changed: before=%+v after=%+v value=%d err=%v", before, after, value, err)
			}
		})
	})
	t.Run("same-name-replacement-retained", func(t *testing.T) {
		runNegative(t, func(m *Manager, stage *hostIngressStage) {
			apply(t, m, stage)
			ingressNativeCommand(t, "/usr/sbin/nft", "delete", "table", "inet", "scin_"+stage.OperationID)
			var commands []map[string]any
			for i, object := range hostIngressNFTObjects(*stage) {
				verb := "add"
				if i == 0 {
					verb = "create"
				}
				commands = append(commands, map[string]any{verb: object})
			}
			data, _ := json.Marshal(map[string]any{"nftables": commands})
			if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				_, err := nativeTUNRunNFT(store, data, "-j", "-f", "-")
				return err
			}); err != nil {
				t.Fatal(err)
			}
			before, err := observeHostIngressNFT(*stage)
			if err != nil || !before.Matches || before.Handle == stage.NFTHandle {
				t.Fatalf("replacement not distinct: %+v %v", before, err)
			}
			if err := recover(m, stage); err == nil {
				t.Fatal("same-name replacement authorized deletion")
			}
			after, err := observeHostIngressNFT(*stage)
			if err != nil || after != before {
				t.Fatalf("replacement changed: before=%+v after=%+v %v", before, after, err)
			}
		})
	})
	t.Run("effect-before-nft-receipt-retained", func(t *testing.T) {
		runNegative(t, func(m *Manager, stage *hostIngressStage) {
			injected := errors.New("injected NFT receipt persistence failure")
			err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				persist := hostIngressJournalPersist(store)
				return applyHostIngressStageWithPersistLocked(store, stage, testGuard, func(old *hostIngressStage, next hostIngressStage) error {
					if next.NFTStage == "observed" {
						return injected
					}
					return persist(old, next)
				})
			})
			if !errors.Is(err, injected) || stage.NFTStage != "effect_possible" {
				t.Fatalf("receipt fault not reached: %+v %v", stage, err)
			}
			before, err := observeHostIngressNFT(*stage)
			if err != nil || !before.Present || !before.Matches {
				t.Fatalf("kernel effect absent: %+v %v", before, err)
			}
			if err := recover(m, stage); err == nil {
				t.Fatal("unacknowledged exact-looking table adopted")
			}
			after, err := observeHostIngressNFT(*stage)
			value, _ := readHostIngressSysctl()
			if err != nil || after != before || value != 1 {
				t.Fatalf("uncertain effect changed: %+v %+v sysctl=%d %v", before, after, value, err)
			}
		})
	})
	t.Run("effect-before-sysctl-receipt-retained", func(t *testing.T) {
		runNegative(t, func(m *Manager, stage *hostIngressStage) {
			injected := errors.New("injected inheritance receipt persistence failure")
			err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				persist := hostIngressJournalPersist(store)
				return applyHostIngressStageWithPersistLocked(store, stage, testGuard, func(old *hostIngressStage, next hostIngressStage) error {
					if next.SysctlStage == "observed" {
						return injected
					}
					return persist(old, next)
				})
			})
			value, _ := readHostIngressSysctl()
			if !errors.Is(err, injected) || stage.SysctlStage != "effect_possible" || value != 1 {
				t.Fatalf("sysctl receipt seam not reached: %+v sysctl=%d %v", stage, value, err)
			}
			if err := recover(m, stage); err == nil {
				t.Fatal("unacknowledged sysctl acquired restoration authority")
			}
			value, _ = readHostIngressSysctl()
			if value != 1 {
				t.Fatal("unacknowledged sysctl effect overwritten")
			}
		})
	})
	t.Run("post-removed-sysctl-write-retained", func(t *testing.T) {
		runNegative(t, func(m *Manager, stage *hostIngressStage) {
			stage.Phase, stage.SysctlStage, stage.NFTStage = "stop_requested", "removed", "removed"
			err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				return writeHostIngressStage(store, *stage, nil)
			})
			if err != nil {
				t.Fatal(err)
			}
			ingressNativeCommand(t, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.tcp_fwmark_accept=1")
			if err := recover(m, stage); err == nil {
				t.Fatal("removed progress reacquired sysctl ownership")
			}
			value, _ := readHostIngressSysctl()
			if value != 1 {
				t.Fatal("later foreign same-value write was overwritten")
			}
		})
	})
	t.Run("preexisting-one-never-restored", func(t *testing.T) {
		runNegative(t, func(m *Manager, stage *hostIngressStage) {
			ingressNativeCommand(t, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.tcp_fwmark_accept=1")
			stage.SysctlBefore = 1
			apply(t, m, stage)
			if err := recover(m, stage); err != nil {
				t.Fatal(err)
			}
			value, _ := readHostIngressSysctl()
			if value != 1 {
				t.Fatal("preexisting inheritance changed")
			}
		})
	})
	if routesBefore != routeRulesSnapshot() {
		t.Fatal("negative seams changed IPv4/IPv6 FIB/RPDB")
	}
	_, rawAfter, err = hostIngressRawSnapshot()
	if err != nil || rawBefore != rawAfter {
		t.Fatalf("negative seams changed foreign raw policy: %v", err)
	}
	fmt.Println("INGRESS_KERNEL_NEGATIVE_PRESERVATION=PASS")
}
