package sc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const workloadSocketTestHeader = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"

func socketRow(inode uint64, local, remote, state string) string {
	return fmt.Sprintf("0: %s %s %s 00000000:00000000 00:00000000 00000000 0 0 %d 1\n",
		local, remote, state, inode)
}

func newWorkloadSocketFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeWorkloadFixture(t, root, 201, 0, 30, "/system.slice/panel.service")
	for _, sub := range []string{"fd", "net", "ns"} {
		if err := os.Mkdir(filepath.Join(root, "201", sub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("net:[4026531993]", filepath.Join(root, "201", "ns", "net")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if err := os.WriteFile(filepath.Join(root, "201", "net", name), []byte(workloadSocketTestHeader), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func addWorkloadSocketFD(t *testing.T, root string, fd int, inode uint64) {
	t.Helper()
	if err := os.Symlink(fmt.Sprintf("socket:[%d]", inode), filepath.Join(root, "201", "fd", strconv.Itoa(fd))); err != nil {
		t.Fatal(err)
	}
}

func setWorkloadNetTable(t *testing.T, root, name, rows string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "201", "net", name), []byte(workloadSocketTestHeader+rows), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestWorkloadSocketsSyntheticFDToNamespaceTableJoin(t *testing.T) {
	root := newWorkloadSocketFixture(t)
	addWorkloadSocketFD(t, root, 3, 12345)
	addWorkloadSocketFD(t, root, 4, 44444) // other socket type, not a TCP/UDP match
	if err := os.Symlink("/dev/null", filepath.Join(root, "201", "fd", "5")); err != nil {
		t.Fatal(err)
	}
	setWorkloadNetTable(t, root, "tcp",
		socketRow(12345, "0100007F:EA60", "0200007F:0050", "01")+
			socketRow(99999, "0300007F:EA61", "0400007F:0050", "01"))
	setWorkloadNetTable(t, root, "udp6",
		socketRow(88888, "00000000000000000000000001000000:1F90",
			"00000000000000000000000000000000:0000", "07"))
	report, err := observeWorkloadWithSocketsAt(root, 201)
	if err != nil {
		t.Fatal(err)
	}
	s := report.Sockets
	if s == nil || !s.ReadOnly || s.SnapshotAtomic || s.JobOwnerVerified ||
		s.DescendantsCovered || s.TrafficPathVerified || s.ActivationReady ||
		report.AttributionVerified || report.TrafficPathVerified || report.ActivationReady {
		t.Fatalf("socket observation claimed job/path/activation proof: %+v", report)
	}
	if s.NetworkNamespace != "net:[4026531993]" || s.SocketInodeCount != 2 ||
		s.UnclassifiedInodes != 1 || len(s.ObservedTCPUDPSocket) != 1 || len(s.Limitations) == 0 {
		t.Fatalf("wrong scoped socket join: %+v", s)
	}
	got := s.ObservedTCPUDPSocket[0]
	if got.Inode != 12345 || got.Protocol != "tcp4" || got.State != "01" ||
		got.Local != "127.0.0.1:60000" || got.Remote != "127.0.0.2:80" {
		t.Fatalf("incorrect FD-bound kernel socket: %+v", got)
	}
}

func TestWorkloadSocketsEmptyFDsNeverInventNetworkTraffic(t *testing.T) {
	root := newWorkloadSocketFixture(t)
	setWorkloadNetTable(t, root, "tcp", socketRow(999, "0100007F:EA60", "0200007F:0050", "01"))
	report, err := observeWorkloadWithSocketsAt(root, 201)
	if err != nil {
		t.Fatal(err)
	}
	if report.Sockets == nil || report.Sockets.SocketInodeCount != 0 ||
		report.Sockets.UnclassifiedInodes != 0 || len(report.Sockets.ObservedTCPUDPSocket) != 0 ||
		report.Sockets.TrafficPathVerified || report.Sockets.JobOwnerVerified {
		t.Fatalf("unheld namespace socket falsely attributed to PID: %+v", report)
	}
}

func TestWorkloadSocketsIPv6NativeHeaderVariant(t *testing.T) {
	root := newWorkloadSocketFixture(t)
	addWorkloadSocketFD(t, root, 3, 12346)
	header := strings.ReplaceAll(workloadSocketTestHeader, "rem_address", "remote_address")
	content := header + socketRow(12346,
		"00000000000000000000000001000000:1F90",
		"00000000000000000000000001000000:01BB", "01")
	if err := os.WriteFile(filepath.Join(root, "201", "net", "tcp6"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := observeWorkloadWithSocketsAt(root, 201)
	if err != nil {
		t.Fatal(err)
	}
	if report.Sockets == nil || len(report.Sockets.ObservedTCPUDPSocket) != 1 {
		t.Fatalf("native IPv6 header was rejected: %+v", report)
	}
	socket := report.Sockets.ObservedTCPUDPSocket[0]
	if socket.Protocol != "tcp6" || socket.Local != "[::1]:8080" ||
		socket.Remote != "[::1]:443" || socket.Inode != 12346 ||
		report.Sockets.TrafficPathVerified {
		t.Fatalf("wrong IPv6 FD-bound address: %+v", report)
	}
}

func TestWorkloadSocketEndpoints(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		ipv6    bool
		want    string
		wantErr bool
	}{
		{"0100007F:0050", false, "127.0.0.1:80", false},
		{"00000000000000000000000001000000:1F90", true, "[::1]:8080", false},
		{"00000000000000000000000000000000:0000", true, "[::]:0", false},
		{"00000000:0000", false, "0.0.0.0:0", false},
		{"0100007F:FFFF", false, "127.0.0.1:65535", false},
		{"ABCD:0050", false, "", true},
		{"0100007F:GGGG", false, "", true},
		{"0100007F:00000", false, "", true},
		{"00000000:0050", true, "", true},
	} {
		got, err := parseWorkloadSocketEndpoint(tc.raw, tc.ipv6)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Fatalf("endpoint %q ipv6=%t: got=%q err=%v want=%q error=%t",
				tc.raw, tc.ipv6, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestWorkloadSocketsRejectsAmbiguousTableAndFD(t *testing.T) {
	for _, scenario := range []string{
		"missing-tcp6", "malformed-header", "malformed-row", "unknown-socket-inode",
		"duplicate-inode-across-protocols", "unreadable-namespace",
		"unparseable-fd", "oversized-table",
	} {
		t.Run(scenario, func(t *testing.T) {
			root := newWorkloadSocketFixture(t)
			addWorkloadSocketFD(t, root, 3, 12345)
			tcp := filepath.Join(root, "201", "net", "tcp")
			switch scenario {
			case "missing-tcp6":
				if err := os.Remove(filepath.Join(root, "201", "net", "tcp6")); err != nil {
					t.Fatal(err)
				}
			case "malformed-header":
				if err := os.WriteFile(tcp, []byte("wrong\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "malformed-row":
				setWorkloadNetTable(t, root, "tcp", "0: broken\n")
			case "unknown-socket-inode":
				if err := os.Remove(filepath.Join(root, "201", "fd", "3")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("socket:[bad]", filepath.Join(root, "201", "fd", "3")); err != nil {
					t.Fatal(err)
				}
			case "duplicate-inode-across-protocols":
				row := socketRow(12345, "0100007F:EA60", "0200007F:0050", "01")
				setWorkloadNetTable(t, root, "tcp", row)
				setWorkloadNetTable(t, root, "udp", row)
			case "unreadable-namespace":
				if err := os.Remove(filepath.Join(root, "201", "ns", "net")); err != nil {
					t.Fatal(err)
				}
			case "unparseable-fd":
				if err := os.Remove(filepath.Join(root, "201", "fd", "3")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("socket:[12345", filepath.Join(root, "201", "fd", "3")); err != nil {
					t.Fatal(err)
				}
			case "oversized-table":
				if err := os.WriteFile(tcp, []byte(workloadSocketTestHeader+strings.Repeat(" ", workloadSocketMaxNetBytes+1)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			report, err := observeWorkloadWithSocketsAt(root, 201)
			if ErrorCode(err) != "workload_observation_unavailable" || report.Sockets != nil {
				t.Fatalf("accepted unsupported procfs socket observation: %+v err=%v", report, err)
			}
		})
	}
}

// A parseable final prefix is still an incomplete procfs record if the
// terminating newline was not observed. The parser must not return partial
// successful socket evidence after a malformed tail or serial identifier.
func TestWorkloadSocketRejectsTruncatedOrNonNativeRows(t *testing.T) {
	held := map[uint64]bool{12345: true}
	legitimate := socketRow(12345, "0100007F:EA60", "0200007F:0050", "01")
	for _, tc := range []struct {
		name string
		data string
	}{
		{"truncated_matching_last_row", workloadSocketTestHeader + strings.TrimSuffix(legitimate, "\n")},
		{"truncated_foreign_last_row", workloadSocketTestHeader + legitimate +
			strings.TrimSuffix(socketRow(98765, "0300007F:EA60", "0400007F:0050", "01"), "\n")},
		{"truncated_header", strings.TrimSuffix(workloadSocketTestHeader, "\n")},
		{"truncated_matching_with_newline", workloadSocketTestHeader + strings.TrimSuffix(legitimate, " 1\n") + "\n"},
		{"truncated_foreign_with_newline", workloadSocketTestHeader + legitimate +
			strings.TrimSuffix(socketRow(98765, "0300007F:EA60", "0400007F:0050", "01"), " 1\n") + "\n"},
		{"malformed_serial_matching", workloadSocketTestHeader + strings.Replace(legitimate, "0:", "bad:", 1)},
		{"malformed_serial_foreign", workloadSocketTestHeader + legitimate +
			strings.Replace(socketRow(98765, "0300007F:EA60", "0400007F:0050", "01"), "0:", "-1:", 1)},
		{"missing_serial", workloadSocketTestHeader + strings.Replace(legitimate, "0:", ":", 1)},
		{"serial_overflow", workloadSocketTestHeader + strings.Replace(legitimate, "0:", "4294967296:", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseWorkloadSocketTable([]byte(tc.data), "tcp4", held)
			if ErrorCode(err) != "workload_observation_unavailable" || len(got) != 0 {
				t.Fatalf("accepted incomplete/unnative procfs row: %+v, %v", got, err)
			}
			root := newWorkloadSocketFixture(t)
			addWorkloadSocketFD(t, root, 3, 12345)
			if err := os.WriteFile(filepath.Join(root, "201", "net", "tcp"), []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			report, err := observeWorkloadWithSocketsAt(root, 201)
			if ErrorCode(err) != "workload_observation_unavailable" || report.Sockets != nil {
				t.Fatalf("integrated observer returned partial socket evidence: %+v, %v", report, err)
			}
		})
	}
	valid, err := parseWorkloadSocketTable([]byte(workloadSocketTestHeader+legitimate), "tcp4", held)
	if err != nil || len(valid) != 1 || valid[0].Inode != 12345 {
		t.Fatalf("strict parsing rejected complete kernel-shaped record: %+v, %v", valid, err)
	}
}

// Ref is a native decimal socket reference count for EVERY namespace-table
// row, not only sockets held by the sampled PID. A broken unrelated row
// invalidates the complete non-atomic snapshot instead of returning the
// earlier matched socket as partial success.
func TestWorkloadSocketRefIntegrityFailClosed(t *testing.T) {
	protocols := []struct {
		name, protocol, table, local, remote, state string
	}{
		{"tcp4", "tcp4", "tcp", "0100007F:EA60", "0200007F:0050", "01"},
		{"tcp6", "tcp6", "tcp6", "00000000000000000000000001000000:EA60",
			"00000000000000000000000001000000:0050", "01"},
		{"udp4", "udp4", "udp", "0100007F:EA60", "00000000:0000", "07"},
		{"udp6", "udp6", "udp6", "00000000000000000000000001000000:EA60",
			"00000000000000000000000000000000:0000", "07"},
	}
	invalidRefs := []struct{ name, ref string }{
		{"alpha", "not-a-number"},
		{"negative", "-1"},
		{"positive_prefix", "+1"},
		{"overflow_uint32", "4294967296"},
		{"overflow_uint64", "18446744073709551616"},
		{"hexadecimal", "0x2"},
		{"fractional", "1.5"},
		{"unicode_digits", "١"},
		{"leading_zero", "01"},
	}
	for _, protocol := range protocols {
		t.Run(protocol.name, func(t *testing.T) {
			valid := socketRow(12345, protocol.local, protocol.remote, protocol.state)
			for _, invalid := range invalidRefs {
				for _, foreign := range []bool{false, true} {
					scope := "held"
					inode := uint64(12345)
					if foreign {
						scope, inode = "foreign", 98765
					}
					t.Run(scope+"_"+invalid.name, func(t *testing.T) {
						bad := socketRow(inode, protocol.local, protocol.remote, protocol.state)
						if !strings.HasSuffix(bad, " 1\n") {
							t.Fatalf("fixture must end in native ref count: %q", bad)
						}
						bad = strings.TrimSuffix(bad, " 1\n") + " " + invalid.ref + "\n"
						rows := bad
						if foreign {
							rows = valid + bad // a good held socket precedes the bad unrelated row
						}
						header := workloadSocketTestHeader
						if protocol.name == "tcp6" {
							header = strings.ReplaceAll(header, "rem_address", "remote_address")
						}
						held := map[uint64]bool{12345: true}
						sockets, err := parseWorkloadSocketTable([]byte(header+rows), protocol.protocol, held)
						if ErrorCode(err) != "workload_observation_unavailable" || len(sockets) != 0 {
							t.Fatalf("parser accepted invalid %s ref %q: %+v, %v", scope, invalid.ref, sockets, err)
						}
						root := newWorkloadSocketFixture(t)
						addWorkloadSocketFD(t, root, 3, 12345)
						if err := os.WriteFile(filepath.Join(root, "201", "net", protocol.table),
							[]byte(header+rows), 0600); err != nil {
							t.Fatal(err)
						}
						report, err := observeWorkloadWithSocketsAt(root, 201)
						if ErrorCode(err) != "workload_observation_unavailable" || report.Sockets != nil {
							t.Fatalf("observer returned partial data for invalid %s ref %q: %+v, %v",
								scope, invalid.ref, report, err)
						}
					})
				}
			}
		})
	}
}

// Use representative post-ref data from the corresponding native kernel
// formats. Suffixes vary with protocol, state and kernel version, so only
// the documented required prefix is validated by the product parser.
func TestWorkloadSocketNativeShapedPositiveRows(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, local, remote, state, suffix string
	}{
		{"tcp4", "tcp4", "0100007F:EA60", "0200007F:0050", "01",
			" 0000000000000000 100 0 0 10 0"},
		{"tcp6", "tcp6", "00000000000000000000000001000000:EA60",
			"00000000000000000000000001000000:0050", "01",
			" 0000000000000000 100 0 0 10 0"},
		{"udp4", "udp4", "0100007F:EA60", "00000000:0000", "07",
			" 0000000000000000 0"},
		{"udp6", "udp6", "00000000000000000000000001000000:EA60",
			"00000000000000000000000000000000:0000", "07",
			" 0000000000000000 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := strings.TrimSuffix(socketRow(12345, tc.local, tc.remote, tc.state), "\n") + tc.suffix + "\n"
			header := workloadSocketTestHeader
			if strings.HasPrefix(tc.protocol, "udp") {
				header = strings.TrimSuffix(header, "\n") + " ref pointer drops\n"
			}
			if strings.HasSuffix(tc.protocol, "6") {
				header = strings.ReplaceAll(header, "rem_address", "remote_address")
			}
			sockets, err := parseWorkloadSocketTable([]byte(header+row), tc.protocol, map[uint64]bool{12345: true})
			if err != nil || len(sockets) != 1 || sockets[0].Inode != 12345 || sockets[0].Protocol != tc.protocol {
				t.Fatalf("native-shaped %s row rejected: %+v, %v", tc.protocol, sockets, err)
			}
		})
	}
}

// Native TCP TIME_WAIT rows may have ref=0 even though that socket FD is
// not held by this PID. Such rows must not invalidate a valid observation.
func TestWorkloadSocketZeroRefForeignRowAllowed(t *testing.T) {
	good := socketRow(12345, "0100007F:EA60", "0200007F:0050", "01")
	foreign := socketRow(98765, "0300007F:EA61", "0400007F:0050", "06")
	if !strings.HasSuffix(foreign, " 1\n") {
		t.Fatalf("unexpected test fixture: %q", foreign)
	}
	foreign = strings.TrimSuffix(foreign, " 1\n") + " 0\n"
	rows := workloadSocketTestHeader + good + foreign
	sockets, err := parseWorkloadSocketTable([]byte(rows), "tcp4", map[uint64]bool{12345: true})
	if err != nil || len(sockets) != 1 || sockets[0].Inode != 12345 {
		t.Fatalf("zero ref count in foreign TIME_WAIT row rejected: %+v, %v", sockets, err)
	}
	root := newWorkloadSocketFixture(t)
	addWorkloadSocketFD(t, root, 3, 12345)
	if err := os.WriteFile(filepath.Join(root, "201", "net", "tcp"), []byte(rows), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := observeWorkloadWithSocketsAt(root, 201)
	if err != nil || report.Sockets == nil ||
		len(report.Sockets.ObservedTCPUDPSocket) != 1 ||
		report.Sockets.JobOwnerVerified || report.Sockets.TrafficPathVerified {
		t.Fatalf("observer rejected native zero or inferred ownership: %+v, %v", report, err)
	}
}

// Mutate the private procfs fixture at the exact moment after all namespace
// socket table reads and before the observer's identity rechecks. This tests
// the integrated fail-closed behavior without scheduling/racing real kernel
// tasks or touching host sockets, routes or network state.
func TestWorkloadSocketsRejectsMidObservationDrift(t *testing.T) {
	for _, scenario := range []string{
		"namespace_moved", "namespace_missing",
		"socket_fd_replaced", "socket_fd_disappeared", "socket_fd_added",
		"pid_generation_reused", "cgroup_membership_moved",
	} {
		t.Run(scenario, func(t *testing.T) {
			root := newWorkloadSocketFixture(t)
			addWorkloadSocketFD(t, root, 3, 12345)
			setWorkloadNetTable(t, root, "tcp", socketRow(12345, "0100007F:EA60", "0200007F:0050", "01"))
			pidDir := filepath.Join(root, "201")
			report, err := observeWorkloadWithSocketsAtAfterTables(root, 201, func() {
				switch scenario {
				case "namespace_moved", "namespace_missing":
					link := filepath.Join(pidDir, "ns", "net")
					if err := os.Remove(link); err != nil {
						t.Fatal(err)
					}
					if scenario == "namespace_moved" {
						if err := os.Symlink("net:[4026531994]", link); err != nil {
							t.Fatal(err)
						}
					}
				case "socket_fd_replaced", "socket_fd_disappeared":
					link := filepath.Join(pidDir, "fd", "3")
					if err := os.Remove(link); err != nil {
						t.Fatal(err)
					}
					if scenario == "socket_fd_replaced" {
						if err := os.Symlink("socket:[23456]", link); err != nil {
							t.Fatal(err)
						}
					}
				case "socket_fd_added":
					addWorkloadSocketFD(t, root, 4, 98765)
				case "pid_generation_reused":
					writeWorkloadFixture(t, root, 201, 0, 31, "/system.slice/panel.service")
				case "cgroup_membership_moved":
					writeWorkloadFixture(t, root, 201, 0, 30, "/system.slice/other.service")
				}
			})
			if ErrorCode(err) != "workload_observation_unavailable" || report.Sockets != nil {
				t.Fatalf("accepted changed procfs identity after scan (%s): %+v, %v", scenario, report, err)
			}
		})
	}
	// Positive control: the exact same instrumented code path accepts a
	// stable fixture, including the rechecks, when no mutation is injected.
	root := newWorkloadSocketFixture(t)
	addWorkloadSocketFD(t, root, 3, 12345)
	setWorkloadNetTable(t, root, "tcp", socketRow(12345, "0100007F:EA60", "0200007F:0050", "01"))
	report, err := observeWorkloadWithSocketsAtAfterTables(root, 201, func() {})
	if err != nil || report.Sockets == nil || len(report.Sockets.ObservedTCPUDPSocket) != 1 ||
		report.Sockets.JobOwnerVerified || report.Sockets.TrafficPathVerified {
		t.Fatalf("stable same-path positive control: %+v %v", report, err)
	}
}

func TestWorkloadSocketsRealLoopbackUDPSockets(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux procfs only")
	}
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !strings.HasPrefix(string(cgroup), "0::/") {
		t.Skip("unified cgroup v2 unavailable")
	}
	for _, tc := range []struct{ network, bind, protocol string }{
		{"udp4", "127.0.0.1:0", "udp4"},
		{"udp6", "[::1]:0", "udp6"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			conn, err := net.ListenPacket(tc.network, tc.bind)
			if err != nil {
				if tc.network == "udp6" {
					t.Skipf("optional IPv6 loopback unavailable on host: %v", err)
				}
				t.Fatal(err)
			}
			defer conn.Close()
			report, err := ObserveWorkloadProcessSockets(os.Getpid())
			if err != nil {
				t.Fatalf("real procfs UDP socket observation: %v", err)
			}
			if report.Sockets == nil || report.Sockets.JobOwnerVerified ||
				report.Sockets.TrafficPathVerified || report.ActivationReady {
				t.Fatalf("UDP observation manufactured ownership or route: %+v", report)
			}
			found := false
			for _, socket := range report.Sockets.ObservedTCPUDPSocket {
				if socket.Protocol == tc.protocol && socket.Local == conn.LocalAddr().String() {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s live held UDP socket missing: %+v", tc.network, report.Sockets)
			}
		})
	}
}

func TestWorkloadSocketsRealLoopbackTCPFD(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux procfs only")
	}
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !strings.HasPrefix(string(cgroup), "0::/") {
		t.Skip("unified cgroup v2 unavailable")
	}
	for _, tc := range []struct{ network, address string }{
		{"tcp4", "127.0.0.1:0"},
		{"tcp6", "[::1]:0"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			ln, err := net.Listen(tc.network, tc.address)
			if err != nil {
				if tc.network == "tcp6" {
					t.Skipf("optional IPv6 loopback unavailable on host: %v", err)
				}
				t.Fatal(err)
			}
			defer ln.Close()
			serverConn := make(chan net.Conn, 1)
			serverErr := make(chan error, 1)
			go func() {
				accepted, err := ln.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				serverConn <- accepted
			}()
			client, err := net.Dial(tc.network, ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var accepted net.Conn
			select {
			case accepted = <-serverConn:
			case err = <-serverErr:
				t.Fatal(err)
			}
			defer accepted.Close()

			report, err := ObserveWorkloadProcessSockets(os.Getpid())
			if err != nil {
				t.Fatalf("real FD-bound loopback observation unavailable: %v", err)
			}
			if report.Sockets == nil || report.AttributionVerified || report.TrafficPathVerified ||
				report.ActivationReady || report.Sockets.JobOwnerVerified ||
				report.Sockets.TrafficPathVerified || report.Sockets.DescendantsCovered {
				t.Fatalf("real socket inferred routing or job ownership: %+v", report)
			}
			found := false
			for _, socket := range report.Sockets.ObservedTCPUDPSocket {
				if socket.Protocol == tc.network && socket.Remote == ln.Addr().String() && socket.State == "01" {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s live open TCP socket not found in PID FD/net join: %+v", tc.network, report.Sockets)
			}
		})
	}
}
