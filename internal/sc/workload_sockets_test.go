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

func TestWorkloadSocketsRealLoopbackTCPFD(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux procfs only")
	}
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !strings.HasPrefix(string(cgroup), "0::/") {
		t.Skip("unified cgroup v2 unavailable")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
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
	client, err := net.Dial("tcp4", ln.Addr().String())
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
		if socket.Protocol == "tcp4" && socket.Remote == ln.Addr().String() && socket.State == "01" {
			found = true
		}
	}
	if !found {
		t.Fatalf("real live open TCP socket was not found in PID FD/net join: %+v", report.Sockets)
	}
}
