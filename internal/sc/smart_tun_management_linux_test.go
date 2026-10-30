//go:build linux

package sc

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func managementStatFixture(pid, parent int, ticks string) []byte {
	fields := strings.Fields("S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 1 0 99 0")
	fields[1], fields[19] = strconv.Itoa(parent), ticks
	return []byte(fmt.Sprintf("%d (shell (name) with ) spaces) %s\n", pid, strings.Join(fields, " ")))
}

func TestSmartTUNManagementProcessLifetimeParsing(t *testing.T) {
	process, err := parseManagementProcess(managementStatFixture(91, 80, "12345"), 91)
	if err != nil || process != (smartTUNManagementProcess{91, 80, 12345}) {
		t.Fatalf("valid kernel process lifetime rejected: %+v %v", process, err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		pid  int
	}{
		{"wrong-pid", managementStatFixture(91, 80, "12345"), 90},
		{"parent-cycle", managementStatFixture(91, 91, "12345"), 91},
		{"negative-parent", managementStatFixture(91, -1, "12345"), 91},
		{"zero-start", managementStatFixture(91, 80, "0"), 91},
		{"negative-start", managementStatFixture(91, 80, "-3"), 91},
		{"overflow", managementStatFixture(91, 80, "18446744073709551616"), 91},
		{"missing-fields", []byte("91 (sshd) S 80"), 91},
		{"missing-comm", []byte("91 S 80"), 91},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseManagementProcess(tc.raw, tc.pid); err == nil {
				t.Fatal("invalid process lifetime accepted")
			}
		})
	}
}

func TestSmartTUNManagementClockTicksFromKernelAuxv(t *testing.T) {
	for _, size := range []int{4, 8} {
		encode := func(pairs ...uint64) []byte {
			raw := make([]byte, len(pairs)*size)
			for i, n := range pairs {
				if size == 4 {
					binary.NativeEndian.PutUint32(raw[i*size:], uint32(n))
				} else {
					binary.NativeEndian.PutUint64(raw[i*size:], n)
				}
			}
			return raw
		}
		value, err := parseManagementClockTicks(encode(6, 4096, 17, 100, 0, 0), size)
		if err != nil || value != 100 {
			t.Fatalf("valid %d-bit auxv rejected: %d %v", size*8, value, err)
		}
		for _, raw := range [][]byte{
			encode(6, 4096, 0, 0), encode(17, 0, 0, 0),
			encode(17, 100, 17, 100, 0, 0), encode(17, 100),
			encode(17, 1000001, 0, 0), append(encode(17, 100, 0, 0), 1),
		} {
			if _, err := parseManagementClockTicks(raw, size); err == nil {
				t.Fatalf("invalid auxv accepted: %x", raw)
			}
		}
	}
	hz, err := managementClockTicks()
	if err != nil || hz == 0 {
		t.Fatalf("read-only live kernel auxv check: %v", err)
	}
	process, err := readManagementProcess(os.Getpid())
	now, clockErr := smartTUNUptimeMillis()
	if err != nil || clockErr != nil || int64(process.StartTicks*1000/hz) > now {
		t.Fatalf("process and boot-relative clocks disagree: %+v %d %v %v", process, now, err, clockErr)
	}
}

func managementSocketFixture() []byte {
	raw := make([]byte, 72)
	raw[0], raw[1] = 2, 1
	binary.BigEndian.PutUint16(raw[4:6], 19224)
	binary.BigEndian.PutUint16(raw[6:8], 49152)
	copy(raw[8:12], []byte{10, 254, 72, 1})
	copy(raw[24:28], []byte{10, 254, 72, 2})
	binary.NativeEndian.PutUint32(raw[44:48], 5)
	binary.NativeEndian.PutUint32(raw[48:52], 1)
	binary.NativeEndian.PutUint32(raw[68:72], 123)
	return raw
}

func TestSmartTUNManagementTransportRequiresKernelGeneration(t *testing.T) {
	socket, err := parseManagementSocket(managementSocketFixture())
	if err != nil || socket.Local.String() != "10.254.72.1" ||
		socket.Peer.String() != "10.254.72.2" || socket.LocalPort != 19224 ||
		socket.PeerPort != 49152 || socket.Cookie != 1<<32|5 || socket.Inode != 123 {
		t.Fatalf("valid kernel socket rejected: %+v %v", socket, err)
	}
	for _, name := range []string{"short", "ipv6", "listening", "noncanonical", "zero-inode", "zero-port", "zero-cookie", "no-cookie"} {
		t.Run(name, func(t *testing.T) {
			raw := managementSocketFixture()
			switch name {
			case "short":
				raw = raw[:71]
			case "ipv6":
				raw[0] = 10
			case "listening":
				raw[1] = 10
			case "noncanonical":
				raw[12] = 1
			case "zero-inode":
				binary.NativeEndian.PutUint32(raw[68:72], 0)
			case "zero-port":
				raw[4], raw[5] = 0, 0
			case "zero-cookie":
				for i := 44; i < 52; i++ {
					raw[i] = 0
				}
			case "no-cookie":
				for i := 44; i < 52; i++ {
					raw[i] = 255
				}
			}
			if _, err := parseManagementSocket(raw); err == nil {
				t.Fatal("unauthenticated or non-established transport accepted")
			}
		})
	}
}

func TestSmartTUNManagementRejectsOldMultiplexedTransport(t *testing.T) {
	socket, err := parseManagementSocket(managementSocketFixture())
	if err != nil {
		t.Fatal(err)
	}
	old := smartTUNManagementOwner{smartTUNManagementProcess{11, 1, 1000}, socket}
	newChannel := smartTUNManagementOwner{smartTUNManagementProcess{12, 11, 2100}, socket}
	if _, _, err := selectFreshManagementOwner([]smartTUNManagementOwner{newChannel, old}, 20000, 100); err == nil {
		t.Fatal("new channel on pre-Apply ControlMaster transport accepted")
	}
	fresh := smartTUNManagementOwner{smartTUNManagementProcess{21, 1, 2100}, socket}
	actual, ms, err := selectFreshManagementOwner([]smartTUNManagementOwner{fresh}, 20000, 100)
	if err != nil || actual != fresh || ms != 21000 {
		t.Fatalf("fresh transport rejected: %+v %d %v", actual, ms, err)
	}
	for _, bound := range []int64{21000, 21001} {
		if _, _, err := selectFreshManagementOwner([]smartTUNManagementOwner{fresh}, bound, 100); err == nil {
			t.Fatal("same-tick or older process accepted")
		}
	}
	replaced := fresh
	replaced.Socket.Cookie++
	if _, _, err := selectFreshManagementOwner([]smartTUNManagementOwner{fresh, replaced}, 20000, 100); err == nil {
		t.Fatal("different socket generations accepted as one authenticated transport")
	}
	for _, owners := range [][]smartTUNManagementOwner{
		nil, {{Process: smartTUNManagementProcess{21, 1, ^uint64(0)}, Socket: socket}},
	} {
		if _, _, err := selectFreshManagementOwner(owners, 20000, 100); err == nil {
			t.Fatal("missing or overflowed transport lifetime accepted")
		}
	}
}

func TestSmartTUNManagementEnvironmentIsNotConfirmation(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "10.254.72.2 49152 10.254.72.1 19224")
	t.Setenv("SSH_CLIENT", "10.254.72.2 49152 19224")
	if _, err := observeFreshSmartTUNManagement("10.254.72.2", "scqaedge0", 1); err == nil {
		t.Fatal("environment values without genuine fresh authenticated SSH accepted")
	}
}

// Ordinary ephemeral loopback sockets plus a read-only kernel dump verify the
// UAPI framing/cookie implementation without CAP_NET_ADMIN or host policy.
func TestSmartTUNManagementLiveReadOnlySocketIdentity(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	local := server.LocalAddr().(*net.TCPAddr)
	peer := server.RemoteAddr().(*net.TCPAddr)
	first, err := managementSockets()
	if err != nil {
		t.Fatal(err)
	}
	var expected smartTUNManagementSocket
	for _, s := range first {
		if s.Local == netip.MustParseAddr("127.0.0.1") && int(s.LocalPort) == local.Port &&
			int(s.PeerPort) == peer.Port {
			expected = s
		}
	}
	if expected.Inode == 0 || expected.Cookie == 0 {
		t.Fatal("established ephemeral connection not found in kernel diagnostics")
	}
	second, err := managementSockets()
	if err != nil || second[expected.Inode] != expected {
		t.Fatalf("stable live socket identity not reproduced: %v", err)
	}
}
