//go:build linux

package sc

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestHostReplyTCPStatesPreserveSSHIdentityBoundary(t *testing.T) {
	valid := managementSocketFixture()
	for _, state := range []byte{1, 2, 3, 4, 5, 6, 8, 9, 11, 12} {
		candidate := append([]byte(nil), valid...)
		candidate[1] = state
		sock, err := parseKernelTCPSocket(candidate, hostReplyTCPStates)
		if err != nil || sock.Inode != 123 {
			t.Fatalf("relevant reply state %d was silently omitted: %+v %v", state, sock, err)
		}
		if state != 1 {
			if _, err := parseManagementSocket(candidate); err == nil {
				t.Fatalf("SSH management unexpectedly accepted TCP state %d", state)
			}
		}
	}
	for _, state := range []byte{0, 7, 10, 13, 255} {
		candidate := append([]byte(nil), valid...)
		candidate[1] = state
		if _, err := parseKernelTCPSocket(candidate, hostReplyTCPStates); err == nil {
			t.Fatalf("unrequested TCP state %d was trusted", state)
		}
	}
	for _, state := range []byte{6, 8, 12} {
		candidate := append([]byte(nil), valid...)
		candidate[1] = state // TIME_WAIT, CLOSE_WAIT, embryonic SYN_RECV.
		binary.NativeEndian.PutUint32(candidate[68:72], 0)
		if _, err := parseKernelTCPSocket(candidate, hostReplyTCPStates); err == nil {
			t.Fatalf("reply state %d without a kernel socket generation was accepted", state)
		}
	}
	if _, err := hostReplySockets(nil); err == nil {
		t.Fatal("a host NOTRACK reply scan must be scoped to validated service ports")
	}
	if _, err := observedKernelTCPSockets(0, nil); err == nil {
		t.Fatal("empty kernel diagnostic state mask was accepted")
	}
	if _, err := observedKernelTCPSockets(1<<31, nil); err == nil {
		t.Fatal("unsupported kernel diagnostic state mask was accepted")
	}
}

// A peer may half-close its sending side before the server sends the final
// HTTP/SSH response. This uses real Linux TCP/inet_diag loopback sockets;
// unlike an artificial parser fixture, it proves CLOSE_WAIT can still emit
// new application data while remaining absent from ESTABLISHED-only SSH diag.
func TestHostReplyKernelHalfClosedSocketStillEmitsAndIsObserved(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientConn, err := net.DialTimeout("tcp4", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	client := clientConn.(*net.TCPConn)
	server := accepted.(*net.TCPConn)
	local := server.LocalAddr().(*net.TCPAddr)
	peer := server.RemoteAddr().(*net.TCPAddr)
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	byteBuf := make([]byte, 1)
	if _, err := server.Read(byteBuf); err != io.EOF {
		t.Fatalf("peer FIN did not reach accepted socket: %v", err)
	}
	match := func(s smartTUNManagementSocket) bool {
		return s.Local == netip.MustParseAddr("127.0.0.1") &&
			int(s.LocalPort) == local.Port && int(s.PeerPort) == peer.Port
	}
	// The production SSH dump intentionally fails closed on *any* unrelated
	// unidentifiable kernel socket. Test only this stable socket generation
	// to avoid ambient network-namespace churn becoming a false test failure.
	management, err := observedKernelTCPSockets(1<<1, map[uint16]bool{uint16(local.Port): true})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range management {
		if match(s) {
			t.Fatal("half-closed socket incorrectly considered ESTABLISHED SSH transport")
		}
	}
	replies, err := hostReplySockets(map[uint16]bool{uint16(local.Port): true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range replies {
		if match(s) {
			found = s.Inode != 0 && s.Cookie != 0 && s.Cookie != ^uint64(0)
		}
	}
	if !found {
		t.Fatal("CLOSE_WAIT reply socket omitted from the host diagnostic snapshot")
	}
	rawPolicy := []byte(fmt.Sprintf("-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n-A OUTPUT -p tcp -m tcp --sport %d -j NOTRACK\n", local.Port))
	status, err := classifiedExistingHostReplies(rawPolicy, replies, 1)
	if err != nil || status != hostRepliesPresent {
		t.Fatalf("real half-closed server misreported as no untracked replies: %s %v", status, err)
	}
	payload := []byte("reply-after-peer-FIN")
	if _, err := server.Write(payload); err != nil {
		t.Fatalf("CLOSE_WAIT socket cannot send final data: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(client, received); err != nil || string(received) != string(payload) {
		t.Fatalf("actual host reply after peer half-close failed: %q %v", received, err)
	}
}
