//go:build linux

package sc

// These are read-only absence/conflict observations, not activation tokens.
// The caller must first establish the owned ingress policy and a real network
// grace barrier. TCP_LISTEN processing bypasses the userspace socket backlog
// in Linux v6.1 tcp_v{4,6}_rcv. Request -> full socket replacement holds the
// same ehash bucket lock and retains its mark/cookie.
//
// A generic paginated inet_diag dump is NOT an absence proof under churn:
// deletions can shift the integer resume cursor. These queries filter unsafe
// marks IN KERNEL while that bucket is locked. A successful empty result emits
// no socket records, so no output-based pagination can omit an unsafe object.
// References: torvalds/linux v6.1 net/ipv4/{inet_diag,inet_hashtables}.c.
//
// Reserved marks remain a cooperative privileged-owner boundary. Hashed socket
// snapshots cannot reserve future SO_MARK writes or observe an as-yet-unhashed
// TCP/UDP socket that is connected later.

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	hostSocketBarrierLegacyTCP           = 18
	hostSocketBarrierByFamily            = 20
	hostSocketBarrierBytecodeAttr        = 1
	hostSocketBarrierMarkCond            = 10
	hostSocketBarrierJump                = 1
	hostSocketBarrierAllTCPStates uint32 = (1 << 13) - 2
	hostSocketBarrierReceiveBytes        = 65536
	hostSocketBarrierDatagrams           = 8
	hostSocketBarrierTimeout             = 4 * time.Second
	hostSocketBarrierPingBytes           = 32768
)

type hostSocketBarrierQuery struct {
	legacy          bool
	family          byte
	protocol        byte
	states          uint32
	port            uint16
	mark            uint32
	mask            uint32
	conflictCode    string
	conflictMessage string
}
type hostSocketBarrierConnection interface {
	send([]byte) error
	receive() ([]byte, uint32, int, error)
}
type hostSocketBarrierSocket struct {
	fd       int
	portID   uint32
	deadline time.Time
}

// Bytecode accepts only (mark & mask) != expected. The final JMP is required:
// inet_diag_bc_audit must reach precisely the end on the yes/linear walk.
func hostSocketBarrierNotMark(mark, mask uint32) ([]byte, error) {
	if mask == 0 || mark & ^mask != 0 {
		return nil, ingressFault("invalid socket mark filter")
	}
	code := make([]byte, 16)
	code[0], code[1] = hostSocketBarrierMarkCond, 12
	binary.NativeEndian.PutUint16(code[2:4], 16)
	binary.NativeEndian.PutUint32(code[4:8], mark)
	binary.NativeEndian.PutUint32(code[8:12], mask)
	code[12], code[13] = hostSocketBarrierJump, 4
	binary.NativeEndian.PutUint16(code[14:16], 8)
	return code, nil
}
func hostSocketBarrierRequest(q hostSocketBarrierQuery, portID uint32) ([]byte, error) {
	if portID == 0 || q.states == 0 ||
		(q.legacy && (q.family != syscall.AF_UNSPEC || q.protocol != syscall.IPPROTO_TCP)) ||
		(!q.legacy && ((q.family != syscall.AF_INET && q.family != syscall.AF_INET6) || (q.protocol != syscall.IPPROTO_UDP && q.protocol != syscall.IPPROTO_RAW))) {
		return nil, ingressFault("invalid socket diagnostic query identity")
	}
	code, err := hostSocketBarrierNotMark(q.mark, q.mask)
	if err != nil {
		return nil, err
	}
	size, kind := 72, uint16(hostSocketBarrierByFamily)
	if q.legacy {
		size, kind = 76, hostSocketBarrierLegacyTCP
	}
	request := make([]byte, size+4+len(code))
	binary.NativeEndian.PutUint32(request[:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], kind)
	binary.NativeEndian.PutUint16(request[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	binary.NativeEndian.PutUint32(request[12:16], portID)
	request[16] = q.family
	if q.legacy {
		// inet_diag_req: 4-byte prefix, 48-byte sockid, states, dbs.
		binary.BigEndian.PutUint16(request[20:22], q.port)
		binary.NativeEndian.PutUint32(request[60:64], ^uint32(0))
		binary.NativeEndian.PutUint32(request[64:68], ^uint32(0))
		binary.NativeEndian.PutUint32(request[68:72], q.states)
	} else {
		// inet_diag_req_v2: family/proto/ext/pad, states, 48-byte sockid.
		request[17] = q.protocol
		binary.NativeEndian.PutUint32(request[20:24], q.states)
		binary.BigEndian.PutUint16(request[24:26], q.port)
		binary.NativeEndian.PutUint32(request[64:68], ^uint32(0))
		binary.NativeEndian.PutUint32(request[68:72], ^uint32(0))
	}
	binary.NativeEndian.PutUint16(request[size:size+2], uint16(4+len(code)))
	binary.NativeEndian.PutUint16(request[size+2:size+4], hostSocketBarrierBytecodeAttr)
	copy(request[size+4:], code)
	return request, nil
}

func openHostSocketBarrierSocket(deadline time.Time) (*hostSocketBarrierSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_INET_DIAG)
	if err != nil {
		return nil, ingressFault(fmt.Sprintf("open filtered socket diagnostics: %v", err))
	}
	retained := false
	defer func() {
		if !retained {
			syscall.Close(fd)
		}
	}()
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, ingressFault("bind filtered socket diagnostics failed")
	}
	address, err := syscall.Getsockname(fd)
	local, ok := address.(*syscall.SockaddrNetlink)
	if err != nil || !ok || local.Pid == 0 || local.Groups != 0 {
		return nil, ingressFault("filtered socket diagnostic identity unavailable")
	}
	retained = true
	return &hostSocketBarrierSocket{fd: fd, portID: local.Pid, deadline: deadline}, nil
}
func (s *hostSocketBarrierSocket) timeout(option int) error {
	remaining := time.Until(s.deadline)
	if remaining <= 0 {
		return syscall.ETIMEDOUT
	}
	tv := syscall.NsecToTimeval(int64(remaining))
	return syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, option, &tv)
}
func (s *hostSocketBarrierSocket) send(data []byte) error {
	if err := s.timeout(syscall.SO_SNDTIMEO); err != nil {
		return err
	}
	return syscall.Sendto(s.fd, data, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}
func (s *hostSocketBarrierSocket) receive() ([]byte, uint32, int, error) {
	if err := s.timeout(syscall.SO_RCVTIMEO); err != nil {
		return nil, 0, 0, err
	}
	data := make([]byte, hostSocketBarrierReceiveBytes)
	n, oobn, flags, address, err := syscall.Recvmsg(s.fd, data, nil, 0)
	peer, ok := address.(*syscall.SockaddrNetlink)
	if err != nil {
		return nil, 0, 0, err
	}
	if !ok || peer.Family != syscall.AF_NETLINK || peer.Groups != 0 || oobn != 0 || n <= 0 || n > len(data) {
		return nil, 0, 0, ingressFault("invalid filtered socket response transport")
	}
	return data[:n], peer.Pid, flags, nil
}

// A returned matching object is a refusal even when inode/cookie is zero.
// Request/TIME_WAIT records intentionally lack a normal userspace inode;
// absence authority must never be inferred from inability to parse one.
func hostSocketBarrierMatchingRecord(raw []byte, q hostSocketBarrierQuery) error {
	if len(raw) < 72 || (raw[0] != syscall.AF_INET && raw[0] != syscall.AF_INET6) ||
		(!q.legacy && raw[0] != q.family) || raw[1] == 0 || raw[1] >= 32 || q.states&(1<<raw[1]) == 0 {
		return ingressFault("filtered socket response family or state is invalid")
	}
	if q.port != 0 && binary.BigEndian.Uint16(raw[4:6]) != q.port {
		return ingressFault("filtered socket response local port disagrees with query")
	}
	if raw[0] == syscall.AF_INET {
		for _, b := range append(append([]byte{}, raw[12:24]...), raw[28:40]...) {
			if b != 0 {
				return ingressFault("filtered socket response has noncanonical IPv4 addresses")
			}
		}
	}
	mark, seen := uint32(0), false
	for attrs := raw[72:]; len(attrs) != 0; {
		if len(attrs) < 4 {
			return ingressFault("truncated filtered socket attribute")
		}
		length, typ := int(binary.NativeEndian.Uint16(attrs[:2])), binary.NativeEndian.Uint16(attrs[2:4])
		aligned := (length + 3) &^ 3
		if length < 4 || aligned > len(attrs) {
			return ingressFault("invalid filtered socket attribute length")
		}
		if typ&0x3fff == 15 {
			if typ != 15 || length != 8 || seen {
				return ingressFault("ambiguous filtered socket mark")
			}
			mark, seen = binary.NativeEndian.Uint32(attrs[4:8]), true
		}
		attrs = attrs[aligned:]
	}
	if !seen {
		return ingressFault("filtered socket mark unavailable; CAP_NET_ADMIN is required")
	}
	if mark&q.mask == q.mark {
		return ingressFault("kernel returned a socket excluded by the requested mark filter")
	}
	return Fault(q.conflictCode, q.conflictMessage)
}

func parseHostSocketBarrierDatagram(data []byte, sender, portID uint32, flags int, q hostSocketBarrierQuery) (bool, error) {
	if sender != 0 || portID == 0 || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || len(data) == 0 || len(data) > hostSocketBarrierReceiveBytes {
		return false, ingressFault("filtered socket response is truncated or not kernel unicast")
	}
	wanted := uint16(hostSocketBarrierByFamily)
	if q.legacy {
		wanted = hostSocketBarrierLegacyTCP
	}
	for len(data) != 0 {
		if len(data) < 16 {
			return false, ingressFault("filtered socket netlink header truncated")
		}
		length := int(binary.NativeEndian.Uint32(data[:4]))
		aligned := (length + 3) &^ 3
		if length < 16 || aligned > len(data) {
			return false, ingressFault("filtered socket netlink framing invalid")
		}
		kind, messageFlags := binary.NativeEndian.Uint16(data[4:6]), binary.NativeEndian.Uint16(data[6:8])
		if binary.NativeEndian.Uint32(data[8:12]) != 1 || binary.NativeEndian.Uint32(data[12:16]) != portID ||
			messageFlags&0x10 != 0 || messageFlags & ^uint16(syscall.NLM_F_MULTI|0x20) != 0 {
			return false, ingressFault("filtered socket dump identity changed or dump was interrupted")
		}
		payload := data[16:length]
		switch kind {
		case syscall.NLMSG_DONE:
			if len(data) != aligned || len(payload) != 4 || binary.NativeEndian.Uint32(payload) != 0 {
				return false, ingressFault("filtered socket dump completion invalid")
			}
			return true, nil
		case syscall.NLMSG_ERROR:
			if len(payload) < 4 {
				return false, ingressFault("filtered socket diagnostic error malformed")
			}
			code := int32(binary.NativeEndian.Uint32(payload[:4]))
			if code >= 0 || code < -4095 {
				return false, ingressFault("unexpected filtered socket diagnostic acknowledgement")
			}
			return false, ingressFault(fmt.Sprintf("filtered socket diagnostics unavailable: %s", syscall.Errno(-code)))
		default:
			if kind != wanted || messageFlags&syscall.NLM_F_MULTI == 0 {
				return false, ingressFault("unexpected filtered socket diagnostic message")
			}
			return false, hostSocketBarrierMatchingRecord(payload, q)
		}
	}
	return false, nil
}
func hostSocketBarrierCheckUsing(q hostSocketBarrierQuery, portID uint32, connection hostSocketBarrierConnection) error {
	request, err := hostSocketBarrierRequest(q, portID)
	if err != nil {
		return err
	}
	if connection == nil {
		return ingressFault("filtered socket transport unavailable")
	}
	if err := connection.send(request); err != nil {
		return ingressFault("filtered socket diagnostic request failed")
	}
	for i := 0; i < hostSocketBarrierDatagrams; i++ {
		data, sender, flags, err := connection.receive()
		if err != nil {
			return ingressFault("filtered socket diagnostic receive failed")
		}
		done, err := parseHostSocketBarrierDatagram(data, sender, portID, flags, q)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return ingressFault("filtered socket diagnostic completion missing")
}
func hostSocketBarrierCheck(q hostSocketBarrierQuery, deadline time.Time) error {
	socket, err := openHostSocketBarrierSocket(deadline)
	if err != nil {
		return err
	}
	defer syscall.Close(socket.fd)
	return hostSocketBarrierCheckUsing(q, socket.portID, socket)
}
func hostSocketBarrierPorts(ports map[uint16]bool) ([]uint16, error) {
	if len(ports) == 0 || len(ports) > 128 {
		return nil, ingressFault("verified nonempty NOTRACK ports required for socket barrier")
	}
	result := make([]uint16, 0, len(ports))
	for port, enabled := range ports {
		if port == 0 || !enabled {
			return nil, ingressFault("invalid NOTRACK port selection")
		}
		result = append(result, port)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func observeUnmarkedHostIngress(ports map[uint16]bool) error {
	ordered, err := hostSocketBarrierPorts(ports)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(hostSocketBarrierTimeout)
	for _, port := range ordered {
		q := hostSocketBarrierQuery{legacy: true, protocol: syscall.IPPROTO_TCP, states: hostReplyTCPStates,
			port: port, mark: nativeTUNBypassMark, mask: nativeTUNMarkMask,
			conflictCode:    "host_ingress_drain_pending",
			conflictMessage: "unmarked TCP generations or pending handshakes must drain before capture"}
		if err := hostSocketBarrierCheck(q, deadline); err != nil {
			return err
		}
	}
	return nil
}
func observeForeignMarkedListeners(ports map[uint16]bool) error {
	ordered, err := hostSocketBarrierPorts(ports)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(hostSocketBarrierTimeout)
	for _, port := range ordered {
		q := hostSocketBarrierQuery{legacy: true, protocol: syscall.IPPROTO_TCP, states: 1 << 10,
			port: port, mask: ^uint32(0), conflictCode: "host_ingress_listener_mark",
			conflictMessage: "a foreign listener SO_MARK prevents safe accepted-socket inheritance"}
		if err := hostSocketBarrierCheck(q, deadline); err != nil {
			return err
		}
	}
	return nil
}

// Inspect all currently hashed TCP, UDP and raw sockets. Unknown/unsupported
// diagnostic families are refusal, never inferred empty. Ping datagram sockets
// have a different hash and no equivalent mark-aware observer here, so any
// active ping socket is conservatively unsupported.
func observeReservedHostSocketMarks() error {
	deadline := time.Now().Add(hostSocketBarrierTimeout)
	base := hostSocketBarrierQuery{legacy: true, protocol: syscall.IPPROTO_TCP, states: hostSocketBarrierAllTCPStates,
		mask: nativeTUNMarkMask, conflictCode: "host_socket_mark_conflict",
		conflictMessage: "a preexisting hashed socket uses the reserved routing mark field"}
	if err := hostSocketBarrierCheck(base, deadline); err != nil {
		return err
	}
	for _, protocol := range []byte{syscall.IPPROTO_UDP, syscall.IPPROTO_RAW} {
		for _, family := range []byte{syscall.AF_INET, syscall.AF_INET6} {
			q := base
			q.legacy = false
			q.family = family
			q.protocol = protocol
			q.states = ^uint32(0)
			if err := hostSocketBarrierCheck(q, deadline); err != nil {
				return err
			}
		}
	}
	for _, path := range []string{"/proc/net/icmp", "/proc/net/icmp6"} {
		raw, err := readManagementProc(path, hostSocketBarrierPingBytes)
		if err != nil {
			return ingressFault("ping socket inventory unavailable")
		}
		if err := hostSocketBarrierEmptyPing(raw); err != nil {
			return err
		}
	}
	return nil
}
func hostSocketBarrierEmptyPing(raw []byte) error {
	if len(raw) == 0 || len(raw) > hostSocketBarrierPingBytes || strings.IndexByte(string(raw), 0) >= 0 {
		return ingressFault("ping socket inventory malformed or oversized")
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	expected := []string{"sl", "local_address", "rem_address", "st", "tx_queue", "rx_queue", "tr", "tm->when", "retrnsmt", "uid", "timeout", "inode"}
	header := strings.Fields(lines[0])
	// Linux kernels differ in /proc/net/icmp{,6} tail columns. Debian 13
	// Linux 6.12 exposes ref/pointer/drops while older kernels omit them.
	// Accept only these two exact layouts: unexpected columns remain refusal,
	// and any nonempty socket row still blocks the reserved-mark claim.
	if len(header) != len(expected) && len(header) != len(expected)+3 {
		return ingressFault("ping socket inventory header unsupported")
	}
	for i, field := range header[:len(expected)] {
		if i == 2 && (field == "rem_address" || field == "remote_address") {
			continue // icmp6 uses remote_address in Linux 6.12
		}
		if field != expected[i] {
			return ingressFault("ping socket inventory header unsupported")
		}
	}
	if len(header) == len(expected)+3 {
		for i, value := range []string{"ref", "pointer", "drops"} {
			if header[len(expected)+i] != value {
				return ingressFault("ping socket inventory header unsupported")
			}
		}
	}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) != "" {
			return Fault("host_socket_mark_unverified", "active ping datagram sockets cannot be checked for reserved SO_MARK")
		}
	}
	return nil
}
