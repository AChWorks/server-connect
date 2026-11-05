//go:build linux

package sc

// The ingress barrier is separate from SSH authentication. It observes kernel
// socket marks and generations, never grants a tuple/port Direct exemption.
// Reference: Linux UAPI inet_diag.h and tcp_fwmark_accept in ip-sysctl.rst.

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
	"time"
)

const ingressTCPStates uint32 = hostReplyTCPStates | (1 << 10) // include listeners
const ingressSocketLimit = 8192

type hostIngressSocket struct {
	Family              byte
	State               byte
	Local, Peer         netip.Addr
	LocalPort, PeerPort uint16
	Interface           uint32
	Inode               uint32
	Cookie              uint64
	Mark                uint32
}

func ingressFault(message string) error {
	return Fault("host_ingress_unverified", message)
}

// Unlike managementSocket, this accepts a listener's zero peer port, but
// never an embryonic/TIME_WAIT record without a full generation. Such a
// record is an admission refusal, not evidence that the backlog is empty.
func parseHostIngressSocket(data []byte, family byte) (hostIngressSocket, error) {
	var s hostIngressSocket
	if len(data) < 72 || (family != syscall.AF_INET && family != syscall.AF_INET6) ||
		data[0] != family || data[1] >= 32 || ingressTCPStates&(1<<data[1]) == 0 {
		return s, ingressFault("kernel ingress socket family or state invalid")
	}
	s.Family, s.State = family, data[1]
	s.LocalPort, s.PeerPort = binary.BigEndian.Uint16(data[4:6]), binary.BigEndian.Uint16(data[6:8])
	if family == syscall.AF_INET {
		for _, b := range append(append([]byte{}, data[12:24]...), data[28:40]...) {
			if b != 0 {
				return s, ingressFault("noncanonical ingress IPv4 socket")
			}
		}
		s.Local, s.Peer = netip.AddrFrom4([4]byte(data[8:12])), netip.AddrFrom4([4]byte(data[24:28]))
	} else {
		s.Local, s.Peer = netip.AddrFrom16([16]byte(data[8:24])), netip.AddrFrom16([16]byte(data[24:40]))
	}
	s.Interface = binary.NativeEndian.Uint32(data[40:44])
	s.Cookie = uint64(binary.NativeEndian.Uint32(data[44:48])) | uint64(binary.NativeEndian.Uint32(data[48:52]))<<32
	s.Inode = binary.NativeEndian.Uint32(data[68:72])
	if s.Inode == 0 || s.Cookie == 0 || s.Cookie == ^uint64(0) || s.LocalPort == 0 ||
		(s.State == 10 && s.PeerPort != 0) || (s.State != 10 && s.PeerPort == 0) {
		return s, ingressFault("ingress socket generation or peer identity unavailable")
	}
	markSeen := false
	for attrs := data[72:]; len(attrs) != 0; {
		if len(attrs) < 4 {
			return s, ingressFault("truncated ingress diagnostic attribute")
		}
		length, typ := int(binary.NativeEndian.Uint16(attrs[:2])), binary.NativeEndian.Uint16(attrs[2:4])
		aligned := (length + 3) &^ 3
		if length < 4 || aligned > len(attrs) {
			return s, ingressFault("invalid ingress diagnostic attribute length")
		}
		if typ&0x3fff == 15 { // INET_DIAG_MARK; no nested/network-byte-order flags
			if typ != 15 || length != 8 || markSeen {
				return s, ingressFault("ambiguous ingress socket mark")
			}
			s.Mark, markSeen = binary.NativeEndian.Uint32(attrs[4:8]), true
		}
		attrs = attrs[aligned:]
	}
	if !markSeen {
		return s, ingressFault("kernel socket mark unavailable; CAP_NET_ADMIN is required")
	}
	return s, nil
}

// Dump both families, including IPv6 listeners which can accept IPv4-mapped
// peers. Filter only the already verified NOTRACK local service ports; the
// ports are NEVER returned as packet bypass rules.
func observeHostIngressSockets(ports map[uint16]bool) ([]hostIngressSocket, error) {
	if len(ports) == 0 || len(ports) > 128 {
		return nil, ingressFault("validated NOTRACK service ports required")
	}
	all := make([]hostIngressSocket, 0)
	for _, family := range []byte{syscall.AF_INET, syscall.AF_INET6} {
		rows, err := dumpHostIngressFamily(family, ports)
		if err != nil {
			return nil, err
		}
		all = append(all, rows...)
		if len(all) > ingressSocketLimit {
			return nil, ingressFault("ingress inventory exceeds safety bound")
		}
	}
	return all, nil
}

func dumpHostIngressFamily(family byte, ports map[uint16]bool) ([]hostIngressSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_INET_DIAG)
	if err != nil {
		return nil, ingressFault(fmt.Sprintf("open ingress diagnostics: %v", err))
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, ingressFault("bind ingress diagnostics failed")
	}
	address, err := syscall.Getsockname(fd)
	local, ok := address.(*syscall.SockaddrNetlink)
	if err != nil || !ok || local.Pid == 0 || local.Groups != 0 {
		return nil, ingressFault("ingress diagnostic identity unavailable")
	}
	deadline := time.Now().Add(2 * time.Second)
	request := make([]byte, 72)
	binary.NativeEndian.PutUint32(request[:4], 72)
	binary.NativeEndian.PutUint16(request[4:6], 20)
	binary.NativeEndian.PutUint16(request[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	binary.NativeEndian.PutUint32(request[12:16], local.Pid)
	request[16], request[17] = family, syscall.IPPROTO_TCP
	binary.NativeEndian.PutUint32(request[20:24], ingressTCPStates)
	binary.NativeEndian.PutUint32(request[64:68], ^uint32(0))
	binary.NativeEndian.PutUint32(request[68:72], ^uint32(0))
	timeout := syscall.NsecToTimeval(int64(2 * time.Second))
	if syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &timeout) != nil ||
		syscall.Sendto(fd, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}) != nil {
		return nil, ingressFault("ingress diagnostic request failed")
	}
	result := make([]hostIngressSocket, 0)
	seen := map[uint64]bool{}
	buffer := make([]byte, 65536)
	for count := 0; count < 256; count++ {
		left := time.Until(deadline)
		if left <= 0 {
			return nil, ingressFault("ingress diagnostic deadline exceeded")
		}
		timeout = syscall.NsecToTimeval(int64(left))
		if syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout) != nil {
			return nil, ingressFault("ingress diagnostic timeout unavailable")
		}
		n, oobn, flags, source, err := syscall.Recvmsg(fd, buffer, nil, 0)
		peer, valid := source.(*syscall.SockaddrNetlink)
		if err != nil || !valid || peer.Pid != 0 || peer.Groups != 0 || oobn != 0 || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
			return nil, ingressFault("ingress dump incomplete or not kernel unicast")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil || len(messages) == 0 {
			return nil, ingressFault("malformed ingress netlink messages")
		}
		for i, msg := range messages {
			if msg.Header.Seq != 1 || msg.Header.Pid != local.Pid || msg.Header.Flags&0x10 != 0 {
				return nil, ingressFault("ingress dump identity changed or interrupted")
			}
			switch msg.Header.Type {
			case syscall.NLMSG_DONE:
				if i != len(messages)-1 || len(msg.Data) != 4 || binary.NativeEndian.Uint32(msg.Data) != 0 {
					return nil, ingressFault("invalid ingress dump completion")
				}
				return result, nil
			case 20:
				if len(msg.Data) < 72 || msg.Data[0] != family || msg.Data[1] >= 32 || ingressTCPStates&(1<<msg.Data[1]) == 0 {
					return nil, ingressFault("unrequested ingress socket family or state")
				}
				if !ports[binary.BigEndian.Uint16(msg.Data[4:6])] {
					continue
				}
				s, err := parseHostIngressSocket(msg.Data, family)
				if err != nil {
					return nil, err
				}
				if seen[s.Cookie] || len(result) >= ingressSocketLimit {
					return nil, ingressFault("duplicate or excessive ingress socket generations")
				}
				seen[s.Cookie] = true
				result = append(result, s)
			default:
				return nil, ingressFault("kernel ingress diagnostic returned an error")
			}
		}
	}
	return nil, ingressFault("ingress dump did not complete within bound")
}

// Stage/guard identity revalidation must surround this observation. A positive
// observation alone is not atomic: SYN-cookie completions have no dumped
// request socket. The actual ingress policy must mark final ACKs as well as
// SYNs and fail closed for unexpected marks at the final egress boundary.
func validateHostIngressDrain(sockets []hostIngressSocket) error {
	if sockets == nil {
		return ingressFault("ingress snapshot absent")
	}
	for _, s := range sockets {
		if s.Inode == 0 || s.Cookie == 0 || s.Cookie == ^uint64(0) ||
			(s.Family != syscall.AF_INET && s.Family != syscall.AF_INET6) || s.LocalPort == 0 {
			return ingressFault("ingress snapshot has no stable socket generation")
		}
		if s.State == 10 {
			if s.Mark != 0 {
				return Fault("host_ingress_listener_mark", "a foreign listener SO_MARK prevents safe accepted-socket inheritance")
			}
		} else if s.Mark&nativeTUNMarkMask != nativeTUNBypassMark {
			return Fault("host_ingress_drain_pending", "preexisting unmarked TCP generations or pending handshakes must drain before capture")
		}
	}
	return nil
}
