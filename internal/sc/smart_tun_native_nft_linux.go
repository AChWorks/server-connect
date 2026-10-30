package sc

// This deliberately small Linux nfnetlink client supports only GETGEN and
// generation-conditioned deletion of ONE inet table by its observed handle.
// The caller must prove the complete table graph belongs to its operation
// between two equal generations. A handle or generation alone is not ownership.
//
// Wire/commit reference: Linux v6.12 include/uapi/linux/netfilter/{nf_tables,
// nfnetlink}.h and net/netfilter/{nf_tables_api,nfnetlink}.c. In particular,
// nf_tables_valid_genid holds commit_mutex through commit/abort, zero disables
// the check, and nfnetlink_rcv_batch acknowledges BATCH_END only after commit.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"
)

const (
	nativeNFTSubsystem      = 10
	nativeNFTGetGen         = nativeNFTSubsystem<<8 | 16
	nativeNFTNewGen         = nativeNFTSubsystem<<8 | 15
	nativeNFTDelTable       = nativeNFTSubsystem<<8 | 2
	nativeNFTBatchBegin     = 0x10
	nativeNFTBatchEnd       = 0x11
	nativeNFTTableHandle    = 4
	nativeNFTBatchGenID     = 1
	nativeNFTGenID          = 1
	nativeNFTGenProcessID   = 2
	nativeNFTGenProcessName = 3
	nativeNFTInet           = 1
	nativeNFTRequestACK     = 0x01 | 0x04
	nativeNFTCapped         = 0x100
	nativeNFTNetByteOrder   = 0x4000
	nativeNFTWireLimit      = 4096
	nativeNFTDatagramLimit  = 16
	nativeNFTTimeout        = 3 * time.Second
)

var (
	// Only a verified BATCH_BEGIN -ERESTART response has this classification.
	// No mutation occurred; reobserve the entire ownership snapshot before retry.
	errNativeNFTGenerationChanged = errors.New("native nft generation changed")
	// After send was attempted, missing/malformed ACKs or transport failure
	// cannot establish whether the kernel committed. Never treat this as absent.
	errNativeNFTOutcomeUnknown = errors.New("native nft transaction outcome unknown")
)

type nativeNFTConnection interface {
	send([]byte) error
	receive() ([]byte, uint32, int, error)
}

type nativeNFTSocket struct {
	fd       int
	portID   uint32
	deadline time.Time
}

func openNativeNFTSocket() (*nativeNFTSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("open native nft socket: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = syscall.Close(fd)
		}
	}()
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("bind native nft socket: %w", err)
	}
	address, err := syscall.Getsockname(fd)
	if err != nil {
		return nil, fmt.Errorf("inspect native nft socket: %w", err)
	}
	local, valid := address.(*syscall.SockaddrNetlink)
	if !valid || local.Family != syscall.AF_NETLINK || local.Pid == 0 || local.Groups != 0 {
		return nil, errors.New("native nft socket identity invalid")
	}
	ok = true
	return &nativeNFTSocket{fd: fd, portID: local.Pid, deadline: time.Now().Add(nativeNFTTimeout)}, nil
}

func (s *nativeNFTSocket) timeout(option int) error {
	remaining := time.Until(s.deadline)
	if remaining <= 0 {
		return syscall.ETIMEDOUT
	}
	value := syscall.NsecToTimeval(remaining.Nanoseconds())
	return syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, option, &value)
}

func (s *nativeNFTSocket) send(data []byte) error {
	if err := s.timeout(syscall.SO_SNDTIMEO); err != nil {
		return err
	}
	// Do not retry send on EINTR: the outcome of the attempted transaction is
	// reconciled by observation, never by sending a second unchecked mutation.
	return syscall.Sendto(s.fd, data, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}

func (s *nativeNFTSocket) receive() ([]byte, uint32, int, error) {
	for {
		if err := s.timeout(syscall.SO_RCVTIMEO); err != nil {
			return nil, 0, 0, err
		}
		data := make([]byte, nativeNFTWireLimit)
		n, oobn, flags, address, err := syscall.Recvmsg(s.fd, data, nil, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return nil, 0, 0, err
		}
		peer, valid := address.(*syscall.SockaddrNetlink)
		if !valid || peer.Family != syscall.AF_NETLINK || peer.Pid != 0 || peer.Groups != 0 || oobn != 0 {
			return nil, 0, 0, errors.New("native nft response is not kernel unicast")
		}
		if n <= 0 || n > len(data) {
			return nil, 0, 0, errors.New("native nft response length invalid")
		}
		return data[:n], peer.Pid, flags, nil
	}
}

func nativeNFTMessageBytes(kind uint16, sequence, portID uint32, family byte, resource uint16, attributes []byte) []byte {
	data := make([]byte, 20+len(attributes))
	binary.NativeEndian.PutUint32(data[0:4], uint32(len(data)))
	binary.NativeEndian.PutUint16(data[4:6], kind)
	binary.NativeEndian.PutUint16(data[6:8], nativeNFTRequestACK)
	binary.NativeEndian.PutUint32(data[8:12], sequence)
	binary.NativeEndian.PutUint32(data[12:16], portID)
	data[16] = family // nfgenmsg.version is NFNETLINK_V0 (zero).
	binary.BigEndian.PutUint16(data[18:20], resource)
	copy(data[20:], attributes)
	return data
}

func nativeNFTAttribute(kind uint16, value []byte) []byte {
	length := 4 + len(value)
	data := make([]byte, (length+3)&^3)
	binary.NativeEndian.PutUint16(data[0:2], uint16(length))
	binary.NativeEndian.PutUint16(data[2:4], kind)
	copy(data[4:], value)
	return data
}

func nativeNFTDeleteRequests(portID uint32, handle uint64, generation uint32) ([3][]byte, error) {
	var requests [3][]byte
	if portID == 0 || handle == 0 || generation == 0 {
		return requests, errors.New("native nft delete requires nonzero port, table handle and generation")
	}
	gen := make([]byte, 4)
	binary.BigEndian.PutUint32(gen, generation)
	h := make([]byte, 8)
	binary.BigEndian.PutUint64(h, handle)
	requests[0] = nativeNFTMessageBytes(nativeNFTBatchBegin, 1, portID, 0, nativeNFTSubsystem, nativeNFTAttribute(nativeNFTBatchGenID, gen))
	requests[1] = nativeNFTMessageBytes(nativeNFTDelTable, 2, portID, nativeNFTInet, 0, nativeNFTAttribute(nativeNFTTableHandle, h))
	requests[2] = nativeNFTMessageBytes(nativeNFTBatchEnd, 3, portID, 0, nativeNFTSubsystem, nil)
	return requests, nil
}

type nativeNFTMessage struct {
	kind     uint16
	flags    uint16
	sequence uint32
	payload  []byte
}

func nativeNFTMessages(data []byte, sender, portID uint32, receiveFlags int) ([]nativeNFTMessage, error) {
	if sender != 0 || portID == 0 || receiveFlags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || len(data) == 0 || len(data) > nativeNFTWireLimit {
		return nil, errors.New("native nft response sender, truncation or size invalid")
	}
	var messages []nativeNFTMessage
	for len(data) != 0 {
		if len(data) < 16 {
			return nil, errors.New("native nft response header truncated")
		}
		length := binary.NativeEndian.Uint32(data[:4])
		if length < 16 || uint64(length) > uint64(len(data)) {
			return nil, errors.New("native nft response framing invalid")
		}
		aligned := (int(length) + 3) &^ 3
		if aligned > len(data) || binary.NativeEndian.Uint32(data[12:16]) != portID {
			return nil, errors.New("native nft response port or alignment invalid")
		}
		messages = append(messages, nativeNFTMessage{kind: binary.NativeEndian.Uint16(data[4:6]), flags: binary.NativeEndian.Uint16(data[6:8]), sequence: binary.NativeEndian.Uint32(data[8:12]), payload: data[16:length]})
		data = data[aligned:]
	}
	return messages, nil
}

func nativeNFTACK(message nativeNFTMessage, request []byte) (syscall.Errno, error) {
	if message.kind != syscall.NLMSG_ERROR || message.flags & ^uint16(nativeNFTCapped) != 0 ||
		message.sequence != binary.NativeEndian.Uint32(request[8:12]) || len(message.payload) < 20 ||
		!bytes.Equal(message.payload[4:20], request[:16]) {
		return 0, errors.New("native nft ACK identity or framing invalid")
	}
	code := int32(binary.NativeEndian.Uint32(message.payload[:4]))
	if code > 0 || code < -4095 {
		return 0, errors.New("native nft ACK error code invalid")
	}
	expected := 20
	if code != 0 && message.flags&nativeNFTCapped == 0 {
		expected = 4 + len(request)
		if len(message.payload) != expected || !bytes.Equal(message.payload[4:], request) {
			return 0, errors.New("native nft ACK request echo invalid")
		}
	}
	if len(message.payload) != expected {
		return 0, errors.New("native nft ACK trailing data unsupported")
	}
	return syscall.Errno(-code), nil
}

func nativeNFTGenerationPayload(message nativeNFTMessage) (uint32, error) {
	if message.kind != nativeNFTNewGen || message.flags != 0 || len(message.payload) < 4 || message.payload[0] != 0 || message.payload[1] != 0 {
		return 0, errors.New("native nft generation response invalid")
	}
	data := message.payload[4:]
	seen := map[uint16]bool{}
	var generation uint32
	for len(data) != 0 {
		if len(data) < 4 {
			return 0, errors.New("native nft generation attribute truncated")
		}
		length := int(binary.NativeEndian.Uint16(data[:2]))
		kind := binary.NativeEndian.Uint16(data[2:4])
		baseKind := kind & ^uint16(nativeNFTNetByteOrder)
		aligned := (length + 3) &^ 3
		if length < 4 || aligned > len(data) || seen[baseKind] {
			return 0, errors.New("native nft generation attribute invalid or duplicate")
		}
		seen[baseKind] = true
		value := data[4:length]
		switch baseKind {
		case nativeNFTGenID, nativeNFTGenProcessID:
			if len(value) != 4 {
				return 0, errors.New("native nft generation integer invalid")
			}
			if baseKind == nativeNFTGenID {
				generation = binary.BigEndian.Uint32(value)
			}
		case nativeNFTGenProcessName:
			if kind != nativeNFTGenProcessName || len(value) < 1 || len(value) > 16 || value[len(value)-1] != 0 || bytes.IndexByte(value[:len(value)-1], 0) >= 0 {
				return 0, errors.New("native nft generation process name invalid")
			}
		default:
			return 0, errors.New("native nft generation attribute unsupported")
		}
		data = data[aligned:]
	}
	if generation == 0 {
		return 0, errors.New("native nft generation missing or zero")
	}
	return generation, nil
}

func nativeNFTGenerationUsing(connection nativeNFTConnection, portID uint32) (uint32, error) {
	if portID == 0 {
		return 0, errors.New("native nft generation port invalid")
	}
	request := nativeNFTMessageBytes(nativeNFTGetGen, 1, portID, 0, 0, nil)
	if err := connection.send(request); err != nil {
		return 0, fmt.Errorf("send native nft generation request: %w", err)
	}
	var generation uint32
	acknowledged := false
	for attempt := 0; attempt < nativeNFTDatagramLimit; attempt++ {
		data, sender, flags, err := connection.receive()
		if err != nil {
			return 0, fmt.Errorf("receive native nft generation: %w", err)
		}
		messages, err := nativeNFTMessages(data, sender, portID, flags)
		if err != nil {
			return 0, err
		}
		for _, message := range messages {
			if message.sequence != 1 {
				return 0, errors.New("native nft generation sequence invalid")
			}
			if message.kind == nativeNFTNewGen {
				if generation != 0 {
					return 0, errors.New("native nft generation duplicated")
				}
				generation, err = nativeNFTGenerationPayload(message)
				if err != nil {
					return 0, err
				}
			} else {
				if acknowledged {
					return 0, errors.New("native nft generation ACK duplicated")
				}
				code, err := nativeNFTACK(message, request)
				if err != nil {
					return 0, err
				}
				if code != 0 {
					return 0, fmt.Errorf("native nft generation rejected: %w", code)
				}
				acknowledged = true
			}
		}
		if generation != 0 && acknowledged {
			return generation, nil
		}
	}
	return 0, errors.New("native nft generation reply limit exceeded")
}

func nativeNFTDeleteTableUsing(connection nativeNFTConnection, portID uint32, handle uint64, generation uint32) error {
	requests, err := nativeNFTDeleteRequests(portID, handle, generation)
	if err != nil {
		return err
	}
	unknown := func(err error) error { return fmt.Errorf("%w: %w", errNativeNFTOutcomeUnknown, err) }
	batch := append(append(append([]byte{}, requests[0]...), requests[1]...), requests[2]...)
	if err := connection.send(batch); err != nil {
		return unknown(err)
	}
	var acknowledged [3]bool
	for attempt := 0; attempt < nativeNFTDatagramLimit; attempt++ {
		data, sender, flags, err := connection.receive()
		if err != nil {
			return unknown(err)
		}
		messages, err := nativeNFTMessages(data, sender, portID, flags)
		if err != nil {
			return unknown(err)
		}
		var rejected syscall.Errno
		var rejectedSequence uint32
		for _, message := range messages {
			if message.sequence < 1 || message.sequence > 3 {
				return unknown(errors.New("native nft batch ACK sequence invalid"))
			}
			index := int(message.sequence - 1)
			code, err := nativeNFTACK(message, requests[index])
			if err != nil {
				return unknown(err)
			}
			if acknowledged[index] {
				return unknown(errors.New("native nft batch ACK duplicated or contradictory"))
			}
			if code != 0 {
				if rejected != 0 {
					return unknown(errors.New("native nft batch multiple error replies"))
				}
				rejected, rejectedSequence = code, message.sequence
			} else {
				acknowledged[index] = true
			}
		}
		if rejected != 0 {
			if acknowledged[2] {
				return unknown(errors.New("native nft batch both rejected and committed"))
			}
			if rejected == syscall.ERESTART && rejectedSequence == 1 {
				if acknowledged[0] || acknowledged[1] {
					return unknown(errors.New("native nft generation rejection follows success ACK"))
				}
				return fmt.Errorf("%w: %w", errNativeNFTGenerationChanged, rejected)
			}
			return fmt.Errorf("native nft batch rejected at sequence %d: %w", rejectedSequence, rejected)
		}
		// A successful individual operation is NOT a successful transaction.
		// END is emitted only after commit, and all three exact ACKs are required.
		if acknowledged[0] && acknowledged[1] && acknowledged[2] {
			return nil
		}
	}
	return unknown(errors.New("native nft batch reply limit exceeded"))
}

func nativeNFTGeneration() (uint32, error) {
	connection, err := openNativeNFTSocket()
	if err != nil {
		return 0, err
	}
	defer syscall.Close(connection.fd)
	return nativeNFTGenerationUsing(connection, connection.portID)
}

func nativeNFTDeleteTableCAS(handle uint64, generation uint32) error {
	if handle == 0 || generation == 0 {
		return errors.New("native nft delete handle and generation must be nonzero")
	}
	connection, err := openNativeNFTSocket()
	if err != nil {
		return err
	}
	defer syscall.Close(connection.fd)
	return nativeNFTDeleteTableUsing(connection, connection.portID, handle, generation)
}
