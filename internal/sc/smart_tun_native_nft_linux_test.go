package sc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"syscall"
	"testing"
)

type testNFTDatagram struct {
	data   []byte
	sender uint32
	flags  int
	err    error
}

type testNFTConnection struct {
	sent    [][]byte
	sendErr error
	replies []testNFTDatagram
}

func (c *testNFTConnection) send(data []byte) error {
	c.sent = append(c.sent, append([]byte(nil), data...))
	return c.sendErr
}

func (c *testNFTConnection) receive() ([]byte, uint32, int, error) {
	if len(c.replies) == 0 {
		return nil, 0, 0, io.EOF
	}
	r := c.replies[0]
	c.replies = c.replies[1:]
	return r.data, r.sender, r.flags, r.err
}

func testNFTReply(kind, flags uint16, sequence, portID uint32, payload []byte) []byte {
	data := make([]byte, (16+len(payload)+3)&^3)
	binary.NativeEndian.PutUint32(data[:4], uint32(16+len(payload)))
	binary.NativeEndian.PutUint16(data[4:6], kind)
	binary.NativeEndian.PutUint16(data[6:8], flags)
	binary.NativeEndian.PutUint32(data[8:12], sequence)
	binary.NativeEndian.PutUint32(data[12:16], portID)
	copy(data[16:], payload)
	return data
}

func testNFTACK(request []byte, code syscall.Errno, capped bool) []byte {
	payload := make([]byte, 4)
	binary.NativeEndian.PutUint32(payload, uint32(-int32(code)))
	flags := uint16(0)
	if code == 0 || capped {
		flags = nativeNFTCapped
		payload = append(payload, request[:16]...)
	} else {
		payload = append(payload, request...)
	}
	return testNFTReply(syscall.NLMSG_ERROR, flags, binary.NativeEndian.Uint32(request[8:12]), binary.NativeEndian.Uint32(request[12:16]), payload)
}

func testNFTGenerationReply(portID, generation uint32) []byte {
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, generation)
	payload := append([]byte{0, 0, 0, 1}, nativeNFTAttribute(1, value)...)
	return testNFTReply(0x0a0f, 0, 1, portID, payload)
}

func TestSmartTUNNativeNFTWire(t *testing.T) {
	requests, err := nativeNFTDeleteRequests(0x10203040, 0x0102030405060708, 0xa1b2c3d4)
	if err != nil {
		t.Fatal(err)
	}
	for i, expected := range []struct {
		length  uint32
		kind    uint16
		payload []byte
	}{
		{28, 0x10, []byte{0, 0, 0, 10}},
		{32, 0x0a02, []byte{1, 0, 0, 0}},
		{20, 0x11, []byte{0, 0, 0, 10}},
	} {
		request := requests[i]
		if uint32(len(request)) != expected.length || binary.NativeEndian.Uint32(request[:4]) != expected.length ||
			binary.NativeEndian.Uint16(request[4:6]) != expected.kind || binary.NativeEndian.Uint16(request[6:8]) != 5 ||
			binary.NativeEndian.Uint32(request[8:12]) != uint32(i+1) || binary.NativeEndian.Uint32(request[12:16]) != 0x10203040 ||
			!bytes.Equal(request[16:20], expected.payload) {
			t.Fatalf("unexpected request %d framing: %x", i, request)
		}
	}
	if binary.NativeEndian.Uint16(requests[0][20:22]) != 8 || binary.NativeEndian.Uint16(requests[0][22:24]) != 1 ||
		!bytes.Equal(requests[0][24:], []byte{0xa1, 0xb2, 0xc3, 0xd4}) ||
		binary.NativeEndian.Uint16(requests[1][20:22]) != 12 || binary.NativeEndian.Uint16(requests[1][22:24]) != 4 ||
		!bytes.Equal(requests[1][24:], []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatal("generation/handle must use the exact UAPI attributes and network byte order")
	}
	for _, args := range []struct {
		port   uint32
		handle uint64
		gen    uint32
	}{{0, 1, 1}, {1, 0, 1}, {1, 1, 0}} {
		connection := &testNFTConnection{}
		if err := nativeNFTDeleteTableUsing(connection, args.port, args.handle, args.gen); err == nil || len(connection.sent) != 0 || errors.Is(err, errNativeNFTOutcomeUnknown) {
			t.Fatalf("invalid selector reached send or claimed an unknown mutation: %+v %v", args, err)
		}
	}
}

func TestSmartTUNNativeNFTCommitReceipt(t *testing.T) {
	const port = 12345
	requests, _ := nativeNFTDeleteRequests(port, 19, 42)
	ack := func(i int) []byte { return testNFTACK(requests[i], 0, true) }
	all := append(append(ack(0), ack(1)...), ack(2)...)
	for _, tc := range []struct {
		name    string
		replies []testNFTDatagram
		sendErr error
		want    error
	}{
		{"complete_combined", []testNFTDatagram{{data: all}}, nil, nil},
		{"complete_separate", []testNFTDatagram{{data: ack(0)}, {data: ack(1)}, {data: ack(2)}}, nil, nil},
		{"first_success_only", []testNFTDatagram{{data: ack(0)}}, nil, errNativeNFTOutcomeUnknown},
		{"operation_success_without_commit", []testNFTDatagram{{data: ack(0)}, {data: ack(1)}}, nil, errNativeNFTOutcomeUnknown},
		{"end_without_other_receipts", []testNFTDatagram{{data: ack(2)}}, nil, errNativeNFTOutcomeUnknown},
		{"send_interrupted", nil, syscall.EINTR, errNativeNFTOutcomeUnknown},
		{"ACK_lost", []testNFTDatagram{{err: syscall.ETIMEDOUT}}, nil, errNativeNFTOutcomeUnknown},
		{"receive_overflow", []testNFTDatagram{{err: syscall.ENOBUFS}}, nil, errNativeNFTOutcomeUnknown},
		{"truncated", []testNFTDatagram{{data: all, flags: syscall.MSG_TRUNC}}, nil, errNativeNFTOutcomeUnknown},
		{"foreign_sender", []testNFTDatagram{{data: all, sender: 44}}, nil, errNativeNFTOutcomeUnknown},
		{"stale_generation", []testNFTDatagram{{data: testNFTACK(requests[0], syscall.ERESTART, true)}}, nil, errNativeNFTGenerationChanged},
		{"missing_handle", []testNFTDatagram{{data: testNFTACK(requests[1], syscall.ENOENT, false)}}, nil, syscall.ENOENT},
		{"commit_error_after_operation_ACK", []testNFTDatagram{{data: ack(1)}, {data: testNFTACK(requests[0], syscall.EINVAL, true)}}, nil, syscall.EINVAL},
		{"success_and_failure_contradiction", []testNFTDatagram{{data: append(ack(2), testNFTACK(requests[0], syscall.EINVAL, true)...)}}, nil, errNativeNFTOutcomeUnknown},
		{"duplicate_ACK", []testNFTDatagram{{data: append(ack(0), ack(0)...)}}, nil, errNativeNFTOutcomeUnknown},
		{"short_header", []testNFTDatagram{{data: []byte{1, 2, 3}}}, nil, errNativeNFTOutcomeUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connection := &testNFTConnection{replies: tc.replies, sendErr: tc.sendErr}
			err := nativeNFTDeleteTableUsing(connection, port, 19, 42)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("outcome classification: got %v want %v", err, tc.want)
			}
			if len(connection.sent) != 1 {
				t.Fatalf("must never resend a transaction after ambiguous send/ACK: %d", len(connection.sent))
			}
			if tc.want == errNativeNFTGenerationChanged || tc.want == syscall.ENOENT || tc.want == syscall.EINVAL {
				if errors.Is(err, errNativeNFTOutcomeUnknown) {
					t.Fatal("verified rejection classified as unknown commit")
				}
			}
		})
	}
}

func TestSmartTUNNativeNFTRejectsMismatchedACK(t *testing.T) {
	requests, _ := nativeNFTDeleteRequests(321, 12, 9)
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"wrong_port", func(b []byte) []byte { binary.NativeEndian.PutUint32(b[12:16], 999); return b }},
		{"wrong_sequence", func(b []byte) []byte { binary.NativeEndian.PutUint32(b[8:12], 99); return b }},
		{"wrong_request_type", func(b []byte) []byte { binary.NativeEndian.PutUint16(b[24:26], 0x0a06); return b }},
		{"wrong_echo_pid", func(b []byte) []byte { binary.NativeEndian.PutUint32(b[32:36], 999); return b }},
		{"positive_errno", func(b []byte) []byte { binary.NativeEndian.PutUint32(b[16:20], 1); return b }},
		{"unsupported_EXTACK", func(b []byte) []byte { binary.NativeEndian.PutUint16(b[6:8], 0x200); return b }},
		{"trailing_partial_message", func(b []byte) []byte { return append(b, 1) }},
		{"truncated_embedded_header", func(b []byte) []byte { b = b[:32]; binary.NativeEndian.PutUint32(b[:4], 32); return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connection := &testNFTConnection{replies: []testNFTDatagram{{data: tc.mutate(testNFTACK(requests[0], 0, true))}}}
			if err := nativeNFTDeleteTableUsing(connection, 321, 12, 9); !errors.Is(err, errNativeNFTOutcomeUnknown) {
				t.Fatalf("malformed or unrelated receipt accepted: %v", err)
			}
		})
	}
}

func TestSmartTUNNativeNFTGeneration(t *testing.T) {
	const port = 444
	request := nativeNFTMessageBytes(nativeNFTGetGen, 1, port, 0, 0, nil)
	good := testNFTGenerationReply(port, 0x10002)
	for _, tc := range []struct {
		name    string
		replies []testNFTDatagram
		want    bool
	}{
		{"full_u32", []testNFTDatagram{{data: good}, {data: testNFTACK(request, 0, true)}}, true},
		{"ACK_then_data", []testNFTDatagram{{data: testNFTACK(request, 0, true)}, {data: good}}, true},
		{"data_without_ACK", []testNFTDatagram{{data: good}}, false},
		{"ACK_without_data", []testNFTDatagram{{data: testNFTACK(request, 0, true)}}, false},
		{"zero_generation", []testNFTDatagram{{data: testNFTGenerationReply(port, 0)}}, false},
		{"duplicate_data", []testNFTDatagram{{data: append(append([]byte{}, good...), good...)}}, false},
		{"kernel_rejected", []testNFTDatagram{{data: testNFTACK(request, syscall.EPERM, false)}}, false},
		{"non_kernel_sender", []testNFTDatagram{{data: good, sender: 12}}, false},
		{"overflow", []testNFTDatagram{{err: syscall.ENOBUFS}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			generation, err := nativeNFTGenerationUsing(&testNFTConnection{replies: tc.replies}, port)
			if tc.want && (err != nil || generation != 0x10002) || !tc.want && (err == nil || generation != 0) {
				t.Fatalf("generation proof: value=%d err=%v", generation, err)
			}
		})
	}
	for _, payload := range [][]byte{
		{0, 0, 0, 0},
		append([]byte{0, 0, 0, 0}, nativeNFTAttribute(1, []byte{0, 0, 1})...),
		append(append([]byte{0, 0, 0, 0}, nativeNFTAttribute(1, []byte{0, 0, 0, 1})...), nativeNFTAttribute(1, []byte{0, 0, 0, 2})...),
		append([]byte{0, 0, 0, 0}, nativeNFTAttribute(99, []byte{0, 0, 0, 1})...),
	} {
		if value, err := nativeNFTGenerationPayload(nativeNFTMessage{kind: nativeNFTNewGen, payload: payload}); err == nil || value != 0 {
			t.Fatalf("unsupported generation attributes accepted: %x %d %v", payload, value, err)
		}
	}
}
