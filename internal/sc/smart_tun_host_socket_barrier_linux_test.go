//go:build linux

package sc

import (
	"encoding/binary"
	"errors"
	"syscall"
	"testing"
)

func barrierQuery() hostSocketBarrierQuery {
	return hostSocketBarrierQuery{legacy: true, protocol: syscall.IPPROTO_TCP, states: hostReplyTCPStates, port: 28993,
		mark: nativeTUNBypassMark, mask: nativeTUNMarkMask, conflictCode: "host_ingress_drain_pending", conflictMessage: "unsafe socket exists"}
}
func barrierMessage(kind, flags uint16, portID uint32, payload []byte) []byte {
	n := 16 + len(payload)
	data := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint32(data[:4], uint32(n))
	binary.NativeEndian.PutUint16(data[4:6], kind)
	binary.NativeEndian.PutUint16(data[6:8], flags)
	binary.NativeEndian.PutUint32(data[8:12], 1)
	binary.NativeEndian.PutUint32(data[12:16], portID)
	copy(data[16:], payload)
	return data
}
func barrierDone(portID uint32) []byte {
	return barrierMessage(syscall.NLMSG_DONE, syscall.NLM_F_MULTI, portID, make([]byte, 4))
}
func barrierRecord(family, state byte, mark uint32) []byte {
	data := make([]byte, 80)
	data[0], data[1] = family, state
	binary.BigEndian.PutUint16(data[4:6], 28993)
	if family == syscall.AF_INET {
		data[8], data[11], data[24], data[27] = 127, 1, 127, 1
	} else {
		data[23], data[39] = 1, 1
	}
	binary.NativeEndian.PutUint16(data[72:74], 8)
	binary.NativeEndian.PutUint16(data[74:76], 15)
	binary.NativeEndian.PutUint32(data[76:80], mark)
	return data
}
func TestHostSocketBarrierWireUsesCombinedLegacyFamilyAndKernelMarkPredicate(t *testing.T) {
	q := barrierQuery()
	request, err := hostSocketBarrierRequest(q, 444)
	if err != nil {
		t.Fatal(err)
	}
	if len(request) != 96 || binary.NativeEndian.Uint16(request[4:6]) != 18 ||
		request[16] != syscall.AF_UNSPEC || binary.BigEndian.Uint16(request[20:22]) != q.port ||
		binary.NativeEndian.Uint32(request[68:72]) != q.states || binary.NativeEndian.Uint32(request[60:64]) != ^uint32(0) ||
		binary.NativeEndian.Uint16(request[76:78]) != 20 || binary.NativeEndian.Uint16(request[78:80]) != 1 {
		t.Fatalf("wrong legacy request: %x", request)
	}
	want := []byte{10, 12, 16, 0, 0, 0, 84, 0, 0, 0, 255, 0, 1, 4, 8, 0}
	// Arguments follow native endian; header bytes are endian-independent on
	// supported amd64, so compare words separately for the request contract.
	if request[80] != want[0] || request[81] != want[1] ||
		binary.NativeEndian.Uint16(request[82:84]) != 16 ||
		binary.NativeEndian.Uint32(request[84:88]) != nativeTUNBypassMark ||
		binary.NativeEndian.Uint32(request[88:92]) != nativeTUNMarkMask ||
		request[92] != 1 || request[93] != 4 || binary.NativeEndian.Uint16(request[94:96]) != 8 {
		t.Fatalf("wrong predicate: %x", request[80:])
	}
	// Interpret the two real UAPI instructions and prove both branch outcomes.
	filter := func(mark uint32) bool {
		code := request[80:]
		left := len(code)
		for left > 0 {
			yes := true
			switch code[0] {
			case 10:
				yes = mark&binary.NativeEndian.Uint32(code[8:12]) == binary.NativeEndian.Uint32(code[4:8])
			case 1:
				yes = false
			default:
				t.Fatal("unknown instruction")
			}
			skip := int(code[1])
			if !yes {
				skip = int(binary.NativeEndian.Uint16(code[2:4]))
			}
			left -= skip
			if left >= 0 {
				code = code[skip:]
			}
		}
		return left == 0
	}
	for _, mark := range []uint32{0, 1, nativeTUNCaptureMark, 0x00220000} {
		if !filter(mark) {
			t.Fatalf("unsafe mark %x omitted", mark)
		}
	}
	for _, mark := range []uint32{nativeTUNBypassMark, nativeTUNBypassMark | 7} {
		if filter(mark) {
			t.Fatalf("safe mark %x included", mark)
		}
	}
}
func TestHostSocketBarrierModernProtocolQueriesAreExplicit(t *testing.T) {
	for _, protocol := range []byte{syscall.IPPROTO_UDP, syscall.IPPROTO_RAW} {
		for _, family := range []byte{syscall.AF_INET, syscall.AF_INET6} {
			q := barrierQuery()
			q.legacy = false
			q.family = family
			q.protocol = protocol
			q.port = 0
			q.states = ^uint32(0)
			req, err := hostSocketBarrierRequest(q, 888)
			if err != nil || len(req) != 92 || binary.NativeEndian.Uint16(req[4:6]) != 20 || req[16] != family || req[17] != protocol ||
				binary.NativeEndian.Uint32(req[20:24]) != ^uint32(0) {
				t.Fatalf("wrong modern request: %x %v", req, err)
			}
		}
	}
	for _, change := range []func(*hostSocketBarrierQuery){
		func(q *hostSocketBarrierQuery) { q.family = syscall.AF_INET },
		func(q *hostSocketBarrierQuery) { q.protocol = syscall.IPPROTO_UDP },
		func(q *hostSocketBarrierQuery) { q.states = 0 },
		func(q *hostSocketBarrierQuery) { q.mask = 0 },
		func(q *hostSocketBarrierQuery) { q.mark = 1; q.mask = nativeTUNMarkMask },
		func(q *hostSocketBarrierQuery) {
			q.legacy = false
			q.family = syscall.AF_INET
			q.protocol = syscall.IPPROTO_TCP
		},
	} {
		q := barrierQuery()
		change(&q)
		if _, err := hostSocketBarrierRequest(q, 44); err == nil {
			t.Fatal("invalid typed request accepted")
		}
	}
	if _, err := hostSocketBarrierRequest(barrierQuery(), 0); err == nil {
		t.Fatal("zero port ID accepted")
	}
}
func TestHostSocketBarrierAnyReturnedUnmarkedGenerationBlocksEvenWithoutInode(t *testing.T) {
	q := barrierQuery()
	for _, family := range []byte{syscall.AF_INET, syscall.AF_INET6} {
		for _, state := range []byte{1, 2, 3, 4, 5, 6, 8, 9, 11, 12} {
			// Both inode and cookie deliberately remain zero. A request/TIME_WAIT
			// existence must never become absence merely because it lacks an inode.
			message := barrierMessage(18, syscall.NLM_F_MULTI, 444, barrierRecord(family, state, 0))
			done, err := parseHostSocketBarrierDatagram(message, 0, 444, 0, q)
			if done || ErrorCode(err) != "host_ingress_drain_pending" {
				t.Fatalf("family %d state %d treated as absence: %v %v", family, state, done, err)
			}
		}
	}
	record := barrierRecord(syscall.AF_INET, 1, nativeTUNBypassMark)
	_, err := parseHostSocketBarrierDatagram(barrierMessage(18, syscall.NLM_F_MULTI, 444, record), 0, 444, 0, q)
	if ErrorCode(err) != "host_ingress_unverified" {
		t.Fatal("kernel filter violation was trusted")
	}
}
func TestHostSocketBarrierRejectsMalformedWrongIdentityAndIncompleteCompletion(t *testing.T) {
	q := barrierQuery()
	valid := barrierDone(444)
	cases := map[string][]byte{"empty": nil, "short": []byte{1}, "trailing": append(append([]byte{}, valid...), 1)}
	change := func(name string, fn func([]byte)) { b := append([]byte{}, valid...); fn(b); cases[name] = b }
	change("wrong sequence", func(b []byte) { binary.NativeEndian.PutUint32(b[8:12], 2) })
	change("wrong port", func(b []byte) { binary.NativeEndian.PutUint32(b[12:16], 445) })
	change("interrupted", func(b []byte) { binary.NativeEndian.PutUint16(b[6:8], syscall.NLM_F_MULTI|0x10) })
	change("unknown flags", func(b []byte) { binary.NativeEndian.PutUint16(b[6:8], 0x4000) })
	change("bad length", func(b []byte) { binary.NativeEndian.PutUint32(b[:4], 15) })
	change("oversized length", func(b []byte) { binary.NativeEndian.PutUint32(b[:4], 90000) })
	change("completion error", func(b []byte) { binary.NativeEndian.PutUint32(b[16:20], 1) })
	change("unexpected kind", func(b []byte) { binary.NativeEndian.PutUint16(b[4:6], 99) })
	cases["done followed by another message"] = append(append([]byte{}, valid...), valid...)
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			done, err := parseHostSocketBarrierDatagram(b, 0, 444, 0, q)
			if done || err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
	for _, flags := range []int{syscall.MSG_TRUNC, syscall.MSG_CTRUNC} {
		if _, err := parseHostSocketBarrierDatagram(valid, 0, 444, flags, q); err == nil {
			t.Fatal("truncated response accepted")
		}
	}
	if _, err := parseHostSocketBarrierDatagram(valid, 99, 444, 0, q); err == nil {
		t.Fatal("foreign sender accepted")
	}
	if done, err := parseHostSocketBarrierDatagram(valid, 0, 444, 0, q); err != nil || !done {
		t.Fatalf("valid completion: %v %v", done, err)
	}
	for _, n := range []int{71, 72, 73, 75, 79} {
		record := barrierRecord(syscall.AF_INET, 1, 0)[:n]
		if err := hostSocketBarrierMatchingRecord(record, q); ErrorCode(err) != "host_ingress_unverified" {
			t.Fatalf("truncated record %d not refused: %v", n, err)
		}
	}
	record := barrierRecord(syscall.AF_INET, 1, 0)
	duplicate := append(append([]byte{}, record...), record[72:]...)
	if ErrorCode(hostSocketBarrierMatchingRecord(duplicate, q)) != "host_ingress_unverified" {
		t.Fatal("duplicate mark accepted")
	}
	binary.NativeEndian.PutUint16(record[74:76], 15|0x8000)
	if ErrorCode(hostSocketBarrierMatchingRecord(record, q)) != "host_ingress_unverified" {
		t.Fatal("nested mark accepted")
	}
}

type hostSocketBarrierFake struct {
	sent             []byte
	data             [][]byte
	sendErr, recvErr error
}

func (f *hostSocketBarrierFake) send(data []byte) error {
	f.sent = append([]byte{}, data...)
	return f.sendErr
}
func (f *hostSocketBarrierFake) receive() ([]byte, uint32, int, error) {
	if f.recvErr != nil {
		return nil, 0, 0, f.recvErr
	}
	if len(f.data) == 0 {
		return nil, 0, 0, errors.New("no completion")
	}
	data := f.data[0]
	f.data = f.data[1:]
	return data, 0, 0, nil
}
func TestHostSocketBarrierOnlyExplicitSuccessfulCompletionCanReturnNil(t *testing.T) {
	q := barrierQuery()
	success := &hostSocketBarrierFake{data: [][]byte{barrierDone(444)}}
	if err := hostSocketBarrierCheckUsing(q, 444, success); err != nil {
		t.Fatal(err)
	}
	if len(success.sent) != 96 {
		t.Fatal("query was not sent")
	}
	for _, f := range []*hostSocketBarrierFake{
		{sendErr: syscall.EPERM}, {recvErr: syscall.EIO}, {},
		{data: [][]byte{barrierMessage(18, syscall.NLM_F_MULTI, 444, barrierRecord(syscall.AF_INET, 12, 0))}},
	} {
		if err := hostSocketBarrierCheckUsing(q, 444, f); err == nil {
			t.Fatal("uncertain/nonempty observation accepted")
		}
	}
	if err := hostSocketBarrierCheckUsing(q, 444, nil); err == nil {
		t.Fatal("missing transport accepted")
	}
}
func TestHostSocketBarrierPingAndPortInventoriesFailClosed(t *testing.T) {
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	if err := hostSocketBarrierEmptyPing([]byte(header)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "unexpected header\n", header + " 0: active socket\n", header + "\x00"} {
		if err := hostSocketBarrierEmptyPing([]byte(raw)); err == nil {
			t.Fatal("unverified ping inventory accepted")
		}
	}
	for _, ports := range []map[uint16]bool{nil, {}, {0: true}, {80: false}} {
		if _, err := hostSocketBarrierPorts(ports); err == nil {
			t.Fatal("invalid port selection accepted")
		}
	}
	ports, err := hostSocketBarrierPorts(map[uint16]bool{443: true, 80: true})
	if err != nil || len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Fatal("ports not deterministic")
	}
}
