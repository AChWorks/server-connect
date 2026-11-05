//go:build linux

package sc

import (
	"encoding/binary"
	"syscall"
	"testing"
)

func ingressSocketFixture(family byte, state byte, mark uint32) []byte {
	data := make([]byte, 80)
	data[0], data[1] = family, state
	binary.BigEndian.PutUint16(data[4:6], 28993)
	if state != 10 {
		binary.BigEndian.PutUint16(data[6:8], 51001)
	}
	if family == syscall.AF_INET {
		data[8], data[11], data[24], data[27] = 127, 1, 127, 1
	} else {
		data[23], data[39] = 1, 1
	}
	binary.NativeEndian.PutUint32(data[44:48], 456)
	binary.NativeEndian.PutUint32(data[68:72], 123)
	binary.NativeEndian.PutUint16(data[72:74], 8)
	binary.NativeEndian.PutUint16(data[74:76], 15)
	binary.NativeEndian.PutUint32(data[76:80], mark)
	return data
}

func TestHostIngressParsesBothFamiliesListenersAndGenerationMarks(t *testing.T) {
	for _, family := range []byte{syscall.AF_INET, syscall.AF_INET6} {
		for _, state := range []byte{1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12} {
			mark := uint32(nativeTUNBypassMark)
			if state == 10 {
				mark = 0
			}
			s, err := parseHostIngressSocket(ingressSocketFixture(family, state, mark), family)
			if err != nil || s.Inode != 123 || s.Cookie != 456 || s.Mark != mark || s.State != state || s.Family != family {
				t.Fatalf("family=%d state=%d: %+v %v", family, state, s, err)
			}
		}
	}
}

func TestHostIngressRejectsMissingAmbiguousAndMalformedKernelEvidence(t *testing.T) {
	valid := ingressSocketFixture(syscall.AF_INET, 1, nativeTUNBypassMark)
	cases := map[string][]byte{}
	for _, n := range []int{0, 71, 72, 73, 75, 79} {
		cases[string(rune(n))] = append([]byte{}, valid[:n]...)
	}
	change := func(name string, fn func([]byte)) { b := append([]byte{}, valid...); fn(b); cases[name] = b }
	change("foreign family", func(b []byte) { b[0] = syscall.AF_INET6 })
	change("unrequested state", func(b []byte) { b[1] = 7 })
	change("invalid state shift", func(b []byte) { b[1] = 255 })
	change("mapped garbage IPv4", func(b []byte) { b[12] = 1 })
	change("zero inode", func(b []byte) { binary.NativeEndian.PutUint32(b[68:72], 0) })
	change("zero cookie", func(b []byte) { binary.NativeEndian.PutUint32(b[44:48], 0) })
	change("invalid cookie", func(b []byte) { binary.NativeEndian.PutUint64(b[44:52], ^uint64(0)) })
	change("zero port", func(b []byte) { binary.BigEndian.PutUint16(b[4:6], 0) })
	change("nonlistener without peer", func(b []byte) { binary.BigEndian.PutUint16(b[6:8], 0) })
	change("listener with peer", func(b []byte) { b[1] = 10 })
	change("missing mark", func(b []byte) { binary.NativeEndian.PutUint16(b[74:76], 1) })
	change("nested mark", func(b []byte) { binary.NativeEndian.PutUint16(b[74:76], 15|0x8000) })
	change("mark wrong byte order", func(b []byte) { binary.NativeEndian.PutUint16(b[74:76], 15|0x4000) })
	change("bad mark length", func(b []byte) { binary.NativeEndian.PutUint16(b[72:74], 7) })
	cases["duplicate mark"] = append(append([]byte{}, valid...), valid[72:]...)
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseHostIngressSocket(raw, syscall.AF_INET); err == nil {
				t.Fatal("invalid kernel evidence accepted")
			}
		})
	}
	// Unknown valid attributes may precede MARK. They cannot stand in for it.
	raw := append(append(append([]byte{}, valid[:72]...), []byte{4, 0, 42, 0}...), valid[72:]...)
	if _, err := parseHostIngressSocket(raw, syscall.AF_INET); err != nil {
		t.Fatal(err)
	}
}

func TestHostIngressDrainNeverCreatesTupleOrSourcePortAuthority(t *testing.T) {
	parse := func(state byte, mark uint32) hostIngressSocket {
		s, e := parseHostIngressSocket(ingressSocketFixture(syscall.AF_INET, state, mark), syscall.AF_INET)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	listener := parse(10, 0)
	marked := parse(1, nativeTUNBypassMark|7)
	if err := validateHostIngressDrain([]hostIngressSocket{listener, marked}); err != nil {
		t.Fatal(err)
	}
	if err := validateHostIngressDrain([]hostIngressSocket{}); err != nil {
		t.Fatal(err)
	}
	if err := validateHostIngressDrain(nil); err == nil {
		t.Fatal("absent inventory accepted")
	}
	for _, state := range []byte{1, 2, 3, 4, 5, 6, 8, 9, 11, 12} {
		old := parse(state, 0)
		if ErrorCode(validateHostIngressDrain([]hostIngressSocket{listener, old})) != "host_ingress_drain_pending" {
			t.Fatalf("old state %d accepted", state)
		}
	}
	// A listener's *any* nonzero mark defeats inheritance, even outside our mask.
	for _, mark := range []uint32{1, 0x220000, nativeTUNBypassMark} {
		if ErrorCode(validateHostIngressDrain([]hostIngressSocket{parse(10, mark)})) != "host_ingress_listener_mark" {
			t.Fatalf("foreign listener mark %x accepted", mark)
		}
	}
	old := parse(1, 0)
	fresh := old
	fresh.Inode++
	fresh.Cookie++
	fresh.Mark = nativeTUNBypassMark
	if validateHostIngressDrain([]hostIngressSocket{old}) == nil || validateHostIngressDrain([]hostIngressSocket{fresh}) != nil {
		t.Fatal("tuple reuse was used instead of generation/mark")
	}
}
