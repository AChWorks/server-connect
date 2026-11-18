//go:build linux

package sc

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func proc4(addr netip.Addr) string {
	a := addr.As4()
	return fmt.Sprintf("%02X%02X%02X%02X", a[3], a[2], a[1], a[0])
}
func proc6(addr netip.Addr) string {
	a := addr.As16()
	var out strings.Builder
	for x := 0; x < 16; x += 4 {
		for i := 3; i >= 0; i-- {
			fmt.Fprintf(&out, "%02X", a[x+i])
		}
	}
	return out.String()
}

func TestNativeAcceptedTCPProcParsingAndIngressSelection(t *testing.T) {
	local := netip.MustParseAddr("203.0.113.10")
	remote := netip.MustParseAddr("198.51.100.77")
	otherLocal := netip.MustParseAddr("203.0.113.11")
	tcp4 := fmt.Sprintf(`sl local_address rem_address st extra
 1: 00000000:0016 00000000:0000 0A 0
 2: %s:0016 %s:C8E6 01 0
 3: %s:8D34 %s:01BB 01 0
 4: %s:01BB %s:C8E5 01 0
 5: %s:0016 %s:C8E6 06 0
`,
		proc4(local), proc4(remote), proc4(local), proc4(remote),
		proc4(otherLocal), proc4(remote), proc4(local), proc4(remote))
	v6Local := netip.MustParseAddr("2001:db8::1")
	v6Remote := netip.MustParseAddr("2001:db8::2")
	tcp6 := fmt.Sprintf(`sl local_address rem_address st extra
 1: %s:20FB %s:0000 0A 0
 2: %s:20FB %s:D368 01 0
`, proc6(v6Local), proc6(netip.IPv6Unspecified()), proc6(v6Local), proc6(v6Remote))
	flows, err := nativeAcceptedTCPSnapshotFromReaders(strings.NewReader(tcp4), strings.NewReader(tcp6))
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("accepted listener-side sockets only: %+v", flows)
	}
	want := map[string]bool{
		nativeAcceptedTCPKey(nativeAcceptedTCPFlow{
			Local: netip.AddrPortFrom(local, 22),
			Peer:  netip.AddrPortFrom(remote, 51430),
		}): true,
		nativeAcceptedTCPKey(nativeAcceptedTCPFlow{
			Local: netip.AddrPortFrom(v6Local, 8443),
			Peer:  netip.AddrPortFrom(v6Remote, 54120),
		}): true,
	}
	for _, f := range flows {
		if !want[nativeAcceptedTCPKey(f)] {
			t.Fatalf("outgoing or unrelated socket was accepted: %+v", f)
		}
		if !f.Local.Addr().IsValid() || !f.Peer.Addr().IsValid() {
			t.Fatalf("invalid address in snapshot %+v", f)
		}
	}
	hash1 := nativeAcceptedTCPFingerprint(flows)
	flows[0], flows[1] = flows[1], flows[0]
	if hash2 := nativeAcceptedTCPFingerprint(flows); hash1 != hash2 || len(hash1) != 64 {
		t.Fatalf("fingerprint is order-sensitive or malformed: %s %s", hash1, hash2)
	}
}

func TestNativeAcceptedTCPProcRejectsInvalidAndNeverAdoptsNewOutgoing(t *testing.T) {
	for _, input := range []string{
		"1: bad 00000000:0000 01 0\n",
		"1: 00000000:0016 00000000:0000 GG 0\n",
		"1: 00000000:999999 00000000:0000 0A 0\n",
	} {
		if _, err := parseNativeProcTCP(strings.NewReader(input), 4); err == nil {
			t.Fatalf("malformed kernel row accepted: %s", input)
		}
	}
	s := `sl local_address rem_address st extra
 1: 00000000:0016 00000000:0000 0A 0
 2: 0A7100CB:8D34 4D6433C6:01BB 01 0
`
	flows, err := nativeAcceptedTCPSnapshotFromReaders(strings.NewReader(s), strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 0 {
		t.Fatalf("new outbound foreign flow was whitelisted: %+v", flows)
	}
}
