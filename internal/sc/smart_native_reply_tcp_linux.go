//go:build linux

package sc

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

// nativeAcceptedTCPFlow identifies one already accepted, established
// listener-side socket. A full four-tuple (not the foreign IP, a listener
// port alone, or all locally originated traffic) is the only additional
// output exemption. New local outbound sockets to the *same peer address*
// are intentionally absent from these snapshots and remain VPN-required.
type nativeAcceptedTCPFlow struct {
	Local netip.AddrPort
	Peer  netip.AddrPort
}

type nativeProcTCPEntry struct {
	Local netip.AddrPort
	Peer  netip.AddrPort
	State string
}

func nativeProcTCPAddr(raw string, family int) (netip.AddrPort, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return netip.AddrPort{}, errors.New("malformed proc TCP endpoint")
	}
	p, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return netip.AddrPort{}, errors.New("invalid proc TCP port")
	}
	if (family == 4 && len(parts[0]) != 8) || (family == 6 && len(parts[0]) != 32) {
		return netip.AddrPort{}, errors.New("invalid proc TCP address width")
	}
	rawAddr, err := hex.DecodeString(parts[0])
	if err != nil {
		return netip.AddrPort{}, errors.New("invalid proc TCP address")
	}
	var addr netip.Addr
	switch family {
	case 4:
		var v4 [4]byte
		for i := 0; i < 4; i++ {
			v4[i] = rawAddr[3-i]
		}
		addr = netip.AddrFrom4(v4)
	case 6:
		var v6 [16]byte
		for i := 0; i < 16; i++ {
			v6[i] = rawAddr[(i/4)*4+(3-i%4)]
		}
		addr = netip.AddrFrom16(v6).Unmap()
	default:
		return netip.AddrPort{}, errors.New("unsupported proc TCP family")
	}
	return netip.AddrPortFrom(addr, uint16(p)), nil
}

func parseNativeProcTCP(r io.Reader, family int) ([]nativeProcTCPEntry, error) {
	scanner := bufio.NewScanner(r)
	var entries []nativeProcTCPEntry
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 && fields[0] == "sl" {
			continue
		}
		if len(fields) < 4 {
			return nil, errors.New("unexpected proc TCP row")
		}
		local, err := nativeProcTCPAddr(fields[1], family)
		if err != nil {
			return nil, err
		}
		peer, err := nativeProcTCPAddr(fields[2], family)
		if err != nil {
			return nil, err
		}
		if len(fields[3]) != 2 {
			return nil, errors.New("invalid proc TCP state")
		}
		if _, err := strconv.ParseUint(fields[3], 16, 8); err != nil {
			return nil, errors.New("non-hex proc TCP state")
		}
		entries = append(entries, nativeProcTCPEntry{Local: local, Peer: peer, State: strings.ToUpper(fields[3])})
	}
	return entries, scanner.Err()
}

func nativeAcceptedTCPSnapshotFromReaders(tcp4, tcp6 io.Reader) ([]nativeAcceptedTCPFlow, error) {
	a, err := parseNativeProcTCP(tcp4, 4)
	if err != nil {
		return nil, err
	}
	b, err := parseNativeProcTCP(tcp6, 6)
	if err != nil {
		return nil, err
	}
	entries := append(a, b...)
	type portFamily struct {
		Family int
		Port   uint16
	}
	// The listener must exist *now*. Reversed conntrack direction is not
	// enough to infer this is an accepted inbound server-side connection.
	listeners := make(map[portFamily][]netip.Addr)
	for _, e := range entries {
		if e.State != "0A" || e.Local.Port() == 0 {
			continue
		}
		family := 6
		if e.Local.Addr().Is4() {
			family = 4
		}
		key := portFamily{family, e.Local.Port()}
		listeners[key] = append(listeners[key], e.Local.Addr())
	}
	unique := make(map[string]nativeAcceptedTCPFlow)
	for _, e := range entries {
		if e.State != "01" || e.Local.Port() == 0 || e.Peer.Port() == 0 ||
			!e.Local.Addr().IsValid() || !e.Peer.Addr().IsValid() ||
			e.Local.Addr().IsUnspecified() || e.Peer.Addr().IsUnspecified() ||
			e.Local.Addr().Is4() != e.Peer.Addr().Is4() {
			continue
		}
		family := 6
		if e.Local.Addr().Is4() {
			family = 4
		}
		key := portFamily{family, e.Local.Port()}
		found := false
		for _, listenAddr := range listeners[key] {
			if listenAddr.IsUnspecified() || listenAddr == e.Local.Addr() {
				found = true
				break
			}
		}
		// tcp6 IPv4-mapped sockets are normalized to IPv4 by Unmap().
		// They can also be accepted by an IPv6 wildcard listener when
		// dual-stack mode is enabled; require a *real* established socket.
		if !found && family == 4 {
			for _, addr := range listeners[portFamily{6, e.Local.Port()}] {
				if addr.IsUnspecified() {
					found = true
					break
				}
			}
		}
		if !found {
			continue
		}
		flow := nativeAcceptedTCPFlow{Local: e.Local, Peer: e.Peer}
		unique[nativeAcceptedTCPKey(flow)] = flow
	}
	flows := make([]nativeAcceptedTCPFlow, 0, len(unique))
	for _, f := range unique {
		flows = append(flows, f)
	}
	sort.Slice(flows, func(i, j int) bool {
		return nativeAcceptedTCPKey(flows[i]) < nativeAcceptedTCPKey(flows[j])
	})
	return flows, nil
}

func nativeAcceptedTCPSnapshot() ([]nativeAcceptedTCPFlow, error) {
	tcp4, err := os.Open("/proc/net/tcp")
	if err != nil {
		return nil, err
	}
	defer tcp4.Close()
	tcp6, err := os.Open("/proc/net/tcp6")
	if errors.Is(err, os.ErrNotExist) {
		// IPv4-only kernels do not have a tcp6 proc entry. Absence is not
		// an error; IPv6 accepted sockets simply cannot exist there.
		return nativeAcceptedTCPSnapshotFromReaders(tcp4, strings.NewReader(""))
	}
	if err != nil {
		return nil, err
	}
	defer tcp6.Close()
	return nativeAcceptedTCPSnapshotFromReaders(tcp4, tcp6)
}

func nativeAcceptedTCPKey(f nativeAcceptedTCPFlow) string {
	family := "v6"
	if f.Local.Addr().Is4() {
		family = "v4"
	}
	return fmt.Sprintf("%s|%s|%d|%s|%d",
		family, f.Local.Addr(), f.Local.Port(), f.Peer.Addr(), f.Peer.Port())
}

func nativeAcceptedTCPFingerprint(flows []nativeAcceptedTCPFlow) string {
	keys := make([]string, 0, len(flows))
	for _, flow := range flows {
		keys = append(keys, nativeAcceptedTCPKey(flow))
	}
	sort.Strings(keys)
	h := sha256.New()
	_, _ = h.Write([]byte("server-connect/inbound-reply-accepted-v2\n"))
	for _, key := range keys {
		_, _ = h.Write([]byte(key + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func nativeAcceptedTCPScriptElement(f nativeAcceptedTCPFlow) string {
	return fmt.Sprintf("%s . %d . %s . %d",
		f.Local.Addr(), f.Local.Port(), f.Peer.Addr(), f.Peer.Port())
}
