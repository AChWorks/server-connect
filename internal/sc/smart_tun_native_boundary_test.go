package sc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestSmartTUNNativeMutatorRetainsSameLockUntilJoined(t *testing.T) {
	if os.Getenv("SC_NATIVE_LOCK_HELPER") == "1" {
		lock := os.NewFile(3, "inherited-native-lock")
		if lock == nil {
			os.Exit(41)
		}
		if _, err := lock.Stat(); err != nil {
			os.Exit(42)
		}
		if _, err := os.Stdout.Write([]byte("ready\n")); err != nil {
			os.Exit(43)
		}
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			os.Exit(44)
		}
		os.Exit(0)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dir := privateJournalTempDir(t)
	m := New(dir, DefaultCore, DefaultPort)
	cmd := exec.Command(os.Args[0], "-test.run=^TestSmartTUNNativeMutatorRetainsSameLockUntilJoined$")
	cmd.Env = append(os.Environ(), "SC_NATIVE_LOCK_HELPER=1")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	started := false
	defer func() {
		_ = in.Close()
		if started && cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := nativeTUNBindMutator(cmd, store); err != nil {
			return err
		}
		if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != store.lock || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
			t.Fatal("mutator lacks exact lock/Pdeathsig binding")
		}
		if err := cmd.Start(); err != nil {
			return err
		}
		started = true
		ready := make([]byte, 6)
		if _, err := io.ReadFull(out, ready); err != nil {
			return err
		}
		if string(ready) != "ready\n" {
			t.Fatal("child not ready")
		}
		// Simulate process death's descriptor release, deliberately NOT a
		// cooperative LOCK_UN. The inherited OFD must keep recovery excluded.
		lock := store.lock
		store.lock = nil
		return lock.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
	observer, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	if err := syscall.Flock(int(observer.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("recovery passed a still-live mutator after manager descriptor loss: %v", err)
	}
	_ = in.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(observer.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("joined mutator retained lock: %v", err)
	}
	_ = syscall.Flock(int(observer.Fd()), syscall.LOCK_UN)
}

func TestSmartTUNNativeFailedStartDoesNotUnlockManager(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		cmd := exec.Command(filepath.Join(m.Dir, "does-not-exist"))
		if err := nativeTUNBindMutator(cmd, store); err != nil {
			return err
		}
		if err := cmd.Run(); err == nil {
			t.Fatal("absent mutator unexpectedly started")
		}
		other, err := os.OpenFile(filepath.Join(m.Dir, ".lock"), os.O_RDWR, 0600)
		if err != nil {
			return err
		}
		defer other.Close()
		if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Fatalf("failed Start unlocked shared operation: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Source-derived Linux single-queue detail: tun_fill_info deliberately omits
// both queue-count attributes when IFF_MULTI_QUEUE is clear.
const nativeSingleQueueLinkJSON = `{"ifindex":7,"ifname":"sctunqa0","flags":["POINTOPOINT","MULTICAST","NOARP","UP","LOWER_UP"],"mtu":1400,"operstate":"UNKNOWN","ifalias":"server-connect:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","linkinfo":{"info_kind":"tun","info_data":{"type":"tun","persist":true,"multi_queue":false}}}`

func TestSmartTUNNativeCarrierDoesNotHideIdentityChanges(t *testing.T) {
	before := nativeSingleQueueLinkJSON
	after := strings.Replace(before, `"LOWER_UP"`, `"NO-CARRIER"`, 1)
	decode := func(raw string) map[string]json.RawMessage {
		var row map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	a, pa, err := nativeTUNLinkShape(decode(before), "2")
	if err != nil {
		t.Fatal(err)
	}
	b, pb, err := nativeTUNLinkShape(decode(after), "2")
	if err != nil || a != b || !pa || !pb {
		t.Fatalf("normal core FD close changed native ownership: %v", err)
	}
	for _, foreign := range []string{strings.Replace(after, `"ifindex":7`, `"ifindex":8`, 1), strings.Replace(after, `"mtu":1400`, `"mtu":1500`, 1), strings.Replace(after, `"UP",`, "", 1)} {
		changed, _, err := nativeTUNLinkShape(decode(foreign), "2")
		if err == nil && changed == a {
			t.Fatal("carrier normalization hid an ownership change")
		}
	}
	changed, _, err := nativeTUNLinkShape(decode(after), "0")
	if err == nil && changed == a {
		t.Fatal("rp_filter drift hidden")
	}
	for _, field := range []string{`"num_queues":1`, `"num_disabled_queues":0`} {
		inconsistent := strings.Replace(before, `"multi_queue":false`, `"multi_queue":false,`+field, 1)
		if _, _, err := nativeTUNLinkShape(decode(inconsistent), "2"); ErrorCode(err) != "trial_resource_conflict" {
			t.Fatal("single-queue ownership normalized away multiqueue details")
		}
	}
	rows, _ := selectiveRows(json.RawMessage(`[{"priority":10399,"src":"all","goto":10400}]`))
	if _, _, err := nativeTUNResourceRows(rows, nativeTrialExample(true), 4, "rule"); ErrorCode(err) != "trial_resource_conflict" {
		t.Fatal("foreign goto adopted as independent rule")
	}
}

func TestSmartTUNNativeSingleQueueAttachNeedsPositiveCarrier(t *testing.T) {
	base := nativeSingleQueueLinkJSON
	detached := strings.Replace(base, `"LOWER_UP"`, `"NO-CARRIER"`, 1)
	withCarrier := func(raw, value string) string { return strings.TrimSuffix(raw, "}") + `,"carrier":` + value + `}` }
	for _, tc := range []struct {
		name, raw          string
		attached, conflict bool
	}{
		{"attached without multiqueue counters", base, true, false},
		{"detached without multiqueue counters", detached, false, false},
		{"missing positive carrier", strings.Replace(base, `,"LOWER_UP"`, "", 1), false, false},
		{"running alone is not carrier proof", strings.Replace(base, `"LOWER_UP"`, `"RUNNING"`, 1), false, false},
		{"matching numeric carrier", withCarrier(base, "1"), true, false},
		{"matching detached carrier", withCarrier(detached, "0"), false, false},
		{"contradictory carrier flags", strings.Replace(base, `"LOWER_UP"`, `"LOWER_UP","NO-CARRIER"`, 1), false, true},
		{"carrier disagrees with lower up", withCarrier(base, "0"), false, true},
		{"carrier alone cannot establish attachment", withCarrier(detached, "1"), false, true},
		{"null carrier is not absence", withCarrier(base, "null"), false, true},
		{"unsupported carrier value", withCarrier(base, "2"), false, true},
		{"administratively down", strings.Replace(base, `"UP",`, "", 1), false, true},
		{"duplicate flags", strings.Replace(base, `"LOWER_UP"`, `"LOWER_UP","LOWER_UP"`, 1), false, true},
		{"multiqueue mode", strings.Replace(base, `"multi_queue":false`, `"multi_queue":true`, 1), false, true},
		{"missing queue mode", strings.Replace(base, `,"multi_queue":false`, "", 1), false, true},
		{"null queue mode", strings.Replace(base, `"multi_queue":false`, `"multi_queue":null`, 1), false, true},
		{"nonpersistent creator attachment", strings.Replace(base, `"persist":true`, `"persist":false`, 1), false, true},
		{"other link kind", strings.Replace(base, `"info_kind":"tun"`, `"info_kind":"dummy"`, 1), false, true},
		{"tap mode", strings.Replace(base, `"type":"tun"`, `"type":"tap"`, 1), false, true},
		{"unsupported queue details", strings.Replace(base, `"multi_queue":false`, `"multi_queue":false,"num_queues":1,"num_disabled_queues":0`, 1), false, true},
		{"null queue count is not absence", strings.Replace(base, `"multi_queue":false`, `"multi_queue":false,"num_queues":null`, 1), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var row map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.raw), &row); err != nil {
				t.Fatal(err)
			}
			attached, err := nativeTUNSingleQueueAttached(row)
			if tc.conflict {
				if attached || ErrorCode(err) != "trial_resource_conflict" {
					t.Fatalf("unsupported attachment accepted: attached=%v err=%v", attached, err)
				}
				return
			}
			if err != nil || attached != tc.attached {
				t.Fatalf("attachment=%v want=%v err=%v", attached, tc.attached, err)
			}
		})
	}
}

type nativeGuardPacket struct {
	family, protocol, iif, oif, icmpType, sport, dport int
	mark                                               uint32
	reply                                              bool
	destination                                        string
}

func nativeGuardNumber(value any) (uint64, bool) {
	switch v := value.(type) {
	case int:
		return uint64(v), v >= 0
	case uint32:
		return uint64(v), true
	case json.Number:
		n, err := strconv.ParseUint(v.String(), 10, 64)
		return n, err == nil
	}
	return 0, false
}

func nativeGuardOperand(value any, p nativeGuardPacket) any {
	m, ok := value.(map[string]any)
	if !ok {
		return value
	}
	if meta, ok := m["meta"].(map[string]any); ok {
		switch meta["key"] {
		case "mark":
			return p.mark
		case "nfproto":
			return p.family
		case "l4proto":
			return p.protocol
		case "iif":
			return p.iif
		case "oif":
			return p.oif
		}
	}
	if _, ok := m["ct"]; ok {
		if p.reply {
			return "reply"
		}
		return "original"
	}
	if payload, ok := m["payload"].(map[string]any); ok {
		// Protocol-typed payload expressions retain these dependencies even
		// when nft's JSON listing omits the redundant explicit meta checks.
		switch payload["protocol"] {
		case "ip":
			if p.family != 2 {
				return nil
			}
		case "ip6":
			if p.family != 10 {
				return nil
			}
		case "udp":
			if p.protocol != 17 {
				return nil
			}
		case "icmpv6":
			if p.family != 10 || p.protocol != 58 {
				return nil
			}
		default:
			return nil
		}
		switch payload["field"] {
		case "daddr":
			return p.destination
		case "type":
			return p.icmpType
		case "sport":
			return p.sport
		case "dport":
			return p.dport
		}
	}
	if parts, ok := m["&"].([]any); ok && len(parts) == 2 {
		a, aok := nativeGuardNumber(nativeGuardOperand(parts[0], p))
		b, bok := nativeGuardNumber(parts[1])
		if aok && bok {
			return json.Number(strconv.FormatUint(a&b, 10))
		}
	}
	return value
}

func nativeGuardMatch(left, right any) bool {
	if n, ok := nativeGuardNumber(left); ok {
		r, ok := nativeGuardNumber(right)
		if ok {
			return n == r
		}
	}
	if set, ok := right.(map[string]any); ok {
		if values, ok := set["set"].([]any); ok {
			for _, v := range values {
				if nativeGuardMatch(left, v) {
					return true
				}
			}
			return false
		}
		if prefix, ok := set["prefix"].(map[string]any); ok {
			address, _ := prefix["addr"].(string)
			bits, _ := nativeGuardNumber(prefix["len"])
			parsed, err := netip.ParsePrefix(address + "/" + strconv.FormatUint(bits, 10))
			dest, ok := left.(string)
			ip, iperr := netip.ParseAddr(dest)
			return ok && err == nil && iperr == nil && parsed.Contains(ip)
		}
	}
	l, lok := left.(string)
	r, rok := right.(string)
	return lok && rok && l == r
}

func nativeGuardAllows(t *testing.T, record smartTUNTrialJournal, p nativeGuardPacket) bool {
	t.Helper()
	for _, object := range nativeNFTObjects(record) {
		rule, ok := object["rule"].(map[string]any)
		if !ok || rule["chain"] != "guard" {
			continue
		}
		matches := true
		for _, value := range rule["expr"].([]any) {
			expr := value.(map[string]any)
			if match, ok := expr["match"].(map[string]any); ok {
				if match["op"] != "==" {
					t.Fatal("test evaluator cannot support changed comparison")
				}
				if !nativeGuardMatch(nativeGuardOperand(match["left"], p), match["right"]) {
					matches = false
					break
				}
				continue
			}
			if _, ok := expr["return"]; ok && matches {
				return true
			}
			if _, ok := expr["drop"]; ok && matches {
				return false
			}
			if _, ok := expr["counter"]; !ok {
				t.Fatal("test evaluator cannot silently skip a new guard statement")
			}
		}
	}
	return true // base-chain policy; final explicit drop should handle all else
}

func TestSmartTUNNativeIndependentClassifierKeepsColdNeighborControl(t *testing.T) {
	r := nativeTrialExample(true)
	// These are inputs at the selected hook, not a kernel hook-order model.
	// Native QA must prove actual POSTROUTING egress and ingress identities.
	for _, object := range nativeNFTObjects(r) {
		chain, ok := object["chain"].(map[string]any)
		if !ok {
			continue
		}
		switch chain["name"] {
		case "capture":
			if chain["type"] != "route" || chain["hook"] != "output" {
				t.Fatal("capture left the OUTPUT rerouting hook")
			}
		case "guard":
			if chain["type"] != "filter" || chain["hook"] != "postrouting" {
				t.Fatal("guard cannot inspect final egress in the original OUTPUT hook")
			}
		}
	}
	for _, tc := range []struct {
		name    string
		p       nativeGuardPacket
		allowed bool
	}{
		{"public unmarked TCP cannot leak after capture loss", nativeGuardPacket{family: 2, protocol: 6, oif: 3, destination: "8.8.8.8"}, false},
		{"public marked UDP cannot leak after rule loss", nativeGuardPacket{family: 10, protocol: 17, oif: 3, mark: nativeTUNCaptureMark, destination: "2606:4700:5::10"}, false},
		{"actual TUN TCP", nativeGuardPacket{family: 2, protocol: 6, oif: 7, destination: "8.8.8.8"}, true},
		{"foreign visitor reply", nativeGuardPacket{family: 2, protocol: 6, oif: 3, reply: true, destination: "8.8.8.8"}, true},
		{"core outer socket", nativeGuardPacket{family: 10, protocol: 17, oif: 3, mark: nativeTUNBypassMark, destination: "2606:4700:5::10"}, true},
		{"cold IPv6 neighbor solicitation", nativeGuardPacket{family: 10, protocol: 58, oif: 3, icmpType: 135, destination: "ff02::1:ff00:2"}, true},
		{"cold IPv6 neighbor advertisement", nativeGuardPacket{family: 10, protocol: 58, oif: 3, icmpType: 136, destination: "ff02::1"}, true},
		{"ND payload type cannot exempt UDP", nativeGuardPacket{family: 10, protocol: 17, oif: 3, icmpType: 135, destination: "ff02::1"}, false},
		{"ND cannot bypass public unicast", nativeGuardPacket{family: 10, protocol: 58, oif: 3, icmpType: 135, destination: "2606:4700:5::10"}, false},
		{"arbitrary public ICMPv6 is unsupported", nativeGuardPacket{family: 10, protocol: 58, oif: 3, icmpType: 128, destination: "2606:4700:5::10"}, false},
		{"link-local multicast DHCP4", nativeGuardPacket{family: 2, protocol: 17, oif: 3, sport: 68, dport: 67, destination: "255.255.255.255"}, true},
		{"DHCP ports cannot exempt TCP", nativeGuardPacket{family: 2, protocol: 6, oif: 3, sport: 68, dport: 67, destination: "255.255.255.255"}, false},
		{"broadcast arbitrary UDP denied", nativeGuardPacket{family: 2, protocol: 17, oif: 3, sport: 1234, dport: 1234, destination: "255.255.255.255"}, false},
		{"local IPv4 link control", nativeGuardPacket{family: 2, protocol: 2, oif: 3, destination: "224.0.0.1"}, true},
		{"forwarded IPv4 public TCP remains foreign-owned", nativeGuardPacket{family: 2, protocol: 6, iif: 9, oif: 3, destination: "8.8.8.8"}, true},
		{"forwarded IPv6 public UDP remains foreign-owned", nativeGuardPacket{family: 10, protocol: 17, iif: 9, oif: 3, destination: "2606:4700:8::8"}, true},
		{"forwarded unsupported public protocol remains foreign-owned", nativeGuardPacket{family: 10, protocol: 58, iif: 9, oif: 3, icmpType: 128, destination: "2606:4700:8::8"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeGuardAllows(t, r, tc.p); got != tc.allowed {
				t.Fatalf("guard classifier allowed=%v, want %v", got, tc.allowed)
			}
		})
	}
}

func TestSmartTUNNativeDeleteACKRequiresExactKernelTransaction(t *testing.T) {
	request := make([]byte, 32)
	binary.NativeEndian.PutUint32(request[:4], 32)
	binary.NativeEndian.PutUint16(request[4:6], syscall.RTM_DELLINK)
	binary.NativeEndian.PutUint16(request[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.NativeEndian.PutUint32(request[8:12], 31)
	binary.NativeEndian.PutUint32(request[12:16], 1234)
	binary.NativeEndian.PutUint32(request[20:24], 7)
	ack := make([]byte, 36)
	binary.NativeEndian.PutUint32(ack[:4], 36)
	binary.NativeEndian.PutUint16(ack[4:6], syscall.NLMSG_ERROR)
	binary.NativeEndian.PutUint32(ack[8:12], 31)
	binary.NativeEndian.PutUint32(ack[12:16], 1234)
	copy(ack[20:], request[:16])
	if err := nativeTUNDeleteACK(ack, 0, 1234, request); err != nil {
		t.Fatalf("header-only successful ACK rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func([]byte)
		flags  int
	}{
		{"foreign port", func(v []byte) { binary.NativeEndian.PutUint32(v[12:16], 999) }, 0},
		{"wrong sequence", func(v []byte) { binary.NativeEndian.PutUint32(v[8:12], 32) }, 0},
		{"wrong echoed request", func(v []byte) { binary.NativeEndian.PutUint16(v[24:26], syscall.RTM_NEWLINK) }, 0},
		{"positive errno", func(v []byte) { binary.NativeEndian.PutUint32(v[16:20], 1) }, 0},
		{"unknown ACK flags", func(v []byte) { binary.NativeEndian.PutUint16(v[6:8], 0x200) }, 0},
		{"truncated datagram", func([]byte) {}, syscall.MSG_TRUNC},
		{"truncated control", func([]byte) {}, syscall.MSG_CTRUNC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := append([]byte{}, ack...)
			tc.change(bad)
			if ErrorCode(nativeTUNDeleteACK(bad, tc.flags, 1234, request)) != "trial_recovery_uncertain" {
				t.Fatal("ambiguous deletion acknowledged as success")
			}
		})
	}
	for _, bad := range [][]byte{ack[:20], append(append([]byte{}, ack...), 0, 0, 0, 0)} {
		if err := nativeTUNDeleteACK(bad, 0, 1234, request); err == nil {
			t.Fatal("malformed ACK length accepted")
		}
	}
	negative := make([]byte, 52)
	copy(negative, ack)
	binary.NativeEndian.PutUint32(negative[:4], 52)
	binary.NativeEndian.PutUint32(negative[16:20], uint32(0xffffffff))
	copy(negative[20:], request)
	if ErrorCode(nativeTUNDeleteACK(negative, 0, 1234, request)) != "trial_recovery_uncertain" {
		t.Fatal("kernel rejection became a successful deletion")
	}
}

func TestSmartTUNNativePhaseReasonAndStartupReceiptCannotConflict(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*smartTUNTrialJournal)
	}{
		{"guard in pending", func(r *smartTUNTrialJournal) { r.Native.StopReason = "guard" }},
		{"stop without reason", func(r *smartTUNTrialJournal) { r.Phase = "trial_stop_requested"; r.Revision = 2 }},
		{"guard as Off recovery", func(r *smartTUNTrialJournal) {
			r.Phase = "trial_recovered"
			r.Revision = 3
			r.Native.StopReason = "guard"
		}},
		{"unverified completed start", func(r *smartTUNTrialJournal) {
			r.Phase = "trial_recovered"
			r.Revision = 2
			r.Native.StopReason = "guard"
			r.Native.StartupVerified = false
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := nativeTrialExample(true)
			tc.change(&r)
			if r.Phase == "trial_recovered" {
				r.Native.LinkStage = "removed"
				r.Native.NFT.Stage = "removed"
				for _, family := range []int{4, 6} {
					f := nativeFamily(r.Native, family)
					f.Route.Stage = "removed"
					f.Rule.Stage = "removed"
					f.Fallback.Stage = "removed"
				}
			}
			if err := validateSmartTUNTrial(r); err == nil {
				t.Fatal("impossible recovery receipt accepted")
			}
		})
	}
	for _, reason := range []string{"off", "guard"} {
		r := nativeTrialExample(true)
		r.Phase = "trial_stop_requested"
		r.Revision = 2
		r.Native.StopReason = reason
		if err := validateSmartTUNTrial(r); err != nil {
			t.Fatal(err)
		}
	}
}
