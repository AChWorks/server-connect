//go:build linux

package sc

// Confirmation observes a real authenticated OpenSSH ancestor and its live
// kernel TCP transport. Environment variables and process names are not
// authentication. This is deliberately limited to the admitted disposable
// IPv4 management path; it does not implement provider-console attestation.

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type smartTUNManagementProof struct {
	SessionSHA256   string
	PeerIP          string
	LocalIP         string
	StartedUptimeMS int64
}

type smartTUNManagementProcess struct {
	PID        int
	Parent     int
	StartTicks uint64
}

type smartTUNManagementSocket struct {
	Local, Peer         netip.Addr
	LocalPort, PeerPort uint16
	Inode               uint32
	Cookie              uint64
}

type smartTUNManagementOwner struct {
	Process smartTUNManagementProcess
	Socket  smartTUNManagementSocket
}

func managementFault(message string) error {
	return Fault("confirmation_unavailable", message)
}

func smartTUNUptimeMillis() (int64, error) {
	var ts syscall.Timespec
	// Linux CLOCK_BOOTTIME includes suspend and shares /proc starttime's
	// boot-relative domain. Wall-clock changes cannot make an old SSH fresh.
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 7, uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 || ts.Sec < 0 || ts.Sec > (1<<63-1)/1000 || ts.Nsec < 0 || ts.Nsec >= 1e9 {
		return 0, managementFault("kernel boot-relative confirmation clock unavailable")
	}
	return ts.Sec*1000 + ts.Nsec/1e6, nil
}

func readManagementProc(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, managementFault(fmt.Sprintf("management process evidence cannot be opened (%s): %v", path, err))
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, managementFault("management process evidence incomplete or exceeds bound")
	}
	return data, nil
}

func parseManagementProcess(raw []byte, pid int) (smartTUNManagementProcess, error) {
	s := string(raw)
	open, close := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 1 || close <= open || close+2 >= len(s) || s[close+1] != ' ' {
		return smartTUNManagementProcess{}, managementFault("invalid management process stat")
	}
	found, err := strconv.Atoi(strings.TrimSpace(s[:open]))
	fields := strings.Fields(s[close+2:])
	if err != nil || found != pid || pid <= 0 || len(fields) < 20 || len(fields[0]) != 1 {
		return smartTUNManagementProcess{}, managementFault("invalid management process identity")
	}
	parent, e1 := strconv.Atoi(fields[1])
	start, e2 := strconv.ParseUint(fields[19], 10, 64)
	if e1 != nil || e2 != nil || parent < 0 || parent == pid || start == 0 {
		return smartTUNManagementProcess{}, managementFault("invalid management process lifetime")
	}
	return smartTUNManagementProcess{PID: pid, Parent: parent, StartTicks: start}, nil
}

func readManagementProcess(pid int) (smartTUNManagementProcess, error) {
	raw, err := readManagementProc(fmt.Sprintf("/proc/%d/stat", pid), 4096)
	if err != nil {
		return smartTUNManagementProcess{}, err
	}
	return parseManagementProcess(raw, pid)
}

func parseManagementClockTicks(raw []byte, wordBytes int) (uint64, error) {
	if (wordBytes != 4 && wordBytes != 8) || len(raw) == 0 || len(raw)%(wordBytes*2) != 0 {
		return 0, managementFault("invalid kernel auxiliary vector")
	}
	readWord := func(b []byte) uint64 {
		if wordBytes == 4 {
			return uint64(binary.NativeEndian.Uint32(b))
		}
		return binary.NativeEndian.Uint64(b)
	}
	var hz uint64
	for offset := 0; offset < len(raw); offset += 2 * wordBytes {
		key, value := readWord(raw[offset:]), readWord(raw[offset+wordBytes:])
		if key == 0 {
			if hz == 0 {
				return 0, managementFault("kernel clock tick frequency missing")
			}
			return hz, nil
		}
		if key == 17 { // AT_CLKTCK, Linux UAPI auxvec.h
			if hz != 0 || value == 0 || value > 1000000 {
				return 0, managementFault("kernel clock tick frequency ambiguous")
			}
			hz = value
		}
	}
	return 0, managementFault("unterminated kernel auxiliary vector")
}

func managementClockTicks() (uint64, error) {
	raw, err := readManagementProc("/proc/self/auxv", 4096)
	if err != nil {
		return 0, err
	}
	return parseManagementClockTicks(raw, strconv.IntSize/8)
}

// SOCK_DIAG_BY_FAMILY / inet_diag_req_v2 and inet_diag_msg are stable Linux
// UAPI (include/uapi/linux/{sock_diag,inet_diag}.h). This is a read-only dump,
// never SOCK_DESTROY. Kernel cookies distinguish socket generations, including
// an inode reused between the two independent observations.
func parseManagementSocket(data []byte) (smartTUNManagementSocket, error) {
	if len(data) < 72 || data[0] != syscall.AF_INET || data[1] != 1 {
		return smartTUNManagementSocket{}, managementFault("unexpected established TCP observation")
	}
	for _, v := range append(append([]byte{}, data[12:24]...), data[28:40]...) {
		if v != 0 {
			return smartTUNManagementSocket{}, managementFault("noncanonical IPv4 socket address")
		}
	}
	local := netip.AddrFrom4([4]byte(data[8:12]))
	peer := netip.AddrFrom4([4]byte(data[24:28]))
	socket := smartTUNManagementSocket{
		Local: local, Peer: peer,
		LocalPort: binary.BigEndian.Uint16(data[4:6]), PeerPort: binary.BigEndian.Uint16(data[6:8]),
		Cookie: uint64(binary.NativeEndian.Uint32(data[44:48])) |
			uint64(binary.NativeEndian.Uint32(data[48:52]))<<32,
		Inode: binary.NativeEndian.Uint32(data[68:72]),
	}
	if socket.Inode == 0 || socket.LocalPort == 0 || socket.PeerPort == 0 ||
		socket.Cookie == 0 || socket.Cookie == ^uint64(0) {
		return smartTUNManagementSocket{}, managementFault("TCP transport generation is unavailable")
	}
	return socket, nil
}

func managementSockets() (map[uint32]smartTUNManagementSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_INET_DIAG)
	if err != nil {
		return nil, managementFault(fmt.Sprintf("kernel TCP transport diagnostics unavailable: %v", err))
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, managementFault(fmt.Sprintf("kernel TCP diagnostics bind failed: %v", err))
	}
	tv := syscall.NsecToTimeval(int64(500 * time.Millisecond))
	if syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv) != nil {
		return nil, managementFault("kernel TCP diagnostics timeout cannot be bounded")
	}
	request := make([]byte, 16+56)
	binary.NativeEndian.PutUint32(request[:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], 20)
	binary.NativeEndian.PutUint16(request[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	request[16], request[17] = syscall.AF_INET, syscall.IPPROTO_TCP
	binary.NativeEndian.PutUint32(request[20:24], 1<<1) // TCP_ESTABLISHED only
	binary.NativeEndian.PutUint32(request[64:68], ^uint32(0))
	binary.NativeEndian.PutUint32(request[68:72], ^uint32(0))
	if syscall.Sendto(fd, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}) != nil {
		return nil, managementFault("kernel TCP diagnostics request failed")
	}
	result := make(map[uint32]smartTUNManagementSocket)
	buffer := make([]byte, 32768)
	started := time.Now()
	for packets := 0; packets < 32 && time.Since(started) < 2*time.Second; packets++ {
		count, _, flags, source, err := syscall.Recvmsg(fd, buffer, nil, 0)
		from, ok := source.(*syscall.SockaddrNetlink)
		if err != nil {
			return nil, managementFault(fmt.Sprintf("kernel TCP diagnostics receive failed: %v", err))
		}
		if !ok || from.Pid != 0 || flags&syscall.MSG_TRUNC != 0 {
			return nil, managementFault("kernel TCP diagnostics incomplete or untrusted")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:count])
		if err != nil || len(messages) == 0 {
			return nil, managementFault("malformed kernel TCP diagnostics")
		}
		for _, msg := range messages {
			if msg.Header.Seq != 1 || msg.Header.Flags&0x10 != 0 { // NLM_F_DUMP_INTR
				return nil, managementFault("kernel TCP diagnostics changed during dump")
			}
			switch msg.Header.Type {
			case syscall.NLMSG_DONE:
				if len(msg.Data) < 4 || binary.NativeEndian.Uint32(msg.Data[:4]) != 0 {
					return nil, managementFault("kernel TCP diagnostics completion failed")
				}
				return result, nil
			case 20:
				socket, err := parseManagementSocket(msg.Data)
				if err != nil {
					return nil, err
				}
				if len(result) >= 512 {
					return nil, managementFault("kernel TCP diagnostics exceeds disposable bound")
				}
				if _, duplicate := result[socket.Inode]; duplicate {
					return nil, managementFault("ambiguous TCP transport inode")
				}
				result[socket.Inode] = socket
			default:
				return nil, managementFault("kernel TCP diagnostics returned an error")
			}
		}
	}
	return nil, managementFault("kernel TCP diagnostics did not complete within bound")
}

func managementOpenSSH(pid int) (bool, error) {
	base := fmt.Sprintf("/proc/%d", pid)
	exe, err := os.Readlink(base + "/exe")
	if err != nil {
		return false, managementFault("management ancestor executable cannot be observed")
	}
	switch exe {
	case "/usr/sbin/sshd", "/usr/lib/openssh/sshd-session":
	default:
		return false, nil
	}
	if verifyTrustedIPPath("/", exe, 0) != nil {
		return false, managementFault("OpenSSH executable or ancestry is untrusted")
	}
	process, e1 := os.Stat(base)
	running, e2 := os.Stat(base + "/exe")
	installed, e3 := os.Stat(exe)
	if e1 != nil || e2 != nil || e3 != nil || !os.SameFile(running, installed) {
		return false, managementFault("OpenSSH executable identity changed")
	}
	stat, ok := process.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false, managementFault("confirmation requires an authenticated root OpenSSH session")
	}
	ours, e1 := os.Stat("/proc/self/ns/net")
	theirs, e2 := os.Stat(base + "/ns/net")
	if e1 != nil || e2 != nil || !os.SameFile(ours, theirs) {
		return false, managementFault("management transport belongs to another network namespace")
	}
	return true, nil
}

func managementProcessSockets(pid int) (map[uint32]bool, error) {
	directory, err := os.Open(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return nil, managementFault("OpenSSH descriptors cannot be observed")
	}
	defer directory.Close()
	names, err := directory.Readdirnames(513)
	if (err != nil && err != io.EOF) || len(names) > 512 {
		return nil, managementFault("OpenSSH descriptor evidence incomplete or exceeds bound")
	}
	result := map[uint32]bool{}
	for _, name := range names {
		target, err := os.Readlink(filepath.Join(directory.Name(), name))
		if err != nil {
			return nil, managementFault("OpenSSH descriptor changed during observation")
		}
		if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		inode, err := strconv.ParseUint(target[8:len(target)-1], 10, 32)
		if err != nil || inode == 0 {
			return nil, managementFault("OpenSSH socket descriptor is malformed")
		}
		result[uint32(inode)] = true
	}
	return result, nil
}

func selectFreshManagementOwner(owners []smartTUNManagementOwner, afterMS int64, hz uint64) (smartTUNManagementOwner, int64, error) {
	if len(owners) == 0 || afterMS <= 0 || hz == 0 || hz > 1000000 {
		return smartTUNManagementOwner{}, 0, managementFault("fresh authenticated management transport not found")
	}
	oldest := owners[0]
	for _, owner := range owners {
		if owner.Socket != oldest.Socket {
			return smartTUNManagementOwner{}, 0, managementFault("multiple management transports in caller ancestry")
		}
		if owner.Process.StartTicks < oldest.Process.StartTicks {
			oldest = owner
		}
	}
	if oldest.Process.StartTicks > uint64((1<<63-1)/1000) {
		return smartTUNManagementOwner{}, 0, managementFault("management process start time exceeds bound")
	}
	// Round DOWN. A start within the Apply/challenge clock tick is refused,
	// rather than rounding an old process forward into apparent freshness.
	startedMS := int64(oldest.Process.StartTicks * 1000 / hz)
	if startedMS <= afterMS {
		return smartTUNManagementOwner{}, 0, Fault("confirmation_stale", "SSH transport predates this confirmation challenge; open a new connection without multiplexing")
	}
	return oldest, startedMS, nil
}

func observeFreshSmartTUNManagement(peer, underlay string, afterUptimeMS int64) (smartTUNManagementProof, error) {
	if os.Geteuid() != 0 {
		return smartTUNManagementProof{}, managementFault("confirmation requires privileged authenticated management")
	}
	localIP := "10.254.72.1"
	if peer == smartTUNVMEndpoint && underlay == smartTUNVMUnderlay {
		localIP = smartTUNVMGuestIP
		if err := smartTUNQAVMContext(); err != nil {
			return smartTUNManagementProof{}, err
		}
	} else if peer == "10.254.72.2" && underlay == "scqaedge0" {
		if err := trialDisposableContext(); err != nil {
			return smartTUNManagementProof{}, err
		}
	} else {
		return smartTUNManagementProof{}, managementFault("management topology is not an admitted trial")
	}
	before, err := managementSockets()
	if err != nil {
		return smartTUNManagementProof{}, err
	}
	hz, err := managementClockTicks()
	if err != nil {
		return smartTUNManagementProof{}, err
	}
	var chain []smartTUNManagementProcess
	var owners []smartTUNManagementOwner
	seen := map[int]bool{}
	pid := os.Getpid()
	for pid > 1 && len(chain) < 64 {
		if seen[pid] {
			return smartTUNManagementProof{}, managementFault("management ancestor cycle")
		}
		seen[pid] = true
		process, err := readManagementProcess(pid)
		if err != nil {
			return smartTUNManagementProof{}, err
		}
		chain = append(chain, process)
		trusted, err := managementOpenSSH(pid)
		if err != nil {
			return smartTUNManagementProof{}, err
		}
		if trusted {
			inodes, err := managementProcessSockets(pid)
			if err != nil {
				return smartTUNManagementProof{}, err
			}
			for inode := range inodes {
				socket, present := before[inode]
				if present && socket.Peer.String() == peer && socket.Local.String() == localIP {
					owners = append(owners, smartTUNManagementOwner{process, socket})
				}
			}
		}
		pid = process.Parent
	}
	if pid > 1 {
		return smartTUNManagementProof{}, managementFault("management ancestor chain exceeds bound")
	}
	selected, startedMS, err := selectFreshManagementOwner(owners, afterUptimeMS, hz)
	if err != nil {
		return smartTUNManagementProof{}, err
	}
	after, err := managementSockets()
	if err != nil {
		return smartTUNManagementProof{}, err
	}
	if after[selected.Socket.Inode] != selected.Socket {
		return smartTUNManagementProof{}, managementFault("authenticated TCP transport disappeared or changed generation")
	}
	for _, expected := range chain {
		actual, err := readManagementProcess(expected.PID)
		if err != nil || actual != expected {
			return smartTUNManagementProof{}, managementFault("management caller ancestry changed during confirmation")
		}
	}
	trusted, err := managementOpenSSH(selected.Process.PID)
	if err != nil || !trusted {
		return smartTUNManagementProof{}, managementFault("OpenSSH identity changed during confirmation")
	}
	inodes, err := managementProcessSockets(selected.Process.PID)
	if err != nil || !inodes[selected.Socket.Inode] {
		return smartTUNManagementProof{}, managementFault("OpenSSH no longer owns the authenticated transport")
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return smartTUNManagementProof{}, err
	}
	binding := fmt.Sprintf("%s:%d:%d:%s:%d:%s:%d:%d:%d", boot,
		selected.Process.PID, selected.Process.StartTicks, selected.Socket.Local,
		selected.Socket.LocalPort, selected.Socket.Peer, selected.Socket.PeerPort,
		selected.Socket.Inode, selected.Socket.Cookie)
	return smartTUNManagementProof{
		SessionSHA256: sha256Hex([]byte(binding)), PeerIP: peer,
		LocalIP: selected.Socket.Local.String(), StartedUptimeMS: startedMS,
	}, nil
}
