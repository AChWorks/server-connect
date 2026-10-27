package sc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// WorkloadSocket is an observed open TCP/UDP socket inode held by the
// selected PID. An FD can be shared, passed or reused; this is NOT proof that
// the PID originated traffic or that a VPN path carries its packets.
type WorkloadSocket struct {
	Inode    uint64 `json:"inode"`
	Protocol string `json:"protocol"`
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	State    string `json:"state"`
}

// WorkloadSocketEvidence is an operator-requested, non-atomic snapshot of
// /proc/PID/fd socket references joined to /proc/PID/net TCP/UDP tables.
// Namespace tables contain OTHER processes too: only matching FD inodes
// appear here. No descendant or per-flow ownership is authenticated.
type WorkloadSocketEvidence struct {
	ReadOnly             bool             `json:"read_only"`
	SnapshotAtomic       bool             `json:"snapshot_atomic"`
	JobOwnerVerified     bool             `json:"job_owner_verified"`
	DescendantsCovered   bool             `json:"descendants_covered"`
	TrafficPathVerified  bool             `json:"traffic_path_verified"`
	ActivationReady      bool             `json:"activation_ready"`
	NetworkNamespace     string           `json:"network_namespace"`
	SocketInodeCount     int              `json:"socket_inode_count"`
	UnclassifiedInodes   int              `json:"unclassified_inodes"`
	ObservedTCPUDPSocket []WorkloadSocket `json:"observed_tcp_udp_sockets"`
	Limitations          []string         `json:"limitations"`
}

const (
	workloadSocketMaxFDs      = 8192
	workloadSocketMaxNetBytes = 8 << 20
	workloadSocketMaxNetRows  = 30000
)

func readWorkloadFDInodes(root string, pid int) (map[uint64]bool, error) {
	dir, err := os.Open(filepath.Join(root, strconv.Itoa(pid), "fd"))
	if err != nil {
		return nil, workloadObservationUnavailable()
	}
	defer dir.Close()
	entries, err := dir.ReadDir(workloadSocketMaxFDs + 1)
	if (err != nil && err != io.EOF) || len(entries) > workloadSocketMaxFDs {
		return nil, workloadObservationUnavailable()
	}
	inodes := make(map[uint64]bool)
	for _, entry := range entries {
		// Do not follow arbitrary FD symlinks or expose any target other than
		// a strictly parsed kernel socket inode.
		link, err := os.Readlink(filepath.Join(root, strconv.Itoa(pid), "fd", entry.Name()))
		if err != nil {
			return nil, workloadObservationUnavailable()
		}
		if !strings.HasPrefix(link, "socket:[") {
			continue
		}
		if !strings.HasSuffix(link, "]") {
			return nil, workloadObservationUnavailable()
		}
		value := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
		inode, err := strconv.ParseUint(value, 10, 64)
		if err != nil || inode == 0 {
			return nil, workloadObservationUnavailable()
		}
		inodes[inode] = true
	}
	return inodes, nil
}

func sameWorkloadSocketInodes(a, b map[uint64]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for inode := range a {
		if !b[inode] {
			return false
		}
	}
	return true
}

func readWorkloadNamespace(root string, pid int) (string, error) {
	link, err := os.Readlink(filepath.Join(root, strconv.Itoa(pid), "ns", "net"))
	if err != nil || !strings.HasPrefix(link, "net:[") || !strings.HasSuffix(link, "]") {
		return "", workloadObservationUnavailable()
	}
	id := strings.TrimSuffix(strings.TrimPrefix(link, "net:["), "]")
	v, err := strconv.ParseUint(id, 10, 64)
	if err != nil || v == 0 {
		return "", workloadObservationUnavailable()
	}
	return "net:[" + id + "]", nil
}

// Linux procfs represents IPv4 in little-endian hex and IPv6 as four
// little-endian 32-bit words. This diagnostic targets the tested Linux
// amd64 family, not platform-independent raw socket wire formats.
func parseWorkloadSocketEndpoint(raw string, ipv6 bool) (string, error) {
	addr, portText, ok := strings.Cut(raw, ":")
	if !ok || len(portText) != 4 {
		return "", workloadObservationUnavailable()
	}
	port, err := strconv.ParseUint(portText, 16, 16)
	if err != nil {
		return "", workloadObservationUnavailable()
	}
	data, err := hex.DecodeString(addr)
	if err != nil {
		return "", workloadObservationUnavailable()
	}
	var ip netip.Addr
	if ipv6 {
		if len(data) != 16 {
			return "", workloadObservationUnavailable()
		}
		var value [16]byte
		for i := 0; i < 16; i += 4 {
			binary.BigEndian.PutUint32(value[i:i+4], binary.LittleEndian.Uint32(data[i:i+4]))
		}
		ip = netip.AddrFrom16(value)
	} else {
		if len(data) != 4 {
			return "", workloadObservationUnavailable()
		}
		ip = netip.AddrFrom4([4]byte{data[3], data[2], data[1], data[0]})
	}
	return netip.AddrPortFrom(ip, uint16(port)).String(), nil
}

func parseWorkloadSocketTable(data []byte, protocol string, held map[uint64]bool) ([]WorkloadSocket, error) {
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) == 0 {
		return nil, workloadObservationUnavailable()
	}
	header := strings.Fields(string(lines[0]))
	if len(header) < 12 || header[1] != "local_address" ||
		(header[2] != "rem_address" && header[2] != "remote_address") || header[3] != "st" || header[11] != "inode" {
		return nil, workloadObservationUnavailable()
	}
	ipv6 := strings.HasSuffix(protocol, "6")
	var matches []WorkloadSocket
	rows := 0
	for _, line := range lines[1:] {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		rows++
		if rows > workloadSocketMaxNetRows {
			return nil, workloadObservationUnavailable()
		}
		fields := strings.Fields(string(line))
		if len(fields) < 10 || !strings.HasSuffix(fields[0], ":") {
			return nil, workloadObservationUnavailable()
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, workloadObservationUnavailable()
		}
		if !held[inode] {
			continue
		}
		local, err := parseWorkloadSocketEndpoint(fields[1], ipv6)
		if err != nil {
			return nil, err
		}
		remote, err := parseWorkloadSocketEndpoint(fields[2], ipv6)
		if err != nil {
			return nil, err
		}
		stateCode, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil || len(fields[3]) != 2 || stateCode == 0 {
			return nil, workloadObservationUnavailable()
		}
		matches = append(matches, WorkloadSocket{
			Inode: inode, Protocol: protocol, Local: local, Remote: remote,
			State: strings.ToUpper(fields[3]),
		})
	}
	return matches, nil
}

func readWorkloadSocketTable(root string, pid int, protocol string, held map[uint64]bool) ([]WorkloadSocket, error) {
	if protocol != "tcp4" && protocol != "tcp6" && protocol != "udp4" && protocol != "udp6" {
		return nil, workloadObservationUnavailable()
	}
	name := protocol[:3]
	if strings.HasSuffix(protocol, "6") {
		name += "6"
	}
	f, err := os.Open(filepath.Join(root, strconv.Itoa(pid), "net", name))
	if err != nil {
		return nil, workloadObservationUnavailable()
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, workloadSocketMaxNetBytes+1))
	if err != nil || len(data) > workloadSocketMaxNetBytes {
		return nil, workloadObservationUnavailable()
	}
	return parseWorkloadSocketTable(data, protocol, held)
}

func observeWorkloadWithSocketsAt(root string, pid int) (WorkloadObservation, error) {
	report, err := observeWorkloadAt(root, pid)
	if err != nil {
		return WorkloadObservation{}, err
	}
	firstNamespace, err := readWorkloadNamespace(root, pid)
	if err != nil {
		return WorkloadObservation{}, err
	}
	held, err := readWorkloadFDInodes(root, pid)
	if err != nil {
		return WorkloadObservation{}, err
	}
	all := make([]WorkloadSocket, 0)
	seen := make(map[uint64]bool)
	for _, protocol := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		sockets, err := readWorkloadSocketTable(root, pid, protocol, held)
		if err != nil {
			return WorkloadObservation{}, err
		}
		for _, socket := range sockets {
			if seen[socket.Inode] {
				return WorkloadObservation{}, workloadObservationUnavailable()
			}
			seen[socket.Inode] = true
			all = append(all, socket)
		}
	}
	// The process, its network namespace and set of open socket inodes must
	// still be visible with the same observed identity. These reads remain
	// NON-ATOMIC, and ownership/traffic cannot be inferred from them.
	finalNamespace, err := readWorkloadNamespace(root, pid)
	if err != nil || finalNamespace != firstNamespace {
		return WorkloadObservation{}, workloadObservationUnavailable()
	}
	finalFDs, err := readWorkloadFDInodes(root, pid)
	if err != nil || !sameWorkloadSocketInodes(held, finalFDs) {
		return WorkloadObservation{}, workloadObservationUnavailable()
	}
	chain := append([]WorkloadProcessIdentity{report.Process}, report.Ancestors...)
	if err := recheckWorkloadAncestryAt(root, chain); err != nil {
		return WorkloadObservation{}, err
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Inode != all[j].Inode {
			return all[i].Inode < all[j].Inode
		}
		return all[i].Protocol < all[j].Protocol
	})
	report.Sockets = &WorkloadSocketEvidence{
		ReadOnly: true, NetworkNamespace: firstNamespace,
		SocketInodeCount: len(held), UnclassifiedInodes: len(held) - len(seen),
		ObservedTCPUDPSocket: all,
		Limitations: []string{
			"Matched file descriptors and TCP/UDP namespace table entries are non-atomic, time-limited observations; socket inodes may be reused.",
			"A socket FD can be inherited or shared by unrelated processes; this does not authenticate an aaPanel job, source flow, or outbound path.",
			"Only the requested PID is sampled; descendants and later sockets, DNS resolution, VPN path, routing and packet delivery are NOT captured.",
			"Unclassified socket FDs may belong to Unix, netlink, or other protocols; other processes share the namespace tables.",
		},
	}
	return report, nil
}

// ObserveWorkloadProcessSockets opt-in adds actual per-PID socket FD evidence
// to the existing conservative workload snapshot. No host-network mutation,
// active probes, service changes, or claim of job/egress authorization.
func ObserveWorkloadProcessSockets(pid int) (WorkloadObservation, error) {
	if pid <= 1 {
		return WorkloadObservation{}, Fault("invalid_arguments", "workload observation requires --pid greater than 1")
	}
	if runtime.GOOS != "linux" {
		return WorkloadObservation{}, workloadObservationUnavailable()
	}
	return observeWorkloadWithSocketsAt("/proc", pid)
}
