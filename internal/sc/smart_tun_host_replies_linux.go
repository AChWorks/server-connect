//go:build linux

package sc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// This is a passive pre-Apply risk observation. A TCP socket's port and
// kernel generation do not establish that it was an inbound hosted session;
// count plausible matches conservatively. The two observations are not an
// atomic reservation and grant NO network-mutation or routing authority.
const (
	hostRepliesUnverified = "unverified"
	hostRepliesPresent    = "possible_preexisting_untracked_tcp_sessions"
	hostRepliesNone       = "none_observed_at_snapshot"
	hostRepliesNoXT       = "no_output_xt_ct_observed"
)

// Only the strict, currently observed iptables-nft OUTPUT NOTRACK dialect
// is recognized. Any foreign OUTPUT target, custom chain, ambiguous syntax,
// range, unexpected line or missing cross-check is UNVERIFIED, not empty.
// PREROUTING rules cannot establish an outbound reply exemption.
func strictHostOutputNOTRACKPorts(raw []byte) (map[uint16]bool, int, error) {
	if len(raw) == 0 || len(raw) > 64*1024 || bytes.IndexByte(raw, 0) >= 0 {
		return nil, 0, errors.New("unavailable raw-table evidence")
	}
	ports := make(map[uint16]bool)
	count, policy := 0, false
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		words := strings.Fields(line)
		if len(words) == 3 && words[0] == "-P" && words[1] == "PREROUTING" && words[2] == "ACCEPT" {
			continue
		}
		if len(words) == 3 && words[0] == "-P" && words[1] == "OUTPUT" && words[2] == "ACCEPT" {
			if policy {
				return nil, 0, errors.New("duplicate output policy")
			}
			policy = true
			continue
		}
		if len(words) >= 2 && words[0] == "-A" && words[1] == "PREROUTING" {
			continue
		}
		if len(words) != 10 && len(words) != 11 {
			return nil, 0, errors.New("unrecognized raw-table rule")
		}
		if words[0] != "-A" || words[1] != "OUTPUT" || words[2] != "-p" || words[3] != "tcp" ||
			words[4] != "-m" || words[5] != "tcp" || words[6] != "--sport" || words[8] != "-j" ||
			!((len(words) == 10 && words[9] == "NOTRACK") ||
				(len(words) == 11 && words[9] == "CT" && words[10] == "--notrack")) {
			return nil, 0, errors.New("unrecognized raw output effect")
		}
		port, err := strconv.ParseUint(words[7], 10, 16)
		if err != nil || port == 0 || strconv.FormatUint(port, 10) != words[7] || count >= 128 {
			return nil, 0, errors.New("invalid or excessive output NOTRACK ports")
		}
		ports[uint16(port)] = true
		count++
	}
	if !policy || count == 0 {
		return nil, 0, errors.New("NOTRACK OUTPUT inventory incomplete")
	}
	return ports, count, nil
}

func classifiedExistingHostReplies(raw []byte, sockets map[uint32]smartTUNManagementSocket, expectedOutputXTCT int) (string, error) {
	ports, count, err := strictHostOutputNOTRACKPorts(raw)
	if err != nil || sockets == nil || expectedOutputXTCT <= 0 || count != expectedOutputXTCT {
		return hostRepliesUnverified, errors.New("raw policy and kernel socket evidence disagree")
	}
	possible := false
	for _, sock := range sockets {
		if sock.Inode == 0 || sock.Cookie == 0 || sock.Cookie == ^uint64(0) || sock.LocalPort == 0 ||
			sock.PeerPort == 0 || !sock.Local.Is4() || !sock.Peer.Is4() {
			return hostRepliesUnverified, errors.New("kernel TCP socket generation invalid")
		}
		if ports[sock.LocalPort] {
			possible = true
		}
	}
	if possible {
		return hostRepliesPresent, nil
	}
	return hostRepliesNone, nil
}

func runReadOnlyHostIptables(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/iptables", args...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Dir = "/"
	cmd.WaitDelay = 250 * time.Millisecond
	var output boundedFirewallOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil || ctx.Err() != nil || output.Len() > 64*1024 {
		return nil, errors.New("host raw policy cannot be observed")
	}
	return bytes.Clone(output.Bytes()), nil
}

func observedHostRawTable() ([]byte, error) {
	// nft JSON xt targets do not distinguish --notrack from other CT actions.
	// iptables-legacy reads a different kernel ruleset: it cannot corroborate
	// the nft trace, even if its textual rule count happens to match.
	version, err := runReadOnlyHostIptables("-V")
	if err != nil || !bytes.HasPrefix(version, []byte("iptables v")) ||
		!bytes.Contains(version, []byte("(nf_tables)")) {
		return nil, errors.New("iptables-nft backend not verified")
	}
	return runReadOnlyHostIptables("-t", "raw", "-S")
}

// Cross-check the same raw-table semantics around an authenticated kernel
// inet_diag ESTABLISHED snapshot. This is a diagnostic only: a new socket can
// appear immediately afterwards and an existing socket can close/reuse its
// tuple. Actual Apply needs generation-aware, independently guarded pinning.
func observeExistingHostReplySessions(expectedOutputXTCT int) (string, error) {
	before, err := observedHostRawTable()
	if err != nil {
		return hostRepliesUnverified, err
	}
	sockets, err := managementSockets()
	if err != nil {
		return hostRepliesUnverified, err
	}
	after, err := observedHostRawTable()
	if err != nil || !bytes.Equal(before, after) {
		return hostRepliesUnverified, errors.New("host raw policy changed during socket observation")
	}
	return classifiedExistingHostReplies(before, sockets, expectedOutputXTCT)
}
