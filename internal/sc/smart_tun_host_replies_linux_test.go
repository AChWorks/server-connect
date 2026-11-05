//go:build linux

package sc

import (
	"net/netip"
	"strings"
	"testing"
)

const rawHostedNOTRACK = `-P PREROUTING ACCEPT
-P OUTPUT ACCEPT
-A PREROUTING -p tcp -m tcp --dport 80 -j NOTRACK
-A OUTPUT -p tcp -m tcp --sport 80 -j NOTRACK
-A OUTPUT -p tcp -m tcp --sport 4433 -j CT --notrack
`

func TestReadOnlyHostReplyNOTRACKPolicyExactCrosscheck(t *testing.T) {
	ports, count, err := strictHostOutputNOTRACKPorts([]byte(rawHostedNOTRACK))
	if err != nil || count != 2 || len(ports) != 2 || !ports[80] || !ports[4433] {
		t.Fatalf("canonical native output inventory rejected: %d, %v, %v", count, ports, err)
	}
	socket := smartTUNManagementSocket{
		Local: netip.MustParseAddr("10.2.3.4"), Peer: netip.MustParseAddr("8.8.8.8"),
		LocalPort: 80, PeerPort: 53218, Inode: 12, Cookie: 1337,
	}
	sockets := map[uint32]smartTUNManagementSocket{socket.Inode: socket}
	if status, err := classifiedExistingHostReplies([]byte(rawHostedNOTRACK), sockets, 2); err != nil || status != hostRepliesPresent {
		t.Fatalf("pre-existing untracked host reply ignored: %s %v", status, err)
	}
	socket.LocalPort = 54322
	sockets[socket.Inode] = socket
	if status, err := classifiedExistingHostReplies([]byte(rawHostedNOTRACK), sockets, 2); err != nil || status != hostRepliesNone {
		t.Fatalf("disjoint established session misclassified: %s %v", status, err)
	}
}

func TestReadOnlyHostReplyNOTRACKFailClosed(t *testing.T) {
	mutations := []struct{ name, input string }{
		{"empty", ""},
		{"missing-output-policy", strings.ReplaceAll(rawHostedNOTRACK, "-P OUTPUT ACCEPT\n", "")},
		{"default-output-drop", strings.ReplaceAll(rawHostedNOTRACK, "-P OUTPUT ACCEPT", "-P OUTPUT DROP")},
		{"duplicate-output-policy", rawHostedNOTRACK + "-P OUTPUT ACCEPT\n"},
		{"unexpected-chain", rawHostedNOTRACK + "-N SUBCHAIN\n"},
		{"output-jump", rawHostedNOTRACK + "-A OUTPUT -j CHAIN\n"},
		{"foreign-output-target", strings.ReplaceAll(rawHostedNOTRACK, "-j NOTRACK", "-j ACCEPT")},
		{"alternate-mark", rawHostedNOTRACK + "-A OUTPUT -p tcp -m tcp --dport 80 -j CT --notrack\n"},
		{"port-range", strings.ReplaceAll(rawHostedNOTRACK, "--sport 80", "--sport 80:90")},
		{"port-zero", strings.ReplaceAll(rawHostedNOTRACK, "--sport 80", "--sport 0")},
		{"noncanonical-port", strings.ReplaceAll(rawHostedNOTRACK, "--sport 80", "--sport 080")},
		{"unsupported-ct-helper", strings.ReplaceAll(rawHostedNOTRACK, "-j CT --notrack", "-j CT --helper ftp")},
		{"extra-source-filter", strings.ReplaceAll(rawHostedNOTRACK, "--sport 80", "-s 8.8.8.8 --sport 80")},
		{"unexpected-null", rawHostedNOTRACK + "\x00"},
		{"oversize", strings.Repeat("X", 65537)},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := strictHostOutputNOTRACKPorts([]byte(tc.input)); err == nil {
				t.Fatal("ambiguous host raw OUTPUT policy accepted")
			}
		})
	}
	if status, err := classifiedExistingHostReplies([]byte(rawHostedNOTRACK), map[uint32]smartTUNManagementSocket{}, 1); err == nil || status != hostRepliesUnverified {
		t.Fatalf("mismatched nft xt CT count treated as safe: %s, %v", status, err)
	}
	if status, err := classifiedExistingHostReplies([]byte(rawHostedNOTRACK), nil, 2); err == nil || status != hostRepliesUnverified {
		t.Fatalf("missing authenticated kernel sockets treated as safe: %s, %v", status, err)
	}
	bad := smartTUNManagementSocket{
		Local: netip.MustParseAddr("10.2.3.4"), Peer: netip.MustParseAddr("8.8.8.8"),
		LocalPort: 80, PeerPort: 1234, Inode: 7,
	}
	if status, err := classifiedExistingHostReplies([]byte(rawHostedNOTRACK), map[uint32]smartTUNManagementSocket{7: bad}, 2); err == nil || status != hostRepliesUnverified {
		t.Fatalf("missing socket generation accepted: %s, %v", status, err)
	}
	valid := bad
	valid.Inode, valid.Cookie = 8, 44
	if status, err := classifiedExistingHostReplies([]byte(rawHostedNOTRACK),
		map[uint32]smartTUNManagementSocket{7: bad, 8: valid}, 2); err == nil || status != hostRepliesUnverified {
		t.Fatalf("another socket hid malformed kernel identity: %s, %v", status, err)
	}
	if status, err := classifiedExistingHostReplies([]byte(rawHostedNOTRACK),
		map[uint32]smartTUNManagementSocket{9: valid}, 2); err == nil || status != hostRepliesUnverified {
		t.Fatalf("socket map inode mismatch produced a trustworthy reply inventory: %s, %v", status, err)
	}
}

func TestReadOnlyHostReplyLegacyRawBackendCrosscheck(t *testing.T) {
	for _, raw := range []string{
		"-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n",
		"-P OUTPUT ACCEPT\n-P PREROUTING ACCEPT\n",
	} {
		if !strictEmptyLegacyRawPolicy([]byte(raw)) {
			t.Fatal("clean legacy kernel raw policy rejected")
		}
	}
	for _, raw := range []string{
		"", "-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT",
		"-P PREROUTING ACCEPT\n-P OUTPUT DROP\n",
		"-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n-P OUTPUT ACCEPT\n",
		"-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n-A OUTPUT -p tcp --sport 80 -j NOTRACK\n",
		"-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n-N foreign\n",
	} {
		if strictEmptyLegacyRawPolicy([]byte(raw)) {
			t.Fatalf("unexpected legacy raw policy accepted: %q", raw)
		}
	}
}
