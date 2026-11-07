//go:build linux

package sc

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Run only inside a fresh, independently verified disposable network namespace.
// This proves refusal and preservation of actual legacy owners, not their
// compatibility with Apply, protection against concurrent root or host rescue.
func TestHostLegacyRealKernelForeignPoliciesRefusedAndPreserved(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_LEGACY_POLICY_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: fresh isolated root network namespace required")
	}
	_ = requireNativeQANetworkNamespace(t)
	links, err := net.Interfaces()
	if err != nil || len(links) != 1 || links[0].Name != "lo" {
		t.Fatal("native legacy QA requires a fresh namespace with loopback only")
	}
	nftObjects := func() []map[string]any {
		t.Helper()
		raw, err := nativeTUNRunNFT(nil, nil, "-n", "-j", "-a", "list", "ruleset")
		if err != nil {
			t.Fatal(err)
		}
		objects, err := nativeTUNNftObjects(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(objects) != 0 {
			t.Fatal("legacy QA requires genuinely empty nft policy")
		}
		return objects
	}
	initialNFT := nftObjects()
	if _, err := observeHostLegacyPacketPolicy(); err != nil {
		if hostIngressForeignNATBoundary(hostIngressStage{}, initialNFT) == nil {
			t.Fatal("unavailable legacy policy was silently treated as empty")
		}
		t.Skipf("UNSUPPORTED: independent legacy inventory unavailable; product refused: %v", err)
	}
	runFixture := func(binary string, args ...string) ([]byte, error) {
		if err := verifyHostNetfilterPath("/", binary, 0); err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, append([]string{"-M", "/usr/bin/false"}, args...)...)
		cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		cmd.Dir = "/"
		cmd.WaitDelay = 250 * time.Millisecond
		return cmd.CombinedOutput()
	}
	for _, tc := range []struct {
		label, binary, table string
		rule                 []string
	}{
		{"IPv4_NAT", "/usr/sbin/iptables-legacy", "nat", []string{"-p", "tcp", "--dport", "29871", "-j", "DNAT", "--to-destination", "192.0.2.99"}},
		{"IPv6_NAT", "/usr/sbin/ip6tables-legacy", "nat", []string{"-p", "tcp", "--dport", "29872", "-j", "DNAT", "--to-destination", "2001:db8::99"}},
		{"IPv4_MANGLE_MARK", "/usr/sbin/iptables-legacy", "mangle", []string{"-j", "MARK", "--set-mark", "4242"}},
		{"IPv6_MANGLE_CONNMARK", "/usr/sbin/ip6tables-legacy", "mangle", []string{"-j", "CONNMARK", "--restore-mark"}},
		{"IPv4_FILTER_DROP", "/usr/sbin/iptables-legacy", "filter", []string{"-p", "tcp", "--dport", "29873", "-j", "DROP"}},
	} {
		t.Run(tc.label, func(t *testing.T) {
			add := append([]string{"-t", tc.table, "-A", "OUTPUT"}, tc.rule...)
			remove := append([]string{"-t", tc.table, "-D", "OUTPUT"}, tc.rule...)
			out, err := runFixture(tc.binary, add...)
			if err != nil {
				// An unsupported kernel is not empty-policy evidence. Require
				// independent absence after the failed atomic fixture insertion.
				if _, proofErr := observeHostLegacyPacketPolicy(); proofErr != nil {
					t.Fatalf("failed fixture has uncertain remainder: %v (%s); %v", err, out, proofErr)
				}
				t.Skipf("UNSUPPORTED: native %s fixture unavailable: %v (%s)", tc.label, err, out)
			}
			present := true
			t.Cleanup(func() {
				if present {
					if out, err := runFixture(tc.binary, remove...); err != nil {
						t.Errorf("exact task-owned rule cleanup failed: %v (%s)", err, out)
					}
				}
			})
			before, err := runReadOnlyHostNetfilter(tc.binary, "-t", tc.table, "-S")
			if err != nil || !bytes.Contains(before, []byte("-A OUTPUT ")) {
				t.Fatalf("actual foreign fixture not observed: %v (%s)", err, before)
			}
			if code := ErrorCode(hostIngressForeignNATBoundary(hostIngressStage{}, nftObjects())); code != "foreign_legacy_policy_unverified" {
				t.Fatalf("clean nft hid actual %s owner: %s", tc.label, code)
			}
			after, err := runReadOnlyHostNetfilter(tc.binary, "-t", tc.table, "-S")
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("refusal altered foreign %s policy: %v", tc.label, err)
			}
			if out, err := runFixture(tc.binary, remove...); err != nil {
				t.Fatalf("exact fixture removal failed: %v (%s)", err, out)
			}
			present = false
			if _, err := observeHostLegacyPacketPolicy(); err != nil {
				t.Fatalf("inert policy not reobserved after exact removal: %v", err)
			}
			fmt.Printf("HOST_LEGACY_%s_REFUSED_PRESERVED_AND_REOBSERVED=PASS\n", tc.label)
		})
	}
	// If raw is already registered, compare actual old -S bytes with the
	// save-derived bytes without deliberately probing an absent raw table.
	snapshot, err := observeHostLegacyPacketPolicy()
	if err != nil {
		t.Fatal(err)
	}
	for family, name := range []string{"ip", "ip6"} {
		names, err := readManagementProc("/proc/net/"+name+"_tables_names", 256)
		if err != nil {
			t.Fatal(err)
		}
		registered, err := hostLegacyRegisteredTables(names)
		if err != nil {
			t.Fatal(err)
		}
		if !registered["raw"] {
			t.Logf("NOT_RUN: %s raw table is unregistered; no absent-table probe", name)
			continue
		}
		raw, err := runReadOnlyHostNetfilter("/usr/sbin/"+name+"tables-legacy", "-t", "raw", "-S")
		if err != nil || !bytes.Equal(raw, snapshot.raw[family]) {
			t.Fatalf("registered %s raw journal bytes changed: %v", name, err)
		}
		fmt.Printf("HOST_LEGACY_%s_RAW_OLD_S_BYTES_PRESERVED=PASS\n", strings.ToUpper(name))
	}
}
