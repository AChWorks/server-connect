//go:build linux

package sc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type nativeStartupFake struct {
	listing string
	body    string
}

func (r nativeStartupFake) output(_ context.Context, binary string, args ...string) (string, error) {
	k := binary + " " + strings.Join(args, " ")
	switch k {
	case "nft list tables":
		return r.listing, nil
	default:
		if strings.HasPrefix(k, "nft -j -a list table inet ") {
			return r.body, nil
		}
	}
	return "", fmt.Errorf("unexpected startup inspection %s", k)
}
func nativeStartupFixture(t *testing.T) (nativeStartupPlan, nativeStartupFake) {
	t.Helper()
	p := nativeStartupPlan{Version: 1, Name: "sc_pre_" + strings.Repeat("a", 32),
		UnderlayIF: "eth0", PeerIPs: []string{"204.11.2.217"}, PeerPort: 18479,
		DirectPrefixes: []string{"193.111.235.0/25"}, Resolvers: []string{"1.1.1.1"}}
	rules, e := nativeStartupRules(p)
	if e != nil {
		t.Fatal(e)
	}
	rows := []any{
		map[string]any{"table": map[string]any{"family": "inet", "name": p.Name, "handle": uint64(5)}},
		map[string]any{"chain": map[string]any{"family": "inet", "table": p.Name, "name": "output",
			"handle": uint64(1), "type": "filter", "hook": "output", "prio": -100, "policy": "accept"}},
	}
	for i, r := range rules {
		rows = append(rows, map[string]any{"rule": map[string]any{"family": "inet", "table": p.Name,
			"chain": "output", "handle": i + 2, "expr": r.Expr}})
	}
	body, e := json.Marshal(map[string]any{"nftables": rows})
	if e != nil {
		t.Fatal(e)
	}
	return p, nativeStartupFake{listing: "table inet " + p.Name + "\n", body: string(body)}
}
func TestNativeStartupBarrierHasEarlyOutboundRejectAndNarrowExceptions(t *testing.T) {
	p, _ := nativeStartupFixture(t)
	script, e := nativeStartupScript(p)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(script, "type filter hook output priority -100;") ||
		!strings.Contains(script, "ct direction reply accept") ||
		!strings.Contains(script, "meta mark 0x2024 accept") ||
		!strings.Contains(script, "ip daddr 204.11.2.217 tcp dport 18479 accept") ||
		!strings.Contains(script, "ip daddr 1.1.1.1 udp dport 53 accept") ||
		!strings.Contains(script, "oifname \"eth0\" ip daddr 0.0.0.0/0 reject") ||
		!strings.Contains(script, "oifname \"eth0\" ip6 daddr ::/0 reject") {
		t.Fatal("pre-core barrier omitted a required outbound containment or bootstrap rule")
	}
	for _, bad := range []nativeStartupPlan{
		{Version: 1, Name: "sc_pre_$(touch /tmp/unsafe)", UnderlayIF: "eth0", PeerIPs: p.PeerIPs, PeerPort: p.PeerPort},
		{Version: 1, Name: p.Name, UnderlayIF: "eth0", PeerIPs: []string{"127.0.0.1;drop"}, PeerPort: 443},
		{Version: 1, Name: p.Name, UnderlayIF: "eth0", PeerIPs: p.PeerIPs, PeerPort: 0},
		{Version: 1, Name: p.Name, UnderlayIF: "eth0", PeerIPs: p.PeerIPs, PeerPort: 443, DirectPrefixes: []string{"0.0.0.0/0"}},
	} {
		if _, e := nativeStartupScript(bad); e == nil {
			t.Fatalf("unsafe startup barrier accepted: %+v", bad)
		}
	}
}
func TestNativeStartupKernelReceiptRefusesAlteredOrForeignObject(t *testing.T) {
	p, r := nativeStartupFixture(t)
	handle, e := nativeStartupReceipt(context.Background(), r, p)
	if e != nil || handle != 5 {
		t.Fatalf("valid kernel receipt failed: %d %v", handle, e)
	}
	if e = requireNativeStartupGuardClaim(context.Background(), r, p, 5); e != nil {
		t.Fatal(e)
	}
	if e = requireNativeStartupGuardClaim(context.Background(), r, p, 6); e == nil {
		t.Fatal("adopted replaced nft handle")
	}
	variants := []struct{ name, body string }{
		{"altered-mark", strings.Replace(r.body, `"right":8228`, `"right":8227`, 1)},
		{"changed-peer", strings.Replace(r.body, "204.11.2.217", "204.11.2.218", 1)},
		{"removed-reject", strings.Replace(r.body, `"reject":{"expr":"port-unreachable","type":"icmp"}`, `"accept":null`, 1)},
		{"extra-object", strings.Replace(r.body, "]}", `,{"table":{"family":"ip","name":"intruder"}}]}`, 1)},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			altered := r
			altered.body = v.body
			if _, e := nativeStartupReceipt(context.Background(), altered, p); e == nil {
				t.Fatal("modified kernel object accepted")
			}
		})
	}
	foreign := r
	foreign.listing += "table inet sc_pre_" + strings.Repeat("b", 32) + "\n"
	if e := requireNativeStartupGuardClaim(context.Background(), foreign, p, 5); e == nil {
		t.Fatal("foreign parallel native barrier ignored")
	}
}

// Executed by the isolated root network-namespace harness, not by ordinary
// source CI users. Genuine nftables JSON and generation-CAS behavior must
// agree with the verified script before any physical installed-host Apply.
func TestNativeStartupRealKernelNamespaceLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root in an isolated network namespace")
	}
	if b, e := exec.Command("ip", "link", "show", "eth0").CombinedOutput(); e == nil {
		t.Fatalf("refusing potential real underlay host namespace: %s", b)
	}
	p, _ := nativeStartupFixture(t)
	ctx := context.Background()
	runner := nativeSystemRunner{}
	present, e := nativeStartupPresent(ctx, runner, p.Name)
	if e != nil || present {
		t.Fatalf("unexpected occupied namespace: %v %v", present, e)
	}
	handle, e := nativeStartupInstall(ctx, runner, p)
	if e != nil || handle == 0 {
		t.Fatalf("nft guard install or ownership verification failed: %d %v", handle, e)
	}
	t.Cleanup(func() {
		// Only this uniquely named test table in a disposable netns is task-owned.
		_ = exec.Command("nft", "delete", "table", "inet", p.Name).Run()
	})
	if e = requireNativeStartupGuardClaim(ctx, runner, p, handle); e != nil {
		t.Fatal(e)
	}
	if e = nativeStartupRecover(ctx, runner, p, handle, "armed"); e != nil {
		t.Fatal(e)
	}
	present, e = nativeStartupPresent(ctx, runner, p.Name)
	if e != nil || present {
		t.Fatalf("nft startup barrier remained: %v %v", present, e)
	}
	if e = nativeStartupRecover(ctx, runner, p, handle, "released"); e != nil {
		t.Fatal(e)
	}
}

// A CONNECT intent alone is not admission. Caller-visible Smart is forbidden
// until the actual startup packet gate has been installed, verified and
// committed. Historical prearm tests did not cover this unsafe interleaving.
func TestNativePrearmMustRemainDirectUntilPacketContainment(t *testing.T) {
	s := NativeSession{Selected: "qa-profile"}
	state := State{Desired: "direct", Selected: "qa-profile"}
	if err := nativePendingPrearmMatches(state, s); err != nil {
		t.Fatalf("safe prearm refused: %v", err)
	}
	for _, mutation := range []struct {
		name    string
		state   State
		session NativeSession
	}{
		{"premature-smart", State{Desired: "smart", Selected: "qa-profile"}, s},
		{"profile-swapped", State{Desired: "direct", Selected: "other"}, s},
		{"unset-profile", State{Desired: "direct"}, s},
		{"replayed-core", state, NativeSession{Selected: "qa-profile", CoreStartAttempted: true}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if err := nativePendingPrearmMatches(mutation.state, mutation.session); err == nil {
				t.Fatal("unsafe native prearm state accepted")
			}
		})
	}
}
