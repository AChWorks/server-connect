package sc

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnderlayTCPPolicyRuleShapes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules string
		ok    bool
	}{
		{"default", `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`, true},
		{"dport", `[{"priority":100,"src":"all","ipproto":"tcp","dport":443,"table":"100"}]`, true},
		{"uid", `[{"priority":100,"src":"all","uid_start":0,"uid_end":1000,"table":"100"}]`, true},
		{"source_sensitive", `[{"priority":100,"src":"192.0.2.0","srclen":24,"table":"100"}]`, false},
		{"source_mask", `[{"priority":100,"src":"all","srclen":24,"table":"100"}]`, false},
		{"fwmark", `[{"priority":100,"src":"all","fwmark":"0x1","fwmask":"0xff","table":"100"}]`, false},
		{"sport_range", `[{"priority":100,"src":"all","ipproto":"tcp","sport_start":1000,"sport_end":60000,"table":"100"}]`, false},
		{"vrf", `[{"priority":100,"src":"all","l3mdev":true,"table":"100"}]`, false},
		{"interface", `[{"priority":100,"src":"all","oif":"eth1","table":"100"}]`, false},
		{"traffic_class", `[{"priority":100,"src":"all","tos":4,"table":"100"}]`, false},
		{"inverted_rule", `[{"priority":100,"src":"all","flags":["not"],"table":"100"}]`, false},
		{"unknown_selector", `[{"priority":100,"src":"all","future_selector":1,"table":"100"}]`, false},
		{"no_identity", `[{"src":"all","table":"100"}]`, false},
		{"object", `{"priority":100}`, false},
		{"null", `null`, false},
		{"malformed", `[{"priority":`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTCPPolicyRules([]byte(tc.rules))
			if tc.ok && err != nil || !tc.ok && ErrorCode(err) != "underlay_policy_unsupported" {
				t.Fatalf("rule eligibility=%v incorrect: %v", tc.ok, err)
			}
		})
	}
}

// Only the child lives in the new user+network namespace and has CAP_NET_ADMIN
// there. The parent never changes the real host's rules, routes or interfaces.
func TestUnderlayTCPFlowPolicyInPrivateNamespace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only rule and socket test")
	}
	if os.Getenv("SC_TEST_UNDERLAY_NETNS") == "child" {
		testUnderlayTCPFlowPolicyNamespaceChild(t)
		return
	}
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("native iproute2 unavailable")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare unavailable")
	}
	probe := exec.Command("unshare", "-Urn", "/usr/bin/true")
	if err := probe.Run(); err != nil {
		t.Skipf("unprivileged disposable network namespace unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "-Urn", os.Args[0], "-test.run=^TestUnderlayTCPFlowPolicyInPrivateNamespace$", "-test.v")
	cmd.Env = append(os.Environ(), "SC_TEST_UNDERLAY_NETNS=child")
	out, err := cmd.CombinedOutput()
	if err != nil || ctx.Err() != nil {
		t.Fatalf("isolated policy test failed: %v context=%v output=%s", err, ctx.Err(), out)
	}
	t.Logf("isolated policy test succeeded: %s", out)
}

func testUnderlayTCPFlowPolicyNamespaceChild(t *testing.T) {
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(nativeIPPath, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("disposable namespace ip %q: %v %s", args, err, out)
		}
	}
	run("link", "set", "lo", "up")
	run("link", "add", "scveth0", "type", "veth", "peer", "name", "scveth1")
	run("addr", "add", "10.77.0.1/24", "dev", "scveth0")
	run("addr", "add", "10.78.0.1/24", "dev", "scveth1")
	run("link", "set", "scveth0", "up")
	run("link", "set", "scveth1", "up")
	run("-4", "route", "add", "198.51.100.0/24", "dev", "lo")
	run("-4", "route", "add", "198.51.100.0/24", "dev", "scveth0", "table", "100")
	run("-4", "route", "add", "198.51.100.0/24", "dev", "scveth1", "table", "101")
	run("-4", "rule", "add", "pref", "100", "ipproto", "tcp", "dport", "443", "table", "100")
	run("-4", "rule", "add", "pref", "101", "uidrange", "0-0", "ipproto", "tcp", "dport", "8443", "table", "101")

	addr := netip.MustParseAddr("198.51.100.9")
	assertRoute := func(port int, device string) {
		t.Helper()
		r, err := tcpFlowRoute(addr, port, os.Geteuid())
		if err != nil || r.Device != device {
			t.Fatalf("dport=%d selected %q rather than %q, error %v", port, r.Device, device, err)
		}
	}
	assertRoute(443, "scveth0") // dport-specific route differs from default.
	assertRoute(80, "lo")
	assertRoute(8443, "scveth1") // UID + TCP + dport-specific policy.
	snapshot := func(args ...string) []byte {
		t.Helper()
		out, err := exec.Command(nativeIPPath, args...).Output()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	routesBefore := snapshot("-j", "-4", "route", "show", "table", "all")
	rulesBefore := snapshot("-j", "-4", "rule", "show")
	if _, err := inspectTCPPolicyRules(addr); err != nil {
		t.Fatalf("representable dport and UID policies rejected: %v", err)
	}
	// User namespaces map the outer UID (994 on the disposable host)
	// to root inside this namespace. That makes the genuine host-owned
	// /usr/bin/ip appear unmapped (65534), so the production trust gate
	// deliberately refuses this process. Exercise the exact flow query
	// and shared socket binding function separately here; the full CLI
	// and root ownership trust are tested on the real host elsewhere.
	var bound atomic.Bool
	dialer := net.Dialer{Timeout: 250 * time.Millisecond, Control: interfaceBoundTCPControl("scveth0", &bound)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(443)))
	if conn != nil {
		_ = conn.Close()
		t.Fatal("unreachable test endpoint unexpectedly connected")
	}
	if err == nil || !bound.Load() {
		t.Fatalf("failed interface binding or unbound fallback: bound=%v error=%v", bound.Load(), err)
	}
	if !bytes.Equal(routesBefore, snapshot("-j", "-4", "route", "show", "table", "all")) ||
		!bytes.Equal(rulesBefore, snapshot("-j", "-4", "rule", "show")) {
		t.Fatal("probe mutated isolated namespace route or rule")
	}

	for _, tc := range []struct {
		name     string
		selector []string
	}{
		{"source", []string{"from", "10.77.0.0/24"}},
		{"mark", []string{"fwmark", "0x1/0xff"}},
		{"source_port", []string{"ipproto", "tcp", "sport", "1000-4000"}},
		{"output_interface", []string{"oif", "scveth0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-4", "rule", "add", "pref", "90"}, tc.selector...)
			run(append(args, "table", "101")...)
			_, err := inspectTCPPolicyRules(addr)
			if ErrorCode(err) != "underlay_policy_unsupported" {
				t.Fatalf("ambiguous policy unexpectedly accepted: %v", err)
			}
			run("-4", "rule", "del", "pref", "90")
		})
	}
}
