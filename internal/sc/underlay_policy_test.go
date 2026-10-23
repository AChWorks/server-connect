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
	"strings"
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

// Environment markers alone must never select a network-mutating path.
// These subprocesses deliberately run without unshare, with no phase token.
// They must refuse the forged invocation before inspecting host networking.
func TestPrivateNamespaceForgedChildMarkersFailClosed(t *testing.T) {
	for _, tc := range []struct{ name, env, testName, refusal string }{
		{"tcp", "SC_TEST_UNDERLAY_NETNS", "TestUnderlayTCPFlowPolicyInPrivateNamespace", "unsupported read-only policy assertion phase"},
		{"dns", "SC_TEST_DNS_NETNS", "TestUnderlayDNSFlowPolicyInPrivateNamespace", "unrecognized read-only DNS regression phase"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^"+tc.testName+"$", "-test.v")
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", tc.env + "=child"}
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.refusal) {
				t.Fatalf("forged child-mode marker did not fail closed: err=%v output=%s", err, out)
			}
		})
	}
}

// Native policy mutations are executed only in a disposable namespace:
// /usr/bin/unshare -Urn starts /usr/bin/sh, which configures the kernel rules
// before starting read-only Go assertions. Environment markers select only
// read-only assertions and cannot reach ip route/rule/link add or delete.
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
	requireDisposableUserNetNamespace(t)
	const script = `set -eu
ip=/usr/bin/ip
"$ip" link set lo up
"$ip" link add scveth0 type veth peer name scveth1
"$ip" addr add 10.77.0.1/24 dev scveth0
"$ip" addr add 10.78.0.1/24 dev scveth1
"$ip" link set scveth0 up
"$ip" link set scveth1 up
"$ip" -4 route add 198.51.100.0/24 dev lo
"$ip" -4 route add 198.51.100.0/24 dev scveth0 table 100
"$ip" -4 route add 198.51.100.0/24 dev scveth1 table 101
"$ip" -4 rule add pref 100 ipproto tcp dport 443 table 100
"$ip" -4 rule add pref 101 uidrange 0-0 ipproto tcp dport 8443 table 101
SC_TEST_UNDERLAY_NETNS=child SC_TEST_UNDERLAY_CASE=base "$1" -test.run=^TestUnderlayTCPFlowPolicyInPrivateNamespace$ -test.timeout=4s -test.v
"$ip" -4 rule add pref 90 from 10.77.0.0/24 table 101
SC_TEST_UNDERLAY_NETNS=child SC_TEST_UNDERLAY_CASE=source "$1" -test.run=^TestUnderlayTCPFlowPolicyInPrivateNamespace$ -test.timeout=4s -test.v
"$ip" -4 rule del pref 90
"$ip" -4 rule add pref 90 fwmark 0x1/0xff table 101
SC_TEST_UNDERLAY_NETNS=child SC_TEST_UNDERLAY_CASE=mark "$1" -test.run=^TestUnderlayTCPFlowPolicyInPrivateNamespace$ -test.timeout=4s -test.v
"$ip" -4 rule del pref 90
"$ip" -4 rule add pref 90 ipproto tcp sport 1000-4000 table 101
SC_TEST_UNDERLAY_NETNS=child SC_TEST_UNDERLAY_CASE=source_port "$1" -test.run=^TestUnderlayTCPFlowPolicyInPrivateNamespace$ -test.timeout=4s -test.v
"$ip" -4 rule del pref 90
"$ip" -4 rule add pref 90 oif scveth0 table 101
SC_TEST_UNDERLAY_NETNS=child SC_TEST_UNDERLAY_CASE=output_interface "$1" -test.run=^TestUnderlayTCPFlowPolicyInPrivateNamespace$ -test.timeout=4s -test.v`
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	out, stderr, err := runBoundedTestProcess(ctx, "/usr/bin/unshare", "-Urn", "/usr/bin/sh", "-c", script, "underlay-isolated", os.Args[0])
	if err != nil || ctx.Err() != nil {
		t.Fatalf("isolated policy test failed: %v context=%v stdout=%s stderr=%s", err, ctx.Err(), out, stderr)
	}
	t.Logf("isolated policy test succeeded: %s", out)
}

func testUnderlayTCPFlowPolicyNamespaceChild(t *testing.T) {
	// This child has no network-mutating command path. Even a forged
	// SC_TEST_UNDERLAY_NETNS marker can only run read-only assertions.
	caseName := os.Getenv("SC_TEST_UNDERLAY_CASE")
	if caseName != "base" {
		switch caseName {
		case "source", "mark", "source_port", "output_interface":
			_, err := inspectTCPPolicyRules(netip.MustParseAddr("198.51.100.9"))
			if ErrorCode(err) != "underlay_policy_unsupported" {
				t.Fatalf("ambiguous policy %s unexpectedly accepted: %v", caseName, err)
			}
		default:
			t.Fatalf("unsupported read-only policy assertion phase %q", caseName)
		}
		return
	}

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

}
