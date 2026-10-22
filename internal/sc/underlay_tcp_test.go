package sc

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUnderlayInputFailClosed(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		port int
	}{
		{"", 443},
		{"example.org", 443},
		{"-o", 443},
		{"127.0.0.1", 0},
		{"127.0.0.1", 65536},
		{"127.0.0.1", -1},
		{"224.0.0.1", 443},
		{"255.255.255.255", 443},
		{"fe80::1%eth0", 443},
		{"::ffff:127.0.0.1", 443},
		{"http://127.0.0.1", 443},
	} {
		report, err := InspectUnderlayTCP(tc.ip, tc.port)
		if err == nil || ErrorCode(err) != "invalid_arguments" {
			t.Fatalf("invalid TCP endpoint %q:%d accepted: %v %+v", tc.ip, tc.port, err, report)
		}
	}
}

func TestUnderlayRouteIdentityComparison(t *testing.T) {
	a := underlayRoute{Dst: "203.0.113.17", Device: "eth0", Gateway: "192.0.2.1", Source: "192.0.2.3", Table: json.RawMessage("123")}
	if !sameUnderlayRoute(a, a) {
		t.Fatal("equal route rejected")
	}
	for _, mutate := range []func(*underlayRoute){
		func(x *underlayRoute) { x.Device = "tun0" },
		func(x *underlayRoute) { x.Gateway = "192.0.2.4" },
		func(x *underlayRoute) { x.Source = "192.0.2.9" },
		func(x *underlayRoute) { x.Table = json.RawMessage("124") },
		func(x *underlayRoute) { x.Kind = "unreachable" },
	} {
		b := a
		mutate(&b)
		if sameUnderlayRoute(a, b) {
			t.Fatalf("changed route treated as stable: %+v", b)
		}
	}
}

func TestUnderlayActualLoopbackTCPBoundAndNonMutating(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux iproute2-specific diagnostic")
	}
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("native iproute2 absent")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_ = conn.Close()
		}
		accepted <- err
	}()
	snapshot := func(flag string) []byte {
		t.Helper()
		cmd := exec.Command(nativeIPPath, "-j", flag, "route", "show", "table", "all")
		b, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	before4, before6 := snapshot("-4"), snapshot("-6")
	ruleSnapshot := func(family string) []byte {
		t.Helper()
		out, err := exec.Command(nativeIPPath, "-j", family, "rule", "show").Output()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	beforeRules4, beforeRules6 := ruleSnapshot("-4"), ruleSnapshot("-6")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	t.Setenv("PATH", t.TempDir()) // an ip shadow, if any, cannot influence native ip.
	report, err := InspectUnderlayTCP("127.0.0.1", port)
	if err != nil {
		t.Fatalf("real interface-bound TCP test failed: %+v: %v", report, err)
	}
	select {
	case acceptErr := <-accepted:
		if acceptErr != nil {
			t.Fatalf("local fixture did not receive probe: %v", acceptErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no fixture TCP connection observed")
	}
	if report.Mode != "underlay_tcp_diagnostic" || !report.ReadOnly || report.ActivationReady ||
		!report.InterfaceBound || !report.RouteStable || !report.SocketConnected ||
		report.Outcome != "tcp_connected" || report.RouteDevice != "lo" || report.Protocol != "tcp" {
		t.Fatalf("wrong underlay evidence, claimed safety or unbound fallback: %+v", report)
	}
	if len(report.Limitations) < 3 || !strings.Contains(strings.ToLower(strings.Join(report.Limitations, " ")), "ssh") {
		t.Fatalf("missing mandatory activation/safety caveats: %+v", report.Limitations)
	}
	if !bytes.Equal(before4, snapshot("-4")) || !bytes.Equal(before6, snapshot("-6")) {
		t.Fatal("TCP diagnostic changed the host route tables")
	}
	if !bytes.Equal(beforeRules4, ruleSnapshot("-4")) || !bytes.Equal(beforeRules6, ruleSnapshot("-6")) {
		t.Fatal("TCP diagnostic changed the host policy-routing rules")
	}
}

func TestUnderlayClosedPortReportsFailureWithPathEvidence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux iproute2-specific diagnostic")
	}
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("native iproute2 absent")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	report, err := InspectUnderlayTCP("127.0.0.1", port)
	if ErrorCode(err) != "underlay_unreachable" || report.Outcome != "tcp_refused" ||
		!report.RouteStable || !report.InterfaceBound || report.SocketConnected || report.ActivationReady {
		t.Fatalf("unreachable endpoint was accepted or silently failed over: %+v error=%v", report, err)
	}
}

func TestUnderlayIPv6LoopbackOnNativeHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux iproute2-specific diagnostic")
	}
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("native iproute2 absent")
	}
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable on this host: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	done := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			_ = c.Close()
		}
		done <- err
	}()
	report, err := InspectUnderlayTCP("::1", port)
	if err != nil {
		t.Fatalf("native IPv6 loopback bound probe failed: %+v error=%v", report, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("IPv6 listener did not accept: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("IPv6 listener timed out")
	}
	if report.Endpoint != "::1" || !report.RouteStable || !report.InterfaceBound ||
		!report.SocketConnected || report.ActivationReady || report.RouteDevice != "lo" {
		t.Fatalf("incorrect IPv6 interface evidence: %+v", report)
	}
}
