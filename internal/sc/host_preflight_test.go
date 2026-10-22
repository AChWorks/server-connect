package sc

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPreflightRejectsAddressesBeforeAnyHostInspection(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		peer     string
	}{
		{"-o", ""},
		{"--help", ""},
		{"https://example.test/path", ""},
		{"example.com", ""},
		{"224.0.0.1", ""},
		{"0.0.0.0", ""},
		{"255.255.255.255", ""},
		{"169.254.10.20", ""}, // ambiguous link-local interface
		{"fe80::1", ""},       // missing scoped interface
		{"fe80::1%eth0", ""},
		{"::ffff:127.0.0.1", ""},
		{"", "not-an-ip"},
		{"", "ff02::1"},
		{"", "255.255.255.255"},
		{"", "169.254.10.20"},
		{"", "fe80::1"},
		{"", "fe80::1%eth0"},
	} {
		_, err := InspectHostRoutes(tc.endpoint, tc.peer)
		if err == nil || ErrorCode(err) != "invalid_arguments" {
			t.Fatalf("endpoint=%q peer=%q expected invalid_arguments, got %v", tc.endpoint, tc.peer, err)
		}
	}
}

func TestPreflightJSONValidationAndBounds(t *testing.T) {
	for _, value := range []string{`{"unexpected":"object"}`, "null", "[12]", `["string"]`, "{", ""} {
		if _, err := decodeRouteArray([]byte(value)); err == nil {
			t.Fatalf("accepted non-array or malformed route data: %q", value)
		}
	}
	if _, err := decodeRouteArray([]byte("[]")); err != nil {
		t.Fatalf("empty native route list is valid: %v", err)
	}
	if _, err := decodeRouteArray([]byte(`[{"dst":"default"}]`)); err != nil {
		t.Fatalf("valid route list rejected: %v", err)
	}
	var capture boundedIPOutput
	if _, err := capture.Write(bytes.Repeat([]byte("x"), hostSnapshotMaxBytes)); err != nil {
		t.Fatalf("capture exactly at limit rejected: %v", err)
	}
	if _, err := capture.Write([]byte("x")); err == nil {
		t.Fatal("capture over limit succeeded")
	}
	if capture.Len() != hostSnapshotMaxBytes {
		t.Fatal("over-limit write modified captured bytes")
	}
}

func TestPreflightCannotExecutePATHShadow(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native Linux iproute2 test")
	}
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("native iproute2 not installed")
	}
	shadow := filepath.Join(t.TempDir(), "ip")
	if err := os.WriteFile(shadow, []byte("#!/bin/sh\nexit 91\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(shadow))
	result, err := InspectHostRoutes("127.0.0.1", "")
	if err != nil || !result.ReadOnly || result.ActivationReady {
		t.Fatalf("host-preflight used untrusted PATH or made unsafe claim: %v", err)
	}
}

func TestPreflightNoHostMutationOrConnectivityAssertion(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native Linux iproute2 test")
	}
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("minimal CI container does not provide iproute2")
	}
	report, err := InspectHostRoutes("127.0.0.1", "127.0.0.2")
	if err != nil {
		t.Fatalf("real native iproute2 inspection: %v", err)
	}
	if !report.ReadOnly || report.ActivationReady || report.SnapshotAtomic || report.Mode != "observation_only" {
		t.Fatalf("unsafe readiness or snapshot claim: %+v", report)
	}
	for _, snapshot := range []json.RawMessage{report.Links, report.IPv4Routes, report.IPv6Routes, report.IPv4Rules, report.IPv6Rules} {
		if !json.Valid(snapshot) || !strings.HasPrefix(string(snapshot), "[") {
			t.Fatalf("invalid native JSON array: %s", snapshot)
		}
	}
	if report.Endpoint == nil || report.Endpoint.Target != "127.0.0.1" ||
		report.ManagementPeer == nil || report.ManagementPeer.Target != "127.0.0.2" {
		t.Fatalf("literal route lookup identity mismatch: %+v", report)
	}
	if len(report.Limitations) < 3 {
		t.Fatalf("missing explicit safety limitations")
	}
}

func TestPreflightAcceptsPrivateLoopbackAndLiteralUnicastSyntax(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.21.0.3", "192.168.2.7", "198.51.100.10", "::1", "fd00::1234", "2001:db8::42"} {
		for _, peer := range []bool{false, true} {
			primary, management := value, ""
			if peer {
				primary, management = "", value
			}
			// Validate both roles without depending on host connectivity.
			for _, entry := range []struct{ addr, label string }{{primary, "endpoint"}, {management, "management peer"}} {
				if _, err := parsePreflightAddress(entry.addr, entry.label); err != nil {
					t.Fatalf("valid %q for peer=%v was rejected: %v", value, peer, err)
				}
			}
		}
	}
}

func TestPreflightTrustedNativeExecutableFixtures(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux executable ownership trust")
	}
	// Fresh independent fixture directories avoid any host-wide chmod/chown.
	makeFixture := func(t *testing.T) (string, string) {
		t.Helper()
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		executable := filepath.Join(root, "usr", "bin", "ip")
		if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := verifyTrustedIPPath(root, executable, uint32(os.Getuid())); err != nil {
			t.Fatalf("valid fixture rejected: %v", err)
		}
		return root, executable
	}
	for _, scenario := range []struct {
		name   string
		damage func(t *testing.T, root, executable string)
	}{
		{"executable-group-writable", func(t *testing.T, _, binary string) {
			t.Helper()
			if err := os.Chmod(binary, 0775); err != nil {
				t.Fatal(err)
			}
		}},
		{"executable-nonexecutable", func(t *testing.T, _, binary string) {
			t.Helper()
			if err := os.Chmod(binary, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"executable-setuid", func(t *testing.T, _, binary string) {
			t.Helper()
			if err := os.Chmod(binary, 0755|os.ModeSetuid); err != nil {
				t.Fatal(err)
			}
		}},
		{"executable-setgid", func(t *testing.T, _, binary string) {
			t.Helper()
			if err := os.Chmod(binary, 0755|os.ModeSetgid); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable-parent", func(t *testing.T, root, _ string) {
			t.Helper()
			if err := os.Chmod(filepath.Join(root, "usr"), 0777); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink-executable", func(t *testing.T, _, binary string) {
			t.Helper()
			if err := os.Rename(binary, binary+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("ip.real", binary); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink-directory", func(t *testing.T, root, _ string) {
			t.Helper()
			bin := filepath.Join(root, "usr", "bin")
			if err := os.Rename(bin, bin+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("bin.real", bin); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			root, executable := makeFixture(t)
			scenario.damage(t, root, executable)
			if err := verifyTrustedIPPath(root, executable, uint32(os.Getuid())); ErrorCode(err) != "host_preflight_unavailable" {
				t.Fatalf("untrusted path accepted: %v", err)
			}
		})
	}
	root, executable := makeFixture(t)
	if err := verifyTrustedIPPath(root, executable, uint32(os.Getuid())+1); ErrorCode(err) != "host_preflight_unavailable" {
		t.Fatalf("incorrect file owner accepted: %v", err)
	}
	if err := verifyTrustedIPPath(root, filepath.Join(root, "..", "foreign", "ip"), uint32(os.Getuid())); ErrorCode(err) != "host_preflight_unavailable" {
		t.Fatalf("path traversal accepted: %v", err)
	}
	if err := trustedHostIPExecutable(); err != nil {
		t.Fatalf("real Debian 13 native iproute2 trust failed: %v", err)
	}
}

func TestPreflightNativeCommandTimeoutAndRetainedPipe(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux subprocess lifecycle regression")
	}
	for _, scenario := range []struct {
		name    string
		script  string
		timeout time.Duration
		limit   time.Duration
	}{
		{"hung-immediate-process", "#!/bin/sh\nexec sleep 5\n", 80 * time.Millisecond, 2 * time.Second},
		// The immediate shell exits 0, but the descendant inherits stdout.
		// Without WaitDelay, cmd.Run would wait for the sleep process to exit.
		{"retained-stdout-pipe", "#!/bin/sh\nsleep 2 &\nexit 0\n", 2 * time.Second, 1500 * time.Millisecond},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if scenario.name == "retained-stdout-pipe" {
				// The controlled descendant is intentionally left holding a pipe
				// to prove WaitDelay. Let the short-lived fixture exit before
				// the Test Server command boundary checks for background work.
				t.Cleanup(func() { time.Sleep(2300 * time.Millisecond) })
			}
			path := filepath.Join(t.TempDir(), "fixture-ip")
			if err := os.WriteFile(path, []byte(scenario.script), 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), scenario.timeout)
			defer cancel()
			start := time.Now()
			_, err := runIPJSONCommand(ctx, path)
			elapsed := time.Since(start)
			if ErrorCode(err) != "host_preflight_unavailable" || elapsed >= scenario.limit {
				t.Fatalf("unbounded process or retained pipe: elapsed=%v err=%v", elapsed, err)
			}
		})
	}
}

func TestPreflightNativeOutputLimitEndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux subprocess output limit fixture")
	}
	path := filepath.Join(t.TempDir(), "fixture-ip")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nhead -c 1100000 /dev/zero\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := runIPJSONCommand(ctx, path); ErrorCode(err) != "host_preflight_unavailable" {
		t.Fatalf("oversized native output accepted or failed with wrong error: %v", err)
	}
}
