package sc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// A caller's PATH is untrusted even if the manager is run by root. No
// read-only status check may resolve a shadow systemctl executable.
func TestSystemctlCommandIgnoresPATHShadow(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd target is Linux")
	}
	if err := trustedSystemctlExecutable(); err != nil {
		t.Fatalf("required native systemctl missing or unsafe: %v", err)
	}
	dir := t.TempDir()
	witness := filepath.Join(dir, "executed")
	shadow := filepath.Join(dir, "systemctl")
	payload := "#!/bin/sh\nprintf 'executed' > '" + witness + "'\nprintf 'active\\n'\n"
	if err := os.WriteFile(shadow, []byte(payload), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	_, _ = New(t.TempDir(), "", 0).unitActive()
	if _, err := os.Stat(witness); !os.IsNotExist(err) {
		t.Fatalf("manager executed untrusted systemctl from PATH: %v", err)
	}
}

func makeSystemctlFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "usr", "bin", "systemctl")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	return root, executable
}

func TestNativeSystemctlTrustBoundary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native filesystem identity is Linux-only")
	}
	root, binary := makeSystemctlFixture(t)
	if err := verifyTrustedSystemctlAt(root, binary, uint32(os.Getuid())); err != nil {
		t.Fatalf("valid private fixture rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, root, binary string) (string, string, uint32)
	}{
		{"writable-ancestor", func(t *testing.T, root, binary string) (string, string, uint32) {
			if err := os.Chmod(filepath.Join(root, "usr"), 0775); err != nil {
				t.Fatal(err)
			}
			return root, binary, uint32(os.Getuid())
		}},
		{"writable-binary", func(t *testing.T, root, binary string) (string, string, uint32) {
			if err := os.Chmod(binary, 0775); err != nil {
				t.Fatal(err)
			}
			return root, binary, uint32(os.Getuid())
		}},
		{"binary-symlink", func(t *testing.T, root, binary string) (string, string, uint32) {
			if err := os.Remove(binary); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/usr/bin/true", binary); err != nil {
				t.Fatal(err)
			}
			return root, binary, uint32(os.Getuid())
		}},
		{"ancestor-symlink", func(t *testing.T, root, binary string) (string, string, uint32) {
			if err := os.Rename(filepath.Join(root, "usr"), filepath.Join(root, "moved")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("moved", filepath.Join(root, "usr")); err != nil {
				t.Fatal(err)
			}
			return root, binary, uint32(os.Getuid())
		}},
		{"nonexecutable", func(t *testing.T, root, binary string) (string, string, uint32) {
			if err := os.Chmod(binary, 0600); err != nil {
				t.Fatal(err)
			}
			return root, binary, uint32(os.Getuid())
		}},
		{"wrong-owner", func(t *testing.T, root, binary string) (string, string, uint32) {
			return root, binary, uint32(os.Getuid()) + 1
		}},
		{"outside-root", func(t *testing.T, root, binary string) (string, string, uint32) {
			return root, filepath.Join(filepath.Dir(root), "outside-systemctl"), uint32(os.Getuid())
		}},
		{"noncanonical-root", func(t *testing.T, root, binary string) (string, string, uint32) {
			return root + "/.", binary, uint32(os.Getuid())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, binary := makeSystemctlFixture(t)
			root, binary, uid := tc.damage(t, root, binary)
			if err := verifyTrustedSystemctlAt(root, binary, uid); ErrorCode(err) != "service_binary_untrusted" {
				t.Fatalf("untrusted fixture allowed or incorrect classification: %v", err)
			}
		})
	}
}

func TestSystemctlCommandPinsNativeAndSanitizesEnvironment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native systemd target is Linux")
	}
	if err := trustedSystemctlExecutable(); err != nil {
		t.Fatalf("required native systemctl missing or unsafe: %v", err)
	}
	t.Setenv("PATH", t.TempDir())
	t.Setenv("LD_PRELOAD", "/tmp/foreign-shared-object")
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/tmp/untrusted")
	t.Setenv("SYSTEMD_PAGER", "cat /tmp/foreign")
	cmd, err := trustedSystemctlCommand(context.Background(), "show", DefaultUnit, "--property=ActiveState")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path != nativeSystemctlPath ||
		!reflect.DeepEqual(cmd.Args, []string{nativeSystemctlPath, "--system", "--no-pager", "show", DefaultUnit, "--property=ActiveState"}) {
		t.Fatalf("systemctl command could resolve an unexpected binary or operation: path=%q args=%v", cmd.Path, cmd.Args)
	}
	if !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}) {
		t.Fatalf("untrusted environment leaked into native control command: %v", cmd.Env)
	}
}

func TestStatusFailsClosedWhenSystemdOrOwnershipUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name, desired, observed, expectedHealth, expectedCode string
		inspectErr, ownerErr                                  error
	}{
		{name: "direct-inactive", desired: "direct", observed: "inactive", expectedHealth: "not_tested"},
		{name: "proxy-active", desired: "proxy", observed: "active", expectedHealth: "not_tested"},
		{name: "proxy-dead", desired: "proxy", observed: "failed", expectedHealth: "core_unavailable"},
		{name: "direct-active", desired: "direct", observed: "active", expectedHealth: "unexpected_active_service"},
		{name: "direct-failed", desired: "direct", observed: "failed", expectedHealth: "historical_proxy_failure_direct_unaffected"},
		{name: "unknown", desired: "direct", observed: "unknown", expectedHealth: "service_state_unavailable", expectedCode: "service_state_unavailable"},
		{name: "transport-error-with-active-looking-output", desired: "proxy", observed: "active", inspectErr: errors.New("transport broken"), expectedHealth: "service_state_unavailable", expectedCode: "service_state_unavailable"},
		{name: "native-executable-untrusted", desired: "direct", observed: "unknown", inspectErr: Fault("service_binary_untrusted", "native systemd controller is missing or untrusted"), expectedHealth: "service_state_unavailable", expectedCode: "service_binary_untrusted"},
		{name: "foreign-active-owner", desired: "proxy", observed: "active", ownerErr: errors.New("foreign unit"), expectedHealth: "service_ownership_conflict", expectedCode: "service_conflict"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New(filepath.Join(t.TempDir(), "private-state"), "", 0)
			if err := m.withLock(func() error { return m.save(State{Version: 1, Desired: tc.desired, Port: m.Port}) }); err != nil {
				t.Fatal(err)
			}
			status, err := m.statusWithService(func() (string, error) { return tc.observed, tc.inspectErr }, func() error { return tc.ownerErr })
			if ErrorCode(err) != tc.expectedCode || status.Observed != tc.observed && !(status.Observed == "unknown" && tc.inspectErr != nil) ||
				status.Health != tc.expectedHealth || status.Desired != tc.desired {
				t.Fatalf("misclassified systemd error: status=%+v err=%v", status, err)
			}
			if tc.expectedCode != "" && err != nil && strings.Contains(err.Error(), "foreign unit") {
				t.Fatal("unsafe native error leaked into status")
			}
		})
	}
}

func TestNativeSystemctlActivityRejectsContradictoryExit(t *testing.T) {
	for _, tc := range []struct {
		name, script, expected string
		ok                     bool
	}{
		{"active", "printf 'active\n'; exit 0", "active", true},
		{"inactive", "printf 'inactive\n'; exit 3", "inactive", true},
		{"failed", "printf 'failed\n'; exit 3", "failed", true},
		{"false-active", "printf 'active\n'; exit 3", "unknown", false},
		{"false-inactive", "printf 'inactive\n'; exit 0", "unknown", false},
		{"incomplete", "printf 'inactive\n'; exit 2", "unknown", false},
		{"unknown-unit", "printf 'unknown\n'; exit 4", "unknown", false},
		{"multiline", "printf 'active\ninactive\n'; exit 0", "unknown", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := exec.Command("/bin/sh", "-c", tc.script).CombinedOutput()
			state, parseErr := parseUnitActivity(out, err)
			if state != tc.expected || (parseErr == nil) != tc.ok {
				t.Fatalf("contradictory status accepted: output=%q exit=%v state=%q parse=%v", out, err, state, parseErr)
			}
		})
	}
}
