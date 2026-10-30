package sc

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func requireNativeAPT(t *testing.T) {
	t.Helper()
	for _, installed := range []string{systemAPT, systemAPTGet, systemAPTConfig} {
		if err := verifyNativeAPTExecutable(installed); err != nil {
			t.Skipf("native Linux APT unavailable (must be proved on target Debian): %v", err)
		}
	}
}

func TestNativeAPTAllowlistCannotBeExpandedByCallerPath(t *testing.T) {
	for _, path := range []string{"/usr/local/bin/apt-get", "/tmp/apt-get",
		"/usr/bin/sh", "/usr/bin/dpkg", ""} {
		if err := verifyNativeAPTExecutable(path); ErrorCode(err) != "apt_untrusted_executable" {
			t.Fatalf("arbitrary executable path wrongly approved: %q", path)
		}
	}
}

func TestNativeAPTCommandIsAnchoredToSystemInstall(t *testing.T) {
	requireNativeAPT(t)
	for token, want := range map[string]string{
		"apt": systemAPT, "apt-get": systemAPTGet,
		systemAPT: systemAPT, systemAPTGet: systemAPTGet,
	} {
		got, err := trustedAPTCommand(token)
		if err != nil || got != want {
			t.Fatalf("native APT token refused: %q -> %q (%v)", token, got, err)
		}
	}
	for _, name := range []string{"apt", "apt-get"} {
		legacy := "/bin/" + name
		real, err := filepath.EvalSymlinks(legacy)
		if err == nil && real == "/usr/bin/"+name {
			got, e := trustedAPTCommand(legacy)
			if e != nil || got != real {
				t.Fatalf("native Debian usrmerge alias refused: %v %q", e, got)
			}
		}
	}
	for _, token := range []string{"", "curl", "./apt-get", "tmp/apt-get", "/tmp/apt-get",
		"/usr/local/bin/apt-get", "/usr/bin/../local/bin/apt-get", "/tmp/apt",
		"/usr/bin/apt-config"} {
		got, err := trustedAPTCommand(token)
		if err == nil || got != "" {
			t.Fatalf("foreign tool path accepted: %q -> %q", token, got)
		}
	}
}

func TestAPTShadowCannotGetCredentialDescriptor(t *testing.T) {
	requireNativeAPT(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "untrusted-executed")
	for _, name := range []string{"apt-get", "apt", "apt-config"} {
		path := filepath.Join(dir, name)
		// A fake process would write a marker (and could read /proc/self/fd/3).
		// It must never run even once, including during APT config preflight.
		script := "#!/bin/sh\nprintf 'executed' > '" + marker + "'\nexit 1\n"
		if err := os.WriteFile(path, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	for _, token := range []string{"apt-get", "apt", filepath.Join(dir, "apt-get"), filepath.Join(dir, "apt")} {
		m := New(filepath.Join(t.TempDir(), "state"), "", 0)
		code, err := m.Apt([]string{token, "update"})
		if code == 0 || ErrorCode(err) != "apt_untrusted_executable" {
			t.Fatalf("shadow APT was not rejected before credential access: code=%d, err=%v", code, err)
		}
	}
	// The internal APT policy inspector must use verified absolute
	// /usr/bin/apt-config; a PATH-shadowed binary is never invoked.
	proxy, _ := url.Parse("http://sc:synthetic-secret-never-log@127.0.0.1:20807")
	fd, err := privateAptConfig(t.TempDir(), proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	if err = verifyEffectiveAptProxy(fd, proxy.String(), nil); err != nil {
		t.Fatalf("trusted native apt-config failed with shadow in PATH: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("shadow executable was invoked")
	}
}

func TestAPTCredentialExecutionEnvDoesNotInheritLoaderOrPath(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/unsafe-preload")
	t.Setenv("LD_LIBRARY_PATH", "/tmp/unsafe-library")
	t.Setenv("GCONV_PATH", "/tmp/untrusted-gconv")
	t.Setenv("PATH", "/tmp/untrusted-binaries")
	t.Setenv("APT_CONFIG", "/tmp/untrusted-apt-config")
	t.Setenv("HTTP_PROXY", "http://untrusted.example")
	env := safeAptEnv()
	haveSafePath := false
	for _, value := range env {
		key, val, ok := strings.Cut(value, "=")
		if !ok {
			t.Fatal("malformed environment")
		}
		switch strings.ToLower(key) {
		case "ld_preload", "ld_library_path", "gconv_path", "apt_config", "http_proxy":
			t.Fatal("inherited untrusted environment affected native APT child")
		case "path":
			if val != "/usr/sbin:/usr/bin:/sbin:/bin" {
				t.Fatal("child PATH was not fixed to system directories")
			}
			haveSafePath = true
		}
	}
	if !haveSafePath {
		t.Fatal("native APT child PATH is missing")
	}
}

func createNativeAPTMethodFixture(t *testing.T, full bool) (string, uint32) {
	t.Helper()
	dir := t.TempDir()
	names := append([]string{}, requiredAPTMethods...)
	if full {
		names = append(names, "rred", "mirror", "copy", "cdrom", "store", "sqv",
			"mirror+http", "mirror+https", "mirror+file", "mirror+copy")
	}
	for _, name := range names {
		path := filepath.Join(dir, name)
		if target, ok := nativeAPTMethodAliases[name]; ok {
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, []byte("fixture - not executed"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Lstat(filepath.Join(dir, "http"))
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("native ownership metadata unavailable")
	}
	return dir, stat.Uid
}

func TestNativeAPTMethodInventorySupportsFullAndMinimalDebian13(t *testing.T) {
	for _, full := range []bool{false, true} {
		dir, uid := createNativeAPTMethodFixture(t, full)
		if err := verifyNativeAPTMethodInventory(dir, uid); err != nil {
			t.Fatalf("full=%t native optional inventory rejected: %v", full, err)
		}
	}
	// Root ownership and modes of every present helper are checked on the
	// actual supported host, not only on test-created files.
	if err := verifyNativeAPTMethods(); err != nil {
		t.Fatalf("present native Debian 13 acquisition helpers not verified: %v", err)
	}
}

func TestNativeAPTMethodInventoryFailsClosedOnUntrustedHelpers(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, dir string)
	}{
		{"missing required method", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "http")); err != nil {
				t.Fatal(err)
			}
		}},
		{"optional non executable rred", func(t *testing.T, dir string) {
			if err := os.Chmod(filepath.Join(dir, "rred"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable mirror", func(t *testing.T, dir string) {
			if err := os.Chmod(filepath.Join(dir, "mirror"), 0775); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable rred", func(t *testing.T, dir string) {
			if err := os.Chmod(filepath.Join(dir, "rred"), 0757); err != nil {
				t.Fatal(err)
			}
		}},
		{"untrusted alias traversal", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "mirror+https")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../outside", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"untrusted absolute alias", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "https")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/usr/bin/sh", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"alias to wrong local executable", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "mirror+http")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("http", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"alias target missing", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "mirror")); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink replaces regular rred", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "rred")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("http", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"unknown executable", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "custom-transport"), []byte("fixture - not executed"), 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{"unknown nonexecutable", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "foreign-readme"), []byte("fixture - not executed"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"disabled sentinel exists", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "false"), []byte("fixture - not executed"), 0755); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, uid := createNativeAPTMethodFixture(t, true)
			tc.mutate(t, dir)
			if err := verifyNativeAPTMethodInventory(dir, uid); ErrorCode(err) != "apt_untrusted_executable" {
				t.Fatalf("untrusted APT method inventory accepted: %v", err)
			}
		})
	}
}

func TestNativeAPTMethodInventoryRejectsNonTrustedOwnership(t *testing.T) {
	dir, uid := createNativeAPTMethodFixture(t, true)
	// The same real UID check used with expectedUID=0 in production must
	// reject a regular native helper that belongs to another principal.
	if err := verifyNativeAPTMethodInventory(dir, uid+1); ErrorCode(err) != "apt_untrusted_executable" {
		t.Fatalf("different-owner native method incorrectly accepted: %v", err)
	}
}

func TestAPTLegacyCompatibilityRequiresExactHostAndBothVersions(t *testing.T) {
	for _, tc := range []struct {
		name, target, command, config string
		want                          aptCompatibility
	}{
		{"stock Debian12", "debian-12-amd64", "apt 2.6.1 (amd64)", "apt 2.6.1 (amd64)", aptDebian12Native261},
		{"Debian13 with old binary", "debian-13-amd64", "apt 2.6.1 (amd64)", "apt 2.6.1 (amd64)", aptStrictNative},
		{"unverified OS", "", "apt 2.6.1 (amd64)", "apt 2.6.1 (amd64)", aptStrictNative},
		{"unknown target", "debian-12-arm64", "apt 2.6.1 (amd64)", "apt 2.6.1 (amd64)", aptStrictNative},
		{"APT3", "debian-12-amd64", "apt 3.0.3 (amd64)", "apt 3.0.3 (amd64)", aptStrictNative},
		{"command mismatch", "debian-12-amd64", "apt 3.0.3 (amd64)", "apt 2.6.1 (amd64)", aptStrictNative},
		{"config mismatch", "debian-12-amd64", "apt 2.6.1 (amd64)", "apt 3.0.3 (amd64)", aptStrictNative},
		{"unknown patch", "debian-12-amd64", "apt 2.6.2 (amd64)", "apt 2.6.2 (amd64)", aptStrictNative},
		{"missing command version", "debian-12-amd64", "", "apt 2.6.1 (amd64)", aptStrictNative},
		{"missing config version", "debian-12-amd64", "apt 2.6.1 (amd64)", "", aptStrictNative},
		{"ambiguous banner", "debian-12-amd64", "apt 2.6.1 (amd64) extra", "apt 2.6.1 (amd64) extra", aptStrictNative},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := aptCompatibilityForVersions(tc.target, tc.command, tc.config); got != tc.want {
				t.Fatalf("incorrect native compatibility boundary: got=%d want=%d", got, tc.want)
			}
		})
	}
}

func createDebian12APTMethodFixture(t *testing.T) (string, uint32) {
	t.Helper()
	dir, uid := createNativeAPTMethodFixture(t, true)
	for _, name := range []string{"ftp", "rsh"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture - not executed"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"ssh": "rsh", "mirror+ftp": "mirror"} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return dir, uid
}

func TestNativeAPTLegacyInventoryRequiresVerified261Compatibility(t *testing.T) {
	dir, uid := createDebian12APTMethodFixture(t)
	if err := verifyNativeAPTMethodInventoryWithCompatibility(dir, uid, aptDebian12Native261); err != nil {
		t.Fatal("stock Debian12 legacy inventory refused:", err)
	}
	for _, mode := range []aptCompatibility{aptStrictNative, aptCompatibility(255)} {
		if err := verifyNativeAPTMethodInventoryWithCompatibility(dir, uid, mode); ErrorCode(err) != "apt_untrusted_executable" {
			t.Fatal("legacy inventory accepted without the verified Debian12/2.6.1 boundary")
		}
	}
	if err := verifyNativeAPTMethodInventoryWithCompatibility(dir, uid+1, aptDebian12Native261); ErrorCode(err) != "apt_untrusted_executable" {
		t.Fatal("legacy compatibility bypassed the native owner check")
	}
}

func TestNativeAPTLegacyInventoryRetainsExactIdentityChecks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(string) error
	}{
		{"writable ftp", func(dir string) error { return os.Chmod(filepath.Join(dir, "ftp"), 0775) }},
		{"writable rsh", func(dir string) error { return os.Chmod(filepath.Join(dir, "rsh"), 0757) }},
		{"nonexecutable ftp", func(dir string) error { return os.Chmod(filepath.Join(dir, "ftp"), 0644) }},
		{"setuid rsh", func(dir string) error { return os.Chmod(filepath.Join(dir, "rsh"), 0755|os.ModeSetuid) }},
		{"missing ssh target", func(dir string) error { return os.Remove(filepath.Join(dir, "rsh")) }},
		{"foreign helper", func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "custom-transport"), []byte("not executed"), 0755)
		}},
		{"disabled sentinel exists", func(dir string) error { return os.WriteFile(filepath.Join(dir, "false"), []byte("not executed"), 0755) }},
		{"ssh traversal", func(dir string) error {
			if err := os.Remove(filepath.Join(dir, "ssh")); err != nil {
				return err
			}
			return os.Symlink("../rsh", filepath.Join(dir, "ssh"))
		}},
		{"mirror ftp wrong target", func(dir string) error {
			if err := os.Remove(filepath.Join(dir, "mirror+ftp")); err != nil {
				return err
			}
			return os.Symlink("ftp", filepath.Join(dir, "mirror+ftp"))
		}},
		{"symlink replaces ftp", func(dir string) error {
			if err := os.Remove(filepath.Join(dir, "ftp")); err != nil {
				return err
			}
			return os.Symlink("http", filepath.Join(dir, "ftp"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, uid := createDebian12APTMethodFixture(t)
			if err := tc.mutate(dir); err != nil {
				t.Fatal(err)
			}
			if err := verifyNativeAPTMethodInventoryWithCompatibility(dir, uid, aptDebian12Native261); ErrorCode(err) != "apt_untrusted_executable" {
				t.Fatal("unsafe legacy method identity accepted")
			}
		})
	}
}
