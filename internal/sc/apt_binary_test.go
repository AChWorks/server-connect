package sc

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
