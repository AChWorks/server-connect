package sc

import (
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnonymousAPTConfigAndLocalOnly(t *testing.T) {
	dir := t.TempDir()
	px, _ := url.Parse("http://sc:syntheticnotreal@127.0.0.1:20807")
	fd, err := privateAptConfig(dir, px)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary credential file persisted: %v", entries)
	}
	data, err := io.ReadAll(fd)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "http://sc:syntheticnotreal@127.0.0.1:20807") != 2 {
		t.Fatal("APT proxy configuration incomplete")
	}
	if _, err := fd.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("apt-config"); err != nil {
		t.Skip("APT binary not available")
	}
	cmd := exec.Command("apt-config", "-c", "/proc/self/fd/3", "dump")
	cmd.ExtraFiles = []*os.File{fd}
	cmd.Env = safeAptEnv()
	output, err := cmd.Output()
	if err != nil {
		t.Fatal("apt-config descriptor parsing failed")
	}
	if !strings.Contains(string(output), "Acquire::http::Proxy") ||
		!strings.Contains(string(output), "Acquire::https::Proxy") {
		t.Fatal("APT did not read an anonymous descriptor")
	}
	if strings.Contains(strings.Join(cmd.Env, "\n"), "syntheticnotreal") {
		t.Fatal("secret was exported into APT environment")
	}
}

func TestAptRejectsForeignProxyAndNonAptCommands(t *testing.T) {
	dir := t.TempDir()
	for _, raw := range []string{
		"http://sc:synthetic@foreign.example:20807",
		"http://sc:synthetic@127.0.0.1:20807\"; debug",
		"socks5://sc:synthetic@127.0.0.1:20807",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		fd, err := privateAptConfig(dir, u)
		if fd != nil {
			fd.Close()
		}
		if err == nil {
			t.Fatal("foreign or unsafe URL accepted")
		}
	}
	m := New(filepath.Join(dir, "state"), "", 0)
	for _, args := range [][]string{nil, {"bash", "-c", "true"}, {"--", "curl", "example.org"}} {
		code, err := m.Apt(args)
		if code != 1 || ErrorCode(err) != "invalid_arguments" {
			t.Fatalf("non-APT command unexpectedly accepted: code=%d err=%v", code, err)
		}
	}
}

func TestAptEnvDropsInheritedProxies(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://inherited.example:45")
	t.Setenv("HTTPS_PROXY", "http://inherited.example:45")
	t.Setenv("APT_CONFIG", "/tmp/sensitive")
	t.Setenv("NO_PROXY", "localhost")
	for _, v := range safeAptEnv() {
		k, _, _ := strings.Cut(v, "=")
		switch strings.ToLower(k) {
		case "http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy", "apt_config":
			t.Fatalf("inherited proxy setting leaked to APT: %s", k)
		}
	}
}
