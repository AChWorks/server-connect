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
	nativeConfig, err := trustedAPTConfig()
	if err != nil {
		t.Skip("trusted native APT configuration tool unavailable")
	}
	cmd := exec.Command(nativeConfig, "-c", "/proc/self/fd/3", "dump")
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

// The generic proxy setting does not take precedence over APT's per-host
// DIRECT, auto-detection, or binary-specific proxy policy.
func TestEffectiveAptProxyPolicyRejectsOverrides(t *testing.T) {
	proxy := "http://sc:syntheticnotreal@127.0.0.1:20807"
	base := "Acquire::http::Proxy \"" + proxy + "\";\n" +
		"Acquire::https::Proxy \"" + proxy + "\";\n"
	for name, extra := range map[string]string{
		"per-host-direct":   "Acquire::http::Proxy::repository.invalid \"DIRECT\";\n",
		"https-host":        "Acquire::https::Proxy::repository.invalid \"DIRECT\";\n",
		"autodetect":        "Acquire::http::Proxy-Auto-Detect \"/bin/false\";\n",
		"legacy-autodetect": "Acquire::http::ProxyAutoDetect \"/bin/false\";\n",
		"binary-specific":   "Binary::apt-get::Acquire::http::Proxy \"DIRECT\";\n",
		"wrong-http":        "Acquire::http::Proxy \"DIRECT\";\n",
	} {
		t.Run(name, func(t *testing.T) {
			err := verifyAptDump(base+extra, proxy)
			if err == nil || ErrorCode(err) != "apt_policy_conflict" {
				t.Fatalf("unsafe config was accepted: %v", err)
			}
			if strings.Contains(err.Error(), "syntheticnotreal") {
				t.Fatal("proxy credential leaked in error")
			}
		})
	}
	if err := verifyAptDump(base, proxy); err != nil {
		t.Fatal(err)
	}
}

func TestAptRejectsCallerProxyAndConfigOverrides(t *testing.T) {
	samples := [][]string{
		{"update", "-o", "Acquire::http::Proxy::example.invalid=DIRECT"},
		{"update", "-oAcquire::http::Proxy=DIRECT"},
		{"update", "--option=Acquire::https::Proxy::example.invalid=DIRECT"},
		{"update", "--option", "Acquire::http::Proxy-Auto-Detect=/bin/echo"},
		{"update", "--option", "Binary::apt::Acquire::http::Proxy=DIRECT"},
		{"update", "-oAPT::Update::Error-Mode=persistent"},
		{"update", "-oDebug::Acquire::http=1"},
		{"update", "-c", "/tmp/untrusted-apt.conf"},
		{"update", "--config-file=/tmp/untrusted-apt.conf"},
		{"update", "-o", "Dir::Etc::parts=/tmp/untrusted"},
		{"update", "--option=Dir::Etc::main=/tmp/untrusted"},
		{"update", "-o", "Dir::Etc::netrc=/tmp/untrusted"},
	}
	for _, args := range samples {
		_, _, err := validateAptArgs(args)
		if err == nil || ErrorCode(err) != "apt_policy_conflict" {
			t.Errorf("allowed conflicting APT override (%q): %v", args[0], err)
		}
	}
	opts, action, err := validateAptArgs([]string{"update", "-o", "Dir::Etc::sourcelist=/tmp/test-list", "-o", "Dir::State::lists=/tmp/test-list-cache"})
	if err != nil || action != "update" || len(opts) != 4 {
		t.Fatalf("valid isolated APT options rejected: %v %q %q", opts, action, err)
	}
}

func TestRealAptConfigPreflightWithAnonymousFD(t *testing.T) {
	if _, err := trustedAPTConfig(); err != nil {
		t.Skip("trusted native APT configuration tool unavailable")
	}
	proxy, _ := url.Parse("http://sc:syntheticnotreal@127.0.0.1:20807")
	file, err := privateAptConfig(t.TempDir(), proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = verifyEffectiveAptProxy(file, proxy.String(), nil); err != nil {
		t.Fatalf("preflight could not read selected localhost proxy: %v", err)
	}
	// Simulate an otherwise inherited per-host host override in the exact
	// apt-config process. No host apt.conf files are ever written/modified.
	if err = verifyEffectiveAptProxy(file, proxy.String(),
		[]string{"-o", "Acquire::http::Proxy::mirror.invalid=DIRECT"}); err == nil {
		t.Fatal("APT host-specific DIRECT override accepted by config inspection")
	}
	if err = verifyEffectiveAptProxy(file, proxy.String(),
		[]string{"-o", "Acquire::http::Proxy-Auto-Detect=/usr/bin/false"}); err == nil {
		t.Fatal("APT proxy autodetection accepted by config inspection")
	}
}

func TestStrictAPTUpdateModesAndOptionOrdering(t *testing.T) {
	for _, args := range [][]string{
		{"update"},
		{"-t", "testing", "update"},
		{"-a", "amd64", "update"},
		{"--target-release", "testing", "update"},
		{"-o", "Dir::Etc::sourcelist=/tmp/qa", "update"},
	} {
		_, action, err := validateAptArgs(args)
		if err != nil || action != "update" {
			t.Fatalf("update not classified: %v %v", args, err)
		}
		a := aptExecArgs(args, action)
		if len(a) == 0 || a[len(a)-1] != "--error-on=any" {
			t.Fatalf("not strict: %v", a)
		}
	}
	_, action, err := validateAptArgs([]string{"install", "example"})
	if err != nil || action != "install" {
		t.Fatalf("unexpected install action: %q %v", action, err)
	}
	for _, a := range aptExecArgs([]string{"install", "example"}, action) {
		if a == "--error-on=any" {
			t.Fatal("strict update flag on unrelated command")
		}
	}
}

func TestCombinedAPTUpdateNeverForwardsToPackageOperation(t *testing.T) {
	requireNativeAPT(t)
	for _, args := range [][]string{
		{"-U", "install", "safe-test-package"},
		{"--update", "install", "safe-test-package"},
		{"--update=true", "install", "safe-test-package"},
		{"install", "--update", "safe-test-package"},
		{"install", "-U", "safe-test-package"},
		{"-qqU", "install", "safe-test-package"},
		{"-Uq", "install", "safe-test-package"},
		{"-yU", "install", "safe-test-package"},
		{"--option=APT::Get::Update=true", "install", "safe-test-package"},
		{"-o", "APT::Update::Error-Mode=persistent", "install", "safe-test-package"},
		{"--error-on=none", "update"},
		{"--error-on", "none", "update"},
		{"-eany", "update"},
		{"-e", "none", "update"},
	} {
		_, _, err := validateAptArgs(args)
		if err == nil {
			t.Fatalf("combined-update/strict-policy bypass accepted: %v", args)
		}
		switch ErrorCode(err) {
		case "apt_combined_update_unsupported", "apt_policy_conflict":
		default:
			t.Fatalf("unexpected rejection category: %v (%v)", args, err)
		}
		// Exercise the PUBLIC manager entrypoint, with no installed product.
		// The arguments MUST be rejected without even loading private state
		// or attempting to run apt-get.
		for _, apt := range []string{"apt", "apt-get"} {
			m := New(filepath.Join(t.TempDir(), "nonexistent-state"), "", 0)
			combined := append([]string{apt}, args...)
			code, runErr := m.Apt(combined)
			if code == 0 || (ErrorCode(runErr) != "apt_combined_update_unsupported" &&
				ErrorCode(runErr) != "apt_policy_conflict") {
				t.Fatalf("combined-update operation crossed credential boundary: %v (%v)", combined, runErr)
			}
			if _, e := os.Stat(m.Dir); !os.IsNotExist(e) {
				t.Fatal("rejected combined update unexpectedly created product state")
			}
		}
	}
}

func TestStandaloneUpdateAndOrdinaryPackageOpsRemainSupported(t *testing.T) {
	for _, args := range [][]string{
		{"update"},
		{"-q", "update"},
		{"-o", "Dir::Etc::sourcelist=/tmp/test-repo", "update"},
	} {
		_, action, err := validateAptArgs(args)
		if err != nil || action != "update" {
			t.Fatalf("standalone update rejected: %v (%v)", args, err)
		}
		execArgs := aptExecArgs(args, action)
		if execArgs[len(execArgs)-1] != "--error-on=any" {
			t.Fatalf("standalone update not strict: %v", execArgs)
		}
	}
	for _, args := range [][]string{
		{"install", "safe-test-package"}, {"download", "safe-test-package"},
		{"--assume-yes", "install", "safe-test-package"},
	} {
		_, action, err := validateAptArgs(args)
		if err != nil {
			t.Fatalf("ordinary non-update APT operation rejected: %v", err)
		}
		execArgs := aptExecArgs(args, action)
		if execArgs[len(execArgs)-1] == "--error-on=any" {
			t.Fatal("standalone update strictness leaked to ordinary operation")
		}
	}
}
