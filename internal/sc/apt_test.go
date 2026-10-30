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

// Baseline for parser-only tests is the observed native Debian 13 APT
// configuration. Real apt-config evaluation is exercised separately.
func nativeAptDumpForTest() string {
	var b strings.Builder
	b.WriteString("Dir \"/\";\nDir::Usr \"usr\";\n")
	for key, value := range nativeAPTBinConfig {
		b.WriteString(key + " \"" + value + "\";\n")
	}
	return b.String()
}

// The generic proxy setting does not take precedence over APT's per-host
// DIRECT, auto-detection, or binary-specific proxy policy.
func TestEffectiveAptProxyPolicyRejectsOverrides(t *testing.T) {
	proxy := "http://sc:syntheticnotreal@127.0.0.1:20807"
	base := nativeAptDumpForTest() + "Acquire::http::Proxy \"" + proxy + "\";\n" +
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

// Refuse paths that relocate native APT execution, while retaining the exact
// source/list/cache controls already used by the genuine-core integration.
func TestAptExecutionMethodRedirectionCallerPolicy(t *testing.T) {
	for _, argument := range []string{
		"Dir::Bin::Methods=/tmp/qa-methods",
		"Dir::Bin::gzip=/tmp/qa-gzip",
		"Dir::Bin::dpkg=/tmp/qa-dpkg",
		"Dir::Bin=/tmp/qa-binaries",
		"RootDir=/tmp/qa-root",
		"Dir=/tmp/qa-root",
		"Dir::Usr=/tmp/qa-usr",
		"Dir::=/tmp/qa-root",
		"Dir::Usr::=/tmp/qa-usr",
		"APT::Compressor::gzip::Binary=/tmp/qa-gzip",
		"Binary::apt-get::Dir::Bin::Methods=/tmp/qa-methods",
		"Binary::apt::RootDir=/tmp/qa-root",
		"Binary::apt::APT::Compressor::gzip::Binary=/tmp/qa-gzip",
	} {
		t.Run(strings.SplitN(argument, "=", 2)[0], func(t *testing.T) {
			for _, args := range [][]string{
				{"update", "-o", argument},
				{"-o" + argument, "update"},
				{"--option=" + argument, "update"},
			} {
				_, _, err := validateAptArgs(args)
				if ErrorCode(err) != "apt_policy_conflict" {
					t.Fatalf("unsafe APT executable-path override accepted: %v: %v", args, err)
				}
				// The public manager entrypoint must stop before loading
				// product profiles or creating the proxy credential FD.
				dir := filepath.Join(t.TempDir(), "does-not-exist")
				code, err := New(dir, "", 0).Apt(append([]string{"apt-get"}, args...))
				if code == 0 || ErrorCode(err) != "apt_policy_conflict" {
					t.Fatalf("unsafe method policy reached child: exit=%d err=%v", code, err)
				}
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Fatal("rejected method override caused unexpected state creation")
				}
			}
		})
	}
	accepted := []string{
		"Dir::Etc::sourcelist=/tmp/qa.list",
		"Dir::Etc::sourceparts=-",
		"Dir::State::lists=/tmp/qa-lists",
		"Dir::Cache::archives=/tmp/qa-cache",
		"Dir::Cache::pkgcache=/dev/null",
		"Dir::Cache::srcpkgcache=/dev/null",
	}
	args := []string{"update"}
	for _, setting := range accepted {
		args = append(args, "-o", setting)
	}
	opts, action, err := validateAptArgs(args)
	if err != nil || action != "update" || len(opts) != 2*len(accepted) {
		t.Fatalf("legitimate isolated APT fixture options were blocked: %v %q %v", opts, action, err)
	}
}

func TestEffectiveAptExecutionMethodsRejectInheritedRedirection(t *testing.T) {
	proxy := "http://sc:synthetic-never-expose@127.0.0.1:20807"
	baseline := nativeAptDumpForTest() +
		"Acquire::http::Proxy \"" + proxy + "\";\n" +
		"Acquire::https::Proxy \"" + proxy + "\";\n"
	if err := verifyAptDump(baseline, proxy); err != nil {
		t.Fatal("supported native Debian baseline failed:", err)
	}
	cases := map[string]string{
		"method-folder":      "Dir::Bin::methods \"/tmp/foreign\";\n",
		"method-extra":       "Dir::Bin::http \"/tmp/foreign-http\";\n",
		"compressor":         "Dir::Bin::gzip \"/tmp/custom\";\n",
		"rootdir":            "RootDir \"/tmp/foreign-root\";\n",
		"rootdir-empty":      "RootDir \"\";\n",
		"dir-root":           "Dir \"/tmp/foreign-root\";\n",
		"dir-usr":            "Dir::Usr \"../../tmp\";\n",
		"dir-root-extension": "Dir:: \"/tmp/qa-root\";\n",
		"usr-extension":      "Dir::Usr:: \"/tmp/qa-usr\";\n",
		"binary-method":      "Binary::apt-get::Dir::Bin::Methods \"/tmp/foreign\";\n",
		"binary-rootdir":     "Binary::apt::RootDir \"/tmp/foreign\";\n",
		"binary-dir":         "Binary::apt::Dir \"/tmp/foreign\";\n",
		"binary-compressor":  "Binary::apt-get::APT::Compressor::gzip::Binary \"/tmp/foreign\";\n",
		"gzip-binary":        "APT::Compressor::gzip::Binary \"/tmp/foreign\";\n",
		"unknown-compressor": "APT::Compressor::custom::Binary \"/tmp/foreign\";\n",
	}
	for label, extra := range cases {
		t.Run(label, func(t *testing.T) {
			err := verifyAptDump(baseline+extra, proxy)
			if ErrorCode(err) != "apt_policy_conflict" {
				t.Fatalf("untrusted inherited APT execution policy accepted: %s (%v)", label, err)
			}
			if strings.Contains(err.Error(), "synthetic-never-expose") {
				t.Fatal("proxy credential leaked in APT policy error")
			}
		})
	}
	// A malicious config may omit, not just replace, an essential method.
	withoutMethods := strings.Replace(baseline, "dir::bin::methods \"/usr/lib/apt/methods\";\n", "", 1)
	if err := verifyAptDump(withoutMethods, proxy); ErrorCode(err) != "apt_policy_conflict" {
		t.Fatal("missing native acquisition methods policy was accepted")
	}
}

func TestRealNativeAPTExecutableMethodPolicyPreflight(t *testing.T) {
	if err := verifyNativeAPTMethods(); err != nil {
		t.Fatalf("system method handler root ownership not established: %v", err)
	}
	proxy, _ := url.Parse("http://sc:synthetic-never-expose@127.0.0.1:20807")
	fd, err := privateAptConfig(t.TempDir(), proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	if err := verifyEffectiveAptProxy(fd, proxy.String(), nil); err != nil {
		t.Fatalf("native effective APT policy rejected: %v", err)
	}
	// These options simulate the *effective inherited policy* as seen by
	// apt-config. This test does not write the live host's /etc/apt.
	for _, option := range []string{
		"Dir::Bin::Methods=/tmp/qa-methods",
		"Dir::Bin::gzip=/tmp/qa-custom",
		"Dir=/tmp/qa-root",
		"Dir::Usr=/tmp/qa-usr",
		"RootDir=/tmp/qa-root",
		"Binary::apt-get::Dir::Bin::Methods=/tmp/qa-methods",
		"Binary::apt::RootDir=/tmp/qa-root",
		"APT::Compressor::gzip::Binary=/tmp/qa-custom",
	} {
		t.Run(strings.SplitN(option, "=", 2)[0], func(t *testing.T) {
			err := verifyEffectiveAptProxy(fd, proxy.String(), []string{"-o", option})
			if ErrorCode(err) != "apt_policy_conflict" {
				t.Fatalf("effective inherited method redirection not rejected: %s %v", option, err)
			}
			if strings.Contains(err.Error(), "synthetic-never-expose") {
				t.Fatal("private proxy credential was printed in diagnostic")
			}
		})
	}
	// No proxy override/secret is sent to the native APT child for a
	// misconfigured host, but ordinary isolated source/index settings work.
	opts := []string{"-o", "Dir::Etc::sourcelist=/tmp/qa.list",
		"-o", "Dir::Etc::sourceparts=-",
		"-o", "Dir::State::lists=/tmp/qa-lists"}
	if err := verifyEffectiveAptProxy(fd, proxy.String(), opts); err != nil {
		t.Fatalf("safe disposable APT source/list configuration blocked: %v", err)
	}
}

// Minimal and full Debian 13 images need not install the same optional
// compressors. "false" is the native disabled form, not a custom executable
// path or general-purpose policy exemption.
func TestNativeAPTMinimalAndFullLZMAPathCompatibility(t *testing.T) {
	proxy := "http://sc:never-expose@127.0.0.1:20807"
	base := nativeAptDumpForTest() +
		"Acquire::http::Proxy \"" + proxy + "\";\n" +
		"Acquire::https::Proxy \"" + proxy + "\";\n"
	if err := verifyAptDump(base, proxy); err != nil {
		t.Fatal("full Debian 13 lzma via xz unexpectedly rejected:", err)
	}
	minimal := strings.Replace(base,
		"dir::bin::lzma \"/usr/bin/xz\";\n",
		"dir::bin::lzma \"/usr/bin/lzma\";\n", 1)
	if err := verifyAptDump(minimal, proxy); err != nil {
		t.Fatal("minimal Debian 13 native lzma unexpectedly rejected:", err)
	}
	unsafe := strings.Replace(base,
		"dir::bin::lzma \"/usr/bin/xz\";\n",
		"dir::bin::lzma \"/tmp/foreign-lzma\";\n", 1)
	if err := verifyAptDump(unsafe, proxy); ErrorCode(err) != "apt_policy_conflict" {
		t.Fatalf("untrusted lzma executable override accepted: %v", err)
	}
}

func TestNativeAPTOptionalCompressorCompatibility(t *testing.T) {
	proxy := "http://sc:never-expose@127.0.0.1:20807"
	base := nativeAptDumpForTest() +
		"Acquire::http::Proxy \"" + proxy + "\";\n" +
		"Acquire::https::Proxy \"" + proxy + "\";\n"
	for _, entry := range []string{
		"APT::Compressor::lz4::Binary \"false\";\n",
		"APT::Compressor::lz4::Binary \"lz4\";\n",
		"APT::Compressor::zstd::Binary \"false\";\n",
		"APT::Compressor::zstd::Binary \"zstd\";\n",
		"APT::Compressor::bzip2::Binary \"false\";\n",
		"APT::Compressor::bzip2::Binary \"bzip2\";\n",
		"APT::Compressor::lzma::Binary \"xz\";\n",
		"APT::Compressor::lzma::Binary \"false\";\n",
	} {
		if err := verifyAptDump(base+entry, proxy); err != nil {
			t.Fatalf("native optional Debian compressor form rejected: %v", err)
		}
	}
	for _, entry := range []string{
		"APT::Compressor::lz4::Binary \"/tmp/untrusted\";\n",
		"APT::Compressor::zstd::Binary \"curl\";\n",
		"APT::Compressor::gzip::Binary \"bzip2\";\n",
		"APT::Compressor::alien::Binary \"gzip\";\n",
	} {
		if err := verifyAptDump(base+entry, proxy); ErrorCode(err) != "apt_policy_conflict" {
			t.Fatalf("untrusted compressor execution still allowed: %v", err)
		}
	}
}

func TestAPT261MayOmitOnlyNativeDirUsr(t *testing.T) {
	proxy := "http://sc:synthetic-never-expose@127.0.0.1:20807"
	base := nativeAptDumpForTest() + "Acquire::http::Proxy \"" + proxy + "\";\n" +
		"Acquire::https::Proxy \"" + proxy + "\";\n"
	withoutUsr := strings.Replace(base, "Dir::Usr \"usr\";\n", "", 1)
	if err := verifyAptDumpWithCompatibility(withoutUsr, proxy, aptDebian12Native261); err != nil {
		t.Fatal("observed Debian12/2.6.1 layout rejected:", err)
	}
	if err := verifyAptDumpWithCompatibility(base, proxy, aptDebian12Native261); err != nil {
		t.Fatal("exact optional Dir::Usr rejected:", err)
	}
	for _, mode := range []aptCompatibility{aptStrictNative, aptCompatibility(255)} {
		if err := verifyAptDumpWithCompatibility(withoutUsr, proxy, mode); ErrorCode(err) != "apt_policy_conflict" {
			t.Fatal("Dir::Usr omission accepted outside verified Debian12/2.6.1")
		}
	}
	for _, setting := range []string{"Dir::Usr \"\";\n", "Dir::Usr \"/tmp/foreign\";\n", "Dir::Usr:: \"usr\";\n"} {
		if err := verifyAptDumpWithCompatibility(withoutUsr+setting, proxy, aptDebian12Native261); ErrorCode(err) != "apt_policy_conflict" {
			t.Fatal("unsafe Dir::Usr spelling accepted in compatibility mode")
		}
	}
	for key, value := range nativeAPTBinConfig {
		missing := strings.Replace(withoutUsr, key+" \""+value+"\";\n", "", 1)
		if err := verifyAptDumpWithCompatibility(missing, proxy, aptDebian12Native261); ErrorCode(err) != "apt_policy_conflict" {
			t.Fatalf("mandatory native path became optional: %s", key)
		}
	}
	if err := verifyAptDumpWithCompatibility(strings.Replace(withoutUsr, "Dir \"/\";\n", "", 1), proxy, aptDebian12Native261); ErrorCode(err) != "apt_policy_conflict" {
		t.Fatal("mandatory native root became optional")
	}
}

func TestAPTLegacyEnablersRemainRejectedBeforeAcquisition(t *testing.T) {
	proxy := "http://sc:synthetic-never-expose@127.0.0.1:20807"
	base := nativeAptDumpForTest() + "Acquire::http::Proxy \"" + proxy + "\";\n" +
		"Acquire::https::Proxy \"" + proxy + "\";\n"
	for _, method := range []string{"ftp", "rsh", "ssh", "mirror+ftp"} {
		for _, prefix := range []string{"", "Binary::apt::", "Binary::apt-get::", "bInArY::ApT-gEt::"} {
			key := prefix + "dIr::bIn::mEtHoDs::" + method
			for _, value := range []string{method, "/usr/lib/apt/methods/" + method, "false", ""} {
				if _, _, err := validateAptArgs([]string{"update", "-o", key + "=" + value}); ErrorCode(err) != "apt_policy_conflict" {
					t.Fatalf("caller legacy enabler reached credential phase: %s", key)
				}
				for _, mode := range []aptCompatibility{aptStrictNative, aptDebian12Native261} {
					dump := base + key + " \"" + value + "\";\n"
					if err := verifyAptDumpWithCompatibility(dump, proxy, mode); ErrorCode(err) != "apt_policy_conflict" {
						t.Fatalf("inherited legacy enabler accepted: %s", key)
					}
				}
			}
		}
	}
}

func ownedDisabledAptDumpForTest() string {
	var result strings.Builder
	for _, method := range []string{"ftp", "rsh", "ssh", "mirror+ftp"} {
		result.WriteString("Dir::Bin::Methods::" + method + " \"" + aptDisabledMethodPath + "\";\n")
	}
	return result.String()
}

func TestAPTOwnedDisabledPolicyMustBeExactAndComplete(t *testing.T) {
	proxy := "http://sc:synthetic-never-expose@127.0.0.1:20807"
	base := nativeAptDumpForTest() + "Acquire::http::Proxy \"" + proxy + "\";\n" +
		"Acquire::https::Proxy \"" + proxy + "\";\n"
	owned := ownedDisabledAptDumpForTest()
	for _, mode := range []aptCompatibility{aptStrictNative, aptDebian12Native261} {
		if err := verifyAptDumpPolicy(base+owned, proxy, mode, true); err != nil {
			t.Fatal("exact owned disabled policy refused:", err)
		}
		if mode == aptDebian12Native261 {
			withoutUsr := strings.Replace(base+owned, "Dir::Usr \"usr\";\n", "", 1)
			if err := verifyAptDumpPolicy(withoutUsr, proxy, mode, true); err != nil {
				t.Fatal("owned policy refused the exact Debian12/2.6.1 layout:", err)
			}
		}
		if err := verifyAptDumpPolicy(base+owned, proxy, mode, false); ErrorCode(err) != "apt_policy_conflict" {
			t.Fatal("first inspection accepted inherited method overrides")
		}
		for _, method := range []string{"ftp", "rsh", "ssh", "mirror+ftp"} {
			line := "Dir::Bin::Methods::" + method + " \"" + aptDisabledMethodPath + "\";\n"
			for _, broken := range []string{
				strings.Replace(owned, line, "", 1),
				strings.Replace(owned, line, "Dir::Bin::Methods::"+method+" \""+method+"\";\n", 1),
				strings.Replace(owned, line, "Dir::Bin::Methods::"+method+" \"\";\n", 1),
				owned + line,
			} {
				if err := verifyAptDumpPolicy(base+broken, proxy, mode, true); ErrorCode(err) != "apt_policy_conflict" {
					t.Fatal("missing, enabled, empty or duplicate method denial accepted")
				}
			}
		}
		for _, extra := range []string{
			"Dir::Bin::Methods::http \"" + aptDisabledMethodPath + "\";\n",
			"Binary::apt::Dir::Bin::Methods::ftp \"ftp\";\n",
			"RootDir \"/tmp/foreign\";\n",
			"Acquire::http::Proxy::mirror.invalid \"DIRECT\";\n",
		} {
			if err := verifyAptDumpPolicy(base+owned+extra, proxy, mode, true); ErrorCode(err) != "apt_policy_conflict" {
				t.Fatal("owned-denial phase weakened another native guard")
			}
		}
	}
}

func TestAPTOwnedDisabledArgumentsFollowValidatedCallerOptions(t *testing.T) {
	for _, args := range [][]string{
		{"update"}, {"-t", "testing", "update"},
		{"update", "-o", "Dir::Etc::sourcelist=/tmp/qa.list"},
		{"install", "safe-test-package"}, {"download", "safe-test-package"},
	} {
		_, action, err := validateAptArgs(args)
		if err != nil {
			t.Fatal(err)
		}
		argv := aptExecArgs(args, action)
		start := 2 + len(args)
		want := []string{
			"-o", "Dir::Bin::Methods::ftp=/usr/lib/apt/methods/false",
			"-o", "Dir::Bin::Methods::rsh=/usr/lib/apt/methods/false",
			"-o", "Dir::Bin::Methods::ssh=/usr/lib/apt/methods/false",
			"-o", "Dir::Bin::Methods::mirror+ftp=/usr/lib/apt/methods/false",
		}
		if len(argv) < start+len(want) || strings.Join(argv[start:start+len(want)], "\x00") != strings.Join(want, "\x00") {
			t.Fatal("owned method denial was not appended after all caller arguments")
		}
	}
	for _, args := range [][]string{{"--", "update"}, {"update", "--"}, {"install", "safe-test-package", "--", "-oDir::Bin::Methods::ftp=ftp"}} {
		if _, _, err := validateAptArgs(args); err == nil {
			t.Fatal("argument separator could hide appended wrapper-owned options")
		}
	}
}

func TestRealAPTTwoStageDisabledMethodPolicy(t *testing.T) {
	requireNativeAPT(t)
	compatibility, err := observedAPTCompatibility(systemAPTGet)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyNativeAPTMethodsWithCompatibility(compatibility); err != nil {
		t.Fatal(err)
	}
	proxy, _ := url.Parse("http://sc:synthetic-never-expose@127.0.0.1:20807")
	fd, err := privateAptConfig(t.TempDir(), proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	if err := verifyEffectiveAptProxyWithCompatibility(fd, proxy.String(), nil, compatibility); err != nil {
		t.Fatal("baseline native policy refused:", err)
	}
	if err := verifyEffectiveAptProxyPolicy(fd, proxy.String(), aptOwnedDisabledOpts(nil), compatibility, true); err != nil {
		t.Fatal("native APT did not retain exact wrapper-owned denial:", err)
	}
	if err := verifyEffectiveAptProxyWithCompatibility(fd, proxy.String(), aptOwnedDisabledOpts(nil), compatibility); ErrorCode(err) != "apt_policy_conflict" {
		t.Fatal("baseline phase accepted inherited per-method overrides")
	}
}
