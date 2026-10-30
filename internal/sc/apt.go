package sc

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

// Apt runs apt-get/apt via the selected authenticated local Proxy Only route.
// No persistent host APT settings or unrelated application paths are changed.
func (m *Manager) Apt(args []string) (int, error) {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return 1, Fault("invalid_arguments", "apt requires an explicit apt-get or apt command")
	}
	// Validate executable identity and flags BEFORE reading the private proxy
	// secret or creating any credential-bearing descriptor.
	nativeAPT, err := trustedAPTCommand(args[0])
	if err != nil {
		return 1, err
	}
	if _, _, err := validateAptArgs(args[1:]); err != nil {
		return 1, err
	}
	// Identity of BOTH children must be established before reading secrets.
	if _, err = trustedAPTConfig(); err != nil {
		return 1, err
	}
	compatibility, err := observedAPTCompatibility(nativeAPT)
	if err != nil {
		return 1, err
	}
	proxy, err := m.proxyURL()
	if err != nil {
		return 1, err
	}
	return aptThroughSelectedProxyChecked(nativeAPT, args[1:], m.Dir, proxy, compatibility)
}

// aptThroughSelectedProxy owns the *entire* credential-bearing subprocess
// operation. This is also used by genuine-core isolated integration tests;
// no test-only implementation of the APT transport is required.
func aptThroughSelectedProxy(nativeAPT string, args []string, dir string, proxy *url.URL) (int, error) {
	compatibility, err := observedAPTCompatibility(nativeAPT)
	if err != nil {
		return 1, err
	}
	return aptThroughSelectedProxyChecked(nativeAPT, args, dir, proxy, compatibility)
}

func aptThroughSelectedProxyChecked(nativeAPT string, args []string, dir string, proxy *url.URL, compatibility aptCompatibility) (int, error) {
	if nativeAPT != systemAPT && nativeAPT != systemAPTGet {
		return 1, Fault("apt_untrusted_executable", "APT command is not a trusted native executable")
	}
	// The credential-bearing operation MUST derive the action and effective
	// overrides from the SAME forwarded arguments. Never trust a separate
	// caller-supplied "action" that could skip strict partial-update handling.
	opts, action, err := validateAptArgs(args)
	if err != nil {
		return 1, err
	}
	if err := verifyNativeAPTExecutable(nativeAPT); err != nil {
		return 1, err
	}
	if _, err := trustedAPTConfig(); err != nil {
		return 1, err
	}
	if err := verifyNativeAPTMethodsWithCompatibility(compatibility); err != nil {
		return 1, err
	}
	file, err := privateAptConfig(dir, proxy)
	if err != nil {
		return 1, Fault("apt_configuration", "unable to prepare private APT proxy configuration")
	}
	defer file.Close()
	// Host-specific and autodetected APT settings take precedence over the
	// generic proxy. Inspect the effective configuration; never log its output.
	if err = verifyEffectiveAptProxyWithCompatibility(file, proxy.String(), opts, compatibility); err != nil {
		return 1, err
	}
	// Reject inherited enablers FIRST. Then verify the stricter policy that the
	// wrapper appends to the actual child, independent of libapt-pkg version.
	if err = verifyEffectiveAptProxyPolicy(file, proxy.String(), aptOwnedDisabledOpts(opts), compatibility, true); err != nil {
		return 1, err
	}
	argv := aptExecArgs(args, action)
	cmd := exec.Command(nativeAPT, argv...)
	cmd.ExtraFiles = []*os.File{file}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = safeAptEnv()
	if err = cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), nil
		}
		return 1, Fault("apt_execution", "APT command could not be started")
	}
	return 0, nil
}

// aptExecArgs forces strict update acquisition semantics, regardless of the
// original APT user option ordering. The anonymous descriptor is FD 3.
func aptExecArgs(arguments []string, action string) []string {
	argv := []string{"-c", "/proc/self/fd/3"}
	argv = append(argv, arguments...)
	argv = append(argv, aptOwnedDisabledOpts(nil)...)
	if action == "update" {
		argv = append(argv, "--error-on=any")
	}
	return argv
}

const aptDisabledMethodPath = "/usr/lib/apt/methods/false"

var aptDisabledMethods = []string{"ftp", "rsh", "ssh", "mirror+ftp"}

// Worker::Start in native APT2.6/2.9/3 honors an explicit method path before
// dispatch. A missing path whose basename is false means disabled, before
// fork/exec. The complete trusted inventory rejects any file named false;
// this policy creates no files and changes no host APT settings.
// https://github.com/Debian/apt/blob/a626a66fece0a7d680e40b9e35b66e29fe9ae12c/apt-pkg/acquire-worker.cc
func aptOwnedDisabledOpts(opts []string) []string {
	result := append([]string{}, opts...)
	for _, method := range aptDisabledMethods {
		result = append(result, "-o", "Dir::Bin::Methods::"+method+"="+aptDisabledMethodPath)
	}
	return result
}

// Validate caller overrides before forwarding them to apt-get. Proxy
// overrides, extra config files, and wire-debugging are not supported.
func validateAptArgs(args []string) ([]string, string, error) {
	// Native APT keeps the first ordinary token as FileList[0]. Requiring the
	// action here avoids guessing which later boolean/integer/HasArg option
	// consumes a separate value and accidentally losing strict update handling.
	if len(args) == 0 || args[0] == "" || strings.HasPrefix(args[0], "-") {
		return nil, "", Fault("invalid_arguments", "put the APT action first, followed by its options and package arguments")
	}
	var opts []string
	action := args[0]
	for i := 1; i < len(args); i++ {
		a := args[i]
		lower := strings.ToLower(a)
		if isCombinedAPTUpdateLongFlag(a) ||
			isCombinedAPTUpdateShortFlag(a) {
			return nil, "", Fault("apt_combined_update_unsupported",
				"APT -U/--update is unsupported in Proxy Only; run a separate strict apt-get update before the package command")
		}
		// The wrapper, not caller input, owns the update error policy.
		// Accepting -e/--error-on risks ambiguous APT precedence.
		if a == "-e" || strings.HasPrefix(a, "-e") ||
			lower == "--error-on" || strings.HasPrefix(lower, "--error-on=") {
			return nil, "", Fault("apt_policy_conflict",
				"APT update error policy is managed by Server Connect")
		}
		if a == "--" {
			return nil, "", Fault("invalid_arguments", "APT argument separator not supported")
		}
		if !supportedAPTShortToken(a) {
			return nil, "", Fault("apt_policy_conflict", "APT short options must be separate; only quiet forms and validated attached -o values are supported")
		}
		if lower == "-c" || lower == "--config-file" || strings.HasPrefix(lower, "--config-file=") ||
			(strings.HasPrefix(lower, "-c") && len(a) > 2) {
			return nil, "", Fault("apt_policy_conflict", "APT extra configuration files are not supported in Proxy Only")
		}
		var opt string
		switch {
		case a == "-o" || lower == "--option":
			i++
			if i == len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
				return nil, "", Fault("invalid_arguments", "APT configuration option value missing")
			}
			opt = args[i]
		case strings.HasPrefix(a, "-o") && len(a) > 2:
			opt = a[2:]
		case strings.HasPrefix(lower, "--option="):
			opt = a[len("--option="):]
		}
		if (a == "-o" || lower == "--option" || strings.HasPrefix(lower, "--option=") ||
			(strings.HasPrefix(a, "-o") && len(a) > 2)) && opt == "" {
			return nil, "", Fault("invalid_arguments", "APT configuration option value missing")
		}
		if opt != "" {
			key, _, ok := strings.Cut(opt, "=")
			key = strings.ToLower(strings.TrimSpace(key))
			if !ok || key == "" || strings.ContainsAny(key, " \t\r\n") {
				return nil, "", Fault("invalid_arguments", "malformed APT configuration option")
			}
			if strings.HasPrefix(key, "acquire::") || strings.HasPrefix(key, "binary::") ||
				strings.HasPrefix(key, "apt::update") ||
				strings.HasPrefix(key, "apt::get::update") ||
				strings.HasPrefix(key, "debug::acquire") ||
				key == "dir" || key == "dir::" ||
				key == "rootdir" || strings.HasPrefix(key, "rootdir::") ||
				key == "dir::bin" || strings.HasPrefix(key, "dir::bin::") ||
				key == "dir::usr" || strings.HasPrefix(key, "dir::usr::") ||
				strings.HasPrefix(key, "apt::compressor") ||
				key == "dir::etc" || key == "dir::etc::main" || key == "dir::etc::parts" ||
				strings.HasPrefix(key, "dir::etc::netrc") {
				return nil, "", Fault("apt_policy_conflict", "APT proxy, policy or configuration-source overrides are not permitted")
			}
			opts = append(opts, "-o", opt)
			continue
		}
		// Scan every other token. Native meanings depend on the command (e.g.
		// -a is boolean for apt show/list but takes a value for build-dep).
		// Only the validated -o assignment above may consume another token.
	}
	return opts, action, nil
}

// Native short options are parsed letter by letter: -qoX=Y hides an arbitrary
// setting and -qcFILE hides a config include. Admit a small unambiguous grammar
// instead of duplicating APT's optional boolean/integer argument parser.
func supportedAPTShortToken(a string) bool {
	if len(a) < 3 || !strings.HasPrefix(a, "-") || strings.HasPrefix(a, "--") {
		return true
	}
	if strings.HasPrefix(a, "-o") {
		return true // The complete assignment is separately validated.
	}
	if a[1] != 'q' {
		return false
	}
	level := strings.TrimLeft(a[1:], "q")
	if level == "" {
		return true
	}
	level = strings.TrimPrefix(level, "=")
	if level == "" {
		return false
	}
	for _, digit := range level {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

// Native long matching ignores case and permits one Boolean prefix, including
// an empty prefix (---update) and the short alias (--yes-U). An explicit value
// such as --no-update=true overrides the prefix, so reject every such spelling.
// https://github.com/Debian/apt/blob/a626a66fece0a7d680e40b9e35b66e29fe9ae12c/apt-pkg/contrib/cmndline.cc
func isCombinedAPTUpdateLongFlag(a string) bool {
	if !strings.HasPrefix(a, "--") {
		return false
	}
	name, _, _ := strings.Cut(a[2:], "=")
	if strings.EqualFold(name, "update") {
		return true
	}
	_, suffix, prefixed := strings.Cut(name, "-")
	return prefixed && (strings.EqualFold(suffix, "update") || suffix == "U")
}

// APT permits short flag groups (e.g. -qU); never allow a combined update
// phase to escape the strict standalone-update contract. The only admitted
// arbitrary attached value is -o's separately validated assignment.
func isCombinedAPTUpdateShortFlag(a string) bool {
	if len(a) < 2 || !strings.HasPrefix(a, "-") || strings.HasPrefix(a, "--") {
		return false
	}
	if strings.HasPrefix(a, "-o") {
		return false
	}
	return strings.Contains(a[1:], "U")
}

// Inspect APT host policy and caller-supplied supported options with the
// same anonymous config FD/environment. apt-config's stdout is a secret.
func verifyEffectiveAptProxy(file *os.File, expected string, opts []string) error {
	compatibility, err := observedAPTCompatibility(systemAPTGet)
	if err != nil {
		return err
	}
	return verifyEffectiveAptProxyWithCompatibility(file, expected, opts, compatibility)
}

func verifyEffectiveAptProxyWithCompatibility(file *os.File, expected string, opts []string, compatibility aptCompatibility) error {
	return verifyEffectiveAptProxyPolicy(file, expected, opts, compatibility, false)
}

func verifyEffectiveAptProxyPolicy(file *os.File, expected string, opts []string, compatibility aptCompatibility, ownedDisabled bool) error {
	if _, err := file.Seek(0, 0); err != nil {
		return Fault("apt_configuration", "private APT configuration unavailable")
	}
	argv := append([]string{"-c", "/proc/self/fd/3"}, opts...)
	argv = append(argv, "dump")
	nativeConfig, err := trustedAPTConfig()
	if err != nil {
		return err
	}
	cmd := exec.Command(nativeConfig, argv...)
	cmd.ExtraFiles = []*os.File{file}
	cmd.Env = safeAptEnv()
	var out bytes.Buffer
	cmd.Stdout = &limitedAptOutput{out: &out, limit: 2 << 20}
	cmd.Stderr = &limitedAptOutput{out: &bytes.Buffer{}, limit: 64 << 10}
	if err := cmd.Run(); err != nil {
		return Fault("apt_policy_conflict", "cannot verify effective APT configuration; refusing Direct fallback")
	}
	return verifyAptDumpPolicy(out.String(), expected, compatibility, ownedDisabled)
}

type limitedAptOutput struct {
	out   *bytes.Buffer
	limit int
}

func (l *limitedAptOutput) Write(p []byte) (int, error) {
	if l.out.Len()+len(p) > l.limit {
		return 0, errors.New("APT config exceeds inspection limit")
	}
	return l.out.Write(p)
}

// Native Debian 13's default executable/method resolution policy. An
// inherited change here can bypass trusted apt/apt-get even when their own
// binaries were verified. Keep these exact native defaults (no arbitrary
// machine-wide rewrite); an unusual host APT layout fails closed.
var nativeAPTBinConfig = map[string]string{
	"dir::bin":             "",
	"dir::bin::methods":    "/usr/lib/apt/methods",
	"dir::bin::solvers":    "",
	"dir::bin::solvers::":  "/usr/lib/apt/solvers",
	"dir::bin::planners":   "",
	"dir::bin::planners::": "/usr/lib/apt/planners",
	"dir::bin::dpkg":       "/usr/bin/dpkg",
	"dir::bin::gzip":       "/bin/gzip",
	"dir::bin::bzip2":      "/bin/bzip2",
	"dir::bin::xz":         "/usr/bin/xz",
	"dir::bin::lz4":        "/usr/bin/lz4",
	"dir::bin::zstd":       "/usr/bin/zstd",
	"dir::bin::lzma":       "/usr/bin/xz",
}

// APT marks unavailable optional native compressors as "false", depending
// on which Debian packages are installed. Accept only each compressor's own
// executable or its disabled representation; never custom executable names
// or paths. This supports minimal and full Debian 13 installations without
// weakening the acquisition-method trust boundary.
var nativeAPTCompressors = map[string][]string{
	"apt::compressor::.::binary":     {""},
	"apt::compressor::zstd::binary":  {"zstd", "false"},
	"apt::compressor::lz4::binary":   {"lz4", "false"},
	"apt::compressor::gzip::binary":  {"gzip", "false"},
	"apt::compressor::xz::binary":    {"xz", "false"},
	"apt::compressor::bzip2::binary": {"bzip2", "false"},
	"apt::compressor::lzma::binary":  {"xz", "false"},
}

func verifyAptDump(dump, expected string) error {
	return verifyAptDumpWithCompatibility(dump, expected, aptStrictNative)
}

func verifyAptDumpWithCompatibility(dump, expected string, compatibility aptCompatibility) error {
	return verifyAptDumpPolicy(dump, expected, compatibility, false)
}

func verifyAptDumpPolicy(dump, expected string, compatibility aptCompatibility, ownedDisabled bool) error {
	seenHTTP, seenHTTPS := false, false
	seenDir, seenUsr := false, false
	seenBins := make(map[string]bool, len(nativeAPTBinConfig))
	seenDisabled := make(map[string]bool, len(aptDisabledMethods))
	for _, line := range strings.Split(dump, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		proxyPath := strings.HasPrefix(key, "acquire::http::proxy") ||
			strings.HasPrefix(key, "acquire::https::proxy")
		auto := strings.Contains(key, "proxy-auto-detect") || strings.Contains(key, "proxyautodetect")
		// apt-config is not apt/apt-get. Reject binary-specific transport and
		// source configuration overrides, while allowing normal presentation
		// and dpkg/UI defaults that Debian ships under Binary::apt.
		binary := strings.HasPrefix(key, "binary::") &&
			(strings.Contains(key, "::acquire") || strings.Contains(key, "::proxy") ||
				strings.Contains(key, "::dir") || strings.Contains(key, "::rootdir") ||
				strings.Contains(key, "::apt::compressor") ||
				strings.Contains(key, "::debug::acquire"))
		// APT's HTTP wire debugging can print Proxy-Authorization (secrets).
		debug := strings.HasPrefix(key, "debug::acquire") ||
			strings.HasPrefix(key, "debug::pkgacquire")
		if binary || auto || debug || (proxyPath && key != "acquire::http::proxy" && key != "acquire::https::proxy") {
			return Fault("apt_policy_conflict", "APT per-host proxy, auto-detection or binary policy may bypass selected route")
		}
		// RootDir prepends even absolute APT paths. A new Dir root or usr
		// prefix can also change where method executables are resolved.
		if key == "rootdir" || strings.HasPrefix(key, "rootdir::") {
			return Fault("apt_policy_conflict", "APT root directory redirection is unsupported in Proxy Only")
		}
		if key == "dir::" || strings.HasPrefix(key, "dir::usr::") {
			return Fault("apt_policy_conflict", "APT root path extension is unsupported")
		}
		if key == "dir" || key == "dir::usr" {
			want := "/"
			if key == "dir::usr" {
				want = "usr"
			}
			if len(fields) != 2 || fields[1] != "\""+want+"\";" {
				return Fault("apt_policy_conflict", "APT root directory policy differs from native Debian layout")
			}
			if key == "dir" {
				seenDir = true
			} else {
				seenUsr = true
			}
		}
		if key == "dir::bin" || strings.HasPrefix(key, "dir::bin::") {
			if strings.HasPrefix(key, "dir::bin::methods::") {
				known := false
				for _, method := range aptDisabledMethods {
					if key == "dir::bin::methods::"+method {
						known = true
					}
				}
				if !ownedDisabled || !known || seenDisabled[key] || len(fields) != 2 || fields[1] != "\""+aptDisabledMethodPath+"\";" {
					return Fault("apt_policy_conflict", "APT per-method execution override is not the verified disabled policy")
				}
				seenDisabled[key] = true
				continue
			}
			want, known := nativeAPTBinConfig[key]
			approved := known && len(fields) == 2 && fields[1] == "\""+want+"\";"
			// Debian 13's minimal image selects the native lzma program
			// while a full installation may use xz for the same compressor.
			// Neither spelling permits a caller-controlled method path.
			if key == "dir::bin::lzma" && len(fields) == 2 && fields[1] == "\"/usr/bin/lzma\";" {
				approved = true
			}
			if !approved {
				return Fault("apt_policy_conflict", "APT executable or acquisition method path differs from native Debian layout")
			}
			seenBins[key] = true
		}
		if strings.HasPrefix(key, "apt::compressor::") && strings.HasSuffix(key, "::binary") {
			nativeNames, known := nativeAPTCompressors[key]
			approved := false
			if known && len(fields) == 2 {
				for _, name := range nativeNames {
					if fields[1] == "\""+name+"\";" {
						approved = true
						break
					}
				}
			}
			if !approved {
				return Fault("apt_policy_conflict", "APT compressor executable is not a supported native binary")
			}
		}
		if key == "acquire::http::proxy" || key == "acquire::https::proxy" {
			if len(fields) != 2 || fields[1] != "\""+expected+"\";" {
				return Fault("apt_policy_conflict", "effective APT proxy differs from selected authenticated route")
			}
			if key == "acquire::http::proxy" {
				seenHTTP = true
			} else {
				seenHTTPS = true
			}
		}
	}
	if !seenHTTP || !seenHTTPS {
		return Fault("apt_policy_conflict", "effective APT HTTP(S) proxy settings not verified")
	}
	if ownedDisabled && len(seenDisabled) != len(aptDisabledMethods) {
		return Fault("apt_policy_conflict", "APT disabled acquisition method policy not established")
	}
	// Native APT2.6.1 has no Dir::Usr default. Only the independently observed
	// Debian12/2.6.1 mode may omit it; a present value was still checked above.
	if !seenDir || (!seenUsr && compatibility != aptDebian12Native261) || len(seenBins) != len(nativeAPTBinConfig) {
		return Fault("apt_policy_conflict", "trusted native APT executable path configuration not established")
	}
	return nil
}

func privateAptConfig(stateDir string, proxy *url.URL) (*os.File, error) {
	if proxy == nil || proxy.Scheme != "http" || proxy.Hostname() != "127.0.0.1" ||
		proxy.User == nil || proxy.Port() == "" {
		return nil, errors.New("APT requires an authenticated local HTTP proxy")
	}
	name := proxy.String()
	if strings.ContainsAny(name, "\r\n\"\\") {
		return nil, errors.New("unexpected proxy characters")
	}
	file, err := os.CreateTemp(stateDir, ".apt-ephemeral-*")
	if err != nil {
		return nil, err
	}
	cleanup := func() { file.Close(); os.Remove(file.Name()) }
	if err = file.Chmod(0600); err != nil {
		cleanup()
		return nil, err
	}
	if _, err = fmt.Fprintf(file, "Acquire::http::Proxy \"%s\";\nAcquire::https::Proxy \"%s\";\n", name, name); err != nil {
		cleanup()
		return nil, err
	}
	if err = file.Sync(); err != nil {
		cleanup()
		return nil, err
	}
	if _, err = file.Seek(0, 0); err != nil {
		cleanup()
		return nil, err
	}
	if err = os.Remove(file.Name()); err != nil {
		cleanup()
		return nil, err
	}
	return file, nil
}

func safeAptEnv() []string {
	env := make([]string, 0, len(os.Environ()))
	for _, val := range os.Environ() {
		key, _, _ := strings.Cut(val, "=")
		lowerKey := strings.ToLower(key)
		switch lowerKey {
		case "apt_config", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy",
			"path", "gconv_path":
			continue
		}
		if strings.HasPrefix(lowerKey, "ld_") {
			continue
		}
		env = append(env, val)
	}
	// Do not allow inherited PATH or dynamic linker settings to shadow APT's
	// child utilities/methods, or preflight itself.
	return append(env, "PATH=/usr/sbin:/usr/bin:/sbin:/bin")
}
