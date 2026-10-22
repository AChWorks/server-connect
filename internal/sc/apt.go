package sc

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Apt runs apt-get/apt via the selected authenticated local Proxy Only route.
// No persistent host APT settings or unrelated application paths are changed.
func (m *Manager) Apt(args []string) (int, error) {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 || (filepath.Base(args[0]) != "apt-get" && filepath.Base(args[0]) != "apt") {
		return 1, Fault("invalid_arguments", "apt requires an explicit apt-get or apt command")
	}
	opts, action, err := validateAptArgs(args[1:])
	if err != nil {
		return 1, err
	}
	proxy, err := m.proxyURL()
	if err != nil {
		return 1, err
	}
	file, err := privateAptConfig(m.Dir, proxy)
	if err != nil {
		return 1, Fault("apt_configuration", "unable to prepare private APT proxy configuration")
	}
	defer file.Close()
	// Host-specific and autodetected APT settings take precedence over the
	// generic proxy. Inspect the effective configuration; never log its output.
	if err = verifyEffectiveAptProxy(file, proxy.String(), opts); err != nil {
		return 1, err
	}
	argv := aptExecArgs(args[1:], action)
	cmd := exec.Command(args[0], argv...)
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
	if action == "update" {
		argv = append(argv, "--error-on=any")
	}
	return argv
}

// Validate caller overrides before forwarding them to apt-get. Proxy
// overrides, extra config files, and wire-debugging are not supported.
func validateAptArgs(args []string) ([]string, string, error) {
	var opts []string
	action := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		lower := strings.ToLower(a)
		if a == "--" {
			return nil, "", Fault("invalid_arguments", "APT argument separator not supported")
		}
		if lower == "-c" || lower == "--config-file" || strings.HasPrefix(lower, "--config-file=") ||
			(strings.HasPrefix(lower, "-c") && len(a) > 2) {
			return nil, "", Fault("apt_policy_conflict", "APT extra configuration files are not supported in Proxy Only")
		}
		var opt string
		switch {
		case a == "-o" || lower == "--option":
			i++
			if i == len(args) {
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
				key == "apt::update::error-mode" || strings.HasPrefix(key, "debug::acquire") ||
				key == "dir::etc" || key == "dir::etc::main" || key == "dir::etc::parts" ||
				strings.HasPrefix(key, "dir::etc::netrc") {
				return nil, "", Fault("apt_policy_conflict", "APT proxy, policy or configuration-source overrides are not permitted")
			}
			opts = append(opts, "-o", opt)
			continue
		}
		// APT accepts options that consume separate arguments before its
		// subcommand. Never misclassify an update as a different action:
		// that would drop mandatory --error-on=any on a partial failure.
		if lower == "-t" || lower == "-a" ||
			lower == "--target-release" || lower == "--host-architecture" {
			i++
			if i == len(args) {
				return nil, "", Fault("invalid_arguments", "APT option value missing")
			}
			continue
		}
		if !strings.HasPrefix(a, "-") && action == "" {
			action = a
		}
	}
	return opts, action, nil
}

// Inspect APT host policy and caller-supplied supported options with the
// same anonymous config FD/environment. apt-config's stdout is a secret.
func verifyEffectiveAptProxy(file *os.File, expected string, opts []string) error {
	if _, err := file.Seek(0, 0); err != nil {
		return Fault("apt_configuration", "private APT configuration unavailable")
	}
	argv := append([]string{"-c", "/proc/self/fd/3"}, opts...)
	argv = append(argv, "dump")
	cmd := exec.Command("apt-config", argv...)
	cmd.ExtraFiles = []*os.File{file}
	cmd.Env = safeAptEnv()
	var out bytes.Buffer
	cmd.Stdout = &limitedAptOutput{out: &out, limit: 2 << 20}
	cmd.Stderr = &limitedAptOutput{out: &bytes.Buffer{}, limit: 64 << 10}
	if err := cmd.Run(); err != nil {
		return Fault("apt_policy_conflict", "cannot verify effective APT configuration; refusing Direct fallback")
	}
	return verifyAptDump(out.String(), expected)
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

func verifyAptDump(dump, expected string) error {
	seenHTTP, seenHTTPS := false, false
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
				strings.Contains(key, "::dir::etc") || strings.Contains(key, "::debug::acquire"))
		// APT's HTTP wire debugging can print Proxy-Authorization (secrets).
		debug := strings.HasPrefix(key, "debug::acquire") ||
			strings.HasPrefix(key, "debug::pkgacquire")
		if binary || auto || debug || (proxyPath && key != "acquire::http::proxy" && key != "acquire::https::proxy") {
			return Fault("apt_policy_conflict", "APT per-host proxy, auto-detection or binary policy may bypass selected route")
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
		switch strings.ToLower(key) {
		case "apt_config", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy":
			continue
		}
		env = append(env, val)
	}
	return env
}
