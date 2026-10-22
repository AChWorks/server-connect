package sc

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Apt executes only apt/apt-get with an explicit, authenticated Proxy Only
// configuration. APT does not reliably honor generic HTTP_PROXY variables.
// The config is passed as an unlinked, mode-0600 file descriptor; nothing is
// written to /etc/apt or left on disk after the operation.
func (m *Manager) Apt(args []string) (int, error) {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 || (filepath.Base(args[0]) != "apt-get" && filepath.Base(args[0]) != "apt") {
		return 1, Fault("invalid_arguments", "apt requires an explicit apt-get or apt command")
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

	// APT parses the file before contacting any repository. Passing a
	// descriptor path in argv avoids putting proxy credentials in argv/env.
	argv := make([]string, 0, len(args)+2)
	argv = append(argv, "-c", "/proc/self/fd/3")
	argv = append(argv, args[1:]...)
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

func privateAptConfig(stateDir string, proxy *url.URL) (*os.File, error) {
	if proxy == nil || proxy.Scheme != "http" || proxy.Hostname() != "127.0.0.1" ||
		proxy.User == nil || proxy.Port() == "" {
		return nil, errors.New("APT requires an authenticated local HTTP proxy")
	}
	// The URL here is produced by the manager from validated port and random
	// local credentials, never an arbitrary untrusted APT configuration line.
	name := proxy.String()
	if strings.ContainsAny(name, "\r\n\"\\") {
		return nil, errors.New("unexpected proxy characters")
	}
	file, err := os.CreateTemp(stateDir, ".apt-ephemeral-*")
	if err != nil {
		return nil, err
	}
	cleanup := func() {
		file.Close()
		os.Remove(file.Name())
	}
	if err = file.Chmod(0600); err != nil {
		cleanup()
		return nil, err
	}
	if _, err = fmt.Fprintf(file,
		"Acquire::http::Proxy \"%s\";\nAcquire::https::Proxy \"%s\";\n", name, name); err != nil {
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
		case "apt_config", "http_proxy", "https_proxy", "all_proxy", "no_proxy",
			"ftp_proxy":
			continue
		}
		env = append(env, val)
	}
	return env
}
