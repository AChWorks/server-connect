package sc

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// Supported Debian 13 APT tools are a fixed, root-owned, non-writable system
// installation. Never execute a caller-supplied basename/path or resolve the
// credentials-bearing child by searching PATH.
const (
	systemAPTGet    = "/usr/bin/apt-get"
	systemAPT       = "/usr/bin/apt"
	systemAPTConfig = "/usr/bin/apt-config"
)

func trustedAPTCommand(token string) (string, error) {
	var installed string
	switch filepath.Base(token) {
	case "apt-get":
		installed = systemAPTGet
	case "apt":
		installed = systemAPT
	default:
		return "", Fault("invalid_arguments", "apt requires an explicit native apt-get or apt command")
	}
	if err := verifyNativeAPTExecutable(installed); err != nil {
		return "", err
	}

	var supplied string
	if token == filepath.Base(token) {
		// A shadow executable anywhere earlier in PATH must not be silently
		// accepted as APT, even when our own exec path is safely fixed.
		found, err := exec.LookPath(token)
		if err != nil {
			return "", Fault("apt_untrusted_executable", "native APT command cannot be resolved safely")
		}
		supplied = found
	} else if filepath.IsAbs(token) {
		supplied = token
	} else {
		return "", Fault("apt_untrusted_executable", "APT command path is not a trusted native executable")
	}
	// /bin is a compatibility alias to /usr/bin on Debian 13 usrmerge.
	switch supplied {
	case installed, "/bin/" + filepath.Base(installed):
	default:
		return "", Fault("apt_untrusted_executable", "APT command path is not a trusted native executable")
	}
	resolved, err := filepath.EvalSymlinks(supplied)
	if err != nil || resolved != installed {
		return "", Fault("apt_untrusted_executable", "APT command path is not a trusted native executable")
	}
	return installed, nil
}

func trustedAPTConfig() (string, error) {
	// apt-config always runs by a known absolute system path, even if PATH
	// contains an executable named apt-config from another directory.
	if err := verifyNativeAPTExecutable(systemAPTConfig); err != nil {
		return "", err
	}
	return systemAPTConfig, nil
}

func verifyNativeAPTExecutable(installed string) error {
	// The verifier is deliberately not a general "root-owned path" checker.
	// A future call site must never approve a different program just because
	// it happens to be executable and owned by root.
	if installed != systemAPTGet && installed != systemAPT && installed != systemAPTConfig {
		return Fault("apt_untrusted_executable", "APT executable is outside the native allowlist")
	}
	// Check the executable and its immutable-by-nonroot ancestor path.
	// A replaced/symlinked native executable is not accepted silently.
	for _, path := range []string{"/", "/usr", "/usr/bin", installed} {
		info, err := os.Lstat(path)
		if err != nil {
			return Fault("apt_untrusted_executable", "trusted native APT executable unavailable")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return Fault("apt_untrusted_executable", "native APT path ownership or permissions unsafe")
		}
		if path == installed {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
				return Fault("apt_untrusted_executable", "trusted native APT executable unavailable")
			}
		} else if !info.IsDir() {
			return Fault("apt_untrusted_executable", "trusted native APT directory unavailable")
		}
	}
	return nil
}
