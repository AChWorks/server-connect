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

// Debian 13 APT can launch native acquisition helpers beyond HTTP(S) for
// PDiff updates, mirror lists, local sources and index signature verification.
// An immutable parent directory alone does not establish the ownership/mode of
// existing children. Keep the supported Debian 13 method inventory explicit:
// custom transport packages and unexpected files fail closed rather than
// executing an unverified helper with the selected proxy.
var nativeAPTMethodExecutables = map[string]bool{
	"http": true, "file": true, "gpgv": true,
	"rred": true, "mirror": true, "copy": true, "cdrom": true,
	"store": true, "sqv": true,
}

// APT method symlinks must stay within the same verified native directory.
// Fixed, single-hop alias targets also prevent loops and directory traversal.
var nativeAPTMethodAliases = map[string]string{
	"https":        "http",
	"mirror+http":  "mirror",
	"mirror+https": "mirror",
	"mirror+file":  "mirror",
	"mirror+copy":  "mirror",
}

// Only the base transport/signature paths are required on every supported
// installation. Other native Debian 13 handlers may be absent, but if they
// exist they must pass the identical trust checks before any APT execution.
var requiredAPTMethods = []string{"http", "https", "file", "gpgv"}

func verifyNativeAPTMethods() error {
	for _, dir := range []string{
		"/", "/usr", "/usr/lib", "/usr/lib/apt", "/usr/lib/apt/methods",
	} {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || !aptRootOwnedNonWritable(info) {
			return Fault("apt_untrusted_executable", "native APT method directory ownership is unsafe")
		}
	}
	return verifyNativeAPTMethodInventory("/usr/lib/apt/methods", 0)
}

// expectedUID is hardcoded to root at the sole production call site. It is
// passed explicitly here to make the same filesystem checks testable without
// privileged ownership changes on a disposable non-root test workspace.
func verifyNativeAPTMethodInventory(dir string, expectedUID uint32) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Fault("apt_untrusted_executable", "native APT acquisition method inventory unavailable")
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		target, alias := nativeAPTMethodAliases[name]
		if !alias && !nativeAPTMethodExecutables[name] {
			return Fault("apt_untrusted_executable", "unsupported APT acquisition method installed")
		}
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return Fault("apt_untrusted_executable", "native APT acquisition method identity unavailable")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != expectedUID {
			return Fault("apt_untrusted_executable", "native APT acquisition method ownership is unsafe")
		}
		if alias {
			relative, err := os.Readlink(path)
			if info.Mode()&os.ModeSymlink == 0 || err != nil || relative != target {
				return Fault("apt_untrusted_executable", "native APT method alias is untrusted")
			}
		} else if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 ||
			info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return Fault("apt_untrusted_executable", "native APT acquisition method permissions are unsafe")
		}
		seen[name] = true
	}
	for _, required := range requiredAPTMethods {
		if !seen[required] {
			return Fault("apt_untrusted_executable", "required native APT acquisition method missing")
		}
	}
	for alias, target := range nativeAPTMethodAliases {
		if seen[alias] && !seen[target] {
			return Fault("apt_untrusted_executable", "native APT method alias target is missing")
		}
	}
	return nil
}

func aptRootOwned(info os.FileInfo) bool {
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == 0
}

func aptRootOwnedNonWritable(info os.FileInfo) bool {
	return aptRootOwned(info) && info.Mode().Perm()&0022 == 0
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
