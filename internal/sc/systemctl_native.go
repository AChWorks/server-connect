package sc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Only the native Debian systemd controller is allowed for internal service
// operations. The operator's PATH is never an authority to select a root-run
// executable. Explicit user-requested child commands have a separate contract.
const nativeSystemctlPath = "/usr/bin/systemctl"

func trustedSystemctlExecutable() error {
	if runtime.GOOS != "linux" {
		return Fault("service_binary_untrusted", "native systemd control requires Linux")
	}
	return verifyTrustedSystemctlAt("/", nativeSystemctlPath, 0)
}

// The fixture parameters test path substitution/permission failures without
// changing the live /usr/bin tree. Production always uses the fixed path and
// UID 0; neither is operator configurable.
func verifyTrustedSystemctlAt(root, executable string, ownerUID uint32) error {
	untrusted := func() error {
		return Fault("service_binary_untrusted", "native systemd controller is missing or untrusted")
	}
	if !filepath.IsAbs(root) || !filepath.IsAbs(executable) ||
		filepath.Clean(root) != root || filepath.Clean(executable) != executable {
		return untrusted()
	}
	relative, err := filepath.Rel(root, executable)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return untrusted()
	}
	current := root
	parts := strings.Split(relative, string(filepath.Separator))
	for i := 0; i <= len(parts); i++ {
		if i > 0 {
			current = filepath.Join(current, parts[i-1])
		}
		info, err := os.Lstat(current)
		if err != nil {
			return untrusted()
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != ownerUID || info.Mode().Perm()&0022 != 0 {
			return untrusted()
		}
		if i < len(parts) {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return untrusted()
			}
		} else if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 ||
			info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return untrusted()
		}
	}
	return nil
}

// Every control-plane systemd call uses the same trusted executable and a
// fixed noninteractive environment. Do not inherit loader/systemd/DBus
// overrides from an arbitrary root shell or an application invoking this CLI.
// The caller still owns its timeout and must classify the result separately.
func trustedSystemctlCommand(ctx context.Context, args ...string) (*exec.Cmd, error) {
	if err := trustedSystemctlExecutable(); err != nil {
		return nil, err
	}
	options := make([]string, 0, len(args)+2)
	options = append(options, "--system", "--no-pager")
	options = append(options, args...)
	cmd := exec.CommandContext(ctx, nativeSystemctlPath, options...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	cmd.WaitDelay = 250 * time.Millisecond
	return cmd, nil
}
