//go:build linux

package sc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// Diagnostic only, after the real admission observer refused in a fresh
// disposable namespace. It cannot authorize a skip or a positive result.
// Never query an absent table with -t or invoke a userspace module loader.
func hostLegacyNativeFailureDiagnostics(t *testing.T) {
	t.Helper()
	requireNativeQANetworkNamespace(t)
	falseErr := verifyTrustedIPPath("/", "/usr/bin/false", 0)
	t.Logf("ISOLATED_LEGACY_TRUST path=/usr/bin/false error=%v", falseErr)
	for _, path := range []string{
		"/", "/usr", "/usr/bin", "/usr/sbin", "/etc", "/etc/alternatives",
		"/usr/bin/false", "/usr/sbin/iptables-legacy-save", "/usr/sbin/ip6tables-legacy-save",
		"/usr/sbin/xtables-legacy-multi",
	} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Logf("ISOLATED_LEGACY_PATH path=%s error=%v", path, err)
			continue
		}
		uid, gid := uint32(^uint32(0)), uint32(^uint32(0))
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			uid, gid = st.Uid, st.Gid
		}
		target := ""
		if info.Mode()&os.ModeSymlink != 0 {
			target, err = os.Readlink(path)
			if len(target) > 256 {
				target = "<oversized symlink target>"
			}
		}
		t.Logf("ISOLATED_LEGACY_PATH path=%s uid=%d gid=%d mode=%s target=%q error=%v", path, uid, gid, info.Mode(), target, err)
	}
	readNames := func(path, phase string) ([]byte, error) {
		f, err := os.Open(path)
		if err != nil {
			t.Logf("ISOLATED_LEGACY_PROC phase=%s path=%s missing=%t error=%v", phase, path, errors.Is(err, os.ErrNotExist), err)
			return nil, err
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, 257))
		if len(raw) > 256 {
			raw = raw[:256]
			err = fmt.Errorf("registered table names exceed 256-byte bound")
		}
		t.Logf("ISOLATED_LEGACY_PROC phase=%s path=%s missing=false bytes=%q error=%v", phase, path, raw, err)
		return raw, err
	}
	for _, family := range []string{"ip", "ip6"} {
		path := "/proc/net/" + family + "_tables_names"
		before, beforeErr := readNames(path, "before")
		binary := "/usr/sbin/" + family + "tables-legacy-save"
		trustErr := verifyHostNetfilterPath("/", binary, 0)
		t.Logf("ISOLATED_LEGACY_TRUST path=%s error=%v", binary, trustErr)
		if falseErr == nil && trustErr == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			cmd := exec.CommandContext(ctx, binary, "-M", "/usr/bin/false")
			cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			cmd.Dir = "/"
			cmd.WaitDelay = 250 * time.Millisecond
			var stdout, stderr boundedFirewallOutput
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			exit := -1
			if cmd.ProcessState != nil {
				exit = cmd.ProcessState.ExitCode()
			}
			bounded := func(raw []byte) string {
				if len(raw) > 4096 {
					return string(raw[:4096]) + "<output truncated after 4096 bytes>"
				}
				return string(raw)
			}
			t.Logf("ISOLATED_LEGACY_SAVE binary=%s args=-M,/usr/bin/false exit=%d timed_out=%t error=%v stdout_bytes=%d stderr_bytes=%d stdout=%q stderr=%q",
				binary, exit, ctx.Err() != nil, err, stdout.Len(), stderr.Len(), bounded(stdout.Bytes()), bounded(stderr.Bytes()))
			cancel()
		} else {
			t.Logf("ISOLATED_LEGACY_SAVE binary=%s NOT_EXECUTED=untrusted_path", binary)
		}
		after, afterErr := readNames(path, "after")
		t.Logf("ISOLATED_LEGACY_PROC_STABLE family=%s verified=%t", family, beforeErr == nil && afterErr == nil && bytes.Equal(before, after))
	}
}
