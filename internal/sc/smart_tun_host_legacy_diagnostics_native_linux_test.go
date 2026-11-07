//go:build linux

package sc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

type hostLegacyNativeProcEvidence struct {
	observed bool
	raw      []byte
	err      error
}
type hostLegacyNativeFamilyEvidence struct {
	before, after           hostLegacyNativeProcEvidence
	trustBefore, trustAfter error
	executed, timedOut      bool
	exit                    int
	err                     error
	stdout, stderr          []byte
}
type hostLegacyNativeEvidence struct {
	families                        [2]hostLegacyNativeFamilyEvidence
	falseBefore, falseAfter         error
	pathsBefore, pathsAfter         string
	namespaceBefore, namespaceAfter [2]uint64
}

// This classifier authorizes only an explicitly unsupported negative test,
// never an empty policy, successful admission, or any product operation.
// Missing proc alone (or legacy-save exit 0 alone) is insufficient.
func hostLegacyNativeMissingIPv6Core(admission error, e hostLegacyNativeEvidence) bool {
	if ErrorCode(admission) != "foreign_legacy_policy_unverified" ||
		admission.Error() != hostLegacyPolicyUnverified().Error() ||
		e.falseBefore != nil || e.falseAfter != nil ||
		!journalHex64.MatchString(e.pathsBefore) || e.pathsBefore != e.pathsAfter ||
		e.namespaceBefore[0] == 0 || e.namespaceBefore[1] == 0 || e.namespaceBefore != e.namespaceAfter {
		return false
	}
	for i, family := range e.families {
		if !family.before.observed || !family.after.observed ||
			family.trustBefore != nil || family.trustAfter != nil ||
			!family.executed || family.timedOut || family.exit != 0 || family.err != nil ||
			len(family.stdout) != 0 || len(family.stderr) != 0 ||
			len(family.before.raw) != 0 || len(family.after.raw) != 0 {
			return false
		}
		if i == 0 {
			if family.before.err != nil || family.after.err != nil {
				return false
			}
		} else if !errors.Is(family.before.err, os.ErrNotExist) || !errors.Is(family.after.err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

// Collect independent bounded evidence only after real admission refused in
// a disposable namespace. Never query an absent table with -t or invoke a
// userspace module loader. Failure/partial evidence remains unclassified.
func hostLegacyNativeFailureDiagnostics(t *testing.T) hostLegacyNativeEvidence {
	t.Helper()
	requireNativeQANetworkNamespace(t)
	var evidence hostLegacyNativeEvidence
	dev, ino, err := nativeTUNNamespace()
	if err != nil {
		t.Fatal(err)
	}
	evidence.namespaceBefore = [2]uint64{dev, ino}
	evidence.falseBefore = verifyTrustedIPPath("/", "/usr/bin/false", 0)
	t.Logf("ISOLATED_LEGACY_TRUST phase=before path=/usr/bin/false error=%v", evidence.falseBefore)
	pathSnapshot := func(phase string) string {
		type witness struct {
			Dev, Ino       uint64
			UID, GID, Mode uint32
			Size           int64
			Mtime, Ctime   syscall.Timespec
			Target         string
		}
		found := map[string]witness{}
		valid := true
		for _, path := range []string{
			"/", "/usr", "/usr/bin", "/usr/sbin",
			"/usr/bin/false", "/usr/sbin/iptables-legacy-save", "/usr/sbin/ip6tables-legacy-save",
			"/usr/sbin/xtables-legacy-multi",
		} {
			info, err := os.Lstat(path)
			if err != nil {
				valid = false
				t.Logf("ISOLATED_LEGACY_PATH phase=%s path=%s error=%v", phase, path, err)
				continue
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				valid = false
				continue
			}
			w := witness{Dev: uint64(st.Dev), Ino: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode, Size: st.Size, Mtime: st.Mtim, Ctime: st.Ctim}
			if info.Mode()&os.ModeSymlink != 0 {
				w.Target, err = os.Readlink(path)
				if len(w.Target) > 256 {
					err = errors.New("oversized symlink target")
					w.Target = "<oversized>"
				}
				if err != nil {
					valid = false
				}
			}
			found[path] = w
			t.Logf("ISOLATED_LEGACY_PATH phase=%s path=%s uid=%d gid=%d mode=%s target=%q error=%v", phase, path, w.UID, w.GID, info.Mode(), w.Target, err)
		}
		if !valid {
			return ""
		}
		raw, err := json.Marshal(found)
		if err != nil {
			return ""
		}
		return sha256Hex(raw)
	}
	evidence.pathsBefore = pathSnapshot("before")
	readNames := func(path, phase string) hostLegacyNativeProcEvidence {
		result := hostLegacyNativeProcEvidence{observed: true}
		f, err := os.Open(path)
		if err != nil {
			result.err = err
			t.Logf("ISOLATED_LEGACY_PROC phase=%s path=%s missing=%t error=%v", phase, path, errors.Is(err, os.ErrNotExist), err)
			return result
		}
		defer f.Close()
		result.raw, result.err = io.ReadAll(io.LimitReader(f, 257))
		if len(result.raw) > 256 {
			result.raw = result.raw[:256]
			result.err = errors.New("registered table names exceed 256-byte bound")
		}
		t.Logf("ISOLATED_LEGACY_PROC phase=%s path=%s missing=false bytes=%q error=%v", phase, path, result.raw, result.err)
		return result
	}
	for i, family := range []string{"ip", "ip6"} {
		item := &evidence.families[i]
		path := "/proc/net/" + family + "_tables_names"
		item.before = readNames(path, "before")
		binary := "/usr/sbin/" + family + "tables-legacy-save"
		item.trustBefore = verifyHostNetfilterPath("/", binary, 0)
		t.Logf("ISOLATED_LEGACY_TRUST phase=before path=%s error=%v", binary, item.trustBefore)
		if evidence.falseBefore == nil && item.trustBefore == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			cmd := exec.CommandContext(ctx, binary, "-M", "/usr/bin/false")
			cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
			cmd.Dir = "/"
			cmd.WaitDelay = 250 * time.Millisecond
			var stdout, stderr boundedFirewallOutput
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			item.executed, item.exit = true, -1
			item.err = cmd.Run()
			if cmd.ProcessState != nil {
				item.exit = cmd.ProcessState.ExitCode()
			}
			item.timedOut, item.stdout, item.stderr = ctx.Err() != nil, stdout.Bytes(), stderr.Bytes()
			bounded := func(raw []byte) string {
				if len(raw) > 4096 {
					return string(raw[:4096]) + "<output truncated after 4096 bytes>"
				}
				return string(raw)
			}
			t.Logf("ISOLATED_LEGACY_SAVE binary=%s args=-M,/usr/bin/false exit=%d timed_out=%t error=%v stdout_bytes=%d stderr_bytes=%d stdout=%q stderr=%q",
				binary, item.exit, item.timedOut, item.err, len(item.stdout), len(item.stderr), bounded(item.stdout), bounded(item.stderr))
			cancel()
		} else {
			t.Logf("ISOLATED_LEGACY_SAVE binary=%s NOT_EXECUTED=untrusted_path", binary)
		}
		item.after = readNames(path, "after")
		item.trustAfter = verifyHostNetfilterPath("/", binary, 0)
		t.Logf("ISOLATED_LEGACY_TRUST phase=after path=%s error=%v", binary, item.trustAfter)
		t.Logf("ISOLATED_LEGACY_PROC_STABLE family=%s verified=%t", family, item.before.err == nil && item.after.err == nil && bytes.Equal(item.before.raw, item.after.raw))
	}
	evidence.falseAfter = verifyTrustedIPPath("/", "/usr/bin/false", 0)
	evidence.pathsAfter = pathSnapshot("after")
	requireNativeQANetworkNamespace(t)
	dev, ino, err = nativeTUNNamespace()
	if err != nil {
		t.Fatal(err)
	}
	evidence.namespaceAfter = [2]uint64{dev, ino}
	t.Logf("ISOLATED_LEGACY_PATHS_STABLE verified=%t namespace_stable=%t false_error=%v", evidence.pathsBefore != "" && evidence.pathsBefore == evidence.pathsAfter, evidence.namespaceBefore == evidence.namespaceAfter, evidence.falseAfter)
	return evidence
}

// Repeat the actual preparation and strict journal writer, bracketed by
// independent namespace, fixture, scalar and legacy observations. Even this
// exact missing-core condition cannot silently become a successful preflight.
func hostLegacyNativeVerifyUnsupportedRefusal(t *testing.T, initial error, prepare func() (func(*activationJournalDir) error, error)) bool {
	t.Helper()
	first := hostLegacyNativeFailureDiagnostics(t)
	if !hostLegacyNativeMissingIPv6Core(initial, first) {
		return false
	}
	before := hostNativeKernelSnapshot(t)
	scalar, err := readHostIngressSysctl()
	if err != nil {
		t.Fatal(err)
	}
	writeRejected, refusal := prepare()
	if ErrorCode(refusal) != "foreign_legacy_policy_unverified" || refusal.Error() != hostLegacyPolicyUnverified().Error() || writeRejected == nil {
		t.Fatalf("missing IPv6 core was admitted or refused for another reason: %v", refusal)
	}
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if ErrorCode(writeRejected(store)) != "activation_journal_invalid" {
			return errors.New("refused preparation yielded a publishable operation parent")
		}
		if _, _, err := store.readJournal(); !errors.Is(err, os.ErrNotExist) {
			return errors.New("refused preparation published a journal")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	last := hostLegacyNativeFailureDiagnostics(t)
	afterScalar, scalarErr := readHostIngressSysctl()
	if !hostLegacyNativeMissingIPv6Core(refusal, last) ||
		first.pathsAfter != last.pathsBefore || first.namespaceAfter != last.namespaceBefore ||
		scalarErr != nil || afterScalar != scalar || hostNativeKernelSnapshot(t) != before {
		t.Fatal("unsupported admission changed fixture/namespace or lost exact prerequisite evidence")
	}
	return true
}
