//go:build linux

package sc

// Shared installed Native Core guard observation/management helpers. V4 trial
// execution does not use these to create new operations.
import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	smartTUNHealthUnit  = "server-connect-smart-health.service"
	smartTUNHealthTimer = "server-connect-smart-health.timer"
)

type nativeGuardUnitIdentity struct {
	UnitDev   uint64 `json:"unit_dev"`
	UnitIno   uint64 `json:"unit_ino"`
	DigestDev uint64 `json:"digest_dev"`
	DigestIno uint64 `json:"digest_ino"`
	SHA256    string `json:"sha256"`
}

func readInstalledGuardUnitFile(path string) ([]byte, activationJournalFileIdentity, error) {
	unavailable := func() ([]byte, activationJournalFileIdentity, error) {
		return nil, activationJournalFileIdentity{}, Fault("guard_unavailable", "installed TUN unit ownership unavailable")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return unavailable()
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before syscall.Stat_t
	if syscall.Fstat(fd, &before) != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		before.Uid != 0 || before.Mode&0022 != 0 || before.Size <= 0 || before.Size > 64*1024 {
		return unavailable()
	}
	data, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	var after, named syscall.Stat_t
	if err != nil || int64(len(data)) != before.Size || syscall.Fstat(fd, &after) != nil ||
		syscall.Lstat(path, &named) != nil || named.Dev != before.Dev || named.Ino != before.Ino ||
		named.Mode != before.Mode || named.Uid != before.Uid || named.Size != before.Size ||
		named.Mtim != before.Mtim || named.Ctim != before.Ctim || after.Size != before.Size ||
		after.Mtim != before.Mtim || after.Ctim != before.Ctim {
		return unavailable()
	}
	return data, activationJournalFileIdentity{dev: uint64(before.Dev), ino: before.Ino}, nil
}

func nativeGuardSystemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, args...)
	if err != nil {
		return err
	}
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		return Fault("guard_unavailable", "trusted systemd TUN/guard operation failed")
	}
	return nil
}

func observeNativeHealthUnit(name string) (nativeGuardUnitIdentity, map[string]string, error) {
	if name != smartTUNHealthUnit && name != smartTUNHealthTimer {
		return nativeGuardUnitIdentity{}, nil, Fault("guard_unavailable", "unknown health role")
	}
	return observeNativeManagedUnit(name)
}

func observeNativeRecoveryUnit(name string) (nativeGuardUnitIdentity, map[string]string, error) {
	if name != trialRecoveryUnit && name != trialRecoveryTimer {
		return nativeGuardUnitIdentity{}, nil, Fault("guard_unavailable", "unknown recovery role")
	}
	return observeNativeManagedUnit(name)
}

func observeNativeManagedUnit(name string) (nativeGuardUnitIdentity, map[string]string, error) {
	var empty nativeGuardUnitIdentity
	if name != smartTUNHealthUnit && name != smartTUNHealthTimer &&
		name != trialRecoveryUnit && name != trialRecoveryTimer {
		return empty, nil, Fault("guard_unavailable", "unknown managed role")
	}
	path := filepath.Join(trialGuardUnitDir, name)
	body, unitID, err := readInstalledGuardUnitFile(path)
	if err != nil {
		return empty, nil, err
	}
	digest, digestID, err := readInstalledGuardUnitFile(filepath.Join(managedPrefix, name+".sha256"))
	if err != nil || strings.TrimSpace(string(digest)) != sha256Hex(body) {
		return empty, nil, Fault("guard_unavailable", "health role digest conflict")
	}
	if err := trialNoRuntimeUnitOverride(trialRuntimeUnitDir, name); err != nil {
		return empty, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, "show", name, "-p", "Id", "-p", "LoadState", "-p", "FragmentPath", "-p", "DropInPaths", "-p", "Transient", "-p", "UnitFileState", "-p", "ActiveState", "-p", "Unit", "-p", "Result")
	if err != nil {
		return empty, nil, err
	}
	out, err := cmd.Output()
	if err != nil || ctx.Err() != nil || len(out) > 16384 {
		return empty, nil, Fault("guard_unavailable", "health role runtime unavailable")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			return empty, nil, Fault("guard_unavailable", "health role runtime malformed")
		}
		if _, exists := fields[kv[0]]; exists {
			return empty, nil, Fault("guard_unavailable", "health role runtime duplicate")
		}
		fields[kv[0]] = kv[1]
	}
	if fields["Id"] != name || fields["LoadState"] != "loaded" || fields["FragmentPath"] != path || fields["DropInPaths"] != "" || fields["Transient"] != "no" {
		return empty, nil, Fault("guard_unavailable", "health role identity changed")
	}
	after, afterID, err := readInstalledGuardUnitFile(path)
	if err != nil || afterID != unitID || !bytes.Equal(after, body) {
		return empty, nil, Fault("guard_unavailable", "health role file changed during observation")
	}
	afterDigest, afterDigestID, err := readInstalledGuardUnitFile(filepath.Join(managedPrefix, name+".sha256"))
	if err != nil || afterDigestID != digestID || !bytes.Equal(afterDigest, digest) {
		return empty, nil, Fault("guard_unavailable", "health digest changed during observation")
	}
	return nativeGuardUnitIdentity{UnitDev: unitID.dev, UnitIno: unitID.ino, DigestDev: digestID.dev, DigestIno: digestID.ino, SHA256: sha256Hex(body)}, fields, nil
}

func nativeHealthUnits(armed bool, expected *[2]nativeGuardUnitIdentity) ([2]nativeGuardUnitIdentity, error) {
	var roles [2]nativeGuardUnitIdentity
	for i, name := range []string{smartTUNHealthUnit, smartTUNHealthTimer} {
		id, f, err := observeNativeHealthUnit(name)
		if err != nil {
			return roles, err
		}
		roles[i] = id
		if expected != nil && expected[i] != id {
			return roles, Fault("guard_unavailable", "health role changed since operation admission")
		}
		if f["Result"] != "success" {
			return roles, Fault("guard_unavailable", "health role failed")
		}
		if i == 0 {
			if f["UnitFileState"] != "static" || (f["ActiveState"] != "inactive" && !(armed && f["ActiveState"] == "activating")) {
				return roles, Fault("guard_unavailable", "health executor unavailable")
			}
		} else if f["Unit"] != smartTUNHealthUnit || (armed && (f["ActiveState"] != "active" || f["UnitFileState"] != "enabled")) || (!armed && (f["ActiveState"] != "inactive" || f["UnitFileState"] != "disabled")) {
			return roles, Fault("guard_unavailable", "health timer state unavailable")
		}
	}
	return roles, nil
}

func nativeUptimeMillis() (int64, error) {
	var ts syscall.Timespec
	// Linux CLOCK_BOOTTIME includes suspend and shares /proc starttime's
	// boot-relative domain. Wall-clock changes cannot make an old SSH fresh.
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 7, uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 || ts.Sec < 0 || ts.Sec > (1<<63-1)/1000 || ts.Nsec < 0 || ts.Nsec >= 1e9 {
		return 0, Fault("guard_unavailable", "kernel boot-relative clock unavailable")
	}
	return ts.Sec*1000 + ts.Nsec/1e6, nil
}

func (m *Manager) pendingLegacyActivationJournal() (string, error) {
	raw, err := readRegular(filepath.Join(m.Dir, activationJournalFilename))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", activationJournalError("legacy journal cannot be inspected")
	}
	if e := rejectAmbiguousJournalJSON(raw); e != nil {
		return "", e
	}
	return "legacy_activation_journal", nil
}
func retiredV4UnitAbsent() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, "show", "server-connect-smart-tun.service", "-p", "LoadState", "--value")
	if err != nil {
		return Fault("guard_unavailable", "retired v4 Core unit cannot be inspected")
	}
	raw, err := cmd.Output()
	if err != nil || ctx.Err() != nil || strings.TrimSpace(string(raw)) != "not-found" {
		return Fault("guard_pending", "retired v4 Core unit remains installed; clean QA before native activation")
	}
	return nil
}
