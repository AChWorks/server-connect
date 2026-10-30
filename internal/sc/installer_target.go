package sc

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf8"
)

const installerMetadataMaxBytes = 16 * 1024

// InstallerTargetVerification is an installability check, not publisher
// authentication or permission to activate host routing. The shared installer
// must verify the complete bundle's ownership and checksums before invoking it.
type InstallerTargetVerification struct {
	Target   string `json:"target"`
	Verified bool   `json:"verified"`
}

func installerTargetInvalid() error {
	return Fault("installer_target_invalid", "bundle target metadata is missing, unsafe or unsupported")
}

// This reader is separate from private-state readers: public package metadata
// may be mode0644. Its bounded root/UID parameters are internal filesystem-test
// seams; production always uses / and UID0, never an environment/CLI override.
func readInstallerFileAt(root, path string, ownerUID uint32, limit int64) ([]byte, error) {
	bad := func() ([]byte, error) { return nil, installerTargetInvalid() }
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path || limit <= 0 {
		return bad()
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return bad()
	}
	trusted := func(info os.FileInfo, directory bool) bool {
		if info == nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		identity, ok := info.Sys().(*syscall.Stat_t)
		if !ok || identity.Uid != ownerUID {
			return false
		}
		if directory {
			return info.IsDir()
		}
		return info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= limit
	}
	info, err := os.Lstat(root)
	if err != nil || !trusted(info, true) {
		return bad()
	}
	current := root
	parts := strings.Split(rel, string(os.PathSeparator))
	var before os.FileInfo
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err = os.Lstat(current)
		if err != nil || !trusted(info, i < len(parts)-1) {
			return bad()
		}
		before = info
	}
	// NOFOLLOW rejects a replaced link; NONBLOCK prevents a substituted FIFO
	// from hanging this privileged pre-mutation check. Reinspect the open object.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return bad()
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !trusted(opened, false) || !os.SameFile(before, opened) {
		return bad()
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit || int64(len(raw)) != opened.Size() {
		return bad()
	}
	after, err := f.Stat()
	currentInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !trusted(after, false) ||
		!trusted(currentInfo, false) || !os.SameFile(opened, currentInfo) ||
		after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return bad()
	}
	return raw, nil
}

// Only the two literal OS identity fields are interpreted; this is not a shell
// evaluator. Quoted canonical os-release values are accepted, but expansion,
// escapes, duplicate/case-aliased identities and ID_LIKE substitution are not.
func installerHostTarget(raw []byte, goos, goarch, machine string) (string, error) {
	bad := func() (string, error) {
		return "", Fault("unsupported_host", "verified Debian 12 or 13 on native linux/amd64 is required")
	}
	if goos != "linux" || goarch != "amd64" || machine != "x86_64" ||
		len(raw) == 0 || len(raw) > installerMetadataMaxBytes || !utf8.Valid(raw) || strings.ContainsRune(string(raw), 0) {
		return bad()
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return bad()
		}
		for i, ch := range key {
			if !(ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || i > 0 && ch >= '0' && ch <= '9') {
				return bad()
			}
		}
		upper := strings.ToUpper(key)
		if upper != "ID" && upper != "VERSION_ID" {
			continue
		}
		if key != upper {
			return bad()
		}
		if _, exists := values[key]; exists {
			return bad()
		}
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	if values["ID"] != "debian" || (values["VERSION_ID"] != "12" && values["VERSION_ID"] != "13") {
		return bad()
	}
	return "debian-" + values["VERSION_ID"] + "-amd64", nil
}

func currentInstallerHostTarget() (string, error) {
	unsupported := func() (string, error) {
		return "", Fault("unsupported_host", "supported host OS identity cannot be verified")
	}
	// Debian's normal /etc/os-release symlink is allowed, but its resolved
	// regular file and complete ancestor chain must remain root-owned/trusted.
	etc, err := os.Lstat("/etc")
	if err != nil || !etc.IsDir() || etc.Mode()&os.ModeSymlink != 0 || etc.Mode().Perm()&0022 != 0 {
		return unsupported()
	}
	etcIdentity, ok := etc.Sys().(*syscall.Stat_t)
	if !ok || etcIdentity.Uid != 0 {
		return unsupported()
	}
	identity, err := os.Lstat("/etc/os-release")
	if err != nil || (!identity.Mode().IsRegular() && identity.Mode()&os.ModeSymlink == 0) ||
		(identity.Mode().IsRegular() && identity.Mode().Perm()&0022 != 0) {
		return unsupported()
	}
	owner, ok := identity.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return unsupported()
	}
	path, err := filepath.EvalSymlinks("/etc/os-release")
	if err != nil {
		return unsupported()
	}
	raw, err := readInstallerFileAt("/", path, 0, installerMetadataMaxBytes)
	if err != nil {
		return unsupported()
	}
	resolvedAgain, err := filepath.EvalSymlinks("/etc/os-release")
	currentIdentity, identityErr := os.Lstat("/etc/os-release")
	if err != nil || identityErr != nil || resolvedAgain != path ||
		!os.SameFile(identity, currentIdentity) || !identity.ModTime().Equal(currentIdentity.ModTime()) {
		return unsupported()
	}
	var system syscall.Utsname
	if err := syscall.Uname(&system); err != nil {
		return unsupported()
	}
	var machine []byte
	for _, ch := range system.Machine {
		if ch == 0 {
			break
		}
		machine = append(machine, byte(ch))
	}
	return installerHostTarget(raw, runtime.GOOS, runtime.GOARCH, string(machine))
}

func verifyInstallerManifestTarget(raw []byte, hostTarget string) error {
	if len(raw) == 0 || len(raw) > installerMetadataMaxBytes || rejectAmbiguousJournalJSON(raw) != nil {
		return installerTargetInvalid()
	}
	// Reuse the existing bounded duplicate/case-ambiguity scanner before map
	// decoding. Other versioned manifest metadata is not reinterpreted here.
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return installerTargetInvalid()
	}
	var schema int
	var target string
	if json.Unmarshal(fields["schema"], &schema) != nil || schema != 1 ||
		json.Unmarshal(fields["target"], &target) != nil ||
		(target != "debian-12-amd64" && target != "debian-13-amd64") {
		return installerTargetInvalid()
	}
	if target != hostTarget {
		return Fault("installer_target_mismatch", "bundle target does not match the actual supported host")
	}
	return nil
}

// VerifyInstallerTarget never creates product state or invokes a service/core.
func VerifyInstallerTarget(manifestPath string) (InstallerTargetVerification, error) {
	if os.Geteuid() != 0 {
		return InstallerTargetVerification{}, Fault("invalid_arguments", "installer-only command")
	}
	target, err := currentInstallerHostTarget()
	if err != nil {
		return InstallerTargetVerification{}, err
	}
	raw, err := readInstallerFileAt("/", manifestPath, 0, installerMetadataMaxBytes)
	if err != nil {
		return InstallerTargetVerification{}, err
	}
	if err := verifyInstallerManifestTarget(raw, target); err != nil {
		return InstallerTargetVerification{}, err
	}
	return InstallerTargetVerification{Target: target, Verified: true}, nil
}

const nativeTrialPlatformRefusal = "native trials require Debian 13; Debian 12 installation supports Direct/Proxy Only only"

func requireNativeTrialTarget(target string) error {
	if target != "debian-13-amd64" {
		return Fault("trial_unsupported", nativeTrialPlatformRefusal)
	}
	return nil
}

// New Apply admission only. Recovery and inspection deliberately keep their
// existing identity/ownership checks, even if the OS has since changed.
func nativeTrialApplyPlatform() error {
	target, err := currentInstallerHostTarget()
	if err != nil {
		return Fault("trial_unsupported", nativeTrialPlatformRefusal)
	}
	return requireNativeTrialTarget(target)
}
