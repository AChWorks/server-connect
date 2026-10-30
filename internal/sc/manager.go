package sc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const DefaultDir = "/var/lib/server-connect"
const DefaultCore = "/opt/server-connect/current/bin/sing-box"
const DefaultUnit = "server-connect.service"
const managedUnitPath = "/etc/systemd/system/server-connect.service"
const managedPrefix = "/opt/server-connect"
const DefaultPort = 20807

var idPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

type Manager struct {
	Dir, Core string
	Port      int
}
type State struct {
	Version  int    `json:"version"`
	Selected string `json:"selected,omitempty"`
	Desired  string `json:"desired"`
	Port     int    `json:"port"`
}
type ProfileInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Selected bool   `json:"selected"`
}
type Status struct {
	Desired     string `json:"desired"`
	Observed    string `json:"observed"`
	Selected    string `json:"selected,omitempty"`
	Port        int    `json:"port"`
	CoreVersion string `json:"core_version"`
	Health      string `json:"health"`
}
type ProbeResult struct {
	Path       string `json:"path"`
	Code       int    `json:"http_status"`
	DurationMs int64  `json:"duration_ms"`
	Result     string `json:"result"`
}

func New(dir, core string, port int) *Manager {
	if dir == "" {
		dir = DefaultDir
	}
	if core == "" {
		core = DefaultCore
	}
	if port == 0 {
		port = DefaultPort
	}
	return &Manager{Dir: dir, Core: core, Port: port}
}

func ensureDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("state path must be absolute")
	}
	s, e := os.Lstat(path)
	if os.IsNotExist(e) {
		// Another local operation may create the private directory at
		// the same instant. Reinspect its type and permissions below;
		// never assume that EEXIST implies a trusted directory.
		if e = os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
			return e
		}
		s, e = os.Lstat(path)
	}
	if e != nil {
		return e
	}
	if !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
		return errors.New("state path is not a real directory")
	}
	if s.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("insecure permissions on %s; expected 0700", path)
	}
	return nil
}
func (m *Manager) prepare() error {
	if e := ensureDir(m.Dir); e != nil {
		return e
	}
	return ensureDir(filepath.Join(m.Dir, "profiles"))
}
func readRegular(path string) ([]byte, error) {
	s, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 {
		return nil, errors.New("insecure or non-regular state file")
	}
	return os.ReadFile(path)
}
func put(path string, data []byte) error {
	dir := filepath.Dir(path)
	if s, e := os.Lstat(path); e == nil {
		if !s.Mode().IsRegular() {
			return errors.New("refusing to replace non-regular state file")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(dir, ".sc-write-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (m *Manager) withLock(fn func() error) error {
	if e := m.prepare(); e != nil {
		return e
	}
	p := filepath.Join(m.Dir, ".lock")
	f, e := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 {
		return errors.New("invalid lock file")
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
		return e
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
func (m *Manager) load() (State, error) {
	s := State{Version: 1, Desired: "direct", Port: m.Port}
	b, e := readRegular(filepath.Join(m.Dir, "state.json"))
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return State{}, e
	}
	if e = json.Unmarshal(b, &s); e != nil {
		return State{}, errors.New("invalid stored state")
	}
	if s.Version != 1 || (s.Desired != "direct" && s.Desired != "proxy") || s.Port < 1024 || s.Port > 65535 {
		return State{}, errors.New("unsupported or invalid stored state")
	}
	return s, nil
}
func (m *Manager) save(s State) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return put(filepath.Join(m.Dir, "state.json"), b)
}
func (m *Manager) profile(id string) (Profile, error) {
	if !idPattern.MatchString(id) {
		return Profile{}, errors.New("invalid profile ID")
	}
	b, e := readRegular(filepath.Join(m.Dir, "profiles", id+".json"))
	if e != nil {
		return Profile{}, e
	}
	var p Profile
	if json.Unmarshal(b, &p) != nil || p.ID != id || len(p.Outbound) == 0 {
		return Profile{}, errors.New("corrupt saved profile")
	}
	return p, nil
}
func (m *Manager) Import(data []byte, tag string) (ProfileInfo, error) {
	p, e := ValidateSource(data, tag)
	if e != nil {
		return ProfileInfo{}, e
	}
	if e = EnsureCore(m.Core); e != nil {
		return ProfileInfo{}, e
	}
	password, e := randomHex(24)
	if e != nil {
		return ProfileInfo{}, e
	}
	cfg, e := CoreConfig(p, m.Port, password)
	if e != nil {
		return ProfileInfo{}, e
	}
	var out ProfileInfo
	e = m.withLock(func() error {
		if e = CheckConfig(m.Core, m.Dir, cfg); e != nil {
			return e
		}
		b, _ := json.MarshalIndent(p, "", "  ")
		if e = put(filepath.Join(m.Dir, "profiles", p.ID+".json"), b); e != nil {
			return e
		}
		out = ProfileInfo{ID: p.ID, Name: p.Name, Kind: p.Kind}
		return nil
	})
	return out, e
}
func (m *Manager) List() ([]ProfileInfo, error) {
	list := []ProfileInfo{}
	e := m.withLock(func() error {
		s, e := m.load()
		if e != nil {
			return e
		}
		es, e := os.ReadDir(filepath.Join(m.Dir, "profiles"))
		if e != nil {
			return e
		}
		for _, entry := range es {
			id := strings.TrimSuffix(entry.Name(), ".json")
			if !idPattern.MatchString(id) {
				continue
			}
			p, e := m.profile(id)
			if e != nil {
				return e
			}
			list = append(list, ProfileInfo{ID: id, Name: p.Name, Kind: p.Kind, Selected: s.Selected == id})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		return nil
	})
	return list, e
}
func (m *Manager) Select(id string) error {
	return m.withLock(func() error {
		if phase, err := m.pendingSmartTUNTrial(); err != nil {
			return err
		} else if phase != "" {
			return Fault("guard_pending", "reconcile the guarded TUN trial before changing the selected profile")
		}
		if _, e := m.profile(id); e != nil {
			return e
		}
		s, e := m.load()
		if e != nil {
			return e
		}
		if s.Desired != "direct" {
			return errors.New("disconnect the active profile before selecting another")
		}
		s.Selected = id
		return m.save(s)
	})
}
func (m *Manager) Remove(id string) error {
	return m.withLock(func() error {
		if phase, err := m.pendingSmartTUNTrial(); err != nil {
			return err
		} else if phase != "" {
			return Fault("guard_pending", "reconcile the guarded TUN trial before removing a profile")
		}
		if _, e := m.profile(id); e != nil {
			return e
		}
		s, e := m.load()
		if e != nil {
			return e
		}
		if s.Selected == id && s.Desired != "direct" {
			return errors.New("disconnect before removing the active profile")
		}
		if s.Selected == id {
			s.Selected = ""
			if e = m.save(s); e != nil {
				return e
			}
		}
		if e = os.Remove(filepath.Join(m.Dir, "profiles", id+".json")); e != nil {
			return e
		}
		d, e := os.Open(filepath.Join(m.Dir, "profiles"))
		if e != nil {
			return e
		}
		defer d.Close()
		return d.Sync()
	})
}
func (m *Manager) unitActive() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, "is-active", DefaultUnit)
	if err != nil {
		return "unknown", err
	}
	b, e := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "unknown", errors.New("systemd service observation timed out")
	}
	return parseUnitActivity(b, e)
}

// systemctl is-active uses a successful zero exit for active and systemd's
// standard inactive exit code 3 for inactive/failed. A printed state from an
// otherwise broken command (signal, bus error, missing unit, etc.) is not proof.
func parseUnitActivity(output []byte, runErr error) (string, error) {
	state := strings.TrimSpace(string(output))
	if state == "active" && runErr == nil {
		return state, nil
	}
	var exitErr *exec.ExitError
	if (state == "inactive" || state == "failed") &&
		errors.As(runErr, &exitErr) && exitErr.ExitCode() == 3 {
		return state, nil
	}
	return "unknown", Fault("service_state_unavailable", "native systemd service state could not be verified")
}

// verifyUnitOwnership executes before any lifecycle mutation. Merely choosing
// an arbitrary --unit/name must never turn unrelated host services into ours.
func (m *Manager) verifyUnitOwnership() error {
	if m.Dir != DefaultDir || m.Core != DefaultCore {
		return errors.New("service lifecycle requires installed Server Connect paths")
	}
	marker := filepath.Join(managedPrefix, ".owner")
	markerData, err := readTrustedRootFile(marker)
	if err != nil || strings.TrimSpace(string(markerData)) != "AChWorks/server-connect" {
		return errors.New("Server Connect installation ownership is not verified")
	}
	unitData, err := readTrustedRootFile(managedUnitPath)
	if err != nil {
		return errors.New("owned systemd unit is missing or unsafe")
	}
	expected, err := readTrustedRootFile(filepath.Join(managedPrefix, "unit.sha256"))
	if err != nil {
		return errors.New("owned systemd unit manifest is missing or unsafe")
	}
	digest, err := hex.DecodeString(strings.TrimSpace(string(expected)))
	if err != nil || len(digest) != sha256.Size {
		return errors.New("invalid systemd unit ownership digest")
	}
	actual := sha256.Sum256(unitData)
	if !bytes.Equal(digest, actual[:]) {
		return Fault("service_conflict", "systemd unit differs from owned manifest")
	}
	dir, err := os.Lstat(managedPrefix)
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0022 != 0 || !ownedByRoot(dir) {
		return errors.New("unsafe systemd installation ownership directory")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, "show", DefaultUnit,
		"--property=LoadState", "--property=FragmentPath", "--property=DropInPaths", "--property=Transient")
	if err != nil {
		return err
	}
	output, err := cmd.Output()
	if err != nil {
		return errors.New("systemd ownership could not be inspected")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) == 2 {
			fields[pair[0]] = pair[1]
		}
	}
	if fields["LoadState"] != "loaded" || fields["FragmentPath"] != managedUnitPath ||
		fields["DropInPaths"] != "" || fields["Transient"] != "no" {
		return Fault("service_conflict", "systemd unit provenance conflict; refusing service mutation")
	}
	return nil
}

func readTrustedRootFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || !ownedByRoot(info) {
		return nil, errors.New("resource is not a root-owned regular non-writable file")
	}
	return os.ReadFile(path)
}

func ownedByRoot(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// VerifyUnitForInstaller must be callable before starting/stopping the
// installed service. It performs no mutation or profile-store write.
func (m *Manager) VerifyUnitForInstaller() error {
	if os.Geteuid() != 0 {
		return Fault("ownership_required", "root required for installed unit verification")
	}
	return m.verifyUnitOwnership()
}

func (m *Manager) systemctl(args ...string) error {
	if err := m.verifyUnitOwnership(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	base := append([]string{}, args...)
	base = append(base, DefaultUnit)
	cmd, err := trustedSystemctlCommand(ctx, base...)
	if err != nil {
		return err
	}
	if e := cmd.Run(); e != nil {
		if ctx.Err() != nil {
			return errors.New("systemctl operation timed out")
		}
		return fmt.Errorf("systemctl %s failed: %w", strings.Join(args, " "), e)
	}
	return nil
}
func (m *Manager) Status() (Status, error) {
	return m.statusWithService(m.unitActive, m.verifyUnitOwnership)
}

// A service status is a machine-visible observation, not an optimistic
// default. Independent test readers cover unavailable systemd and ownership
// conflicts without installing or changing any service on the host.
func (m *Manager) statusWithService(observe func() (string, error), verifyOwnership func() error) (Status, error) {
	var status Status
	err := m.withLock(func() error {
		s, err := m.load()
		if err != nil {
			return err
		}
		if phase, err := m.pendingSmartTUNTrial(); err != nil {
			return err
		} else if phase != "" {
			status = Status{Desired: s.Desired, Observed: "smart_tun_" + phase,
				Selected: s.Selected, Port: s.Port, CoreVersion: CoreVersion,
				Health: "guarded_trial_unconfirmed"}
			if strings.HasPrefix(phase, "supervised_") {
				status.Health = "supervised_record_not_freshly_verified"
			}
			return Fault("guard_pending", "Smart Routing trial is not Direct; inspect smart-tun-trial-status")
		}
		observed, inspectErr := observe()
		status = Status{Desired: s.Desired, Observed: observed, Selected: s.Selected, Port: s.Port, CoreVersion: CoreVersion, Health: "not_tested"}
		if inspectErr != nil || (observed != "active" && observed != "inactive" && observed != "failed") {
			status.Observed = "unknown"
			status.Health = "service_state_unavailable"
			// Retain the specific, already sanitized native-binary trust failure.
			// Arbitrary subprocess errors can contain unsafe raw host details.
			if inspectErr != nil && ErrorCode(inspectErr) == "service_binary_untrusted" {
				return inspectErr
			}
			return Fault("service_state_unavailable", "native systemd service state cannot be verified")
		}
		if s.Desired == "proxy" && observed != "active" {
			status.Health = "core_unavailable"
		}
		if s.Desired == "direct" && observed == "active" {
			status.Health = "unexpected_active_service"
		}
		if s.Desired == "direct" && observed == "failed" {
			status.Health = "historical_proxy_failure_direct_unaffected"
		}
		if observed == "active" && verifyOwnership() != nil {
			status.Health = "service_ownership_conflict"
			return Fault("service_conflict", "active systemd unit ownership is unverified")
		}
		return nil
	})
	return status, err
}

// New credentials are staged in memory until all service observations pass.
// A failed or contradictory status must not mutate auth or runtime state.
func (m *Manager) stagedPassword() (password string, needsSave bool, err error) {
	b, err := readRegular(filepath.Join(m.Dir, "proxy-auth"))
	if os.IsNotExist(err) {
		secret, err := randomHex(24)
		return secret, true, err
	}
	if err != nil {
		return "", false, err
	}
	if len(b) != 48 {
		return "", false, errors.New("invalid local proxy authentication state")
	}
	return string(b), false, nil
}

// checkLocalAuth proves that the selected local listener speaks SOCKS5 and
// accepts the manager's private credentials, without opening foreign traffic.
func checkLocalAuth(port int, password string) error {
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 350*time.Millisecond)
	if err != nil {
		return errors.New("authenticated loopback listener unavailable")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(900 * time.Millisecond))
	if _, err = conn.Write([]byte{5, 1, 2}); err != nil {
		return errors.New("SOCKS5 greeting failed")
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(conn, reply); err != nil || reply[0] != 5 || reply[1] != 2 {
		return errors.New("SOCKS5 listener does not require expected authentication")
	}
	if len(password) > 255 {
		return errors.New("proxy authentication length unsupported")
	}
	authentication := append([]byte{1, 2, 's', 'c', byte(len(password))}, []byte(password)...)
	if _, err = conn.Write(authentication); err != nil {
		return errors.New("proxy authentication handshake failed")
	}
	if _, err = io.ReadFull(conn, reply); err != nil || reply[0] != 1 || reply[1] != 0 {
		return errors.New("proxy authentication rejected")
	}
	return nil
}

func (m *Manager) waitReady(port int, password string) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		active, err := m.unitActive()
		if err != nil {
			return err
		}
		if active != "active" {
			return errors.New("sing-box service exited before its listener became ready")
		}
		if checkLocalAuth(port, password) == nil {
			time.Sleep(150 * time.Millisecond)
			after, _ := m.unitActive()
			if after == "active" {
				return nil
			}
			return errors.New("sing-box service exited immediately after listener readiness")
		}
		time.Sleep(125 * time.Millisecond)
	}
	return errors.New("sing-box authenticated loopback listener readiness timeout")
}

// Ready is read-only: state is written atomically and installer updates hold
// the lifecycle lock while checking readiness. Avoid re-locking that FD here.
func (m *Manager) Ready() error {
	if err := m.verifyUnitOwnership(); err != nil {
		return err
	}
	s, e := m.load()
	if e != nil {
		return e
	}
	if s.Desired != "proxy" {
		return Fault("proxy_unavailable", "proxy mode is not desired")
	}
	b, e := readRegular(filepath.Join(m.Dir, "proxy-auth"))
	if e != nil {
		return Fault("proxy_unavailable", "proxy authentication state unavailable")
	}
	return m.waitReady(s.Port, string(b))
}

// ReconcileDirectUnderInstaller runs only from a root-owned installer while
// its shared .lock is held and after systemd has confirmed service shutdown.
// This resets active intent but preserves stored profiles for later opt-in.
// verifyInheritedInstallerLock validates FD 9 inherited from the actual
// installer flock. Re-acquiring LOCK_EX on the same open file description
// succeeds; a different command cannot mutate while another holder owns it.
// An outside invocation lacking this protected descriptor is rejected.
func (m *Manager) verifyInheritedInstallerLock() error {
	if os.Geteuid() != 0 || m.Dir != DefaultDir {
		return Fault("lifecycle_conflict", "installed root-owned lifecycle lock required")
	}
	lockPath := filepath.Join(m.Dir, ".lock")
	fileInfo, err := os.Lstat(lockPath)
	if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0600 || !ownedByRoot(fileInfo) {
		return Fault("lifecycle_conflict", "trusted lifecycle lock unavailable")
	}
	procInfo, err := os.Stat("/proc/self/fd/9")
	if err != nil || !os.SameFile(fileInfo, procInfo) {
		return Fault("lifecycle_conflict", "inherited installer lock descriptor missing")
	}
	if err = syscall.Flock(9, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return Fault("lifecycle_conflict", "lifecycle lock held by another operation")
	}
	return nil
}

func (m *Manager) ReconcileDirectUnderInstaller() error {
	if err := m.verifyInheritedInstallerLock(); err != nil {
		return err
	}
	// A valid lifecycle lock alone cannot adopt a foreign or missing service.
	if err := m.verifyUnitOwnership(); err != nil {
		return err
	}
	if os.Geteuid() != 0 || m.Dir != DefaultDir || m.Core != DefaultCore {
		return Fault("lifecycle_conflict", "only the installed root-owned lifecycle can reconcile Direct")
	}
	state, err := m.unitActive()
	if err != nil {
		return err
	}
	if state == "active" {
		return Fault("lifecycle_conflict", "cannot reconcile Direct with active proxy service")
	}
	if err = m.prepare(); err != nil {
		return err
	}
	desired, err := m.load()
	if err != nil {
		return err
	}
	desired.Desired = "direct"
	if err = m.save(desired); err != nil {
		return err
	}
	target := filepath.Join(m.Dir, "runtime.json")
	if _, err = readRegular(target); err == nil {
		if err = os.Remove(target); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Connect refuses any unverified service state before touching private
// credentials/runtime. Raw service diagnostics are never reflected to users.
func checkedConnectActivity(observe func() (string, error)) (string, error) {
	state, err := observe()
	if err != nil {
		if ErrorCode(err) == "service_binary_untrusted" {
			return "unknown", Fault("service_binary_untrusted", "native systemd controller is missing or untrusted")
		}
		return "unknown", Fault("service_state_unavailable", "native systemd service activity cannot be verified before activation")
	}
	switch state {
	case "active", "inactive", "failed":
		return state, nil
	default:
		return "unknown", Fault("service_state_unavailable", "native systemd returned an unsupported service activity state")
	}
}

func (m *Manager) Connect() error {
	if err := m.verifyUnitOwnership(); err != nil {
		return err
	}
	if err := EnsureCore(m.Core); err != nil {
		return err
	}
	return m.withLock(func() error { return m.connectLocked(m.unitActive) })
}

// connectLocked holds the existing exclusive Manager lock. Only its
// read-only service observer is injectable for isolated regression tests.
func (m *Manager) connectLocked(observe func() (string, error)) error {
	if phase, err := m.pendingSmartTUNTrial(); err != nil {
		return err
	} else if phase != "" {
		return Fault("guard_pending", "guarded TUN trial must be reconciled before Proxy Only activation")
	}
	s, err := m.load()
	if err != nil {
		return err
	}
	if s.Selected == "" {
		return errors.New("select a profile before connecting")
	}
	p, err := m.profile(s.Selected)
	if err != nil {
		return err
	}
	activity, err := checkedConnectActivity(observe)
	if err != nil {
		return err
	}
	if activity == "active" {
		if s.Desired != "proxy" {
			return Fault("service_conflict", "unexpected active service; refusing to overwrite its runtime")
		}
		b, err := readRegular(filepath.Join(m.Dir, "proxy-auth"))
		if err != nil {
			return err
		}
		return m.waitReady(s.Port, string(b))
	}
	pass, needsSave, err := m.stagedPassword()
	if err != nil {
		return err
	}
	cfg, err := CoreConfig(p, s.Port, pass)
	if err != nil {
		return err
	}
	if err = CheckConfig(m.Core, m.Dir, cfg); err != nil {
		return err
	}
	// Validation can take seconds; observe again before either durable secret
	// or runtime write. A service appearing now is never safe to overwrite.
	activity, err = checkedConnectActivity(observe)
	if err != nil {
		return err
	}
	if activity == "active" {
		return Fault("service_conflict", "service became active during validation; refusing runtime overwrite")
	}
	if needsSave {
		if err = put(filepath.Join(m.Dir, "proxy-auth"), []byte(pass)); err != nil {
			return err
		}
	}
	target := filepath.Join(m.Dir, "runtime.json")
	if err = put(target, cfg); err != nil {
		return err
	}
	startErr := m.systemctl("enable", "--now")
	if startErr == nil {
		startErr = m.waitReady(s.Port, pass)
	}
	if startErr != nil {
		stopErr := m.systemctl("stop")
		disableErr := m.systemctl("disable")
		if stopErr != nil || disableErr != nil {
			return fmt.Errorf("proxy activation failed and cleanup is incomplete: %w", startErr)
		}
		if err = os.Remove(target); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("proxy activation failed; runtime cleanup error: %w", err)
		}
		s.Desired = "direct"
		if err = m.save(s); err != nil {
			return fmt.Errorf("proxy activation failed; state cleanup error: %w", err)
		}
		return startErr
	}
	s.Desired = "proxy"
	if err = m.save(s); err != nil {
		return fmt.Errorf("service activated but state persistence failed; disconnect required: %w", err)
	}
	return nil
}

func (m *Manager) Disconnect() error {
	return m.withLock(func() error {
		if phase, err := m.pendingSmartTUNTrial(); err != nil {
			return err
		} else if phase != "" {
			return Fault("guard_pending", "cannot claim Direct while a guarded TUN trial remains")
		}
		// Stop first: never claim Direct if our proxy process is still active.
		if e := m.systemctl("stop"); e != nil {
			return e
		}
		if e := m.systemctl("disable"); e != nil {
			return e
		}
		s, e := m.load()
		if e != nil {
			return e
		}
		s.Desired = "direct"
		if e = m.save(s); e != nil {
			return e
		}
		path := filepath.Join(m.Dir, "runtime.json")
		if _, e := readRegular(path); e == nil {
			if e = os.Remove(path); e != nil {
				return e
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		return nil
	})
}
func (m *Manager) proxyURL() (*url.URL, error) {
	var raw string
	e := m.withLock(func() error {
		s, e := m.load()
		if e != nil {
			return e
		}
		active, _ := m.unitActive()
		if s.Desired != "proxy" || active != "active" {
			return Fault("proxy_unavailable", "local proxy is not active")
		}
		if err := m.verifyUnitOwnership(); err != nil {
			return err
		}
		b, e := readRegular(filepath.Join(m.Dir, "proxy-auth"))
		if e != nil {
			return e
		}
		if len(b) != 48 {
			return errors.New("invalid proxy auth")
		}
		raw = "http://" + url.UserPassword("sc", string(b)).String() + "@127.0.0.1:" + strconv.Itoa(s.Port)
		return nil
	})
	if e != nil {
		return nil, e
	}
	return url.Parse(raw)
}
func (m *Manager) Probe(via, destination string) (ProbeResult, error) {
	if via != "direct" && via != "proxy" {
		return ProbeResult{}, errors.New("via must be direct or proxy")
	}
	u, e := url.Parse(destination)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ProbeResult{}, errors.New("probe URL must be http(s)")
	}
	var proxy *url.URL
	if via == "proxy" {
		proxy, e = m.proxyURL()
		if e != nil {
			return ProbeResult{Path: via, Result: "unavailable"}, e
		}
	}
	// Never substitute Direct for a requested Proxy, including if the
	// selected service stops before the actual HTTP request.
	return probeHTTPPath(via, destination, proxy)
}
func (m *Manager) Exec(command []string) (int, error) {
	if len(command) == 0 {
		return 1, errors.New("no command supplied")
	}
	proxy, e := m.proxyURL()
	if e != nil {
		return 1, e
	}
	env := []string{}
	for _, v := range os.Environ() {
		key := strings.SplitN(v, "=", 2)[0]
		switch strings.ToLower(key) {
		case "http_proxy", "https_proxy", "all_proxy", "no_proxy":
			continue
		}
		env = append(env, v)
	}
	s := proxy.String()
	env = append(env, "HTTP_PROXY="+s, "HTTPS_PROXY="+s, "ALL_PROXY="+s, "http_proxy="+s, "https_proxy="+s, "all_proxy="+s, "NO_PROXY=", "no_proxy=")
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if e = cmd.Run(); e != nil {
		var code *exec.ExitError
		if errors.As(e, &code) {
			return code.ExitCode(), nil
		}
		return 1, e
	}
	return 0, nil
}
