package sc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
const DefaultPort = 20807

var idPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

type Manager struct {
	Dir, Core, Unit string
	Port            int
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

func New(dir, core, unit string, port int) *Manager {
	if dir == "" {
		dir = DefaultDir
	}
	if core == "" {
		core = DefaultCore
	}
	if unit == "" {
		unit = DefaultUnit
	}
	if port == 0 {
		port = DefaultPort
	}
	return &Manager{Dir: dir, Core: core, Unit: unit, Port: port}
}

func ensureDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("state path must be absolute")
	}
	s, e := os.Lstat(path)
	if os.IsNotExist(e) {
		if e = os.Mkdir(path, 0700); e != nil {
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
	b, e := exec.CommandContext(ctx, "systemctl", "is-active", m.Unit).CombinedOutput()
	state := strings.TrimSpace(string(b))
	if e != nil && state != "inactive" && state != "failed" && state != "unknown" {
		return "unknown", errors.New("systemd service state unavailable")
	}
	if state == "active" {
		return "active", nil
	}
	return "inactive", nil
}
func (m *Manager) systemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	base := append([]string{}, args...)
	base = append(base, m.Unit)
	if e := exec.CommandContext(ctx, "systemctl", base...).Run(); e != nil {
		if ctx.Err() != nil {
			return errors.New("systemctl operation timed out")
		}
		return fmt.Errorf("systemctl %s failed: %w", strings.Join(args, " "), e)
	}
	return nil
}
func (m *Manager) Status() (Status, error) {
	var status Status
	e := m.withLock(func() error {
		s, e := m.load()
		if e != nil {
			return e
		}
		observed, _ := m.unitActive()
		status = Status{Desired: s.Desired, Observed: observed, Selected: s.Selected, Port: s.Port, CoreVersion: CoreVersion, Health: "not_tested"}
		if s.Desired == "proxy" && observed != "active" {
			status.Health = "core_unavailable"
		}
		if s.Desired == "direct" && observed == "active" {
			status.Health = "unexpected_active_service"
		}
		return nil
	})
	return status, e
}
func (m *Manager) password() (string, error) {
	path := filepath.Join(m.Dir, "proxy-auth")
	b, e := readRegular(path)
	if os.IsNotExist(e) {
		s, e := randomHex(24)
		if e != nil {
			return "", e
		}
		if e = put(path, []byte(s)); e != nil {
			return "", e
		}
		return s, nil
	}
	if e != nil {
		return "", e
	}
	if len(b) != 48 {
		return "", errors.New("invalid local proxy authentication state")
	}
	return string(b), nil
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

// Ready is a local-only readiness check; it does not claim upstream health.
func (m *Manager) Ready() error {
	return m.withLock(func() error {
		s, e := m.load()
		if e != nil {
			return e
		}
		if s.Desired != "proxy" {
			return errors.New("proxy mode is not desired")
		}
		b, e := readRegular(filepath.Join(m.Dir, "proxy-auth"))
		if e != nil {
			return e
		}
		return m.waitReady(s.Port, string(b))
	})
}

func (m *Manager) Connect() error {
	if e := EnsureCore(m.Core); e != nil {
		return e
	}
	return m.withLock(func() error {
		s, e := m.load()
		if e != nil {
			return e
		}
		if s.Selected == "" {
			return errors.New("select a profile before connecting")
		}
		p, e := m.profile(s.Selected)
		if e != nil {
			return e
		}
		if s.Desired == "proxy" {
			status, _ := m.unitActive()
			if status == "active" {
				b, e := readRegular(filepath.Join(m.Dir, "proxy-auth"))
				if e != nil {
					return e
				}
				return m.waitReady(s.Port, string(b))
			}
		}
		pass, e := m.password()
		if e != nil {
			return e
		}
		cfg, e := CoreConfig(p, s.Port, pass)
		if e != nil {
			return e
		}
		if e = CheckConfig(m.Core, m.Dir, cfg); e != nil {
			return e
		}
		if status, _ := m.unitActive(); status == "active" && s.Desired != "proxy" {
			return errors.New("unowned or unexpected active service; refusing to overwrite")
		}
		target := filepath.Join(m.Dir, "runtime.json")
		// Do not overwrite an active runtime or another operator's temporary file.
		if e = put(target, cfg); e != nil {
			return e
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
			if e = os.Remove(target); e != nil && !os.IsNotExist(e) {
				return fmt.Errorf("proxy activation failed; runtime cleanup error: %w", e)
			}
			s.Desired = "direct"
			if e = m.save(s); e != nil {
				return fmt.Errorf("proxy activation failed; state cleanup error: %w", e)
			}
			return startErr
		}
		s.Desired = "proxy"
		if e = m.save(s); e != nil {
			return fmt.Errorf("service activated but state persistence failed; disconnect required: %w", e)
		}
		return nil
	})
}
func (m *Manager) Disconnect() error {
	return m.withLock(func() error {
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
			return errors.New("local proxy is not active")
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
	t := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 6 * time.Second}).DialContext, TLSHandshakeTimeout: 7 * time.Second, DisableKeepAlives: true}
	if via == "proxy" {
		px, e := m.proxyURL()
		if e != nil {
			return ProbeResult{}, e
		}
		t.Proxy = http.ProxyURL(px)
	}
	defer t.CloseIdleConnections()
	cli := &http.Client{Transport: t, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	req, e := http.NewRequest(http.MethodGet, destination, nil)
	if e != nil {
		return ProbeResult{}, errors.New("invalid probe request")
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, e := cli.Do(req)
	result := ProbeResult{Path: via, DurationMs: time.Since(start).Milliseconds(), Result: "failed"}
	if e != nil {
		return result, fmt.Errorf("%s probe failed (DNS, connect, TLS, upstream or proxy path); host routing unchanged", via)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
	result.Code = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		result.Result = "reachable"
	} else {
		result.Result = "http_error"
		return result, fmt.Errorf("%s path returned HTTP %d; request is not healthy", via, resp.StatusCode)
	}
	return result, nil
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
