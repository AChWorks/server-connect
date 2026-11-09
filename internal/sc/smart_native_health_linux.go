//go:build linux

package sc

// Native Smart Routing reuses the two already-installed independent guard
// timers. No second tunnel, route owner, firewall manager or always-on daemon.
// A failed selected path is re-probed for a finite interval while the official
// Core retains its fail-closed native policy. We intentionally do not restart
// the Core: its ExecStopPost must restore Direct on every Core exit.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const nativeHealthFile = "native-health.json"
const nativeHealthLeaseMS int64 = 35000 // health oneshot: 20s max; next tick: 5s
const nativeHealthGraceMS int64 = 20000

type NativeHealthState struct {
	Version          int    `json:"version"`
	OperationID      string `json:"operation_id"`
	ConfigSHA256     string `json:"config_sha256"`
	BootID           string `json:"boot_id"`
	StartedMS        int64  `json:"started_uptime_ms"`
	HeartbeatMS      int64  `json:"heartbeat_uptime_ms"`
	LastProbeMS      int64  `json:"last_probe_uptime_ms"`
	Rounds           int    `json:"rounds"`
	Failures         int    `json:"failures"`
	UnhealthyRounds  int    `json:"unhealthy_rounds"`
	FailureThreshold int    `json:"failure_threshold"`
	Phase            string `json:"phase"`
	Reason           string `json:"reason"`
	ProbeScope       string `json:"probe_scope"`
}

type nativeHealthOutcome struct {
	OK     bool
	Reason string
}

func nativeHealthAdvance(s NativeHealthState, outcome nativeHealthOutcome, now int64) (NativeHealthState, bool) {
	s.HeartbeatMS, s.LastProbeMS = now, now
	s.Rounds++
	if outcome.OK {
		s.Phase, s.Reason, s.Failures = "healthy", "selected_https_verified", 0
		return s, false
	}
	// A fresh installation may need several seconds to create its first TUN.
	// Never make the grace a renewed lease after an established healthy round.
	if s.Phase == "starting" && now < s.StartedMS+nativeHealthGraceMS {
		s.Reason = "startup_" + outcome.Reason
		return s, false
	}
	s.Failures++
	s.UnhealthyRounds++
	s.Reason = outcome.Reason
	// Cumulative budget prevents a flapping provider from resetting the incident forever.
	if s.Failures >= s.FailureThreshold || s.UnhealthyRounds >= s.FailureThreshold*3 {
		s.Phase = "stopping"
		return s, true
	}
	s.Phase = "degraded"
	return s, false
}

func (m *Manager) readNativeHealth() (NativeHealthState, error) {
	raw, err := readRegular(filepath.Join(m.Dir, nativeHealthFile))
	if err != nil {
		return NativeHealthState{}, err
	}
	if len(raw) > 4096 || rejectAmbiguousJournalJSON(raw) != nil {
		return NativeHealthState{}, Fault("invalid_state", "native health record ambiguous")
	}
	var s NativeHealthState
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var end any
	if dec.Decode(&s) != nil || !errors.Is(dec.Decode(&end), io.EOF) || s.Version != 1 ||
		!journalHex64.MatchString(s.ConfigSHA256) || len(s.OperationID) != 32 || !trialBootIDPattern.MatchString(s.BootID) ||
		s.StartedMS <= 0 || s.HeartbeatMS < s.StartedMS || s.LastProbeMS < 0 ||
		s.Rounds < 0 || s.Rounds > 100000000 || s.Failures < 0 || s.Failures > 10 || s.UnhealthyRounds < 0 || s.UnhealthyRounds > 100000000 ||
		s.FailureThreshold < 1 || s.FailureThreshold > 10 || s.UnhealthyRounds < s.Failures || len(s.Reason) > 96 ||
		(s.ProbeScope != "internet_https" && s.ProbeScope != "synthetic_https") {
		return NativeHealthState{}, Fault("invalid_state", "native health record invalid")
	}
	if _, e := hex.DecodeString(s.OperationID); e != nil {
		return NativeHealthState{}, Fault("invalid_state", "native health operation invalid")
	}
	switch s.Phase {
	case "starting", "healthy", "degraded", "stopping", "off", "uncertain":
	default:
		return NativeHealthState{}, Fault("invalid_state", "native health phase invalid")
	}
	return s, nil
}
func (m *Manager) saveNativeHealth(s NativeHealthState) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return put(filepath.Join(m.Dir, nativeHealthFile), b)
}
func (m *Manager) stageNativeHealth(session NativeSession, threshold int, scope string) error {
	if threshold < 1 || threshold > 10 {
		return Fault("invalid_arguments", "native health failure threshold must be 1-10")
	}
	if scope != "internet_https" && scope != "synthetic_https" {
		return Fault("invalid_arguments", "unsupported native health probe scope")
	}
	now, e := smartTUNUptimeMillis()
	if e != nil {
		return e
	}
	boot, e := trialBootIdentity()
	if e != nil {
		return e
	}
	id := make([]byte, 16)
	if _, e = rand.Read(id); e != nil {
		return Fault("guard_unavailable", "native operation randomness unavailable")
	}
	return m.saveNativeHealth(NativeHealthState{Version: 1, OperationID: hex.EncodeToString(id), ConfigSHA256: session.ConfigSHA256, BootID: boot,
		StartedMS: now, HeartbeatMS: now, FailureThreshold: threshold, Phase: "starting", Reason: "awaiting_selected_probe", ProbeScope: scope})
}

// The configured policy is authoritative, not a process heartbeat. Never
// accept a health HTTPS target that the Core intentionally routes Direct.
func nativeHealthTargets(config []byte, scope string) ([]nativeProbeTarget, error) {
	targets := []nativeProbeTarget{{"1.0.0.1", "one.one.one.one", 443}, {"8.8.8.8", "dns.google", 443}}
	if scope == "synthetic_https" {
		targets = []nativeProbeTarget{{"8.8.8.8", smartTUNHealthHTTPSName, smartTUNHealthHTTPSPort}, {"198.51.100.42", smartTUNHealthHTTPSName, smartTUNHealthHTTPSPort}}
	}
	var document struct {
		Route struct {
			Rules []struct {
				IPCIDR   []string `json:"ip_cidr"`
				Outbound string   `json:"outbound"`
				RuleSet  []string `json:"rule_set"`
			} `json:"rules"`
			Final string `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(config, &document); err != nil || document.Route.Final != "upstream" {
		return nil, Fault("invalid_state", "native health cannot prove VPN routing policy")
	}
	selected := make([]nativeProbeTarget, 0, len(targets))
	for _, target := range targets {
		ip, _ := netip.ParseAddr(target.IP)
		direct := false
		for _, rule := range document.Route.Rules {
			if rule.Outbound != "direct" {
				continue
			}
			for _, cidr := range rule.IPCIDR {
				p, e := netip.ParsePrefix(cidr)
				if e != nil {
					return nil, Fault("invalid_state", "native health route rule invalid")
				}
				if p.Contains(ip) {
					direct = true
				}
			}
		}
		if !direct {
			selected = append(selected, target)
		}
	}
	if len(selected) == 0 {
		return nil, Fault("invalid_state", "all native HTTPS health destinations have Direct exceptions")
	}
	return selected, nil
}

type nativeProbeTarget struct {
	IP, Name string
	Port     int
}

// TLS certificate validation and device-bound, unproxied sockets are both
// required. The fixed IP is sent to the kernel; neither ambient HTTP_PROXY nor
// the host resolver can silently change the observed route.
func probeNativeHTTPS(ctx context.Context, iface string, target nativeProbeTarget, synthetic bool) nativeHealthOutcome {
	dialer := net.Dialer{Timeout: 2500 * time.Millisecond, Control: func(_, _ string, raw syscall.RawConn) error {
		var setErr error
		if e := raw.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, nativeSelectedMark)
		}); e != nil {
			return e
		}
		return setErr
	}}
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(target.IP, fmt.Sprint(target.Port)))
	if err != nil {
		return nativeHealthOutcome{Reason: "selected_tcp_unreachable"}
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if synthetic {
		nonce := make([]byte, 16)
		if _, e := rand.Read(nonce); e != nil {
			return nativeHealthOutcome{Reason: "nonce_unavailable"}
		}
		proof := smartTUNHealthExchangeWithDeadline(ctx, conn, smartTUNHealthProbe{family: 4, protocol: "https", address: target.IP, expectedSource: target.IP}, nonce)
		if proof.Result == "pass" && proof.StatusCode == 200 && ctx.Err() == nil {
			return nativeHealthOutcome{OK: true, Reason: "selected_https_verified"}
		}
		return nativeHealthOutcome{Reason: "synthetic_" + proof.Result}
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: target.Name, MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nativeHealthOutcome{Reason: "selected_tls_unavailable"}
	}
	// Request deliberately uses a fixed path and accepts an authenticated HTTP
	// error response: success measures transport/TLS, not a third party's page.
	if _, err := io.WriteString(tlsConn, "HEAD / HTTP/1.1\r\nHost: "+target.Name+"\r\nConnection: close\r\n\r\n"); err != nil {
		return nativeHealthOutcome{Reason: "selected_https_write_failed"}
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(tlsConn, 8192)), &http.Request{Method: http.MethodHead})
	if err != nil {
		return nativeHealthOutcome{Reason: "selected_https_invalid_response"}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 500 || ctx.Err() != nil {
		return nativeHealthOutcome{Reason: "selected_https_unhealthy"}
	}
	return nativeHealthOutcome{OK: true, Reason: "selected_https_verified"}
}
func runNativeHealthProbes(ctx context.Context, iface, scope string, targets []nativeProbeTarget, probe func(context.Context, string, nativeProbeTarget, bool) nativeHealthOutcome) nativeHealthOutcome {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	results := make(chan nativeHealthOutcome, len(targets))
	for _, target := range targets {
		go func(p nativeProbeTarget) { results <- probe(ctx, iface, p, scope == "synthetic_https") }(target)
	}
	outcome := nativeHealthOutcome{Reason: "selected_https_unreachable"}
	for range targets {
		r := <-results
		// A single authenticated selected-path positive is sufficient; a failed
		// public endpoint alone must not force Direct. Record a specific safe
		// class when every target fails.
		if r.OK {
			outcome = r
		} else if !outcome.OK && outcome.Reason == "selected_https_unreachable" && r.Reason != "" {
			outcome.Reason = r.Reason
		}
	}
	if ctx.Err() != nil {
		return nativeHealthOutcome{Reason: "selected_probe_timeout"}
	}
	return outcome
}

// Both timers must be effective and authenticated; inactive oneshots are
// normal between ticks. An executor failure is not a healthy timer.
func nativeHealthGuardRoles() error {
	for _, role := range []struct {
		name     string
		timer    bool
		expected string
	}{{trialRecoveryUnit, false, ""}, {trialRecoveryTimer, true, trialRecoveryUnit}, {smartTUNHealthUnit, false, ""}, {smartTUNHealthTimer, true, smartTUNHealthUnit}} {
		_, f, e := observeSmartTUNManagedUnit(role.name)
		if e != nil {
			return e
		}
		if f["Result"] != "success" {
			return Fault("guard_unavailable", "native health or recovery executor failed")
		}
		if role.timer {
			if f["ActiveState"] != "active" || f["UnitFileState"] != "enabled" || f["Unit"] != role.expected {
				return Fault("guard_unavailable", "native runtime guard timer stopped")
			}
		} else if f["UnitFileState"] != "static" || (f["ActiveState"] != "inactive" && f["ActiveState"] != "activating") {
			return Fault("guard_unavailable", "native runtime guard executor unavailable")
		}
	}
	return nil
}
func (m *Manager) armNativeHealthGuards() error {
	for _, name := range []string{trialRecoveryUnit, trialRecoveryTimer, smartTUNHealthUnit, smartTUNHealthTimer} {
		_, f, e := observeSmartTUNManagedUnit(name)
		if e != nil {
			return e
		}
		if f["Result"] != "success" {
			return Fault("guard_unavailable", "native guard was previously failed")
		}
		if strings.HasSuffix(name, ".timer") && (f["ActiveState"] != "inactive" || f["UnitFileState"] != "disabled") {
			return Fault("guard_unavailable", "native guard timer already owned by another operation")
		}
	}
	for _, name := range []string{trialRecoveryTimer, smartTUNHealthTimer} {
		if err := smartTUNTrialSystemctl("enable", "--now", name); err != nil {
			return err
		}
	}
	return nativeHealthGuardRoles()
}
func (m *Manager) disarmNativeHealthGuards() error {
	for _, name := range []string{smartTUNHealthTimer, trialRecoveryTimer} {
		_, _, e := observeSmartTUNManagedUnit(name)
		if e != nil {
			return e
		}
		if e = smartTUNTrialSystemctl("disable", "--now", name); e != nil {
			return e
		}
	}
	return nil
}

// Serialize native start/stop with health-driven Off, independently of the
// .lock used by ExecStopPost. Holding .lock across systemctl would deadlock.
func (m *Manager) withNativeTransition(fn func() error) error {
	if err := m.prepare(); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(m.Dir, ".native-transition.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
func (m *Manager) stopNativeHealthOperation(id, reason string) (bool, error) {
	stopped := false
	err := m.withNativeTransition(func() error {
		shouldStop := false
		err := m.withLock(func() error {
			s, e := m.readNativeHealth()
			if e != nil {
				return e
			}
			claim, e := m.readNativeSession()
			if errors.Is(e, os.ErrNotExist) {
				return nil
			}
			if e != nil {
				return e
			}
			if s.OperationID != id || s.ConfigSHA256 != claim.ConfigSHA256 {
				return nil
			}
			s.Phase = "stopping"
			if reason != "selected_path_failure_exhausted" {
				s.Reason = reason
			}
			if e = m.saveNativeHealth(s); e != nil {
				return e
			}
			shouldStop = true
			return nil
		})
		if err != nil {
			return err
		}
		if !shouldStop {
			return nil
		}
		if e := m.disconnectNativeSmartRoutingUnlocked(); e != nil {
			return e
		}
		stopped = true
		return nil
	})
	return stopped, err
}

// systemctl is-active intentionally refuses transient "activating". A
// second trusted read may observe "active" once ExecStart finishes while
// the first read reported "unknown". This short race is not a Core failure.
// An initially ACTIVE Core must never use startup grace to skip health/guard.
func nativeStartupTransientState(state string) bool {
	return state == "activating" || state == "active"
}

// Only the pre-Core idle state or a transient inconclusive first read can
// use the bounded startup grace. A definitively active, failed, or stopped
// Core is checked immediately by both independent guard roles.
func nativeStartupGraceDecision(phase string, elapsedMS int64, activity string, uncertain, resampled bool) bool {
	if phase != "starting" || elapsedMS < 0 || elapsedMS >= nativeHealthGraceMS {
		return false
	}
	if uncertain {
		return resampled
	}
	return activity == "inactive"
}
func (m *Manager) nativeStartupGraceApplies(s NativeHealthState, now int64, activity string, observationErr error) bool {
	elapsed := now - s.StartedMS
	if s.Phase != "starting" || elapsed < 0 || elapsed >= nativeHealthGraceMS {
		return false
	}
	resampled := false
	if observationErr != nil {
		resampled = m.nativeStartupInProgress()
	}
	return nativeStartupGraceDecision(s.Phase, elapsed, activity, observationErr != nil, resampled)
}
func (m *Manager) nativeStartupInProgress() bool {
	if m.nativeUnitOwnership() != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, "show", nativeSmartUnit, "-p", "ActiveState", "--value")
	if err != nil {
		return false
	}
	out, err := cmd.Output()
	return err == nil && ctx.Err() == nil && nativeStartupTransientState(strings.TrimSpace(string(out)))
}

// Called by the existing independent health oneshot, never by the Core.
func (m *Manager) RunNativeHealthRound() (NativeHealthState, error) {
	if err := m.nativeUnitOwnership(); err != nil {
		return NativeHealthState{}, err
	}
	var s NativeHealthState
	var claim NativeSession
	var targets []nativeProbeTarget
	err := m.withLock(func() error {
		var e error
		claim, e = m.readNativeSession()
		if e != nil {
			return e
		}
		s, e = m.readNativeHealth()
		if e != nil {
			return e
		}
		if s.ConfigSHA256 != claim.ConfigSHA256 {
			return Fault("invalid_state", "native health is not bound to session")
		}
		raw, e := readRegular(filepath.Join(m.Dir, nativeConfigFile))
		if e != nil {
			return e
		}
		if e = m.validateNativeSessionConfig(claim); e != nil {
			return e
		}
		targets, e = nativeHealthTargets(raw, s.ProbeScope)
		return e
	})
	if err != nil {
		return s, err
	}
	boot, be := trialBootIdentity()
	now, te := smartTUNUptimeMillis()
	guard := nativeHealthGuardRoles()
	observed, oe := m.nativeActivity()
	reason := ""
	if be != nil || te != nil || boot != s.BootID || now < s.StartedMS {
		reason = "native_boot_identity_changed"
	} else if m.nativeStartupGraceApplies(s, now, observed, oe) {
		// No kernel capture yet: tolerate the timer prearm window, not a live
		// Core with a missing guard.
		return s, nil
	} else if guard != nil {
		reason = "runtime_guard_unavailable"
	} else if oe != nil || observed != "active" {
		reason = "native_core_unavailable"
	}
	if reason != "" {
		stopped, e := m.stopNativeHealthOperation(s.OperationID, reason)
		if e != nil {
			return s, e
		}
		if !stopped {
			return s, Fault("guard_pending", "health result superseded by another native session")
		}
		s.Phase, s.Reason = "off", reason
		return s, nil
	}
	if e := inspectNativeHealthPolicy(context.Background(), nativeHealthKernelReader{}, claim.recoveryScope(), targets); e != nil {
		stopped, stopErr := m.stopNativeHealthOperation(s.OperationID, "native_policy_unverified")
		if stopErr != nil {
			return s, stopErr
		}
		if !stopped {
			return s, Fault("guard_pending", "native health kernel witness belongs to old session")
		}
		s.Phase, s.Reason = "off", "native_policy_unverified"
		return s, nil
	}
	outcome := runNativeHealthProbes(context.Background(), claim.InterfaceName, s.ProbeScope, targets, probeNativeHTTPS)
	stop := false
	err = m.withLock(func() error {
		current, e := m.readNativeSession()
		if e != nil {
			return e
		}
		latest, e := m.readNativeHealth()
		if e != nil {
			return e
		}
		state, e := m.load()
		if e != nil {
			return e
		}
		// A second manual executor may have completed while our bounded
		// probe was outside the lock. Never overwrite its newer verdict,
		// renew a stale lease or replenish its outage/failure budget.
		if current != claim || latest != s || state.Desired != "smart" || latest.Phase == "stopping" || latest.Phase == "off" {
			return Fault("guard_pending", "native health result belongs to an old session")
		}
		if e = m.validateNativeSessionConfig(claim); e != nil {
			return e
		}
		if activity, e := m.nativeActivity(); e != nil || activity != "active" {
			return Fault("guard_pending", "Core stopped before selected-path proof was published")
		}
		if e = nativeHealthGuardRoles(); e != nil {
			return Fault("guard_unavailable", "native guard lost during probe round")
		}
		if e = inspectNativeHealthPolicy(context.Background(), nativeHealthKernelReader{}, claim.recoveryScope(), targets); e != nil {
			return Fault("guard_unavailable", "native kernel policy changed during selected-path probe")
		}
		if newBoot, e := trialBootIdentity(); e != nil || newBoot != s.BootID {
			return Fault("guard_pending", "native boot changed during health round")
		}
		if now, e = smartTUNUptimeMillis(); e != nil {
			return e
		}
		s, stop = nativeHealthAdvance(latest, outcome, now)
		return m.saveNativeHealth(s)
	})
	if err != nil {
		return s, err
	}
	if stop {
		stopped, e := m.stopNativeHealthOperation(s.OperationID, "selected_path_failure_exhausted")
		if e != nil {
			return s, e
		}
		if !stopped {
			return s, Fault("guard_pending", "exhausted health result belongs to old operation")
		}
		s.Phase = "off"
	}
	return s, nil
}

// Existing independent activation-recovery timer is the supervising role.
// It checks the health executor's heartbeat, the other timer and the Core.
func (m *Manager) SuperviseNativeHealth() (NativeHealthState, error) {
	if err := m.nativeUnitOwnership(); err != nil {
		return NativeHealthState{}, err
	}
	var s NativeHealthState
	var claim NativeSession
	err := m.withLock(func() error {
		var e error
		claim, e = m.readNativeSession()
		if e != nil {
			return e
		}
		s, e = m.readNativeHealth()
		if e != nil {
			return e
		}
		if s.ConfigSHA256 != claim.ConfigSHA256 {
			return Fault("invalid_state", "native supervisor session mismatch")
		}
		return m.validateNativeSessionConfig(claim)
	})
	if err != nil {
		return s, err
	}
	now, te := smartTUNUptimeMillis()
	boot, be := trialBootIdentity()
	reason := ""
	if be != nil || te != nil || boot != s.BootID || now < s.StartedMS {
		reason = "native_boot_identity_changed"
	} else if now-s.HeartbeatMS > nativeHealthLeaseMS {
		reason = "native_health_executor_stale"
	} else {
		activity, activityErr := m.nativeActivity()
		if m.nativeStartupGraceApplies(s, now, activity, activityErr) {
			// A first scheduled timer can fire before the second is armed;
			// until the Core exists, there is no traffic interception.
			return s, nil
		}
		if e := nativeHealthGuardRoles(); e != nil {
			reason = "runtime_guard_unavailable"
		} else if activityErr != nil || activity != "active" {
			reason = "native_core_unavailable"
		}
	}
	if reason != "" {
		stopped, e := m.stopNativeHealthOperation(s.OperationID, reason)
		if e != nil {
			return s, e
		}
		if !stopped {
			return s, Fault("guard_pending", "health result superseded by another native session")
		}
		s.Phase, s.Reason = "off", reason
		return s, nil
	}
	return s, nil
}

// Historical trial executor command names are retained so the same owned
// timers can serve one native session or the (mutually exclusive) legacy QA
// journal. This decision is made under the lifecycle lock at each dispatch.
func (m *Manager) NativeHealthGuardMode() (string, error) {
	mode := "legacy"
	err := m.withLock(func() error {
		phase, e := m.pendingSmartTUNTrial()
		if e != nil {
			return e
		}
		if phase != "" {
			if _, claimErr := m.readNativeSession(); claimErr == nil {
				return Fault("guard_pending", "conflicting legacy and native runtime claims")
			} else if !errors.Is(claimErr, os.ErrNotExist) {
				return claimErr
			}
			return nil
		}
		if _, e := m.readNativeSession(); e == nil {
			mode = "native"
			return nil
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		s, e := m.readNativeHealth()
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		if e != nil {
			return e
		}
		if s.Phase != "off" {
			return Fault("guard_pending", "orphaned native health record needs reconciliation")
		}
		mode = "native_off"
		return nil
	})
	return mode, err
}

// The exported idle path and the Connect/Disconnect internal path use the
// same transition mutex. Acquiring the Manager lifecycle lock across timer
// disabling excludes a legacy trial taking over the same exact units.
func (m *Manager) CleanupIdleNativeHealthGuards() error {
	return m.withNativeTransition(m.cleanupIdleNativeHealthGuardsUnlocked)
}
func (m *Manager) cleanupIdleNativeHealthGuardsUnlocked() error {
	if e := m.nativeUnitOwnership(); e != nil {
		return e
	}
	return m.withLock(func() error {
		if _, e := m.readNativeSession(); !errors.Is(e, os.ErrNotExist) {
			return Fault("guard_pending", "cannot disarm guard while native claim exists")
		}
		phase, e := m.pendingSmartTUNTrial()
		if e != nil {
			return e
		}
		if phase != "" {
			return Fault("guard_pending", "legacy guard owns timer")
		}
		h, e := m.readNativeHealth()
		if e != nil {
			return e
		}
		if h.Phase != "off" {
			return Fault("guard_pending", "native Direct recovery has not finished")
		}
		s, e := m.load()
		if e != nil {
			return e
		}
		if s.Desired != "direct" {
			return Fault("guard_pending", "native desired mode is not Direct")
		}
		activity, e := m.nativeActivity()
		if e != nil || activity != "inactive" && activity != "failed" {
			return Fault("guard_pending", "native Core may still be active")
		}
		return m.disarmNativeHealthGuards()
	})
}
