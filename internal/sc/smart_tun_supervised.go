package sc

// Supervision is an explicitly different journal intent. The old deadline-only
// trial can never acquire ongoing authority by finding a new installed service.
// All admission remains limited to the existing disconnected synthetic guest.
import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	smartTUNSupervisionVersion = 2
	smartTUNSupervisedIntent   = "smart_tun_native_supervised_trial_v1"
	smartTUNHealthUnit         = "server-connect-smart-health.service"
	smartTUNHealthTimer        = "server-connect-smart-health.timer"
	// The timer starts five seconds after the bounded (20s) executor exits.
	// This lease includes that entire bound and scheduling margin, not merely
	// the four-second aggregate measurement deadline.
	smartTUNHealthLeaseMS int64 = 35000
)

type SmartTUNHealthOptions struct {
	IntervalSeconds     int `json:"interval_seconds"`
	StartupGraceSeconds int `json:"startup_grace_seconds"`
	FailureThreshold    int `json:"failure_threshold"`
	MaxAttempts         int `json:"max_attempts"`
	RecoverySeconds     int `json:"recovery_seconds"`
}

type smartTUNHealthUnitIdentity struct {
	UnitDev   uint64 `json:"unit_dev"`
	UnitIno   uint64 `json:"unit_ino"`
	DigestDev uint64 `json:"digest_dev"`
	DigestIno uint64 `json:"digest_ino"`
	SHA256    string `json:"sha256"`
}

// Comparable by value: every publication binds the complete previous record,
// including heartbeat, retry budget, evidence and one-use confirmation state.
type smartTUNSupervision struct {
	Version            int                           `json:"version"`
	Generation         uint64                        `json:"generation"`
	State              string                        `json:"state"`
	Options            SmartTUNHealthOptions         `json:"options"`
	Roles              [2]smartTUNHealthUnitIdentity `json:"roles"`
	ReadyAfterMS       int64                         `json:"ready_after_uptime_ms"`
	ChallengeSHA256    string                        `json:"challenge_sha256"`
	Confirmed          bool                          `json:"confirmed"`
	SessionSHA256      string                        `json:"session_sha256"`
	SessionStartedMS   int64                         `json:"session_started_uptime_ms"`
	CorePID            uint64                        `json:"core_pid"`
	CoreStartTicks     uint64                        `json:"core_start_ticks"`
	HeartbeatMS        int64                         `json:"heartbeat_uptime_ms"`
	LeaseDeadlineMS    int64                         `json:"lease_deadline_uptime_ms"`
	LastProbeMS        int64                         `json:"last_probe_uptime_ms"`
	NextProbeMS        int64                         `json:"next_probe_uptime_ms"`
	Rounds             uint64                        `json:"rounds"`
	Failures           int                           `json:"failures"`
	Attempts           int                           `json:"attempts"`
	RecoveryDeadlineMS int64                         `json:"recovery_deadline_uptime_ms"`
	ReconnectStage     string                        `json:"reconnect_stage"`
	Reason             string                        `json:"reason"`
	Evidence           SmartTUNHealthEvidence        `json:"evidence"`
}

func validateSmartTUNHealthOptions(o SmartTUNHealthOptions) error {
	if o.IntervalSeconds < 5 || o.IntervalSeconds > 30 || o.StartupGraceSeconds < 0 || o.StartupGraceSeconds > 120 ||
		o.FailureThreshold < 1 || o.FailureThreshold > 10 || o.MaxAttempts < 1 || o.MaxAttempts > 5 ||
		o.RecoverySeconds < 10 || o.RecoverySeconds > 600 {
		return Fault("invalid_arguments", "supervised health requires interval 5-30s, grace 0-120s, failure threshold 1-10, attempts 1-5 and recovery 10-600s")
	}
	return nil
}

func validateSmartTUNSupervision(r smartTUNTrialJournal) error {
	s := r.Supervised
	bad := func() error { return activationJournalError("supervised TUN identity, state or evidence invalid") }
	if s == nil || (s.Version != 1 && s.Version != smartTUNSupervisionVersion) || s.Generation == 0 || s.Generation > 1<<62 || validateSmartTUNHealthOptions(s.Options) != nil ||
		s.HeartbeatMS <= 0 || s.LeaseDeadlineMS != s.HeartbeatMS+smartTUNHealthLeaseMS || s.ReadyAfterMS < 0 ||
		s.LastProbeMS < 0 || s.NextProbeMS < 0 || s.Rounds > 1<<62 || s.Failures < 0 || s.Failures > s.Options.FailureThreshold ||
		s.Attempts < 0 || s.Attempts > s.Options.MaxAttempts || s.RecoveryDeadlineMS < 0 || len(s.Reason) > 96 {
		return bad()
	}
	for _, id := range s.Roles {
		if id.UnitIno == 0 || id.DigestIno == 0 || !journalHex64.MatchString(id.SHA256) {
			return bad()
		}
	}
	switch s.State {
	case "initializing", "awaiting_confirmation", "healthy", "degraded", "reconnecting", "stopped", "uncertain":
	default:
		return bad()
	}
	if s.State == "initializing" {
		if s.ReadyAfterMS != 0 || s.ChallengeSHA256 != "" || s.Confirmed || s.Rounds != 0 || s.CorePID != 0 || s.CoreStartTicks != 0 {
			return bad()
		}
	} else if s.State != "stopped" && s.State != "uncertain" && s.ReadyAfterMS <= 0 {
		return bad()
	}
	if s.ReadyAfterMS > 0 && (s.CorePID == 0 || s.CoreStartTicks == 0) {
		return bad()
	}
	if s.Confirmed {
		if s.ChallengeSHA256 != "" || !journalHex64.MatchString(s.SessionSHA256) || s.SessionStartedMS <= s.ReadyAfterMS || s.Rounds == 0 {
			return bad()
		}
	} else {
		if s.SessionSHA256 != "" || s.SessionStartedMS != 0 || s.State == "healthy" {
			return bad()
		}
		if s.ReadyAfterMS > 0 && !journalHex64.MatchString(s.ChallengeSHA256) {
			return bad()
		}
	}
	switch s.ReconnectStage {
	case "none":
	case "stop_requested", "stopped", "start_requested":
		if s.Attempts == 0 || !s.Confirmed || s.RecoveryDeadlineMS == 0 {
			return bad()
		}
	default:
		return bad()
	}
	if (r.Phase == "trial_recovered" || r.Phase == "trial_cleanup_pending") && (s.State != "stopped" || s.ReconnectStage == "start_requested") {
		return bad()
	}
	if r.Phase == "trial_pending" && (s.State == "stopped" || s.State == "uncertain") {
		return bad()
	}
	if r.Phase == "trial_stop_requested" && s.State != "stopped" && s.State != "uncertain" {
		return bad()
	}
	if s.State == "awaiting_confirmation" && s.Confirmed {
		return bad()
	}
	if s.State == "healthy" && (s.Failures != 0 || !s.Evidence.VPNHealthy || !s.Evidence.UnderlayHealthy || s.LastProbeMS <= 0) {
		return bad()
	}
	if s.Rounds == 0 && (s.LastProbeMS != 0 || s.Evidence != (SmartTUNHealthEvidence{})) {
		return bad()
	}
	if s.Rounds > 0 && (s.LastProbeMS <= 0 || s.LastProbeMS > s.HeartbeatMS || s.NextProbeMS > s.HeartbeatMS+30000) {
		return bad()
	}
	if s.Evidence.VPNHealthy && (!s.Evidence.IPv4TCP || (r.EndpointIP != smartTUNVMEndpoint && (!s.Evidence.IPv4UDP || !s.Evidence.IPv4DNS || (r.Native.IPv6.Address != "" && (!s.Evidence.IPv6TCP || !s.Evidence.IPv6UDP || !s.Evidence.IPv6DNS))))) {
		return bad()
	}
	if r.Native.IPv6.Address == "" && (s.Evidence.IPv6TCP || s.Evidence.IPv6UDP || s.Evidence.IPv6DNS) {
		return bad()
	}
	if s.Evidence.ElapsedMS < 0 || s.Evidence.ElapsedMS > 6000 || s.Evidence.ProbeCount < 0 || s.Evidence.ProbeCount > 20 ||
		s.Evidence.FailedTargets < 0 || s.Evidence.FailedTargets > s.Evidence.ProbeCount || len(s.Evidence.Reason) > 96 {
		return bad()
	}
	if s.Rounds > 0 {
		count, targets := 7, 2
		if r.EndpointIP == smartTUNVMEndpoint {
			count, targets = 2, 1
		} else if r.Native.IPv6.Address != "" {
			count, targets = 13, 4
		}
		if s.Version == smartTUNSupervisionVersion && r.EndpointIP != smartTUNVMEndpoint {
			count += targets
		}
		if s.Evidence.ProbeCount != count && !(s.Evidence.ProbeCount == 0 && s.Evidence.Reason == "round_canceled") {
			return bad()
		}
		if s.Evidence.FailedTargets > targets {
			return bad()
		}
		switch s.Evidence.Reason {
		case "vm_https_only_udp_dns_not_run", "vm_protected_underlay_failed", "vm_selected_https_failed", "vm_round_canceled":
			if r.EndpointIP != smartTUNVMEndpoint {
				return bad()
			}
		case "healthy", "healthy_partial_targets", "protected_underlay_failed", "vpn_path_mismatch", "vpn_ipv4_tcp_failed", "vpn_ipv4_udp_failed", "vpn_ipv4_dns_failed", "vpn_ipv6_tcp_failed", "vpn_ipv6_udp_failed", "vpn_ipv6_dns_failed", "round_canceled":
		case "vpn_ipv4_https_failed", "vpn_ipv6_https_failed":
			if s.Version == 1 {
				return bad()
			}
		default:
			return bad()
		}
	}
	if s.Version == 1 {
		if s.Evidence.IPv4HTTPS || s.Evidence.IPv6HTTPS || s.Evidence.HTTPSResults != ([4]SmartTUNHTTPSResult{}) {
			return bad()
		}
	} else if s.Rounds > 0 {
		if r.EndpointIP == smartTUNVMEndpoint {
			if !validSmartTUNQAVMHealthEvidence(s.Evidence) {
				return bad()
			}
		} else if !validSmartTUNHTTPSEvidence(s.Evidence, r.Native.IPv6.Address != "") {
			return bad()
		}
	}
	return nil
}

// Reject null, case aliases, duplicate and unknown fields at every nested
// level. Numeric/bool types are then checked by the ordinary Go decoder.
func strictSupervisedObject(raw json.RawMessage, names string) (map[string]json.RawMessage, error) {
	keys := map[string]bool{}
	for _, name := range strings.Fields(names) {
		keys[name] = true
	}
	if err := requireExactJournalKeys(raw, keys); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, activationJournalError("invalid supervision object")
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, activationJournalError("null supervision member")
		}
	}
	return fields, nil
}

func strictSmartTUNSupervisionJSON(raw json.RawMessage) error {
	f, err := strictSupervisedObject(raw, "version generation state options roles ready_after_uptime_ms challenge_sha256 confirmed session_sha256 session_started_uptime_ms core_pid core_start_ticks heartbeat_uptime_ms lease_deadline_uptime_ms last_probe_uptime_ms next_probe_uptime_ms rounds failures attempts recovery_deadline_uptime_ms reconnect_stage reason evidence")
	if err != nil {
		return err
	}
	if _, err := strictSupervisedObject(f["options"], "interval_seconds startup_grace_seconds failure_threshold max_attempts recovery_seconds"); err != nil {
		return err
	}
	var roles []json.RawMessage
	if json.Unmarshal(f["roles"], &roles) != nil || len(roles) != 2 {
		return activationJournalError("supervision roles must have exactly two identities")
	}
	for _, role := range roles {
		if _, err := strictSupervisedObject(role, "unit_dev unit_ino digest_dev digest_ino sha256"); err != nil {
			return err
		}
	}
	var version int
	if json.Unmarshal(f["version"], &version) != nil || (version != 1 && version != smartTUNSupervisionVersion) {
		return activationJournalError("unsupported supervision evidence version")
	}
	keys := "underlay_healthy vpn_healthy ipv4_tcp ipv4_udp ipv4_dns ipv6_tcp ipv6_udp ipv6_dns failed_targets probe_count elapsed_ms reason"
	if version == smartTUNSupervisionVersion {
		keys += " ipv4_https ipv6_https https_results"
	}
	evidence, err := strictSupervisedObject(f["evidence"], keys)
	if err != nil || version == 1 {
		return err
	}
	var results []json.RawMessage
	if json.Unmarshal(evidence["https_results"], &results) != nil || len(results) != 4 {
		return activationJournalError("HTTPS evidence must have exactly four target slots")
	}
	for _, result := range results {
		if _, err := strictSupervisedObject(result, "result status_code"); err != nil {
			return err
		}
	}
	return nil
}

func smartTUNChallengeDigest(r smartTUNTrialJournal, challenge string) string {
	return sha256Hex([]byte(fmt.Sprintf("%s\n%s\n%s\n%d\n%d\n%s", r.OperationID, r.BootID, r.ConfigSHA256, r.Revision, r.Supervised.ReadyAfterMS, challenge)))
}

func smartTUNConfirmMatches(r smartTUNTrialJournal, op string, revision uint64, challenge string, boot string, now int64) bool {
	s := r.Supervised
	return s != nil && s.Version == smartTUNSupervisionVersion && r.Phase == "trial_pending" && !s.Confirmed && s.ReadyAfterMS > 0 &&
		matchingSmartTUNOperation(r, op, revision) && boot == r.BootID && now > s.ReadyAfterMS && now < r.DeadlineUptimeSec*1000 &&
		now >= s.HeartbeatMS && now < s.LeaseDeadlineMS &&
		journalHex64.MatchString(challenge) && subtle.ConstantTimeCompare([]byte(s.ChallengeSHA256), []byte(smartTUNChallengeDigest(r, challenge))) == 1
}

func observeSmartTUNHealthUnit(name string) (smartTUNHealthUnitIdentity, map[string]string, error) {
	var empty smartTUNHealthUnitIdentity
	if name != smartTUNHealthUnit && name != smartTUNHealthTimer {
		return empty, nil, Fault("guard_unavailable", "unknown health role")
	}
	path := filepath.Join(trialGuardUnitDir, name)
	body, unitID, err := readSmartTUNTrialUnitFile(path)
	if err != nil {
		return empty, nil, err
	}
	digest, digestID, err := readSmartTUNTrialUnitFile(filepath.Join(managedPrefix, name+".sha256"))
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
	after, afterID, err := readSmartTUNTrialUnitFile(path)
	if err != nil || afterID != unitID || !bytes.Equal(after, body) {
		return empty, nil, Fault("guard_unavailable", "health role file changed during observation")
	}
	afterDigest, afterDigestID, err := readSmartTUNTrialUnitFile(filepath.Join(managedPrefix, name+".sha256"))
	if err != nil || afterDigestID != digestID || !bytes.Equal(afterDigest, digest) {
		return empty, nil, Fault("guard_unavailable", "health digest changed during observation")
	}
	return smartTUNHealthUnitIdentity{UnitDev: unitID.dev, UnitIno: unitID.ino, DigestDev: digestID.dev, DigestIno: digestID.ino, SHA256: sha256Hex(body)}, fields, nil
}

func smartTUNHealthUnits(armed bool, expected *[2]smartTUNHealthUnitIdentity) ([2]smartTUNHealthUnitIdentity, error) {
	var roles [2]smartTUNHealthUnitIdentity
	for i, name := range []string{smartTUNHealthUnit, smartTUNHealthTimer} {
		id, f, err := observeSmartTUNHealthUnit(name)
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

// A timed-out oneshot remains FAILED after the independent guard has safely
// removed every owned TUN resource. The systemd failure receipt must never be
// treated as a live guard; equally, a stale result must not strand a NEW,
// separately admitted QA VM operation. Only after a held journal lock proves
// absence, the trusted recovery timer is disarmed, the core is completely
// quiescent and the exact health timer is inactive may we reset this ONE owned
// failed oneshot. This does not start, stop or modify any data-plane service.
func normalizeQuiescentSmartTUNHealthUnit(store *activationJournalDir) error {
	if _, _, err := store.readJournal(); !errors.Is(err, os.ErrNotExist) {
		return Fault("guard_unavailable", "health result cannot be normalized while an activation journal exists")
	}
	if err := trialGuardUnits(false); err != nil {
		return err
	}
	core, err := observeSmartTUNTrialUnit(context.Background())
	if err != nil || !core.stopped() {
		return Fault("guard_unavailable", "TUN core must be verified inactive before health normalization")
	}
	serviceID, service, err := observeSmartTUNHealthUnit(smartTUNHealthUnit)
	if err != nil {
		return err
	}
	if service["ActiveState"] == "inactive" && service["Result"] == "success" {
		return nil
	}
	if service["ActiveState"] != "failed" || service["UnitFileState"] != "static" {
		return Fault("guard_unavailable", "only an idle failed owned health executor may be normalized")
	}
	_, timer, err := observeSmartTUNHealthUnit(smartTUNHealthTimer)
	if err != nil || timer["ActiveState"] != "inactive" ||
		timer["UnitFileState"] != "disabled" || timer["Result"] != "success" {
		return Fault("guard_unavailable", "health timer must be disabled and inactive before normalization")
	}
	if err := smartTUNTrialSystemctl("reset-failed", smartTUNHealthUnit); err != nil {
		return err
	}
	sameID, next, err := observeSmartTUNHealthUnit(smartTUNHealthUnit)
	if err != nil || sameID != serviceID ||
		next["Result"] != "success" || next["ActiveState"] != "inactive" {
		return Fault("guard_unavailable", "owned health executor failed-state normalization was not verified")
	}
	return nil
}

// Stop only the timer. The health oneshot might be this very caller, or a
// contender waiting for this lock: synchronous service stop would deadlock.
// Disabling the timer prevents future starts; the bounded current executor
// returns without effects after the journal has been removed.
func disarmSmartTUNHealthTimer(r smartTUNTrialJournal) error {
	if r.Supervised == nil {
		return nil
	}
	serviceID, _, serviceErr := observeSmartTUNHealthUnit(smartTUNHealthUnit)
	if serviceErr != nil || serviceID != r.Supervised.Roles[0] {
		return Fault("guard_unavailable", "health executor ownership must be reconciled before final cleanup")
	}
	id, _, err := observeSmartTUNHealthUnit(smartTUNHealthTimer)
	if err != nil || id != r.Supervised.Roles[1] {
		return Fault("guard_unavailable", "cannot disarm changed health timer")
	}
	if err := smartTUNTrialSystemctl("disable", "--now", smartTUNHealthTimer); err != nil {
		return err
	}
	id, f, err := observeSmartTUNHealthUnit(smartTUNHealthTimer)
	if err != nil || id != r.Supervised.Roles[1] || f["ActiveState"] != "inactive" || f["UnitFileState"] != "disabled" {
		return Fault("guard_unavailable", "health timer disarm not verified")
	}
	return nil
}

func (m *Manager) disarmUncommittedSmartTUNHealth(roles [2]smartTUNHealthUnitIdentity) {
	_ = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if _, _, err := store.readJournal(); !errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if active, err := smartTUNTrialUnitState(); err != nil || active != "inactive" {
			return nil
		}
		return disarmSmartTUNHealthTimer(smartTUNTrialJournal{Supervised: &smartTUNSupervision{Roles: roles}})
	})
}

func (m *Manager) BeginSupervisedSmartTUNTrial(opts SmartTUNCandidateOptions, peer string, deadline int, health SmartTUNHealthOptions, qaKill string) (SmartTUNTrialReceipt, error) {
	if err := validateSmartTUNHealthOptions(health); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	return m.beginSmartTUNTrial(opts, peer, deadline, qaKill, nil, &health)
}

func (m *Manager) BeginSavedSupervisedSmartTUNTrial(deadline int, health SmartTUNHealthOptions, qaKill string) (SmartTUNTrialReceipt, error) {
	if m.Dir != DefaultDir || m.Core != DefaultCore {
		return SmartTUNTrialReceipt{}, Fault("trial_unsupported", "installed trial paths required")
	}
	if err := nativeTrialApplyPlatform(); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if err := validateSmartTUNHealthOptions(health); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	var policy smartTUNSavedPolicy
	var binding smartTUNSavedPolicyBinding
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		data, id, err := store.readSmartTUNFile(smartTUNSavedPolicyFile)
		if err != nil {
			return Fault("saved_policy_invalid", "saved TUN policy absent or untrusted")
		}
		policy, err = decodeSavedSmartTUNPolicy(data)
		binding = smartTUNSavedPolicyBinding{identity: id, digest: sha256Hex(data)}
		return err
	})
	if err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	return m.beginSmartTUNTrial(policy.Options, policy.ManagementPeerIP, deadline, qaKill, &binding, &health)
}

func supervisedRuntimeReason(r smartTUNTrialJournal, unit smartTUNTrialUnitObservation, credentialValid bool, boot string, now int64) string {
	s := r.Supervised
	if s == nil {
		return "supervision_missing"
	}
	if s.Version == 1 {
		return "legacy_reapply_required"
	}
	if boot != r.BootID {
		return "boot_changed"
	}
	if !credentialValid {
		return "credential_conflict"
	}
	if terminalSupervisedReason(s.Reason) {
		return s.Reason
	}
	if !s.Confirmed && now >= r.DeadlineUptimeSec*1000 {
		return "activation_expired"
	}
	if s.RecoveryDeadlineMS > 0 && now >= s.RecoveryDeadlineMS {
		return "recovery_deadline_expired"
	}
	if now < s.HeartbeatMS || now >= s.LeaseDeadlineMS {
		return "supervisor_lease_expired"
	}
	if s.ReconnectStage != "none" {
		return "reconnect_interrupted"
	}
	if unit.activeState != "active" || unit.mainPID == 0 || unit.result != "success" {
		return "core_unavailable"
	}
	return ""
}

func terminalSupervisedReason(reason string) bool {
	switch reason {
	case "protected_underlay_failed", "vpn_path_mismatch", "unconfirmed_path_failed", "recovery_deadline_expired", "reconnect_exhausted":
		return true
	}
	return false
}

func inspectSupervisedRuntime(store *activationJournalDir, r smartTUNTrialJournal, checkHealth bool) string {
	// Legacy TCP-only authority is never probed, confirmed or renewed by the
	// HTTPS executor. The existing exact owned stop path handles its ledger.
	if r.Supervised != nil && r.Supervised.Version == 1 {
		return "legacy_reapply_required"
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return "boot_unavailable"
	}
	now, err := smartTUNUptimeMillis()
	if err != nil {
		return "clock_unavailable"
	}
	unit, err := observeSmartTUNTrialUnit(context.Background())
	if err != nil {
		return "core_identity_unavailable"
	}
	data, _, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
	if reason := supervisedRuntimeReason(r, unit, err == nil && sha256Hex(data) == r.ConfigSHA256, boot, now); reason != "" {
		return reason
	}
	process, err := readManagementProcess(int(unit.mainPID))
	if err != nil || unit.mainPID != r.Supervised.CorePID || process.StartTicks != r.Supervised.CoreStartTicks {
		return "core_generation_changed"
	}
	if trialGuardScheduled() != nil {
		return "recovery_executor_unavailable"
	}
	if checkHealth {
		if _, err := smartTUNHealthUnits(true, &r.Supervised.Roles); err != nil {
			return "supervisor_unavailable"
		}
	}
	if nativeTUNVerifyPending(r) != nil {
		return "native_resource_conflict"
	}
	return ""
}

func supervisedKillValid(point string, confirm bool) bool {
	if point == "" {
		return true
	}
	if confirm {
		return point == "before-confirm-publish" || point == "after-confirm-publish"
	}
	switch point {
	case "before-health-publish", "after-health-publish", "after-reconnect-intent", "after-reconnect-stop", "after-reconnect-start", "after-reconnect-verified":
		return true
	}
	return false
}

func (m *Manager) ConfirmSmartTUNTrial(op string, revision uint64, challenge string, qaKill string) (SmartTUNTrialReceipt, error) {
	if m.Dir != DefaultDir || m.Core != DefaultCore || !supervisedKillValid(qaKill, true) {
		return SmartTUNTrialReceipt{}, Fault("invalid_arguments", "installed supervised confirmation and supported kill boundary required")
	}
	if err := smartTUNNativeHostContext(); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	var receipt SmartTUNTrialReceipt
	var snapshot smartTUNTrialJournal
	var proof smartTUNManagementProof
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		r, _, err := loadSmartTUNTrialLocked(store)
		if err != nil {
			return err
		}
		if r.Supervised != nil && r.Supervised.Version == 1 {
			if r.Phase != "trial_pending" || !matchingSmartTUNOperation(r, op, revision) {
				return Fault("confirmation_rejected", "confirmation does not match a live legacy operation")
			}
			receipt, err = supervisedFinishStop(store, &r, "legacy_reapply_required")
			if err != nil {
				return err
			}
			return Fault("legacy_reapply_required", "legacy TCP-only supervision requires a fresh guarded Apply")
		}
		boot, err := trialBootIdentity()
		if err != nil {
			return err
		}
		now, err := smartTUNUptimeMillis()
		if err != nil {
			return err
		}
		if !smartTUNConfirmMatches(r, op, revision, challenge, boot, now) {
			return Fault("confirmation_rejected", "confirmation is stale, replayed, expired or does not match this operation")
		}
		if reason := inspectSupervisedRuntime(store, r, true); reason != "" {
			return Fault("confirmation_unavailable", reason)
		}
		proof, err = observeFreshSmartTUNManagement(r.ManagementPeerIP, r.UnderlayInterface, r.Supervised.ReadyAfterMS)
		if err != nil {
			return err
		}
		snapshot = cloneSmartTUNTrial(r)
		return nil
	})
	if err != nil {
		return receipt, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	var evidence SmartTUNHealthEvidence
	if snapshot.EndpointIP == smartTUNVMEndpoint {
		evidence = probeSmartTUNQAVMHealth(ctx)
	} else {
		evidence = probeSmartTUNHealth(ctx, snapshot.Native.IPv6.Address != "")
	}
	cancel()
	measuredMS, err := smartTUNUptimeMillis()
	if err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if !evidence.UnderlayHealthy || !evidence.VPNHealthy {
		return SmartTUNTrialReceipt{}, Fault("confirmation_unavailable", "fresh selected VPN and protected underlay health are required")
	}
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if _, err := reloadSmartTUNTrialLocked(store, snapshot); err != nil {
			return err
		}
		boot, err := trialBootIdentity()
		if err != nil {
			return err
		}
		now, err := smartTUNUptimeMillis()
		if err != nil {
			return err
		}
		if !smartTUNConfirmMatches(snapshot, op, revision, challenge, boot, now) {
			return Fault("confirmation_rejected", "confirmation expired before publication")
		}
		if now < measuredMS || now-measuredMS > 5000 {
			return Fault("confirmation_unavailable", "selected-path evidence expired before publication")
		}
		if reason := inspectSupervisedRuntime(store, snapshot, true); reason != "" {
			return Fault("confirmation_unavailable", reason)
		}
		again, err := observeFreshSmartTUNManagement(snapshot.ManagementPeerIP, snapshot.UnderlayInterface, snapshot.Supervised.ReadyAfterMS)
		if err != nil {
			return err
		}
		if again != proof {
			return Fault("confirmation_rejected", "authenticated management session changed")
		}
		now, err = smartTUNUptimeMillis()
		if err != nil {
			return err
		}
		if !smartTUNConfirmMatches(snapshot, op, revision, challenge, boot, now) {
			return Fault("confirmation_rejected", "confirmation or supervisor lease expired during final observation")
		}
		if now < measuredMS || now-measuredMS > 5000 {
			return Fault("confirmation_unavailable", "selected-path evidence expired during final observation")
		}
		if err := trialQAKillAt("before-confirm-publish", qaKill); err != nil {
			return err
		}
		next := cloneSmartTUNTrial(snapshot)
		s := next.Supervised
		s.Confirmed, s.ChallengeSHA256, s.State = true, "", "healthy"
		s.SessionSHA256, s.SessionStartedMS = proof.SessionSHA256, proof.StartedUptimeMS
		s.HeartbeatMS, s.LeaseDeadlineMS = now, now+smartTUNHealthLeaseMS
		s.LastProbeMS, s.NextProbeMS = measuredMS, now+int64(s.Options.IntervalSeconds)*1000
		s.Evidence, s.Reason, s.Failures = evidence, "confirmed_fresh_paths", 0
		s.Generation++
		s.Rounds++
		if err := nativeTUNAdvance(store, &snapshot, next); err != nil {
			return err
		}
		if err := trialQAKillAt("after-confirm-publish", qaKill); err != nil {
			return err
		}
		receipt = smartTUNReceipt(snapshot, true, false)
		return nil
	})
	return receipt, err
}

func supervisedRequestStop(store *activationJournalDir, r *smartTUNTrialJournal, reason string) error {
	next := cloneSmartTUNTrial(*r)
	next.Supervised.State, next.Supervised.Reason = "stopped", reason
	next.Supervised.Generation++
	next.Phase, next.Revision = "trial_stop_requested", 2
	if next.Native.StopReason == "" {
		next.Native.StopReason = "guard"
	}
	return nativeTUNAdvance(store, r, next)
}

func supervisedFinishStop(store *activationJournalDir, r *smartTUNTrialJournal, reason string) (SmartTUNTrialReceipt, error) {
	if r.Phase == "trial_pending" {
		if err := supervisedRequestStop(store, r, reason); err != nil {
			return SmartTUNTrialReceipt{}, err
		}
	}
	result, err := recoverSmartTUNNativeLocked(store, r, "")
	if err != nil {
		result = smartTUNReceipt(*r, true, false)
		result.SupervisionState = "uncertain"
		return result, err
	}
	id, err := reloadSmartTUNTrialLocked(store, *r)
	if err != nil {
		return result, err
	}
	return finalizeSmartTUNTrialLocked(store, id, *r, "")
}

// The retry budget is operation-lifetime: one healthy round never replenishes
// it. Each new incident additionally has an absolute bounded recovery deadline.
func advanceSupervisedHealth(r smartTUNTrialJournal, e SmartTUNHealthEvidence, now int64) (smartTUNTrialJournal, string, bool) {
	next := cloneSmartTUNTrial(r)
	if next.Supervised.Version == 1 {
		return next, "legacy_reapply_required", false
	}
	s := next.Supervised
	s.Generation++
	s.Rounds++
	s.Evidence = e
	s.LastProbeMS = now
	s.NextProbeMS = now + int64(s.Options.IntervalSeconds)*1000
	s.HeartbeatMS, s.LeaseDeadlineMS = now, now+smartTUNHealthLeaseMS
	if s.RecoveryDeadlineMS > 0 && now >= s.RecoveryDeadlineMS {
		s.State, s.Reason = "degraded", "recovery_deadline_expired"
		return next, s.Reason, false
	}
	if !e.UnderlayHealthy {
		s.State, s.Reason = "degraded", "protected_underlay_failed"
		return next, s.Reason, false
	}
	if e.Reason == "vpn_path_mismatch" {
		s.State, s.Reason = "degraded", "vpn_path_mismatch"
		return next, s.Reason, false
	}
	if e.VPNHealthy {
		s.Failures, s.RecoveryDeadlineMS = 0, 0
		s.Reason = "selected_path_healthy"
		if s.Confirmed {
			s.State = "healthy"
		} else {
			s.State = "awaiting_confirmation"
		}
		return next, "", false
	}
	s.State, s.Reason = "degraded", "selected_vpn_failed"
	if now < s.ReadyAfterMS+int64(s.Options.StartupGraceSeconds)*1000 {
		return next, "", false
	}
	if s.Failures < s.Options.FailureThreshold {
		s.Failures++
	}
	if s.Failures < s.Options.FailureThreshold {
		return next, "", false
	}
	if !s.Confirmed {
		s.Reason = "unconfirmed_path_failed"
		return next, s.Reason, false
	}
	if s.RecoveryDeadlineMS == 0 {
		s.RecoveryDeadlineMS = now + int64(s.Options.RecoverySeconds)*1000
	}
	if now >= s.RecoveryDeadlineMS {
		return next, "recovery_deadline_expired", false
	}
	if s.Attempts >= s.Options.MaxAttempts {
		s.Reason = "reconnect_exhausted"
		return next, s.Reason, false
	}
	return next, "", true
}

func supervisedReconnectBudget(r smartTUNTrialJournal, now int64) (time.Duration, string) {
	s := r.Supervised
	if s != nil && s.Version == 1 {
		return 0, "legacy_reapply_required"
	}
	if s == nil || !s.Confirmed || r.Phase != "trial_pending" || r.Native.StopReason != "" {
		return 0, "reconnect_authority_unavailable"
	}
	if s.RecoveryDeadlineMS == 0 || now >= s.RecoveryDeadlineMS {
		return 0, "recovery_deadline_expired"
	}
	if now < s.HeartbeatMS || now >= s.LeaseDeadlineMS {
		return 0, "supervisor_lease_expired"
	}
	remaining := s.RecoveryDeadlineMS - now
	if lease := s.LeaseDeadlineMS - now; lease < remaining {
		remaining = lease
	}
	if remaining > 18000 {
		remaining = 18000
	}
	return time.Duration(remaining) * time.Millisecond, ""
}

func supervisedBudgetFault(reason string) error {
	return Fault(reason, "bounded supervised reconnect cannot continue: "+reason)
}

// A durable start intent is not proof that a command was dispatched. When a
// final deadline check or command construction fails BEFORE Run, record the
// known stopped state. An ambiguous Run outcome keeps start_requested and its
// attach uncertainty; it is never downgraded from a later service snapshot.
func abandonUnstartedSupervisedCore(store *activationJournalDir, r *smartTUNTrialJournal, reason string) error {
	next := cloneSmartTUNTrial(*r)
	next.Supervised.ReconnectStage = "stopped"
	next.Supervised.Generation++
	if err := nativeTUNAdvance(store, r, next); err != nil {
		return err
	}
	return supervisedBudgetFault(reason)
}

func startSupervisedCoreWithinBudget(store *activationJournalDir, r *smartTUNTrialJournal) error {
	now, err := smartTUNUptimeMillis()
	if err != nil {
		return abandonUnstartedSupervisedCore(store, r, "clock_unavailable")
	}
	budget, reason := supervisedReconnectBudget(*r, now)
	if reason != "" {
		return abandonUnstartedSupervisedCore(store, r, reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, "start", smartTUNTrialUnit)
	if err != nil {
		return abandonUnstartedSupervisedCore(store, r, "service_binary_untrusted")
	}
	if err := nativeTUNBindMutator(cmd, store); err != nil {
		return abandonUnstartedSupervisedCore(store, r, "activation_journal_conflict")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		return Fault("trial_recovery_uncertain", "bounded core start outcome or attach remains unresolved")
	}
	return nil
}

func stopSupervisedCoreForReconnect(store *activationJournalDir, original smartTUNTrialUnitObservation) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return stopSmartTUNTrialCoreWith(original, true, true,
		func() (smartTUNTrialUnitObservation, error) { return observeSmartTUNTrialUnit(ctx) },
		func(action string) error {
			cmd, err := trustedSystemctlCommand(ctx, action, smartTUNTrialUnit)
			if err != nil {
				return err
			}
			if err := nativeTUNBindMutator(cmd, store); err != nil {
				return err
			}
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if err := cmd.Run(); err != nil || ctx.Err() != nil {
				return Fault("trial_recovery_uncertain", "owned supervised core stop or normalization outcome unavailable")
			}
			return nil
		})
}

func recordSupervisedVerifiedAttach(store *activationJournalDir, r *smartTUNTrialJournal, pid, startTicks uint64) error {
	next := cloneSmartTUNTrial(*r)
	next.Supervised.ReconnectStage = "none"
	next.Supervised.Generation++
	next.Supervised.CorePID, next.Supervised.CoreStartTicks = pid, startTicks
	next.Supervised.State, next.Supervised.Reason = "degraded", "reconnect_awaiting_fresh_paths"
	// Receipt only: neither a new health result nor renewed time authority.
	return nativeTUNAdvance(store, r, next)
}

func reconnectSupervisedCore(store *activationJournalDir, r *smartTUNTrialJournal, qaKill string) error {
	if reason := inspectSupervisedRuntime(store, *r, true); reason != "" {
		return Fault("trial_recovery_uncertain", reason)
	}
	unit, err := observeSmartTUNTrialUnit(context.Background())
	if err != nil {
		return err
	}
	next := cloneSmartTUNTrial(*r)
	next.Supervised.Attempts++
	next.Supervised.Generation++
	next.Supervised.State, next.Supervised.ReconnectStage = "reconnecting", "stop_requested"
	if err := nativeTUNAdvance(store, r, next); err != nil {
		return err
	}
	if err := trialQAKillAt("after-reconnect-intent", qaKill); err != nil {
		return err
	}
	if err := stopSupervisedCoreForReconnect(store, unit); err != nil {
		return err
	}
	next = cloneSmartTUNTrial(*r)
	next.Supervised.ReconnectStage = "stopped"
	next.Supervised.Generation++
	if err := nativeTUNAdvance(store, r, next); err != nil {
		return err
	}
	if err := trialQAKillAt("after-reconnect-stop", qaKill); err != nil {
		return err
	}
	if err := nativeTUNVerifyPending(*r); err != nil {
		return err
	}
	watch, err := nativeTUNWatchStart(*r)
	if err != nil {
		return err
	}
	defer watch.close()
	now, err := smartTUNUptimeMillis()
	if err != nil {
		return err
	}
	if _, reason := supervisedReconnectBudget(*r, now); reason != "" {
		return supervisedBudgetFault(reason)
	}
	next = cloneSmartTUNTrial(*r)
	next.Supervised.ReconnectStage = "start_requested"
	next.Supervised.Generation++
	if err := nativeTUNAdvance(store, r, next); err != nil {
		return err
	}
	if err := startSupervisedCoreWithinBudget(store, r); err != nil {
		return err
	}
	if err := trialQAKillAt("after-reconnect-start", qaKill); err != nil {
		return err
	}
	if err := watch.verify(*r); err != nil {
		return err
	}
	started, err := observeSmartTUNTrialUnit(context.Background())
	if err != nil || started.activeState != "active" || started.mainPID == 0 {
		return Fault("trial_recovery_uncertain", "restarted core identity unavailable")
	}
	process, err := readManagementProcess(int(started.mainPID))
	if err != nil {
		return err
	}
	// Persist positive attach evidence even when the budget expired during
	// observation. Recovery can then stop this known generation safely; a
	// timeout alone must not erase an attachment that was actually verified.
	if err := recordSupervisedVerifiedAttach(store, r, started.mainPID, process.StartTicks); err != nil {
		return err
	}
	now, err = smartTUNUptimeMillis()
	if err != nil {
		return err
	}
	if _, reason := supervisedReconnectBudget(*r, now); reason != "" {
		return supervisedBudgetFault(reason)
	}
	next = cloneSmartTUNTrial(*r)
	next.Supervised.Generation++
	next.Supervised.NextProbeMS = now + 5000
	next.Supervised.HeartbeatMS, next.Supervised.LeaseDeadlineMS = now, now+smartTUNHealthLeaseMS
	if err := nativeTUNAdvance(store, r, next); err != nil {
		return err
	}
	return trialQAKillAt("after-reconnect-verified", qaKill)
}

func (m *Manager) RunSmartTUNHealthRound(qaKill string) (SmartTUNTrialReceipt, error) {
	if m.Dir != DefaultDir || m.Core != DefaultCore || !supervisedKillValid(qaKill, false) {
		return SmartTUNTrialReceipt{}, Fault("invalid_arguments", "installed supervised health executor required")
	}
	if err := smartTUNNativeHostContext(); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	var snapshot smartTUNTrialJournal
	var receipt SmartTUNTrialReceipt
	measure := false
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		r, _, err := loadSmartTUNTrialLocked(store)
		if errors.Is(err, os.ErrNotExist) {
			receipt = SmartTUNTrialReceipt{Phase: "absent", ExperimentOnly: true}
			return nil
		}
		if err != nil {
			return err
		}
		if r.Supervised == nil {
			receipt = smartTUNReceipt(r, false, false)
			return nil
		}
		if r.Phase != "trial_pending" {
			receipt, err = supervisedFinishStop(store, &r, r.Supervised.Reason)
			return err
		}
		if reason := inspectSupervisedRuntime(store, r, true); reason != "" {
			receipt, err = supervisedFinishStop(store, &r, reason)
			return err
		}
		now, err := smartTUNUptimeMillis()
		if err != nil {
			return err
		}
		if now < r.Supervised.NextProbeMS {
			next := cloneSmartTUNTrial(r)
			next.Supervised.Generation++
			next.Supervised.HeartbeatMS = now
			next.Supervised.LeaseDeadlineMS = now + smartTUNHealthLeaseMS
			if err := nativeTUNAdvance(store, &r, next); err != nil {
				return err
			}
			receipt = smartTUNReceipt(r, true, false)
			return nil
		}
		snapshot = cloneSmartTUNTrial(r)
		measure = true
		return nil
	})
	if err != nil || !measure {
		return receipt, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	var evidence SmartTUNHealthEvidence
	if snapshot.EndpointIP == smartTUNVMEndpoint {
		evidence = probeSmartTUNQAVMHealth(ctx)
	} else {
		evidence = probeSmartTUNHealth(ctx, snapshot.Native.IPv6.Address != "")
	}
	cancel()
	measuredMS, err := smartTUNUptimeMillis()
	if err != nil {
		return receipt, err
	}
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		current, _, err := loadSmartTUNTrialLocked(store)
		if errors.Is(err, os.ErrNotExist) {
			receipt = SmartTUNTrialReceipt{Phase: "absent", ExperimentOnly: true}
			return nil
		}
		if err != nil {
			return err
		}
		// A competing confirmation, Off or health round wins. Discard the old
		// measurement without claiming it describes the new operation/state.
		if !sameSmartTUNTrial(current, snapshot) {
			receipt = smartTUNReceipt(current, false, false)
			return nil
		}
		if reason := inspectSupervisedRuntime(store, current, true); reason != "" {
			receipt, err = supervisedFinishStop(store, &current, reason)
			return err
		}
		now, err := smartTUNUptimeMillis()
		if err != nil {
			return err
		}
		if now >= current.Supervised.LeaseDeadlineMS {
			receipt, err = supervisedFinishStop(store, &current, "supervisor_lease_expired")
			return err
		}
		if now < measuredMS || now-measuredMS > 5000 {
			receipt = smartTUNReceipt(current, false, false)
			return nil
		}
		next, stop, reconnect := advanceSupervisedHealth(current, evidence, now)
		next.Supervised.LastProbeMS = measuredMS
		if err := trialQAKillAt("before-health-publish", qaKill); err != nil {
			return err
		}
		if err := nativeTUNAdvance(store, &current, next); err != nil {
			return err
		}
		if err := trialQAKillAt("after-health-publish", qaKill); err != nil {
			return err
		}
		if stop != "" {
			receipt, err = supervisedFinishStop(store, &current, stop)
			return err
		}
		if reconnect {
			if err := reconnectSupervisedCore(store, &current, qaKill); err != nil {
				var stopErr error
				reason := "reconnect_failed"
				if code := ErrorCode(err); code == "recovery_deadline_expired" || code == "supervisor_lease_expired" || code == "clock_unavailable" {
					reason = code
				}
				receipt, stopErr = supervisedFinishStop(store, &current, reason)
				if stopErr != nil {
					return stopErr
				}
				return err
			}
		}
		receipt = smartTUNReceipt(current, true, false)
		return nil
	})
	return receipt, err
}

// Diagnostic label only. It never renews the lease or supplies fresh proof.
func smartTUNSupervisedStatusLabel(r smartTUNTrialJournal) string {
	if r.Supervised == nil {
		return r.Phase
	}
	if r.Supervised.Version == 1 && r.Phase == "trial_pending" {
		return "supervised_reapply_required"
	}
	return "supervised_" + r.Supervised.State
}
