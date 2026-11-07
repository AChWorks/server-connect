//go:build linux

package sc

// Host supervision is an explicit v9 intent in the same durable resource
// parent. Legacy preparation records never gain an active lease on upgrade.
// There is deliberately no general-host Connect admission in this package.
import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/netip"
)

const hostRouteSupervisedIntent = "host_native_supervised_policy_v1"

type hostRouteSupervision struct {
	Generation         uint64                        `json:"generation"`
	State              string                        `json:"state"`
	ManagementPeer     string                        `json:"management_peer"`
	Options            SmartTUNHealthOptions         `json:"options"`
	Roles              [2]smartTUNHealthUnitIdentity `json:"roles"`
	Plans              [2]HostHealthPlan             `json:"plans"`
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
	Evidence           [2]HostHealthEvidence         `json:"evidence"`
}

// Keep the old v9 document shape exactly recoverable. The optional field
// belongs only to the explicit supervised intent; null/partial fields refuse.
func (r hostRouteJournal) MarshalJSON() ([]byte, error) {
	var supervision *hostRouteSupervision
	if r.Intent == hostRouteSupervisedIntent || r.Supervision != (hostRouteSupervision{}) {
		value := r.Supervision
		supervision = &value
	}
	return json.Marshal(struct {
		hostCoreJournal
		Route       hostRouteStage        `json:"route"`
		Supervision *hostRouteSupervision `json:"supervision,omitempty"`
	}{r.hostCoreJournal, r.Route, supervision})
}

func hostRouteSupervised(r hostRouteJournal) bool { return r.Intent == hostRouteSupervisedIntent }

func hostRouteSupervisionReason(reason string) bool {
	switch reason {
	case "", "selected_path_healthy", "confirmed_fresh_paths", "selected_path_failed",
		"protected_underlay_failed", "path_mismatch", "unconfirmed_path_failed",
		"activation_expired", "supervisor_lease_expired", "recovery_deadline_expired",
		"reconnect_exhausted", "reconnect_interrupted", "reconnect_failed",
		"reconnect_awaiting_fresh_paths", "operator_disconnect", "boot_changed",
		"boot_unavailable", "clock_unavailable", "credential_conflict",
		"core_unavailable", "core_generation_changed", "core_identity_unavailable",
		"recovery_executor_unavailable", "supervisor_unavailable",
		"native_resource_conflict", "host_ingress_conflict", "management_path_changed",
		"initialization_interrupted", "operation_not_active", "recovery_requested":
		return true
	}
	return false
}

func hostRouteHealthPlans(r hostRouteJournal, round uint64) [2]HostHealthPlan {
	plans := r.Supervision.Plans
	for i := range plans {
		plans[i].Round = round
	}
	return plans
}

func validateHostRouteSupervision(r hostRouteJournal) error {
	bad := func() error { return activationJournalError("host supervision identity, state or evidence invalid") }
	if !hostRouteSupervised(r) {
		if r.Supervision != (hostRouteSupervision{}) {
			return bad()
		}
		return nil
	}
	s := r.Supervision
	peer, err := netip.ParseAddr(s.ManagementPeer)
	if err != nil || !plausibleHostManagementAddress(peer) || peer.String() != s.ManagementPeer ||
		r.Progress.Ingress.Deadline > (1<<63-1)/1000 ||
		s.Generation == 0 || s.Generation > 1<<60 || validateSmartTUNHealthOptions(s.Options) != nil ||
		s.HeartbeatMS <= 0 || s.HeartbeatMS > (1<<63-1)-smartTUNHealthLeaseMS ||
		s.LeaseDeadlineMS != s.HeartbeatMS+smartTUNHealthLeaseMS ||
		s.ReadyAfterMS < 0 || s.ReadyAfterMS > s.HeartbeatMS || s.LastProbeMS < 0 ||
		s.NextProbeMS < 0 || s.NextProbeMS > s.HeartbeatMS+30000 ||
		s.Rounds > 1<<60 || s.Failures < 0 || s.Failures > s.Options.FailureThreshold ||
		s.Attempts < 0 || s.Attempts > s.Options.MaxAttempts || s.RecoveryDeadlineMS < 0 ||
		!hostRouteSupervisionReason(s.Reason) {
		return bad()
	}
	for _, id := range s.Roles {
		if id.UnitIno == 0 || id.DigestIno == 0 || !journalHex64.MatchString(id.SHA256) {
			return bad()
		}
	}
	for _, p := range s.Plans {
		if ValidateHostHealthPlan(p) != nil || p.Round != 1 ||
			p.OperationID != r.Progress.Ingress.OperationID || p.BootID != r.Progress.Ingress.BootID ||
			p.ConfigSHA256 != r.Core.ConfigSHA256 || p.EndpointIP != r.Core.PinnedEndpoint ||
			p.UnderlayInterface != r.Progress.Ingress.Underlay || p.TunnelInterface != r.TunnelInterface ||
			p.IPv6 != (HostHealthFamilyPlan{}) || r.Native.IPv6.Address != "" {
			return bad()
		}
	}
	a, b := s.Plans[0], s.Plans[1]
	if a.IPv4.Trace.Address == b.IPv4.Trace.Address || a.IPv4.Trace.ServerName == b.IPv4.Trace.ServerName {
		return bad()
	}
	a.IPv4.Trace = b.IPv4.Trace
	if a != b {
		return bad()
	}
	switch s.State {
	case "initializing":
		if s.ReadyAfterMS != 0 || s.ChallengeSHA256 != "" || s.Confirmed || s.Rounds != 0 ||
			s.CorePID != 0 || s.CoreStartTicks != 0 {
			return bad()
		}
	case "awaiting_confirmation", "healthy", "degraded", "reconnecting":
		if s.ReadyAfterMS <= 0 || r.Route.State != "observed" {
			return bad()
		}
	case "stopped", "uncertain":
		if r.Route.State != "off_pending" && r.Route.State != "removed" {
			return bad()
		}
	default:
		return bad()
	}
	if s.ReadyAfterMS > 0 && (s.CorePID == 0 || s.CoreStartTicks == 0 ||
		s.ReadyAfterMS >= r.Progress.Ingress.Deadline*1000) {
		return bad()
	}
	if s.Confirmed {
		if s.ChallengeSHA256 != "" || !journalHex64.MatchString(s.SessionSHA256) ||
			s.SessionStartedMS <= s.ReadyAfterMS || s.SessionStartedMS > s.HeartbeatMS || s.Rounds == 0 {
			return bad()
		}
	} else if s.SessionSHA256 != "" || s.SessionStartedMS != 0 || s.State == "healthy" ||
		s.ReadyAfterMS > 0 && !journalHex64.MatchString(s.ChallengeSHA256) {
		return bad()
	}
	if s.State == "awaiting_confirmation" && s.Confirmed {
		return bad()
	}
	switch s.ReconnectStage {
	case "none":
		if s.State == "reconnecting" {
			return bad()
		}
	case "stop_requested", "stopped", "start_requested":
		if !s.Confirmed || s.Attempts == 0 || s.RecoveryDeadlineMS == 0 ||
			s.State != "reconnecting" && s.State != "stopped" && s.State != "uncertain" {
			return bad()
		}
	default:
		return bad()
	}
	if s.Rounds == 0 {
		if s.LastProbeMS != 0 || s.NextProbeMS != 0 || s.Failures != 0 || s.Attempts != 0 || s.RecoveryDeadlineMS != 0 || s.Evidence != ([2]HostHealthEvidence{}) {
			return bad()
		}
	} else {
		if s.LastProbeMS <= 0 || s.LastProbeMS > s.HeartbeatMS {
			return bad()
		}
		plans := hostRouteHealthPlans(r, s.Rounds)
		last := int64(0)
		for i := range plans {
			if ValidateHostHealthEvidence(plans[i], s.Evidence[i]) != nil ||
				s.Evidence[i].StartedUptimeMS < s.ReadyAfterMS || s.Evidence[i].CompletedUptimeMS <= 0 ||
				s.Evidence[i].CompletedUptimeMS > s.LastProbeMS {
				return bad()
			}
			if s.Evidence[i].CompletedUptimeMS > last {
				last = s.Evidence[i].CompletedUptimeMS
			}
		}
		if last != s.LastProbeMS {
			return bad()
		}
	}
	healthy, _ := hostRouteHealthSummary(s.Plans, s.Evidence)
	if s.State == "healthy" && (!s.Confirmed || !healthy || s.Failures != 0) {
		return bad()
	}
	if r.Route.State == "removed" && (s.State != "stopped" || s.ReconnectStage != "none") {
		return bad()
	}
	return nil
}

// Parent CAS does not authorize replacing an intent, witness, confirmation or budget.
func hostRouteSupervisionTransition(previous, next hostRouteJournal) bool {
	if !hostRouteSupervised(previous) {
		return next.Supervision == (hostRouteSupervision{})
	}
	a, b := previous.Supervision, next.Supervision
	if a == b {
		return true
	}
	if b.Generation != a.Generation+1 || b.Plans != a.Plans || b.Roles != a.Roles ||
		b.Options != a.Options || b.ManagementPeer != a.ManagementPeer ||
		b.HeartbeatMS < a.HeartbeatMS || b.LastProbeMS < a.LastProbeMS ||
		b.Rounds < a.Rounds || b.Rounds > a.Rounds+1 || b.Attempts < a.Attempts || b.Attempts > a.Attempts+1 {
		return false
	}
	if a.ReadyAfterMS > 0 && b.ReadyAfterMS != a.ReadyAfterMS {
		return false
	}
	if a.ReadyAfterMS > 0 && (b.CorePID != a.CorePID || b.CoreStartTicks != a.CoreStartTicks) &&
		(a.ReconnectStage != "start_requested" || b.ReconnectStage != "none" || b.State != "degraded") {
		return false
	}
	if a.Confirmed && (!b.Confirmed || b.SessionSHA256 != a.SessionSHA256 || b.SessionStartedMS != a.SessionStartedMS) {
		return false
	}
	if a.ChallengeSHA256 != "" && !b.Confirmed && b.ChallengeSHA256 != a.ChallengeSHA256 {
		return false
	}
	if b.Attempts == a.Attempts+1 && (a.ReconnectStage != "none" || b.ReconnectStage != "stop_requested") {
		return false
	}
	if b.Rounds == a.Rounds && (b.Evidence != a.Evidence || b.LastProbeMS != a.LastProbeMS) {
		return false
	}
	return true
}

func strictHostHealthTraceJSON(raw json.RawMessage) error {
	_, err := strictSupervisedObject(raw, "address port server_name path")
	return err
}
func strictHostHealthPlanJSON(raw json.RawMessage) error {
	f, err := strictSupervisedObject(raw, "round operation_id boot_id config_sha256 tunnel_interface underlay_interface endpoint_ip endpoint_port ipv4 ipv6 domestic")
	if err != nil {
		return err
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		p, err := strictSupervisedObject(f[family], "direct_unavailable enabled underlay_source dns_resolver trace expected_direct_ip expected_vpn_ip")
		if err != nil {
			return err
		}
		if err := strictHostHealthTraceJSON(p["trace"]); err != nil {
			return err
		}
	}
	return strictHostHealthTraceJSON(f["domestic"])
}
func strictHostHealthResultJSON(raw json.RawMessage) error {
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil {
		return activationJournalError("invalid host health result")
	}
	names := "result http_status"
	if _, found := keys["observed_ip"]; found {
		names += " observed_ip"
	}
	_, err := strictSupervisedObject(raw, names)
	return err
}
func strictHostHealthEvidenceJSON(raw json.RawMessage) error {
	f, err := strictSupervisedObject(raw, "round started_uptime_ms completed_uptime_ms operation_id boot_id config_sha256 plan_sha256 ipv4 ipv6 endpoint_tcp domestic_https domestic_verified healthy probe_count elapsed_ms reason")
	if err != nil {
		return err
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		e, err := strictSupervisedObject(f[family], "direct_unavailable enabled selected_https direct_https tcp udp dns egress_verified direct_verified")
		if err != nil {
			return err
		}
		for _, result := range []string{"selected_https", "direct_https"} {
			if err := strictHostHealthResultJSON(e[result]); err != nil {
				return err
			}
		}
	}
	return strictHostHealthResultJSON(f["domestic_https"])
}
func strictHostRouteSupervisionJSON(raw json.RawMessage) error {
	f, err := strictSupervisedObject(raw, "generation state management_peer options roles plans ready_after_uptime_ms challenge_sha256 confirmed session_sha256 session_started_uptime_ms core_pid core_start_ticks heartbeat_uptime_ms lease_deadline_uptime_ms last_probe_uptime_ms next_probe_uptime_ms rounds failures attempts recovery_deadline_uptime_ms reconnect_stage reason evidence")
	if err != nil {
		return err
	}
	if _, err := strictSupervisedObject(f["options"], "interval_seconds startup_grace_seconds failure_threshold max_attempts recovery_seconds"); err != nil {
		return err
	}
	for _, group := range []string{"roles", "plans", "evidence"} {
		var values []json.RawMessage
		if json.Unmarshal(f[group], &values) != nil || len(values) != 2 {
			return activationJournalError("host supervision requires exactly two role and witness slots")
		}
		for _, value := range values {
			switch group {
			case "roles":
				_, err = strictSupervisedObject(value, "unit_dev unit_ino digest_dev digest_ino sha256")
			case "plans":
				err = strictHostHealthPlanJSON(value)
			case "evidence":
				err = strictHostHealthEvidenceJSON(value)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// A positive secondary trace prevents a lone website failure from being
// mistaken for a VPN outage. A wrong egress is always fatal. Canceled/late
// rounds never contribute positive evidence, even if individual I/O succeeded.
func hostRouteHealthSummary(plans [2]HostHealthPlan, evidence [2]HostHealthEvidence) (bool, string) {
	direct, selected, dns, endpoint, domestic := false, false, false, false, plans[0].Domestic == (HostHealthTraceTarget{})
	for _, e := range evidence {
		if e.Reason == "path_mismatch" {
			return false, "path_mismatch"
		}
		if e.ProbeCount == 0 || e.CompletedUptimeMS == 0 || e.Reason == "round_canceled" ||
			e.Reason == "clock_unavailable" || e.ElapsedMS > smartTUNHealthRoundTimeout.Milliseconds() ||
			e.CompletedUptimeMS < e.StartedUptimeMS ||
			e.CompletedUptimeMS-e.StartedUptimeMS > smartTUNHealthRoundTimeout.Milliseconds() {
			continue
		}
		direct = direct || e.IPv4.DirectVerified
		selected = selected || e.IPv4.EgressVerified
		dns = dns || e.IPv4.DNS == "pass" && e.IPv4.UDP == "pass"
		endpoint = endpoint || e.EndpointTCP == "pass"
		domestic = domestic || e.DomesticVerified
	}
	if !direct || !endpoint || !domestic {
		return false, "protected_underlay_failed"
	}
	if !selected || !dns {
		return false, "selected_path_failed"
	}
	return true, ""
}

func hostRouteChallengeDigest(r hostRouteJournal, challenge string) string {
	return sha256Hex([]byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%d\n%s",
		r.Progress.Ingress.OperationID, r.Progress.Ingress.BootID, r.Core.ConfigSHA256,
		r.Route.PolicySHA256, r.Supervision.ReadyAfterMS, challenge)))
}
func hostRouteConfirmMatches(r hostRouteJournal, op, challenge, boot string, now int64) bool {
	s := r.Supervision
	return hostRouteSupervised(r) && r.Route.State == "observed" && !s.Confirmed &&
		s.State == "awaiting_confirmation" && s.ReadyAfterMS > 0 &&
		journalHex32.MatchString(op) && op == r.Progress.Ingress.OperationID &&
		boot == r.Progress.Ingress.BootID && now > s.ReadyAfterMS &&
		now < r.Progress.Ingress.Deadline*1000 && now >= s.HeartbeatMS && now < s.LeaseDeadlineMS &&
		journalHex64.MatchString(challenge) &&
		subtle.ConstantTimeCompare([]byte(s.ChallengeSHA256), []byte(hostRouteChallengeDigest(r, challenge))) == 1
}
func hostRouteRuntimeDeadline(r hostRouteJournal, boot string, now int64) string {
	s := r.Supervision
	if !hostRouteSupervised(r) {
		return "operation_not_active"
	}
	if boot != r.Progress.Ingress.BootID {
		return "boot_changed"
	}
	if s.State == "initializing" {
		return "initialization_interrupted"
	}
	if r.Route.State != "observed" || s.State == "stopped" || s.State == "uncertain" {
		return "operation_not_active"
	}
	if !s.Confirmed && now >= r.Progress.Ingress.Deadline*1000 {
		return "activation_expired"
	}
	if now < s.HeartbeatMS || now >= s.LeaseDeadlineMS {
		return "supervisor_lease_expired"
	}
	if s.RecoveryDeadlineMS > 0 && now >= s.RecoveryDeadlineMS {
		return "recovery_deadline_expired"
	}
	if s.ReconnectStage != "none" {
		return "reconnect_interrupted"
	}
	return ""
}

func advanceHostRouteHealth(r hostRouteJournal, evidence [2]HostHealthEvidence, now int64) (hostRouteJournal, string, error) {
	next := r
	if validateHostRouteJournal(r) != nil || !hostRouteSupervised(r) ||
		hostRouteRuntimeDeadline(r, r.Progress.Ingress.BootID, now) != "" {
		return next, "", Fault("activation_journal_conflict", "host health cannot renew an invalid or expired operation")
	}
	plans := hostRouteHealthPlans(r, r.Supervision.Rounds+1)
	last := int64(0)
	for i := range evidence {
		if ValidateHostHealthEvidence(plans[i], evidence[i]) != nil || evidence[i].StartedUptimeMS < r.Supervision.HeartbeatMS ||
			evidence[i].CompletedUptimeMS > now || evidence[i].CompletedUptimeMS == 0 ||
			now-evidence[i].CompletedUptimeMS > 5000 {
			return next, "", Fault("host_health_plan_invalid", "host health measurement is stale or does not match the exact round")
		}
		if evidence[i].CompletedUptimeMS > last {
			last = evidence[i].CompletedUptimeMS
		}
	}
	s := &next.Supervision
	s.Generation++
	s.Rounds++
	s.Evidence = evidence
	s.LastProbeMS, s.NextProbeMS = last, now+int64(s.Options.IntervalSeconds)*1000
	s.HeartbeatMS, s.LeaseDeadlineMS = now, now+smartTUNHealthLeaseMS
	healthy, reason := hostRouteHealthSummary(plans, evidence)
	if healthy {
		s.Failures, s.RecoveryDeadlineMS, s.Reason = 0, 0, "selected_path_healthy"
		s.State = "awaiting_confirmation"
		if s.Confirmed {
			s.State = "healthy"
		}
		return next, "", nil
	}
	s.State, s.Reason = "degraded", reason
	if reason != "selected_path_failed" {
		return next, "stop", nil
	}
	if now < s.ReadyAfterMS+int64(s.Options.StartupGraceSeconds)*1000 {
		return next, "", nil
	}
	if s.Failures < s.Options.FailureThreshold {
		s.Failures++
	}
	if s.Failures < s.Options.FailureThreshold {
		return next, "", nil
	}
	if !s.Confirmed {
		s.Reason = "unconfirmed_path_failed"
		return next, "stop", nil
	}
	if s.RecoveryDeadlineMS == 0 {
		s.RecoveryDeadlineMS = now + int64(s.Options.RecoverySeconds)*1000
	}
	if s.Attempts >= s.Options.MaxAttempts {
		s.Reason = "reconnect_exhausted"
		return next, "stop", nil
	}
	return next, "reconnect", nil
}

// This is control metadata, never an activation permit or a geographic/DNS
// routing claim. RecoveryVerified is set only by fresh native Off verification.
type HostRouteSupervisionReceipt struct {
	OperationID                string `json:"operation_id,omitempty"`
	Phase                      string `json:"phase"`
	ExperimentOnly             bool   `json:"experiment_only"`
	GeneralHostAdmitted        bool   `json:"general_host_admitted"`
	Generation                 uint64 `json:"generation,omitempty"`
	Confirmed                  bool   `json:"confirmed"`
	GuardScheduled             bool   `json:"guard_scheduled"`
	RecoveryVerified           bool   `json:"recovery_verified"`
	Reason                     string `json:"reason,omitempty"`
	HealthRound                uint64 `json:"health_round,omitempty"`
	HealthLastUptimeMS         int64  `json:"health_last_uptime_ms,omitempty"`
	LeaseDeadlineUptimeMS      int64  `json:"lease_deadline_uptime_ms,omitempty"`
	ActivationDeadlineUptimeMS int64  `json:"activation_deadline_uptime_ms,omitempty"`
	Failures                   int    `json:"failures"`
	ReconnectAttempts          int    `json:"reconnect_attempts"`
	RecoveryDeadlineUptimeMS   int64  `json:"recovery_deadline_uptime_ms,omitempty"`
	IPv4SelectedVerified       bool   `json:"ipv4_selected_verified"`
	IPv6                       string `json:"ipv6"`
	DomesticGeography          string `json:"domestic_geography"`
	DNSRouting                 string `json:"dns_routing"`
}

func hostRouteSupervisionReceipt(r hostRouteJournal) HostRouteSupervisionReceipt {
	s := r.Supervision
	return HostRouteSupervisionReceipt{
		OperationID: r.Progress.Ingress.OperationID, Phase: "host_route_" + s.State, ExperimentOnly: true,
		Generation: s.Generation, Confirmed: s.Confirmed, Reason: s.Reason, HealthRound: s.Rounds,
		HealthLastUptimeMS: s.LastProbeMS, LeaseDeadlineUptimeMS: s.LeaseDeadlineMS,
		ActivationDeadlineUptimeMS: r.Progress.Ingress.Deadline * 1000,
		Failures:                   s.Failures, ReconnectAttempts: s.Attempts, RecoveryDeadlineUptimeMS: s.RecoveryDeadlineMS,
		IPv4SelectedVerified: false, IPv6: "not_supported", DomesticGeography: "not_verified", DNSRouting: "not_verified",
	}
}
