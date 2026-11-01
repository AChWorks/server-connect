package sc

// This is a deliberately narrow, DISPOSABLE-GUEST-ONLY product TUN
// transaction. It starts the official core from an installed, separately
// privilege-bounded systemd unit, and reuses the installed independent
// recovery timer and the descriptor-pinned activation journal. It cannot
// claim production Smart Routing or run on a physical/production host. The
// distinct supervised intent adds confirmed synthetic operation with a
// separately bounded health executor; legacy trials keep their expiry rules.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	smartTUNTrialVersion    = 4
	smartTUNTrialIntent     = "smart_tun_pending_trial_v4"
	smartTUNTrialUnit       = "server-connect-smart-tun.service"
	smartTUNTrialConfigFile = "smart-tun-trial.json"
)

type smartTUNTrialJournal struct {
	Version            int                   `json:"version"`
	Revision           uint64                `json:"revision"`
	OperationID        string                `json:"operation_id"`
	IntentType         string                `json:"intent_type"`
	Phase              string                `json:"phase"`
	CreatedUnix        int64                 `json:"created_unix"`
	BootID             string                `json:"boot_id"`
	DeadlineUptimeSec  int64                 `json:"deadline_uptime_sec"`
	ProfileID          string                `json:"profile_id"`
	EndpointIP         string                `json:"endpoint_ip"`
	ManagementPeerIP   string                `json:"management_peer_ip"`
	TunnelInterface    string                `json:"tunnel_interface"`
	UnderlayInterface  string                `json:"underlay_interface"`
	ConfigSHA256       string                `json:"config_sha256"`
	CoreStartAttempted bool                  `json:"core_start_attempted"`
	BaselineSHA256     string                `json:"baseline_sha256"`
	Native             *smartTUNNativeLedger `json:"native,omitempty"`
	Supervised         *smartTUNSupervision  `json:"supervised,omitempty"`
}

var smartTUNTrialFields = map[string]bool{
	"version": true, "revision": true, "operation_id": true, "intent_type": true,
	"phase": true, "created_unix": true, "boot_id": true, "deadline_uptime_sec": true,
	"profile_id": true, "endpoint_ip": true, "management_peer_ip": true,
	"tunnel_interface": true, "underlay_interface": true,
	"config_sha256": true, "core_start_attempted": true, "baseline_sha256": true,
}

// Transaction and optional supervision metadata for an experimental fixture,
// NEVER production readiness. Health evidence has explicit timestamps and
// does not promote a synthetic confirmed operation to ACTIVE_VERIFIED.
type SmartTUNTrialReceipt struct {
	OperationID                  string                  `json:"operation_id,omitempty"`
	Revision                     uint64                  `json:"revision,omitempty"`
	Phase                        string                  `json:"phase"`
	ExperimentOnly               bool                    `json:"experiment_only"`
	GuardScheduled               bool                    `json:"guard_scheduled"`
	ActivationReady              bool                    `json:"activation_ready"`
	VPNVerified                  bool                    `json:"vpn_verified"`
	RecoveryVerified             bool                    `json:"recovery_verified"`
	ConfirmationChallenge        string                  `json:"confirmation_challenge,omitempty"`
	SupervisionState             string                  `json:"supervision_state,omitempty"`
	ManagementConfirmed          bool                    `json:"management_confirmed"`
	ConfirmationDeadlineUptimeMS int64                   `json:"confirmation_deadline_uptime_ms,omitempty"`
	SupervisorDeadlineUptimeMS   int64                   `json:"supervisor_deadline_uptime_ms,omitempty"`
	HealthRound                  uint64                  `json:"health_round,omitempty"`
	HealthLastUptimeMS           int64                   `json:"health_last_uptime_ms,omitempty"`
	HealthNextUptimeMS           int64                   `json:"health_next_uptime_ms,omitempty"`
	HealthFailures               int                     `json:"health_failures,omitempty"`
	ReconnectAttempts            int                     `json:"reconnect_attempts,omitempty"`
	RecoveryDeadlineUptimeMS     int64                   `json:"recovery_deadline_uptime_ms,omitempty"`
	HealthReason                 string                  `json:"health_reason,omitempty"`
	HealthEvidenceVersion        int                     `json:"health_evidence_version,omitempty"`
	HealthEvidence               *SmartTUNHealthEvidence `json:"health_evidence,omitempty"`
}

func smartTUNReceipt(record smartTUNTrialJournal, scheduled, recovered bool) SmartTUNTrialReceipt {
	receipt := SmartTUNTrialReceipt{
		OperationID: record.OperationID, Revision: record.Revision,
		Phase: record.Phase, ExperimentOnly: true, GuardScheduled: scheduled,
		RecoveryVerified: recovered,
	}
	if s := record.Supervised; s != nil {
		receipt.SupervisionState, receipt.ManagementConfirmed = s.State, s.Confirmed
		receipt.ConfirmationDeadlineUptimeMS = record.DeadlineUptimeSec * 1000
		receipt.SupervisorDeadlineUptimeMS = s.LeaseDeadlineMS
		receipt.HealthRound, receipt.HealthLastUptimeMS, receipt.HealthNextUptimeMS = s.Rounds, s.LastProbeMS, s.NextProbeMS
		receipt.HealthFailures, receipt.ReconnectAttempts = s.Failures, s.Attempts
		receipt.RecoveryDeadlineUptimeMS, receipt.HealthReason = s.RecoveryDeadlineMS, s.Reason
		receipt.HealthEvidenceVersion = s.Version
		evidence := s.Evidence
		if s.Version == 1 || s.Rounds == 0 {
			evidence.HTTPSResults = smartTUNHealthNotRunEvidence().HTTPSResults
		}
		if s.Version == 1 {
			// Historical TCP proof remains identified as Version1. It cannot
			// claim HTTPS execution or current supervised healthy authority.
			if record.Phase == "trial_pending" {
				receipt.SupervisionState, receipt.HealthReason = "reapply_required", "legacy_reapply_required"
			}
		}
		receipt.HealthEvidence = &evidence
	}
	return receipt
}

func validateSmartTUNTrial(record smartTUNTrialJournal) error {
	if record.Version != smartTUNTrialVersion ||
		(record.IntentType != smartTUNTrialIntent && record.IntentType != smartTUNNativeIntent && record.IntentType != smartTUNSupervisedIntent) ||
		(record.IntentType == smartTUNTrialIntent && record.Native != nil) ||
		((record.IntentType == smartTUNNativeIntent || record.IntentType == smartTUNSupervisedIntent) && record.Native == nil) ||
		((record.IntentType == smartTUNSupervisedIntent) != (record.Supervised != nil)) ||
		!journalHex32.MatchString(record.OperationID) ||
		!trialBootIDPattern.MatchString(record.BootID) ||
		!idPattern.MatchString(record.ProfileID) ||
		!journalHex64.MatchString(record.ConfigSHA256) ||
		!journalHex64.MatchString(record.BaselineSHA256) ||
		record.CreatedUnix <= 0 || record.DeadlineUptimeSec <= 0 ||
		!smartTUNDeviceName.MatchString(record.TunnelInterface) ||
		!smartTUNDeviceName.MatchString(record.UnderlayInterface) ||
		record.TunnelInterface == record.UnderlayInterface ||
		record.TunnelInterface == "lo" || record.UnderlayInterface == "lo" {
		return activationJournalError("invalid guarded Smart Routing trial identity or resource")
	}
	if !smartTUNTrialPhaseRevisionValid(record.Phase, record.Revision) {
		return activationJournalError("unsupported guarded Smart Routing trial phase/revision")
	}
	for _, ip := range []string{record.EndpointIP, record.ManagementPeerIP} {
		address, err := netip.ParseAddr(ip)
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() ||
			address.IsLoopback() || address.IsLinkLocalUnicast() {
			return activationJournalError("unsupported guarded trial underlay/management identity")
		}
	}
	if record.Native != nil {
		if err := validateSmartTUNNative(record); err != nil {
			return err
		}
	}
	if record.Supervised != nil {
		return validateSmartTUNSupervision(record)
	}
	return nil
}

func decodeSmartTUNTrial(data []byte) (smartTUNTrialJournal, error) {
	var record smartTUNTrialJournal
	if err := rejectAmbiguousJournalJSON(data); err != nil {
		return record, err
	}
	var discriminator struct {
		Intent string `json:"intent_type"`
	}
	if json.Unmarshal(data, &discriminator) != nil {
		return record, activationJournalError("guarded TUN intent invalid")
	}
	keys := smartTUNTrialFields
	if discriminator.Intent == smartTUNNativeIntent || discriminator.Intent == smartTUNSupervisedIntent {
		keys = make(map[string]bool, len(smartTUNTrialFields)+1)
		for key, required := range smartTUNTrialFields {
			keys[key] = required
		}
		keys["native"] = true
		if discriminator.Intent == smartTUNSupervisedIntent {
			keys["supervised"] = true
		}
	}
	if err := requireExactJournalKeys(data, keys); err != nil {
		return record, err
	}
	// encoding/json treats null as the zero value for a Go bool. A
	// missing-or-null start-intent could then turn a once-started core into
	// an apparently benign precredential crash during recovery. Reject any
	// non-boolean wire value before decoding this safety-critical field.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil ||
		(string(fields["core_start_attempted"]) != "true" && string(fields["core_start_attempted"]) != "false") {
		return record, activationJournalError("guarded Smart Routing start-intent type invalid")
	}
	if discriminator.Intent == smartTUNNativeIntent || discriminator.Intent == smartTUNSupervisedIntent {
		if err := strictSmartTUNNativeJSON(fields["native"]); err != nil {
			return record, err
		}
	}
	if discriminator.Intent == smartTUNSupervisedIntent {
		if err := strictSmartTUNSupervisionJSON(fields["supervised"]); err != nil {
			return record, err
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&record); err != nil {
		return smartTUNTrialJournal{}, activationJournalError("guarded Smart Routing journal schema invalid")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return smartTUNTrialJournal{}, activationJournalError("guarded Smart Routing journal trailing data")
	}
	if err := validateSmartTUNTrial(record); err != nil {
		return smartTUNTrialJournal{}, err
	}
	return record, nil
}

func loadSmartTUNTrialLocked(store *activationJournalDir) (smartTUNTrialJournal, activationJournalFileIdentity, error) {
	data, identity, err := store.readJournal()
	if err != nil {
		return smartTUNTrialJournal{}, identity, err
	}
	record, err := decodeSmartTUNTrial(data)
	return record, identity, err
}

// Atomic journal writes legitimately change the inode. Refresh that identity
// only if the ENTIRE expected operation still matches, not merely its schema
// or operation ID. Otherwise a valid substituted record could be adopted and
// later overwritten/removed using another operation's recovery evidence.
func reloadSmartTUNTrialLocked(store *activationJournalDir, expected smartTUNTrialJournal) (activationJournalFileIdentity, error) {
	record, identity, err := loadSmartTUNTrialLocked(store)
	if errors.Is(err, os.ErrNotExist) {
		return activationJournalFileIdentity{}, Fault("activation_journal_conflict", "expected TUN operation disappeared during transition")
	}
	if err != nil {
		return activationJournalFileIdentity{}, err
	}
	if !sameSmartTUNTrial(record, expected) {
		return activationJournalFileIdentity{}, Fault("activation_journal_conflict", "TUN operation contents changed during transition")
	}
	return identity, nil
}

func writeSmartTUNTrialLocked(store *activationJournalDir, record smartTUNTrialJournal, old *activationJournalFileIdentity) error {
	if err := validateSmartTUNTrial(record); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return activationJournalError("cannot serialize guarded Smart Routing trial")
	}
	return store.writeJournal(append(raw, '\n'), old)
}

// Bind the recovery receipt to a full, native semantic Linux observation.
// This fingerprint is an equality test, NOT a claim of authenticated kernel
// ownership. The only environment admitted by this API is a disposable guest.
func smartTUNTrialSnapshot(host HostPreflight) (string, error) {
	if validateHostDriftSnapshot(host) != nil || host.Firewall == nil ||
		host.Endpoint == nil || host.ManagementPeer == nil {
		return "", Fault("trial_observation_uncertain", "complete native host and firewall baseline unavailable")
	}
	items := []struct {
		raw       json.RawMessage
		unordered bool
	}{
		{host.Links, true},
		{host.IPv4Routes, true},
		{host.IPv6Routes, true},
		{host.IPv4Rules, false},
		{host.IPv6Rules, false},
		{host.Endpoint.KernelRoute, false},
		{host.ManagementPeer.KernelRoute, false},
	}
	parts := make([]string, 0, len(items)+6)
	for _, item := range items {
		digest, err := hostDriftFingerprint(item.raw, item.unordered)
		if err != nil {
			return "", Fault("trial_observation_uncertain", "native host fingerprint unavailable")
		}
		parts = append(parts, digest)
	}
	parts = append(parts, host.Endpoint.Target, host.ManagementPeer.Target,
		host.Firewall.RulesetSHA256, strconv.Itoa(host.Firewall.ObjectCount))
	return sha256Hex([]byte(strings.Join(parts, "\n"))), nil
}

func inspectSmartTUNBaseline(endpoint, peer string) (string, error) {
	host, err := InspectHostRoutesAndFirewall(endpoint, peer)
	if err != nil {
		return "", err
	}
	return smartTUNTrialSnapshot(host)
}

// The Docker fixture remains restricted to lo + its sole VETH underlay.
// The exact non-Docker VM additionally accepts one independently validated,
// preexisting test-only hosted-ingress VETH, never an arbitrary third device.
// No general host or multi-interface routing authority is granted.
func smartTUNTrialGuest(underlay, tunnel, endpoint string) error {
	if err := smartTUNNativeHostContext(); err != nil {
		return err
	}
	raw, err := nativeIPJSON("-j", "link", "show")
	if err != nil {
		return Fault("trial_unsupported", "disposable link inventory unavailable")
	}
	rows, err := selectiveRows(raw)
	if err != nil || !smartTUNTrialLinkInventoryAllowed(rows, underlay, tunnel) {
		return Fault("trial_unsupported", "unrecognized disposable guest network interfaces")
	}
	if len(rows) == 3 {
		if err := smartTUNVMIngressFixture(); err != nil {
			return err
		}
	}
	lookup, err := lookupHostRoute(netip.MustParseAddr(endpoint))
	if err != nil || lookup == nil {
		return Fault("trial_unsupported", "guest endpoint underlay cannot be proven")
	}
	routes, err := selectiveRows(lookup.KernelRoute)
	if err != nil || len(routes) != 1 || selectiveText(routes[0]["dev"]) != underlay {
		return Fault("trial_unsupported", "VPN endpoint does not use the protected VETH underlay")
	}
	return nil
}

type smartTUNTrialUnitIdentity struct {
	unitFile, digestFile     activationJournalFileIdentity
	unitSHA256, digestSHA256 string
}

type smartTUNTrialUnitObservation struct {
	identity                      smartTUNTrialUnitIdentity
	activeState, subState, result string
	mainPID, controlPID           uint64
	job, controlGroup             string
}

// Keep the exact installed files bound across stop/query/reset. A same-name
// replacement, even with identical bytes, is not this recovery's authority.
func readSmartTUNTrialUnitFile(path string) ([]byte, activationJournalFileIdentity, error) {
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

func smartTUNTrialReadUnitIdentity() (smartTUNTrialUnitIdentity, error) {
	var identity smartTUNTrialUnitIdentity
	unit, unitFile, err := readSmartTUNTrialUnitFile(filepath.Join(trialGuardUnitDir, smartTUNTrialUnit))
	if err != nil {
		return identity, err
	}
	digest, digestFile, err := readSmartTUNTrialUnitFile(filepath.Join(managedPrefix, smartTUNTrialUnit+".sha256"))
	if err != nil || strings.TrimSpace(string(digest)) != sha256Hex(unit) {
		return identity, Fault("guard_unavailable", "installed TUN unit digest conflict")
	}
	identity = smartTUNTrialUnitIdentity{unitFile: unitFile, digestFile: digestFile,
		unitSHA256: sha256Hex(unit), digestSHA256: sha256Hex(digest)}
	return identity, nil
}

// Read-only observation; neither status nor a recovered-journal check resets
// failed state. Empty ControlGroup is significant: pinned systemd releases its
// tracked cgroup only after proving recursive emptiness. It can clear tracked
// MainPID/ControlPID while failed work still remains in that cgroup.
func observeSmartTUNTrialUnit(parent context.Context) (smartTUNTrialUnitObservation, error) {
	var empty smartTUNTrialUnitObservation
	identity, err := smartTUNTrialReadUnitIdentity()
	if err != nil {
		return empty, err
	}
	if err := trialNoRuntimeUnitOverride(trialRuntimeUnitDir, smartTUNTrialUnit); err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, "show", smartTUNTrialUnit,
		"-p", "Id", "-p", "LoadState", "-p", "FragmentPath", "-p", "DropInPaths",
		"-p", "Transient", "-p", "UnitFileState", "-p", "ActiveState", "-p", "SubState",
		"-p", "Result", "-p", "MainPID", "-p", "ControlPID", "-p", "Job", "-p", "ControlGroup")
	if err != nil {
		return empty, err
	}
	out, err := cmd.Output()
	if err != nil || ctx.Err() != nil {
		return empty, Fault("guard_unavailable", "TUN unit runtime identity unavailable")
	}
	after, err := smartTUNTrialReadUnitIdentity()
	if err != nil || after != identity {
		return empty, Fault("guard_unavailable", "installed TUN unit changed during observation")
	}
	if err := trialNoRuntimeUnitOverride(trialRuntimeUnitDir, smartTUNTrialUnit); err != nil {
		return empty, err
	}
	return parseSmartTUNTrialUnitObservation(out, identity)
}

func parseSmartTUNTrialUnitObservation(out []byte, identity smartTUNTrialUnitIdentity) (smartTUNTrialUnitObservation, error) {
	invalid := func() (smartTUNTrialUnitObservation, error) {
		return smartTUNTrialUnitObservation{}, Fault("guard_unavailable", "TUN unit runtime identity or state is ambiguous")
	}
	if len(out) == 0 || len(out) > 16*1024 {
		return invalid()
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 {
			return invalid()
		}
		switch pair[0] {
		case "Id", "LoadState", "FragmentPath", "DropInPaths", "Transient", "UnitFileState",
			"ActiveState", "SubState", "Result", "MainPID", "ControlPID", "Job", "ControlGroup":
		default:
			return invalid()
		}
		if _, exists := fields[pair[0]]; exists {
			return invalid()
		}
		fields[pair[0]] = pair[1]
	}
	if len(fields) != 13 || fields["Id"] != smartTUNTrialUnit || fields["LoadState"] != "loaded" ||
		fields["FragmentPath"] != filepath.Join(trialGuardUnitDir, smartTUNTrialUnit) ||
		fields["DropInPaths"] != "" || fields["Transient"] != "no" || fields["UnitFileState"] != "static" ||
		fields["SubState"] == "" || fields["Result"] == "" {
		return invalid()
	}
	switch fields["ActiveState"] {
	case "inactive", "active", "activating", "failed", "deactivating":
	default:
		return invalid()
	}
	mainPID, err := strconv.ParseUint(fields["MainPID"], 10, 32)
	if err != nil || strconv.FormatUint(mainPID, 10) != fields["MainPID"] {
		return invalid()
	}
	controlPID, err := strconv.ParseUint(fields["ControlPID"], 10, 32)
	if err != nil || strconv.FormatUint(controlPID, 10) != fields["ControlPID"] {
		return invalid()
	}
	return smartTUNTrialUnitObservation{identity: identity, activeState: fields["ActiveState"],
		subState: fields["SubState"], result: fields["Result"], mainPID: mainPID, controlPID: controlPID,
		job: fields["Job"], controlGroup: fields["ControlGroup"]}, nil
}

func (s smartTUNTrialUnitObservation) noLiveWork() bool {
	return s.mainPID == 0 && s.controlPID == 0 && (s.job == "" || s.job == "0") && s.controlGroup == ""
}

func (s smartTUNTrialUnitObservation) stopped() bool {
	return s.activeState == "inactive" && s.subState == "dead" && s.result == "success" && s.noLiveWork()
}

func smartTUNTrialUnitState() (string, error) {
	state, err := observeSmartTUNTrialUnit(context.Background())
	return state.activeState, err
}

// Stop, all identity observations and optional failed-state normalization share
// one budget under the existing 30s recovery service. Never add independent
// 18s control timeouts for each step or accept an acknowledged reset as proof.
func stopSmartTUNTrialCore(original smartTUNTrialUnitObservation, startAttempted, credentialValid bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return stopSmartTUNTrialCoreWith(original, startAttempted, credentialValid,
		func() (smartTUNTrialUnitObservation, error) { return observeSmartTUNTrialUnit(ctx) },
		func(action string) error {
			cmd, err := trustedSystemctlCommand(ctx, action, smartTUNTrialUnit)
			if err != nil {
				return err
			}
			if err := cmd.Run(); err != nil || ctx.Err() != nil {
				return Fault("trial_recovery_uncertain", "owned TUN core stop or normalization outcome unavailable")
			}
			return nil
		})
}

// This argument-local seam is also the production path; it permits failure
// boundary tests without systemd, native effects or alternate recovery logic.
func stopSmartTUNTrialCoreWith(original smartTUNTrialUnitObservation, startAttempted, credentialValid bool,
	observe func() (smartTUNTrialUnitObservation, error), command func(string) error) error {
	readOwned := func() (smartTUNTrialUnitObservation, error) {
		state, err := observe()
		if err != nil {
			return state, err
		}
		if state.identity != original.identity {
			return state, Fault("trial_recovery_uncertain", "owned TUN core identity changed during stop")
		}
		return state, nil
	}
	before, err := readOwned()
	if err != nil {
		return err
	}
	if !startAttempted {
		// Without durable start intent, activity belongs to no authorized
		// operation. Stopping it would erase the conflict and let a later
		// recovery tick mistake inactive state for clean pre-start evidence.
		// Both snapshots must instead prove an already empty, inactive core.
		if !original.stopped() || !before.stopped() {
			return Fault("trial_resource_conflict", "TUN core activity has no durable start authority")
		}
		return nil
	}
	if (before.job != "" && before.job != "0") || (original.activeState == "inactive" && before.activeState != "inactive") {
		return Fault("trial_recovery_uncertain", "owned TUN core has an unexpected pending operation")
	}
	if err := command("stop"); err != nil {
		return err
	}
	stopped, err := readOwned()
	if err != nil {
		return err
	}
	if stopped.stopped() {
		return nil
	}
	if stopped.activeState != "failed" || stopped.subState != "failed" ||
		stopped.result == "" || stopped.result == "success" || !stopped.noLiveWork() {
		return Fault("trial_recovery_uncertain", "owned TUN core is not quiescent after stop")
	}
	if !credentialValid {
		// Durable start intent permits containment, but only the exact operation
		// credential permits clearing failed bookkeeping. Keep that conflict
		// visible across repeated recovery ticks.
		return Fault("trial_resource_conflict", "failed TUN core lacks trusted credential evidence")
	}
	// systemd v257 unit_stop returns EALREADY for FAILED, which JOB_STOP
	// acknowledges as done. reset-failed does not stop processes: only apply
	// it to this same proven-empty core, then demand fresh inactive proof.
	if err := command("reset-failed"); err != nil {
		return err
	}
	normalized, err := readOwned()
	if err != nil {
		return err
	}
	if !normalized.stopped() {
		return Fault("trial_recovery_uncertain", "owned TUN core did not become inactive after normalization")
	}
	return nil
}

func smartTUNTrialSystemctl(args ...string) error {
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

// Called only while holding the shared Manager lifecycle lock. A v4 trial
// must block Proxy Only Connect/Disconnect/profile replacement and prevent
// generic status from falsely presenting Direct while the TUN is pending.
func (m *Manager) pendingSmartTUNTrial() (string, error) {
	data, err := readRegular(filepath.Join(m.Dir, activationJournalFilename))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", Fault("activation_journal_invalid", "private activation journal cannot be inspected")
	}
	if err := rejectAmbiguousJournalJSON(data); err != nil {
		return "", err
	}
	var marker struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &marker); err != nil {
		return "", activationJournalError("activation journal version is invalid")
	}
	if marker.Version != smartTUNTrialVersion {
		return "", nil // legacy journal protection remains with its original API
	}
	record, err := decodeSmartTUNTrial(data)
	if err != nil {
		return "", err
	}
	return smartTUNSupervisedStatusLabel(record), nil
}

type smartTUNTrialAdmission struct {
	profile  Profile
	endpoint string
	policy   []byte
	baseline string
	native   smartTUNNativeLedger
}

// The first pass is entirely side-effect-free on Linux networking/systemd.
// Repeat the same admission under the lifecycle lock AFTER independently
// prearming the timer. Never start/enable a guard for an invalid request.
func (m *Manager) admitSmartTUNTrialLocked(store *activationJournalDir, opts SmartTUNCandidateOptions, managementPeer string) (smartTUNTrialAdmission, error) {
	if _, _, err := store.readJournal(); err == nil {
		return smartTUNTrialAdmission{}, Fault("activation_journal_conflict", "existing operation must be reconciled before TUN trial")
	} else if !errors.Is(err, os.ErrNotExist) {
		return smartTUNTrialAdmission{}, err
	}
	state, err := m.load()
	if err != nil {
		return smartTUNTrialAdmission{}, err
	}
	if state.Selected == "" || state.Desired != "direct" {
		return smartTUNTrialAdmission{}, Fault("trial_unsupported", "TUN trial requires one selected profile and Direct mode")
	}
	proxyActivity, err := m.unitActive()
	if err != nil || proxyActivity != "inactive" {
		return smartTUNTrialAdmission{}, Fault("service_conflict", "Proxy Only must be inactive before TUN trial")
	}
	profile, err := m.profile(state.Selected)
	if err != nil {
		return smartTUNTrialAdmission{}, err
	}
	var upstream struct {
		Server string `json:"server"`
	}
	if json.Unmarshal(profile.Outbound, &upstream) != nil {
		return smartTUNTrialAdmission{}, Fault("invalid_profile", "selected endpoint cannot be decoded")
	}
	endpoint, err := netip.ParseAddr(upstream.Server)
	if err != nil || !endpoint.Is4() || !endpoint.IsGlobalUnicast() ||
		endpoint.IsLoopback() || endpoint.IsLinkLocalUnicast() {
		return smartTUNTrialAdmission{}, Fault("trial_unsupported", "selected profile requires a literal public IPv4 endpoint")
	}
	if (endpoint.String() == "10.254.72.2" && managementPeer == "10.254.72.2") ||
		(endpoint.String() == smartTUNVMEndpoint && managementPeer == smartTUNVMEndpoint && smartTUNVMPolicySupported(opts)) {
		// Continue with the independently observed underlay and guarded native admission.
	} else {
		return smartTUNTrialAdmission{}, Fault("trial_unsupported", "unrecognized disconnected peer identity")
	}
	if err := smartTUNTrialGuest(opts.UnderlayInterface, opts.TunnelInterface, endpoint.String()); err != nil {
		return smartTUNTrialAdmission{}, err
	}
	if _, err := parsePreflightAddress(managementPeer, "management peer"); err != nil {
		return smartTUNTrialAdmission{}, err
	}
	policy, err := smartTUNNativeConfig(profile, opts)
	if err != nil {
		return smartTUNTrialAdmission{}, err
	}
	if err := CheckConfig(m.Core, m.Dir, policy); err != nil {
		return smartTUNTrialAdmission{}, err
	}
	if unitState, err := smartTUNTrialUnitState(); err != nil || unitState != "inactive" {
		return smartTUNTrialAdmission{}, Fault("guard_unavailable", "owned TUN unit is not inactive or trustworthy")
	}
	if _, _, err := store.readSmartTUNFile(smartTUNTrialConfigFile); err == nil {
		return smartTUNTrialAdmission{}, Fault("activation_journal_conflict", "unreconciled TUN trial config exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return smartTUNTrialAdmission{}, Fault("activation_journal_unavailable", "cannot inspect private TUN config absence")
	}
	host, err := InspectHostRoutesAndFirewall(endpoint.String(), managementPeer)
	if err != nil {
		return smartTUNTrialAdmission{}, err
	}
	// The full baseline detects drift during admission. Native rollback uses
	// the independent per-object ledger; disjoint foreign changes are allowed
	// after activation and never grant the core host cleanup authority.
	if host.Firewall == nil || !host.Firewall.Observed {
		return smartTUNTrialAdmission{}, Fault("trial_observation_uncertain", "complete native nftables observation required before guarded guest trial")
	}
	baseline, err := smartTUNTrialSnapshot(host)
	if err != nil {
		return smartTUNTrialAdmission{}, err
	}
	native, err := nativeTUNAdmission(opts, host)
	if err != nil {
		return smartTUNTrialAdmission{}, err
	}
	return smartTUNTrialAdmission{profile: profile, endpoint: endpoint.String(),
		policy: policy, baseline: baseline, native: native}, nil
}

// Only two exact, pre-tested disconnected fixtures are admitted. The
// candidate compiler supports broader policy construction, but a real
// privileged product trial must not inherit that authority. In particular,
// dual-stack is opt-in and cannot grant arbitrary public IPv6 Direct routes.
func smartTUNTrialFixturePolicySupported(opts SmartTUNCandidateOptions) bool {
	if len(opts.DomesticCIDRs) != 1 || opts.DomesticCIDRs[0] != "5.22.0.10/32" ||
		len(opts.ProtectedCIDRs) != 1 || opts.ProtectedCIDRs[0] != "10.254.72.0/30" ||
		opts.TunnelIPv4 != "172.31.99.1/30" ||
		len(opts.Exceptions) != 0 || len(opts.DomainExceptions) != 0 ||
		opts.TunnelInterface != "sctunqa0" || opts.UnderlayInterface != "scqaedge0" ||
		len(opts.ProtectedIPv6CIDRs) != 0 {
		return false
	}
	if opts.TunnelIPv6 == "" {
		return len(opts.DomesticIPv6CIDRs) == 0 && len(opts.IPv6Exceptions) == 0
	}
	return opts.TunnelIPv6 == "fd73:99::1/64" &&
		len(opts.DomesticIPv6CIDRs) == 1 && opts.DomesticIPv6CIDRs[0] == "2606:4700:5::/64" &&
		len(opts.IPv6Exceptions) == 2 &&
		opts.IPv6Exceptions[0] == (SmartTUNCIDRException{CIDR: "2606:4700:5::10/128", Via: "vpn"}) &&
		opts.IPv6Exceptions[1] == (SmartTUNCIDRException{CIDR: "2606:4700:8::9/128", Via: "direct"})
}

func (m *Manager) BeginSmartTUNTrial(opts SmartTUNCandidateOptions, managementPeer string, deadlineSeconds int, qaKillPoint string) (SmartTUNTrialReceipt, error) {
	return m.beginSmartTUNTrial(opts, managementPeer, deadlineSeconds, qaKillPoint, nil, nil)
}

// An unsuccessful read-only admission must never authorize privileged
// bookkeeping (including systemctl reset-failed). Keep this ordering explicit
// and independently testable; the caller holds the operation journal lock.
func smartTUNAdmitBeforeHealthBookkeeping(admit func() (smartTUNTrialAdmission, error), normalize func() error) (smartTUNTrialAdmission, error) {
	planned, err := admit()
	if err != nil {
		return smartTUNTrialAdmission{}, err
	}
	if normalize != nil {
		if err := normalize(); err != nil {
			return smartTUNTrialAdmission{}, err
		}
	}
	return planned, nil
}

func (m *Manager) beginSmartTUNTrial(opts SmartTUNCandidateOptions, managementPeer string, deadlineSeconds int, qaKillPoint string, saved *smartTUNSavedPolicyBinding, health *SmartTUNHealthOptions) (SmartTUNTrialReceipt, error) {
	if qaKillPoint != "" && qaKillPoint != "after-journal" && qaKillPoint != "after-start" && !nativeTUNQAKillValid(qaKillPoint, true) && !(health != nil && qaKillPoint == "after-supervised-ready") {
		return SmartTUNTrialReceipt{}, Fault("invalid_arguments", "unsupported disposable TUN SIGKILL boundary")
	}
	if m.Dir != DefaultDir || m.Core != DefaultCore ||
		deadlineSeconds < 4 || deadlineSeconds > 600 {
		return SmartTUNTrialReceipt{}, Fault("trial_unsupported", "installed paths and deadline 4-600s required")
	}
	if err := nativeTrialApplyPlatform(); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if !smartTUNTrialFixturePolicySupported(opts) && !smartTUNVMPolicySupported(opts) {
		return SmartTUNTrialReceipt{}, Fault("trial_unsupported", "unsupported disposable native TUN policy")
	}
	if err := EnsureCore(m.Core); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if err := smartTUNNativeCandidateContext(opts, managementPeer); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	var planned smartTUNTrialAdmission
	var vmRulesDigest string
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		var err error
		if err := checkSavedSmartTUNPolicyLocked(store, saved); err != nil {
			return err
		}
		if opts.TunnelInterface == smartTUNVMInterface {
			if saved == nil && len(opts.Exceptions) != 0 {
				return Fault("routing_rules_invalid", "VM Smart Routing exceptions must come from the saved operator rule registry")
			}
			var next SmartTUNCandidateOptions
			next, vmRulesDigest, err = smartTUNVMReadSavedRulesLocked(store, opts)
			if err != nil {
				return err
			}
			opts = next
		}
		// Complete the side-effect-free topology, route and resource admission
		// BEFORE any optional systemctl reset-failed. The same journal lock
		// protects the admitted session and owned Health Unit normalization.
		var normalize func() error
		if health != nil && opts.TunnelInterface == smartTUNVMInterface {
			normalize = func() error { return normalizeQuiescentSmartTUNHealthUnit(store) }
		}
		planned, err = smartTUNAdmitBeforeHealthBookkeeping(
			func() (smartTUNTrialAdmission, error) {
				return m.admitSmartTUNTrialLocked(store, opts, managementPeer)
			}, normalize)
		return err
	}); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	var roles [2]smartTUNHealthUnitIdentity
	if health != nil {
		if err := validateSmartTUNHealthOptions(*health); err != nil {
			return SmartTUNTrialReceipt{}, err
		}
		var err error
		roles, err = smartTUNHealthUnits(false, nil)
		if err != nil {
			return SmartTUNTrialReceipt{}, err
		}
	}
	if err := trialGuardUnits(false); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	// Do not start the independent oneshot while holding its SAME journal
	// lock: the systemd executor acquires that lock and would deadlock.
	// Prearming is a separate no-network transaction. If the caller dies
	// here, an enabled but journal-less timer owns no host networking.
	if err := smartTUNTrialSystemctl("start", trialRecoveryUnit); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if err := smartTUNTrialSystemctl("enable", "--now", trialRecoveryTimer); err != nil {
		m.disarmUncommittedSmartTUNGuard()
		return SmartTUNTrialReceipt{}, err
	}
	if err := trialGuardScheduled(); err != nil {
		// Prearm failure may leave a service timer installed/enabled but no
		// journal. Reconcile only its exact known state; never disarm another
		// operation or claim a recovery after a conflicted observation.
		m.disarmUncommittedSmartTUNGuard()
		return SmartTUNTrialReceipt{}, err
	}
	if health != nil {
		if err := smartTUNTrialSystemctl("start", smartTUNHealthUnit); err != nil {
			m.disarmUncommittedSmartTUNHealth(roles)
			m.disarmUncommittedSmartTUNGuard()
			return SmartTUNTrialReceipt{}, err
		}
		if err := smartTUNTrialSystemctl("enable", "--now", smartTUNHealthTimer); err != nil {
			m.disarmUncommittedSmartTUNHealth(roles)
			m.disarmUncommittedSmartTUNGuard()
			return SmartTUNTrialReceipt{}, err
		}
		var err error
		_, err = smartTUNHealthUnits(true, &roles)
		if err != nil {
			m.disarmUncommittedSmartTUNHealth(roles)
			m.disarmUncommittedSmartTUNGuard()
			return SmartTUNTrialReceipt{}, err
		}
	}
	var receipt SmartTUNTrialReceipt
	journalPersisted := false
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := checkSavedSmartTUNPolicyLocked(store, saved); err != nil {
			return err
		}
		if vmRulesDigest != "" {
			_, digest, err := smartTUNVMReadSavedRulesLocked(store, opts)
			if err != nil {
				return err
			}
			if digest != vmRulesDigest {
				return Fault("routing_rules_conflict", "operator rules changed while prearming native Smart Routing")
			}
		}
		admission, err := m.admitSmartTUNTrialLocked(store, opts, managementPeer)
		if err != nil {
			return err
		}
		if admission.profile.ID != planned.profile.ID ||
			admission.endpoint != planned.endpoint ||
			!bytes.Equal(admission.policy, planned.policy) ||
			admission.baseline != planned.baseline || admission.native != planned.native {
			return Fault("trial_observation_uncertain", "selected profile or kernel baseline changed while arming guard")
		}
		profile, endpoint, policy, baseline := admission.profile, admission.endpoint, admission.policy, admission.baseline
		boot, err := trialBootIdentity()
		if err != nil {
			return err
		}
		uptime, err := trialUptime()
		if err != nil {
			return err
		}
		op, err := randomHex(16)
		if err != nil {
			return err
		}
		record := smartTUNTrialJournal{
			Version: smartTUNTrialVersion, Revision: 1, IntentType: smartTUNNativeIntent,
			OperationID: op, Phase: "trial_pending", CreatedUnix: time.Now().Unix(),
			BootID: boot, DeadlineUptimeSec: uptime + int64(deadlineSeconds),
			ProfileID: profile.ID, EndpointIP: endpoint, ManagementPeerIP: managementPeer,
			TunnelInterface: opts.TunnelInterface, UnderlayInterface: opts.UnderlayInterface,
			ConfigSHA256: sha256Hex(policy), BaselineSHA256: baseline,
			Native: &admission.native,
		}
		record.Native.NFTName = "scnt_" + op
		if health != nil {
			nowMS, err := smartTUNUptimeMillis()
			if err != nil {
				return err
			}
			record.IntentType = smartTUNSupervisedIntent
			record.Supervised = &smartTUNSupervision{Version: smartTUNSupervisionVersion, Generation: 1, State: "initializing", Options: *health, Roles: roles, HeartbeatMS: nowMS, LeaseDeadlineMS: nowMS + smartTUNHealthLeaseMS, ReconnectStage: "none"}
		}
		if err := validateSmartTUNTrial(record); err != nil {
			return err
		}
		if err := trialGuardScheduled(); err != nil {
			return err
		}
		// Reobserve after guard arming and core validation. Disconnected
		// guest access + exact baseline are deliberately stricter than host
		// read-only preflight, but NOT production physical ownership proof.
		now, err := inspectSmartTUNBaseline(endpoint, managementPeer)
		if err != nil || now != baseline {
			return Fault("trial_observation_uncertain", "network changed before guarded TUN mutation")
		}
		// Save only validated non-secret routing settings. Saving configuration
		// never authorizes an activation; every reapply repeats full admission.
		if err := saveSmartTUNPolicyLocked(store, opts, managementPeer); err != nil {
			return err
		}
		// The self-contained native intent is durable before link creation,
		// persistence, credential staging or core start. Every partial effect
		// is reconciled using its own receipt, never the broad host baseline.
		if err := writeSmartTUNTrialLocked(store, record, nil); err != nil {
			return err
		}
		journalPersisted = true
		if qaKillPoint == "after-journal" {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			return Fault("trial_pending_recovery", "disposable precredential SIGKILL unexpectedly returned")
		}
		if err := nativeTUNPrepareLink(store, &record, qaKillPoint); err != nil {
			return err
		}
		if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, policy, nil); err != nil {
			return Fault("trial_pending_recovery", "guarded journal durable but TUN credential staging failed; independent recovery required")
		}
		// Record the *durable* intention to start before invoking systemd.
		// A later missing credential can therefore never be confused with
		// a legitimate precredential crash, even on the NEXT guard tick
		// after the service has been stopped. No sensitive policy is stored
		// in this journal: only immutable operation and hash evidence.
		watch, err := nativeTUNWatchStart(record)
		if err != nil {
			return err
		}
		defer watch.close()
		identity, err := reloadSmartTUNTrialLocked(store, record)
		if err != nil {
			return err
		}
		record.CoreStartAttempted = true
		if err := writeSmartTUNTrialLocked(store, record, &identity); err != nil {
			return Fault("trial_pending_recovery", "cannot durably record TUN start intent; independent recovery required")
		}
		if err := smartTUNTrialSystemctl("start", smartTUNTrialUnit); err != nil {
			return Fault("trial_pending_recovery", "TUN service failed after durable pending journal; independent guard must reconcile")
		}
		if err := watch.verify(record); err != nil {
			return err
		}
		next := cloneSmartTUNTrial(record)
		next.Native.StartupVerified = true
		if err := nativeTUNAdvance(store, &record, next); err != nil {
			return err
		}
		watch.close()
		if err := nativeTUNApplyPolicy(store, &record, qaKillPoint); err != nil {
			return err
		}
		if err := nativeTUNVerifyPending(record); err != nil {
			return err
		}
		if err := trialQAKillAt("after-native-capture", qaKillPoint); err != nil {
			return err
		}
		if qaKillPoint == "after-start" {
			// The independent systemd timer must reconcile a real process
			// SIGKILL after the journal and TUN service are both live.
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			return Fault("trial_pending_recovery", "disposable SIGKILL injection unexpectedly returned")
		}
		challenge := ""
		if record.Supervised != nil {
			nowMS, err := smartTUNUptimeMillis()
			if err != nil {
				return err
			}
			unit, err := observeSmartTUNTrialUnit(context.Background())
			if err != nil || unit.activeState != "active" || unit.mainPID == 0 {
				return Fault("trial_pending_recovery", "native core identity unavailable after capture")
			}
			process, err := readManagementProcess(int(unit.mainPID))
			if err != nil {
				return err
			}
			challenge, err = randomHex(32)
			if err != nil {
				return err
			}
			next := cloneSmartTUNTrial(record)
			next.Supervised.CorePID, next.Supervised.CoreStartTicks = unit.mainPID, process.StartTicks
			next.Supervised.State, next.Supervised.ReadyAfterMS = "awaiting_confirmation", nowMS
			next.Supervised.HeartbeatMS, next.Supervised.LeaseDeadlineMS = nowMS, nowMS+smartTUNHealthLeaseMS
			next.Supervised.ChallengeSHA256 = smartTUNChallengeDigest(next, challenge)
			next.Supervised.Generation++
			if err := nativeTUNAdvance(store, &record, next); err != nil {
				return err
			}
			if err := trialQAKillAt("after-supervised-ready", qaKillPoint); err != nil {
				return err
			}
		}
		receipt = smartTUNReceipt(record, true, false)
		receipt.ConfirmationChallenge = challenge
		return nil
	})
	if err != nil && !journalPersisted {
		if health != nil {
			m.disarmUncommittedSmartTUNHealth(roles)
		}
		m.disarmUncommittedSmartTUNGuard()
	}
	return receipt, err
}

// Safe only on the fully admitted disconnected disposable guest. A journal
// appearance, unowned service, or uncertain filesystem state forbids cleanup.
func (m *Manager) disarmUncommittedSmartTUNGuard() {
	_ = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if _, _, e := store.readJournal(); !errors.Is(e, os.ErrNotExist) {
			return nil
		}
		if active, e := smartTUNTrialUnitState(); e != nil || active != "inactive" {
			return nil
		}
		return smartTUNTrialSystemctl("disable", "--now", trialRecoveryTimer)
	})
}

// The independent executor dispatches a fully decoded v4 record while still
// holding the SAME lock used for current/legacy selection. This helper must
// never acquire a second lock or let an absent observation fall through after
// an intervening Apply has published a different journal version.
func recoverSmartTUNTrialJournalLocked(store *activationJournalDir, identity activationJournalFileIdentity, record smartTUNTrialJournal) (TrialReceipt, error) {
	result, err := recoverSmartTUNTrialLocked(store, identity, &record, "")
	if err != nil {
		return TrialReceipt{}, err
	}
	// A durable operator stop/cleanup request authorizes completion of
	// that exact operation by this already-independent executor. Ordinary
	// deadline recovery retains its historical recovered receipt.
	if result.Phase == "trial_cleanup_pending" ||
		(result.Phase == "trial_recovered" && (result.Revision == 3 || record.Supervised != nil)) {
		record.Phase, record.Revision = result.Phase, result.Revision
		identity, err = reloadSmartTUNTrialLocked(store, record)
		if err != nil {
			return TrialReceipt{}, err
		}
		result, err = finalizeSmartTUNTrialLocked(store, identity, record, "")
		if err != nil {
			return TrialReceipt{}, err
		}
	}
	return smartTUNRecoveryReceipt(result), nil
}

// The independent executor logs this value before returning to systemd. Keep
// the supervised decision here even when successful Off removed its journal.
func smartTUNRecoveryReceipt(result SmartTUNTrialReceipt) TrialReceipt {
	return TrialReceipt{
		OperationID: result.OperationID, Revision: result.Revision,
		Phase: result.Phase, ExperimentOnly: true,
		GuardScheduled:   result.GuardScheduled,
		RecoveryVerified: result.RecoveryVerified,
		SupervisionState: result.SupervisionState, ManagementConfirmed: result.ManagementConfirmed,
		HealthReason: result.HealthReason, HealthRound: result.HealthRound, HealthLastUptimeMS: result.HealthLastUptimeMS,
		HealthFailures: result.HealthFailures, ReconnectAttempts: result.ReconnectAttempts,
		RecoveryDeadlineUptimeMS: result.RecoveryDeadlineUptimeMS, HealthEvidence: result.HealthEvidence,
		HealthEvidenceVersion: result.HealthEvidenceVersion,
	}
}

// An absent credential is legitimate ONLY for journal-first failure before
// a core start could be attempted. An exact restored kernel baseline does not
// license silently discarding a tampered or vanished start credential.
func smartTUNTrialCredentialRecoveryCheck(record smartTUNTrialJournal, originalUnitState string, present, matches bool) error {
	if present && !matches {
		return Fault("trial_resource_conflict", "pending TUN credential was replaced")
	}
	if !present && record.CoreStartAttempted {
		return Fault("trial_resource_conflict", "credential missing after durable TUN start intent")
	}
	if !record.CoreStartAttempted && originalUnitState != "inactive" {
		return Fault("trial_resource_conflict", "TUN unit has unexpected activity before any durable start intent")
	}
	return nil
}

// A kernel-visible active service is not authority to keep a pending TUN.
// The owner must first have durably recorded core-start intent on this boot,
// while the same operation still has time and its credential still matches.
// The independent supervisor must ALSO pass a fresh runtime check before
// this predicate can authorize leaving an active TUN pending.
func smartTUNTrialMayRemainPending(record smartTUNTrialJournal, unitState string, credentialValid, sameBoot bool, uptime int64) bool {
	return record.Phase == "trial_pending" && record.CoreStartAttempted &&
		credentialValid && sameBoot && uptime < record.DeadlineUptimeSec &&
		(unitState == "active" || unitState == "activating")
}

func recoverSmartTUNTrialLocked(store *activationJournalDir, identity activationJournalFileIdentity, record *smartTUNTrialJournal, qaPoint string) (SmartTUNTrialReceipt, error) {
	if record.Native != nil {
		return recoverSmartTUNNativeLocked(store, record, qaPoint)
	}
	receipt, err := recoverLegacySmartTUNTrialLocked(store, identity, *record)
	if err == nil {
		record.Phase, record.Revision = receipt.Phase, receipt.Revision
	}
	return receipt, err
}

// Preserve the historical v4 intent's core-owned teardown and baseline contract.
func recoverLegacySmartTUNTrialLocked(store *activationJournalDir, identity activationJournalFileIdentity, record smartTUNTrialJournal) (SmartTUNTrialReceipt, error) {
	// Never silently recover a physical host or unowned systemd unit even if
	// a journal is copied to it. Persist an unresolved receipt for console.
	if err := trialDisposableContext(); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	unit, err := observeSmartTUNTrialUnit(context.Background())
	if err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	status := unit.activeState
	credentialPresent, credentialValid := false, false
	var credentialReadErr error
	if record.Phase == "trial_pending" || record.Phase == "trial_stop_requested" {
		cfg, _, checkErr := store.readSmartTUNFile(smartTUNTrialConfigFile)
		switch {
		case checkErr == nil:
			credentialPresent, credentialValid = true, sha256Hex(cfg) == record.ConfigSHA256
		case errors.Is(checkErr, os.ErrNotExist):
			// Journal-first interrupted operation; no core could have
			// started through the trusted LoadCredential unit without it.
		default:
			// Untrusted bytes must never authorize continued routing. Still
			// contain the exact proven-owned core before returning a conflict;
			// retain both journal and credential evidence for reconciliation.
			credentialReadErr = Fault("trial_resource_conflict", "pending TUN credential cannot be inspected")
		}
	}
	if record.Phase == "trial_recovered" || record.Phase == "trial_cleanup_pending" {
		if !unit.stopped() {
			return SmartTUNTrialReceipt{}, Fault("trial_recovery_uncertain", "recovered journal lacks inactive and empty TUN unit proof")
		}
		current, err := inspectSmartTUNBaseline(record.EndpointIP, record.ManagementPeerIP)
		if err != nil || current != record.BaselineSHA256 {
			return SmartTUNTrialReceipt{}, Fault("trial_recovery_uncertain", "recovered TUN native baseline no longer matches")
		}
		return smartTUNReceipt(record, false, true), nil
	}
	if record.Phase == "trial_pending" {
		boot, err := trialBootIdentity()
		if err != nil {
			return SmartTUNTrialReceipt{}, err
		}
		uptime, err := trialUptime()
		if err != nil {
			return SmartTUNTrialReceipt{}, err
		}
		if smartTUNTrialMayRemainPending(record, status, credentialValid, boot == record.BootID, uptime) {
			if trialGuardScheduled() == nil {
				return smartTUNReceipt(record, true, false), nil
			}
			// A valid deadline cannot preserve active TUN after guard loss.
		}
	}
	// A durable explicit stop does not depend on the old boot clock or
	// deadline. Core mutation still requires its recorded start authority.
	// Expired, rebooted, stopped, failed, or unguarded: stop ONLY the
	// trusted, pinned systemd service and demand EXACT baseline restoration.
	originalUnitState := status
	if err := stopSmartTUNTrialCore(unit, record.CoreStartAttempted, credentialValid); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	current, err := inspectSmartTUNBaseline(record.EndpointIP, record.ManagementPeerIP)
	if err != nil || current != record.BaselineSHA256 {
		return SmartTUNTrialReceipt{}, Fault("trial_recovery_uncertain", "host routing or firewall baseline differs after TUN stop")
	}
	if credentialReadErr != nil {
		return SmartTUNTrialReceipt{}, credentialReadErr
	}
	// Stopping/normalizing a service can change ActiveState to inactive. Do not use its
	// *post-stop* state to decide whether a missing credential was ever
	// trusted. The journal's prior durable start intent is authoritative
	// across repeated watchdog ticks and missing/modified credential bytes.
	if err := smartTUNTrialCredentialRecoveryCheck(record, originalUnitState, credentialPresent, credentialValid); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	requestedStop := record.Phase == "trial_stop_requested"
	record.Phase, record.Revision = "trial_recovered", 2
	if requestedStop {
		record.Revision = 3
	}
	if err := writeSmartTUNTrialLocked(store, record, &identity); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	return smartTUNReceipt(record, false, true), nil
}

func (m *Manager) InspectSmartTUNTrial() (SmartTUNTrialReceipt, error) {
	if m.Dir != DefaultDir {
		return SmartTUNTrialReceipt{}, Fault("trial_unsupported", "installed trial state required")
	}
	var receipt SmartTUNTrialReceipt
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record, _, err := loadSmartTUNTrialLocked(store)
		if errors.Is(err, os.ErrNotExist) {
			receipt = SmartTUNTrialReceipt{Phase: "absent", ExperimentOnly: true}
			return nil
		}
		if err != nil {
			return err
		}
		if record.Phase == "trial_recovered" || record.Phase == "trial_cleanup_pending" {
			// These phases only reobserve the inactive unit/native baseline.
			// Status MUST NOT finish stop/cleanup or manufacture watchdog proof.
			result, err := recoverSmartTUNTrialLocked(store, activationJournalFileIdentity{}, &record, "")
			if err != nil {
				return err
			}
			receipt = result
			return nil
		}
		receipt = smartTUNReceipt(record, false, false)
		if record.Supervised != nil && record.Phase == "trial_pending" {
			// Pure observation: no probes, lease renewal or cleanup. Historical
			// healthy evidence cannot hide a dead supervisor, changed core,
			// expired lease or substituted native resource at inspection time.
			if reason := inspectSupervisedRuntime(store, record, true); reason != "" {
				receipt.SupervisionState, receipt.HealthReason = "uncertain", reason
				return Fault("trial_observation_uncertain", reason)
			}
			receipt.GuardScheduled = true
			return nil
		}
		if err := trialGuardScheduled(); err != nil {
			if record.Supervised != nil {
				receipt.SupervisionState, receipt.HealthReason = "uncertain", "recovery_executor_unavailable"
			}
			return err
		}
		if record.Supervised != nil {
			if _, err := smartTUNHealthUnits(true, &record.Supervised.Roles); err != nil {
				receipt.SupervisionState, receipt.HealthReason = "uncertain", "supervisor_unavailable"
				return err
			}
		}
		receipt.GuardScheduled = true
		return nil
	})
	return receipt, err
}
