package sc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Experimental, rule-only transaction: the routing table stays EMPTY. This
// exercises the product journal, native RPDB, independent systemd deadline,
// interruption and reboot reconciliation without starting a VPN or diverting
// traffic. No non-disposable host may invoke this development operation.
const (
	trialIntentType      = "guarded_rule_trial_v2"
	trialRouteIntentType = "guarded_loopback_route_trial_v3"
	trialProtocol        = "247"
	trialRecoveryUnit    = "server-connect-activation-recover.service"
	trialRecoveryTimer   = "server-connect-activation-recover.timer"
	trialGuardUnitDir    = "/etc/systemd/system/"
	trialRuntimeUnitDir  = "/run/systemd/system/"
)

var trialBootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var trialJournalFields = map[string]bool{
	"version": true, "revision": true, "operation_id": true, "phase": true,
	"created_unix": true, "observation_sha256": true, "plan_sha256": true,
	"intent_type": true, "selective": true, "changes": true,
	"boot_id": true, "deadline_uptime_sec": true,
}

// Each journal version requires EXACTLY its own member set. The v2 parser
// must continue accepting existing route-less receipts without a new field;
// v3 must explicitly persist its real disposable route device.
var trialRouteJournalFields = func() map[string]bool {
	fields := make(map[string]bool, len(trialJournalFields)+1)
	for key, required := range trialJournalFields {
		fields[key] = required
	}
	fields["trial_route_device"] = true
	return fields
}()

type trialJournal struct {
	activationJournal
	BootID            string `json:"boot_id"`
	DeadlineUptimeSec int64  `json:"deadline_uptime_sec"`
	RouteDevice       string `json:"trial_route_device,omitempty"`
}

type TrialReceipt struct {
	OperationID              string                  `json:"operation_id"`
	Revision                 uint64                  `json:"revision"`
	Phase                    string                  `json:"phase"`
	ExperimentOnly           bool                    `json:"experiment_only"`
	GuardScheduled           bool                    `json:"guard_scheduled"`
	ActivationReady          bool                    `json:"activation_ready"`
	VPNVerified              bool                    `json:"vpn_verified"`
	RecoveryVerified         bool                    `json:"recovery_verified"`
	TrialRuleRecovered       bool                    `json:"trial_rule_recovered"`
	TrialRouteRecovered      bool                    `json:"trial_route_recovered,omitempty"`
	SupervisionState         string                  `json:"supervision_state,omitempty"`
	ManagementConfirmed      bool                    `json:"management_confirmed,omitempty"`
	HealthReason             string                  `json:"health_reason,omitempty"`
	HealthRound              uint64                  `json:"health_round,omitempty"`
	HealthLastUptimeMS       int64                   `json:"health_last_uptime_ms,omitempty"`
	HealthFailures           int                     `json:"health_failures,omitempty"`
	ReconnectAttempts        int                     `json:"reconnect_attempts,omitempty"`
	RecoveryDeadlineUptimeMS int64                   `json:"recovery_deadline_uptime_ms,omitempty"`
	HealthEvidenceVersion    int                     `json:"health_evidence_version,omitempty"`
	HealthEvidence           *SmartTUNHealthEvidence `json:"health_evidence,omitempty"`
}

func trialReceipt(record trialJournal, scheduled, recovered bool) TrialReceipt {
	return TrialReceipt{OperationID: record.OperationID, Revision: record.Revision, Phase: record.Phase,
		ExperimentOnly: true, GuardScheduled: scheduled, TrialRuleRecovered: recovered,
		TrialRouteRecovered: recovered && record.Version == 3}
}

// The v1 record is retained in full, including before=absence and exact plan
// bindings. v2 remains rule-only, always pointing at an empty table. v3 is a
// separately identified, disposable-only loopback route+rule transaction;
// it never creates a tunnel, interface, outbound VPN or production policy.
func validateTrialJournal(record trialJournal) error {
	modeValid := (record.Version == 2 && record.IntentType == trialIntentType && record.RouteDevice == "") ||
		(record.Version == 3 && record.IntentType == trialRouteIntentType && record.RouteDevice == "lo")
	if !modeValid || (record.Phase != "trial_pending" && record.Phase != "trial_recovered") ||
		(record.Phase == "trial_pending" && record.Revision != 2) ||
		(record.Phase == "trial_recovered" && record.Revision != 3) ||
		!trialBootIDPattern.MatchString(record.BootID) ||
		record.DeadlineUptimeSec <= 0 || len(record.Changes) != 2 || record.Selective == nil ||
		record.Changes[0].Kind != "route" || record.Changes[1].Kind != "rule" {
		return activationJournalError("unsupported guarded-rule trial record or phase")
	}
	check := record.activationJournal
	check.Version, check.Revision, check.Phase, check.IntentType = 1, 1, "prepared", selectiveIntentType
	if err := validateActivationJournal(check); err != nil {
		return err
	}
	var route PlannedRoute
	var rule PlannedRule
	if err := exactSelectiveEvidence(check.Changes[0].Intended, selectiveRouteEvidenceFields, &route); err != nil {
		return err
	}
	if err := exactSelectiveEvidence(check.Changes[1].Intended, selectiveRuleEvidenceFields, &rule); err != nil {
		return err
	}
	if route.Family != "ipv4" || rule.Family != "ipv4" || route.Destination != rule.Destination ||
		route.Table != rule.Table || route.Table != record.Selective.RouteTable ||
		rule.Priority < selectiveFirstPriority || rule.Priority > selectiveLastPriority {
		return activationJournalError("guarded trial supports exactly one matching IPv4 rule")
	}
	return nil
}

func decodeTrialJournal(raw []byte) (trialJournal, error) {
	var record trialJournal
	if err := rejectAmbiguousJournalJSON(raw); err != nil {
		return record, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return record, activationJournalError("guard trial root invalid")
	}
	var version int
	if err := json.Unmarshal(root["version"], &version); err != nil {
		return record, activationJournalError("guard trial version missing or unsupported")
	}
	fields := trialJournalFields
	if version == 3 {
		fields = trialRouteJournalFields
	}
	if err := requireExactJournalKeys(raw, fields); err != nil {
		return record, err
	}
	if err := requireExactJournalKeys(root["selective"], selectiveJournalBindingFields); err != nil {
		return record, err
	}
	var changes []json.RawMessage
	if err := json.Unmarshal(root["changes"], &changes); err != nil || len(changes) != 2 {
		return record, activationJournalError("guard trial changes malformed")
	}
	for _, change := range changes {
		if err := requireExactJournalKeys(change, activationChangeFields); err != nil {
			return record, err
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return trialJournal{}, activationJournalError("guard trial schema invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return trialJournal{}, activationJournalError("guard trial trailing data")
	}
	if err := validateTrialJournal(record); err != nil {
		return trialJournal{}, err
	}
	return record, nil
}

func loadTrialLocked(store *activationJournalDir) (trialJournal, activationJournalFileIdentity, error) {
	raw, id, err := store.readJournal()
	if err != nil {
		return trialJournal{}, id, err
	}
	record, err := decodeTrialJournal(raw)
	return record, id, err
}

func writeTrialLocked(store *activationJournalDir, record trialJournal, expected *activationJournalFileIdentity) error {
	if err := validateTrialJournal(record); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return activationJournalError("guard trial serialization failure")
	}
	return store.writeJournal(append(data, '\n'), expected)
}

func trialBootIdentity() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	id := strings.TrimSpace(string(raw))
	if err != nil || !trialBootIDPattern.MatchString(id) {
		return "", Fault("guard_unavailable", "kernel boot identity unavailable")
	}
	return id, nil
}

func trialUptime() (int64, error) {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil || info.Uptime < 0 {
		return 0, Fault("guard_unavailable", "kernel monotonic uptime unavailable")
	}
	return info.Uptime, nil
}

func trialDisposableContext() error {
	if os.Geteuid() != 0 {
		return Fault("unsupported_host", "guarded trial requires isolated guest root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return Fault("unsupported_host", "guarded trial is restricted to disposable Docker guests")
	}
	pid1, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(pid1)) != "systemd" {
		return Fault("unsupported_host", "guarded trial requires isolated systemd PID 1")
	}
	if err := trustedHostIPExecutable(); err != nil {
		return err
	}
	return nil
}

func trialNativeRules() ([]map[string]json.RawMessage, error) {
	// -N asks native iproute2 to render numeric protocol AND routing-table
	// identities even when local rt_protos/rt_tables assign arbitrary names.
	// Without it, a product-created rule could become unrecognizable to the
	// independent watchdog after an administrator changes presentation aliases.
	// A host without working numeric observation fails closed before apply.
	raw, err := nativeIPJSON("-N", "-j", "-4", "rule", "show")
	if err != nil {
		return nil, Fault("trial_observation_uncertain", "native IPv4 rules unavailable")
	}
	rows, err := selectiveRows(raw)
	if err != nil {
		return nil, Fault("trial_observation_uncertain", "native IPv4 rules unsupported")
	}
	return rows, nil
}

func trialSingleRule(record trialJournal) (PlannedRule, error) {
	var rule PlannedRule
	if err := exactSelectiveEvidence(record.Changes[1].Intended, selectiveRuleEvidenceFields, &rule); err != nil {
		return rule, err
	}
	return rule, nil
}

// A complete namespace-wide snapshot is required before lab mutation. No
// default route / foreign interface can exist; a synthetic default via lo is
// allowed in the disconnected systemd acceptance guest.
func trialIsolatedNetwork() error {
	raw, err := nativeIPJSON("-j", "link", "show")
	if err != nil {
		return Fault("unsupported_host", "isolated link inventory unavailable")
	}
	links, err := selectiveRows(raw)
	if err != nil || len(links) != 1 || selectiveText(links[0]["ifname"]) != "lo" {
		return Fault("unsupported_host", "guarded trial requires loopback-only disposable namespace")
	}
	routes, err := nativeIPJSON("-j", "-4", "route", "show", "table", "all")
	if err != nil {
		return Fault("unsupported_host", "isolated route inventory unavailable")
	}
	routeRows, err := selectiveRows(routes)
	if err != nil {
		return Fault("unsupported_host", "isolated routes unsupported")
	}
	for _, r := range routeRows {
		if selectiveText(r["dev"]) != "lo" {
			return Fault("unsupported_host", "disposable routing includes non-loopback device")
		}
	}
	return nil
}

// A competing runtime unit or mask can exist while systemctl reports a
// loaded/static installed /etc unit (which has HIGHER precedence than /run).
// Never trust that name collision as a clean, uniquely owned guard. A
// runtime mask alone is NOT evidence that the /etc unit stopped executing.
func trialNoRuntimeUnitOverride(runtimeDir, name string) error {
	_, err := os.Lstat(filepath.Join(runtimeDir, name))
	if err == nil {
		return Fault("guard_unavailable", "runtime recovery unit override or mask present")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Fault("guard_unavailable", "cannot verify runtime recovery unit ownership")
	}
	return nil
}

// Availability is a present-tense observation, not a promise that a future
// service start will succeed. In particular a timer can remain active after
// its oneshot executor failed or exhausted its start-rate limit. Do not
// report a positive scheduled guard from that degraded combination.
func trialGuardUnitReady(name string, fields map[string]string) error {
	if fields["Result"] != "success" {
		if name == trialRecoveryUnit {
			switch fields["Result"] {
			case "start-limit-hit":
				return Fault("guard_unavailable", "independent recovery executor start-rate limited")
			case "exit-code", "signal", "core-dump", "timeout":
				return Fault("guard_unavailable", "independent recovery executor failed")
			default:
				return Fault("guard_unavailable", "independent recovery executor result untrusted")
			}
		}
		return Fault("guard_unavailable", "independent recovery timer failed or unavailable")
	}
	if name == trialRecoveryUnit {
		if fields["UnitFileState"] != "static" {
			return Fault("guard_unavailable", "independent recovery service no longer static and available")
		}
		// A trusted installed oneshot may be inactive or presently activating.
		// A failed, missing or unexpected service state cannot be an armed guard.
		if fields["ActiveState"] != "inactive" && fields["ActiveState"] != "activating" {
			return Fault("guard_unavailable", "independent recovery executor not runnable")
		}
		return nil
	}
	if name == trialRecoveryTimer && (fields["ActiveState"] != "active" || fields["UnitFileState"] != "enabled" || fields["Unit"] != trialRecoveryUnit) {
		return Fault("guard_unavailable", "independent recovery timer not enabled and running")
	}
	return nil
}

// This verifies both installed unit provenance and the live independent timer
// rather than trusting a cached service result or a PATH-selected systemctl.
func trialGuardScheduled() error { return trialGuardUnits(true) }

// Prearm admission validates the exact installed executor and timer BEFORE
// starting/enabling either unit. Never execute an untrusted same-name systemd
// service merely because a later observation would detect the replacement.
func trialGuardUnits(armed bool) error {
	for _, name := range []string{trialRecoveryUnit, trialRecoveryTimer} {
		if err := trialNoRuntimeUnitOverride(trialRuntimeUnitDir, name); err != nil {
			return err
		}
		unitPath := trialGuardUnitDir + name
		body, err := readTrustedRootFile(unitPath)
		if err != nil || len(body) == 0 {
			return Fault("guard_unavailable", "installed recovery unit ownership unavailable")
		}
		digest, err := readTrustedRootFile(managedPrefix + "/" + name + ".sha256")
		if err != nil || strings.TrimSpace(string(digest)) != sha256Hex(body) {
			return Fault("guard_unavailable", "installed recovery unit digest conflict")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd, err := trustedSystemctlCommand(ctx, "show", name, "-p", "LoadState", "-p", "FragmentPath", "-p", "DropInPaths", "-p", "Transient", "-p", "ActiveState", "-p", "UnitFileState", "-p", "Unit", "-p", "Result")
		if err != nil {
			cancel()
			return err
		}
		output, runErr := cmd.Output()
		cancel()
		if runErr != nil {
			return Fault("guard_unavailable", "independent recovery unit cannot be inspected")
		}
		fields := map[string]string{}
		for _, line := range strings.Split(string(output), "\n") {
			pair := strings.SplitN(line, "=", 2)
			if len(pair) == 2 {
				fields[pair[0]] = pair[1]
			}
		}
		if fields["LoadState"] != "loaded" || fields["FragmentPath"] != unitPath ||
			fields["DropInPaths"] != "" || fields["Transient"] != "no" {
			return Fault("guard_unavailable", "independent recovery unit identity mismatch")
		}
		if armed {
			if err := trialGuardUnitReady(name, fields); err != nil {
				return err
			}
		} else {
			if fields["Result"] != "success" || fields["ActiveState"] != "inactive" {
				return Fault("guard_unavailable", "independent recovery unit not idle before prearm")
			}
			if name == trialRecoveryUnit && fields["UnitFileState"] != "static" {
				return Fault("guard_unavailable", "independent recovery executor not static")
			}
			if name == trialRecoveryTimer && (fields["UnitFileState"] != "disabled" || fields["Unit"] != trialRecoveryUnit) {
				return Fault("guard_unavailable", "recovery timer already enabled or owns wrong executor")
			}
		}
	}
	return nil
}

func sha256Hex(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// These explicit SIGKILL boundaries are available ONLY in the loopback-only,
// disconnected disposable systemd guest. Invalid phase/point combinations are
// rejected before writing the private journal or changing kernel state.
func trialValidateQACrashPoint(phase, point string) error {
	if point == "" {
		return nil
	}
	switch phase {
	case "apply", "route-apply":
		if point == "before-journal" || point == "after-journal" || point == "after-add" ||
			(phase == "route-apply" && point == "after-route") {
			return nil
		}
	case "recover":
		if point == "after-delete" || point == "before-recovered-journal" || point == "after-route-delete" {
			return nil
		}
	}
	return Fault("invalid_arguments", "unsupported rule-trial QA crash boundary")
}

// These error-path probes are restricted to the same strict disposable
// systemd Docker guest as the v3 trial. They exercise the real native-ip
// command failure handler (with a deliberately invalid, non-mutating command)
// and the recovered-journal persistence error branch. They do NOT simulate
// Linux netlink EIO or a physical disk/fsync failure.
func trialValidateQAFaultPoint(phase, point string) error {
	if point == "" {
		return nil
	}
	switch phase {
	case "route-apply":
		if point == "route-add" || point == "rule-add" {
			return nil
		}
	case "recover":
		if point == "route-delete" || point == "recovered-journal-write" {
			return nil
		}
	}
	return Fault("invalid_arguments", "unsupported v3 disposable QA failure boundary")
}

func trialRunIPWithQAFault(actual, requested string, args ...string) error {
	if requested != "" && actual == requested {
		// Intentionally invalid native iproute2 command: no network mutation.
		// An unexpected success is still an error, never a successful trial.
		if err := trialRunIP("sc-qa-nonexistent-subcommand"); err != nil {
			return err
		}
		return Fault("trial_kernel_error", "disposable QA native failure injection unexpectedly succeeded")
	}
	return trialRunIP(args...)
}

func trialQAFailRecoveredJournal(requested string) error {
	if requested == "recovered-journal-write" {
		return journalFSUnavailable("disposable QA injected recovered-journal persistence failure")
	}
	return nil
}

// A requested v3-only fault must never be acknowledged as a successful
// recovery no-op for an absent, unarmed v1, v2, or already recovered journal.
// The independent watchdog passes no QA fault and retains those semantics.
func trialRequirePendingV3ForQAFault(qaFaultPoint string, record *trialJournal) error {
	if qaFaultPoint != "" && (record == nil || record.Version != 3 || record.Phase != "trial_pending") {
		return Fault("invalid_arguments", "v3 QA failure requires pending route trial")
	}
	return nil
}

func trialQAKillAt(actual, requested string) error {
	if actual != requested {
		return nil
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
		return Fault("trial_kernel_error", "disposable QA process interruption failed")
	}
	return nil
}

// A persisted trial_recovered phase is not permanent evidence that a kernel
// object stayed absent. Native reinspection refuses stale recovered receipts.
func trialVerifyRecoveredNative(record trialJournal) error {
	if err := trialDisposableContext(); err != nil {
		return err
	}
	rule, err := trialSingleRule(record)
	if err != nil {
		return err
	}
	rows, err := trialNativeRules()
	if err != nil {
		return err
	}
	present, err := trialRulePresence(rows, rule)
	if err != nil {
		return err
	}
	if present {
		return Fault("trial_recovery_uncertain", "guarded rule exists after recorded recovery")
	}
	if record.Version == 3 {
		route, err := trialSingleRoute(record)
		if err != nil {
			return err
		}
		present, err := trialNativeRoutePresence(route)
		if err != nil {
			return err
		}
		if present {
			return Fault("trial_recovery_uncertain", "route exists after recorded recovery")
		}
	}
	return nil
}

// A recovery conflict cannot clear the journal. Absent/owned counts are
// observed anew; a different rule at the same priority is foreign, never ours.
func trialProtocolMatches(raw json.RawMessage) bool {
	value, ok := selectiveInt(raw)
	// Never infer ownership from a configurable presentation alias. The
	// observation caller must have requested -N from native iproute2.
	return ok && strconv.Itoa(value) == trialProtocol
}

func trialRulePresence(rows []map[string]json.RawMessage, rule PlannedRule) (bool, error) {
	count := 0
	for _, row := range rows {
		priority, ok := selectiveInt(row["priority"])
		if !ok {
			return false, Fault("trial_observation_uncertain", "native rule priority unsupported")
		}
		if priority != rule.Priority {
			// A product-tagged selector unexpectedly found at a different
			// priority is ambiguous residue, not proof of complete rollback.
			if trialProtocolMatches(row["protocol"]) {
				table, tableErr := selectiveTable(row["table"], false)
				destination, hasDestination, destErr := selectiveRuleDestination(row, false)
				if tableErr != nil || destErr != nil {
					return false, Fault("trial_observation_uncertain", "unexpected protocol-tagged rule is unsupported")
				}
				if table == rule.Table && hasDestination && destination.String() == rule.Destination {
					return false, Fault("trial_resource_conflict", "tagged trial selector exists at foreign priority")
				}
			}
			continue
		}
		count++
		destination, hasDestination, destErr := selectiveRuleDestination(row, false)
		if destErr != nil || !hasDestination || destination.String() != rule.Destination {
			return false, Fault("trial_resource_conflict", "guarded rule has foreign destination")
		}
		table, err := selectiveTable(row["table"], false)
		if err != nil {
			return false, Fault("trial_resource_conflict", "guarded priority contains foreign table")
		}
		if count != 1 || table != rule.Table ||
			(selectiveText(row["src"]) != "" && selectiveText(row["src"]) != "all") ||
			!trialProtocolMatches(row["protocol"]) {
			return false, Fault("trial_resource_conflict", "guarded rule priority has foreign or ambiguous identity")
		}
		for key := range row {
			switch key {
			case "priority", "dst", "dstlen", "src", "table", "protocol":
			default:
				return false, Fault("trial_resource_conflict", "guarded rule contains unsupported attributes")
			}
		}
	}
	return count == 1, nil
}

func trialRunIP(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, nativeIPPath, args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "LANG=C"}
	command.WaitDelay = 250 * time.Millisecond
	if err := command.Run(); err != nil {
		return Fault("trial_kernel_error", "bounded native experimental route or rule mutation failed")
	}
	return nil
}

// Activation is deliberately unavailable. This experimental path only adds a
// route-less RPDB rule to an otherwise unused table, then MUST expire. A
// successful trial is NOT a working tunnel, safe production activation, or
// evidence of live foreign transport.
func (m *Manager) BeginGuardedRuleTrial(operationID string, revision uint64, ttlSeconds int, qaCrashPoint string) (TrialReceipt, error) {
	return m.beginGuardedTrial(operationID, revision, ttlSeconds, qaCrashPoint, "", false)
}

// The v3 lab path inserts a real native IPv4 route via lo into the isolated
// table BEFORE the matching rule. It still cannot transport any VPN traffic.
func (m *Manager) BeginGuardedRouteTrial(operationID string, revision uint64, ttlSeconds int, qaCrashPoint, qaFaultPoint string) (TrialReceipt, error) {
	return m.beginGuardedTrial(operationID, revision, ttlSeconds, qaCrashPoint, qaFaultPoint, true)
}

func (m *Manager) beginGuardedTrial(operationID string, revision uint64, ttlSeconds int, qaCrashPoint, qaFaultPoint string, withRoute bool) (TrialReceipt, error) {
	// The fixed independent systemd unit has exactly one private state root.
	// A custom --state-dir would arm a watchdog that can never find this
	// transaction, leaving a real kernel rule unowned after controller death.
	if m.Dir != DefaultDir {
		return TrialReceipt{}, Fault("trial_unsupported", "guarded trial requires the installed default private state directory")
	}
	phase := "apply"
	if withRoute {
		phase = "route-apply"
	}
	if err := trialValidateQACrashPoint(phase, qaCrashPoint); err != nil {
		return TrialReceipt{}, err
	}
	if err := trialValidateQAFaultPoint(phase, qaFaultPoint); err != nil {
		return TrialReceipt{}, err
	}
	if qaCrashPoint != "" && qaFaultPoint != "" {
		return TrialReceipt{}, Fault("invalid_arguments", "only one disposable QA intervention is allowed")
	}
	if !journalHex32.MatchString(operationID) || revision != 1 || ttlSeconds < 4 || ttlSeconds > 600 {
		return TrialReceipt{}, Fault("invalid_arguments", "exact staged revision and trial deadline (4-600s) required")
	}
	if err := nativeTrialApplyPlatform(); err != nil {
		return TrialReceipt{}, err
	}
	if err := trialDisposableContext(); err != nil {
		return TrialReceipt{}, err
	}
	if err := trialIsolatedNetwork(); err != nil {
		return TrialReceipt{}, err
	}
	if err := trialGuardScheduled(); err != nil {
		return TrialReceipt{}, err
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return TrialReceipt{}, err
	}
	uptime, err := trialUptime()
	if err != nil {
		return TrialReceipt{}, err
	}
	var receipt TrialReceipt
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record, id, err := loadActivationJournalLocked(store)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(operationID), []byte(record.OperationID)) != 1 || record.Revision != revision {
			return Fault("activation_journal_conflict", "guard trial requires exact staged operation")
		}
		if _, err := selectiveRequestFromValidatedJournal(record); err != nil {
			return err
		}
		if len(record.Changes) != 2 {
			return Fault("trial_unsupported", "guarded trial currently supports one IPv4 prefix only")
		}
		trial := trialJournal{activationJournal: record, BootID: boot, DeadlineUptimeSec: uptime + int64(ttlSeconds)}
		trial.Version, trial.Revision, trial.Phase, trial.IntentType = 2, 2, "trial_pending", trialIntentType
		if withRoute {
			trial.Version, trial.IntentType, trial.RouteDevice = 3, trialRouteIntentType, "lo"
		}
		if err := validateTrialJournal(trial); err != nil {
			return err
		}
		req, err := selectiveRequestFromValidatedJournal(record)
		if err != nil {
			return err
		}
		intent, err := validateSelectiveRequest(req)
		if err != nil {
			return err
		}
		for i := 0; i < 2; i++ {
			host, err := InspectHostRoutes(req.EndpointIP, req.ManagementPeerIP)
			if err != nil {
				return Fault("route_plan_uncertain", "fresh native trial observation failed")
			}
			plan, err := buildSelectivePlan(intent, host)
			if err != nil {
				return Fault("route_plan_uncertain", "fresh trial plan cannot be compared")
			}
			if plan.PlanSHA256 != record.PlanSHA256 || plan.ObservationSHA256 != record.ObservationSHA256 {
				return Fault("route_plan_changed", "trial kernel state no longer matches staged operation")
			}
		}
		rule, err := trialSingleRule(trial)
		if err != nil {
			return err
		}
		rows, err := trialNativeRules()
		if err != nil {
			return err
		}
		present, err := trialRulePresence(rows, rule)
		if err != nil {
			return err
		}
		if present {
			return Fault("trial_resource_conflict", "rule already exists before guarded trial")
		}
		var route PlannedRoute
		if withRoute {
			route, err = trialSingleRoute(trial)
			if err != nil {
				return err
			}
			routePresent, err := trialNativeRoutePresence(route)
			if err != nil {
				return err
			}
			if routePresent {
				return Fault("trial_resource_conflict", "route exists before guarded trial")
			}
			if err := trialNoForeignTableRules(rows, rule); err != nil {
				return err
			}
		}
		if err := trialGuardScheduled(); err != nil {
			return err
		}
		if err := trialQAKillAt("before-journal", qaCrashPoint); err != nil {
			return err
		}
		if err := writeTrialLocked(store, trial, &id); err != nil {
			return err
		}
		if err := trialQAKillAt("after-journal", qaCrashPoint); err != nil {
			return err
		}
		// Durable pending record and independently active timer PRECEDE the one
		// kernel effect. Crash before or after add is recoverable by inspection.
		receipt = trialReceipt(trial, true, false)
		if withRoute {
			if err := trialRunIPWithQAFault("route-add", qaFaultPoint, trialRouteCommand(route, "add")...); err != nil {
				return err
			}
			if err := trialQAKillAt("after-route", qaCrashPoint); err != nil {
				return err
			}
		}
		if err := trialRunIPWithQAFault("rule-add", qaFaultPoint, "-4", "rule", "add", "pref", strconv.Itoa(rule.Priority), "to", rule.Destination,
			"table", strconv.Itoa(rule.Table), "protocol", trialProtocol); err != nil {
			return err
		}
		if err := trialQAKillAt("after-add", qaCrashPoint); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return TrialReceipt{}, err
	}
	return receipt, nil
}

// Called from a standalone systemd oneshot: no dependency on sing-box or a
// living initiating shell. The v2 record must survive a process crash. A
// changed boot ID triggers recovery immediately, not a new 600s allowance.
func (m *Manager) RecoverGuardedRuleTrial(qaCrashPoint, qaFaultPoint string) (TrialReceipt, error) {
	if m.Dir != DefaultDir {
		return TrialReceipt{}, Fault("trial_unsupported", "guard recovery requires the installed default private state directory")
	}
	if err := trialValidateQACrashPoint("recover", qaCrashPoint); err != nil {
		return TrialReceipt{}, err
	}
	if err := trialValidateQAFaultPoint("recover", qaFaultPoint); err != nil {
		return TrialReceipt{}, err
	}
	if qaCrashPoint != "" && qaFaultPoint != "" {
		return TrialReceipt{}, Fault("invalid_arguments", "only one disposable QA intervention is allowed")
	}
	if qaFaultPoint != "" {
		// Reject an explicitly requested QA intervention even if no journal exists;
		// an absent/non-guest state must never yield a simulated-success receipt.
		if err := trialDisposableContext(); err != nil {
			return TrialReceipt{}, err
		}
	}
	return m.recoverGuardedTrialWithHandler(qaCrashPoint, qaFaultPoint,
		func(store *activationJournalDir, selected trialRecoverySelection) (TrialReceipt, error) {
			switch selected.version {
			case 0:
				return TrialReceipt{Phase: "absent", ExperimentOnly: true}, nil
			case 1:
				return TrialReceipt{Phase: "unarmed_prepared", ExperimentOnly: true}, nil
			case smartTUNTrialVersion:
				return recoverSmartTUNTrialJournalLocked(store, selected.identity, selected.tun)
			case 2, 3:
				return recoverLegacyGuardedTrialLocked(store, selected.identity, selected.trial, qaCrashPoint, qaFaultPoint)
			default:
				return TrialReceipt{}, activationJournalError("unsupported recovery journal selection")
			}
		})
}

// Selection and its selected handler share one uninterrupted manager lock.
// An executor must not observe absence, unlock, then feed a newly published
// v4 Apply to legacy recovery. The private typed handler permits no-native
// tests of that exact lock boundary; production uses the wrapper above.
type trialRecoverySelection struct {
	version  int
	identity activationJournalFileIdentity
	trial    trialJournal
	tun      smartTUNTrialJournal
}

func (m *Manager) recoverGuardedTrialWithHandler(qaCrashPoint, qaFaultPoint string,
	handle func(*activationJournalDir, trialRecoverySelection) (TrialReceipt, error)) (TrialReceipt, error) {
	var receipt TrialReceipt
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		selected, err := selectTrialRecoveryLocked(store, qaCrashPoint, qaFaultPoint)
		if err != nil {
			return err
		}
		receipt, err = handle(store, selected)
		return err
	})
	if err != nil {
		return TrialReceipt{}, err
	}
	return receipt, nil
}

func selectTrialRecoveryLocked(store *activationJournalDir, qaCrashPoint, qaFaultPoint string) (trialRecoverySelection, error) {
	raw, identity, err := store.readJournal()
	if errors.Is(err, os.ErrNotExist) {
		return trialRecoverySelection{}, trialRequirePendingV3ForQAFault(qaFaultPoint, nil)
	}
	if err != nil {
		return trialRecoverySelection{}, err
	}
	if err := rejectAmbiguousJournalJSON(raw); err != nil {
		return trialRecoverySelection{}, err
	}
	var marker struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(raw, &marker); err == nil && marker.Version == smartTUNTrialVersion &&
		qaCrashPoint == "" && qaFaultPoint == "" {
		record, err := decodeSmartTUNTrial(raw)
		if err != nil {
			return trialRecoverySelection{}, err
		}
		return trialRecoverySelection{version: smartTUNTrialVersion, identity: identity, tun: record}, nil
	}
	record, err := decodeTrialJournal(raw)
	if err != nil {
		// Only an exact valid v1 PREPARED intent is a no-op. Keep the same
		// lock during this legacy check; corrupt/future/v4-with-QA records
		// must never become an accepted legacy recovery selection.
		legacy, legacyID, legacyErr := loadActivationJournalLocked(store)
		if legacyErr == nil && legacyID == identity && legacy.Version == 1 && legacy.Phase == "prepared" {
			if err := trialRequirePendingV3ForQAFault(qaFaultPoint, nil); err != nil {
				return trialRecoverySelection{}, err
			}
			return trialRecoverySelection{version: 1, identity: identity}, nil
		}
		return trialRecoverySelection{}, err
	}
	if err := trialRequirePendingV3ForQAFault(qaFaultPoint, &record); err != nil {
		return trialRecoverySelection{}, err
	}
	if qaCrashPoint == "after-route-delete" && record.Version != 3 {
		return trialRecoverySelection{}, Fault("invalid_arguments", "route-delete crash point requires the v3 route trial")
	}
	return trialRecoverySelection{version: record.Version, identity: identity, trial: record}, nil
}

func recoverLegacyGuardedTrialLocked(store *activationJournalDir, id activationJournalFileIdentity, record trialJournal, qaCrashPoint, qaFaultPoint string) (TrialReceipt, error) {
	if record.Phase == "trial_recovered" {
		if err := trialVerifyRecoveredNative(record); err != nil {
			return TrialReceipt{}, err
		}
		return trialReceipt(record, false, true), nil
	}
	if err := trialDisposableContext(); err != nil {
		return TrialReceipt{}, err
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return TrialReceipt{}, err
	}
	uptime, err := trialUptime()
	if err != nil {
		return TrialReceipt{}, err
	}
	if boot == record.BootID && uptime < record.DeadlineUptimeSec {
		// The timer may have been stopped/masked since application. A
		// pending return must NEVER claim a scheduled guard from journal
		// intent alone, even when the rule is still within its deadline.
		if err := trialGuardScheduled(); err != nil {
			return TrialReceipt{}, err
		}
		return trialReceipt(record, true, false), nil
	}
	rule, err := trialSingleRule(record)
	if err != nil {
		return TrialReceipt{}, err
	}
	rows, err := trialNativeRules()
	if err != nil {
		return TrialReceipt{}, err
	}
	present, err := trialRulePresence(rows, rule)
	if err != nil {
		return TrialReceipt{}, err
	}
	if record.Version == 3 {
		// Refuse foreign route/table consumers BEFORE deleting even the
		// owned rule. Otherwise the two-object rollback could half-succeed.
		route, err := trialSingleRoute(record)
		if err != nil {
			return TrialReceipt{}, err
		}
		if _, err := trialNativeRoutePresence(route); err != nil {
			return TrialReceipt{}, err
		}
		if err := trialNoForeignTableRules(rows, rule); err != nil {
			return TrialReceipt{}, err
		}
	}
	if present {
		// This narrowly identifies our exact protocol/table/destination/priority
		// rather than deleting any rule at the occupied priority.
		if err := trialRunIP("-4", "rule", "del", "pref", strconv.Itoa(rule.Priority), "to", rule.Destination,
			"table", strconv.Itoa(rule.Table), "protocol", trialProtocol); err != nil {
			return TrialReceipt{}, err
		}
		if err := trialQAKillAt("after-delete", qaCrashPoint); err != nil {
			return TrialReceipt{}, err
		}
	}
	after, err := trialNativeRules()
	if err != nil {
		return TrialReceipt{}, err
	}
	remains, err := trialRulePresence(after, rule)
	if err != nil {
		return TrialReceipt{}, err
	}
	if remains {
		return TrialReceipt{}, Fault("trial_recovery_uncertain", "guarded rule persists after recovery")
	}
	if record.Version == 3 {
		if err := trialRecoverRoute(record, qaCrashPoint, qaFaultPoint); err != nil {
			return TrialReceipt{}, err
		}
	}
	if err := trialQAKillAt("before-recovered-journal", qaCrashPoint); err != nil {
		return TrialReceipt{}, err
	}
	record.Phase, record.Revision = "trial_recovered", 3
	if err := trialQAFailRecoveredJournal(qaFaultPoint); err != nil {
		return TrialReceipt{}, err
	}
	if err := writeTrialLocked(store, record, &id); err != nil {
		return TrialReceipt{}, err
	}
	return trialReceipt(record, false, true), nil
}

func (m *Manager) InspectGuardedRuleTrial() (TrialReceipt, error) {
	if m.Dir != DefaultDir {
		return TrialReceipt{}, Fault("trial_unsupported", "guard trial inspection requires the installed default private state directory")
	}
	var receipt TrialReceipt
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record, _, err := loadTrialLocked(store)
		if err != nil {
			return err
		}
		if record.Phase == "trial_recovered" {
			if err := trialVerifyRecoveredNative(record); err != nil {
				return err
			}
		}
		receipt = trialReceipt(record, false, record.Phase == "trial_recovered")
		return nil
	})
	return receipt, err
}

// An exact recovered receipt may be removed after observing an empty owned
// priority. It cannot be used to abandon pending or conflicting resources.
func (m *Manager) ClearRecoveredRuleTrial(operationID string, revision uint64) error {
	if m.Dir != DefaultDir {
		return Fault("trial_unsupported", "guard trial clearance requires the installed default private state directory")
	}
	return m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record, id, err := loadTrialLocked(store)
		if err != nil {
			return err
		}
		if record.Phase != "trial_recovered" || record.Revision != revision ||
			!journalHex32.MatchString(operationID) || subtle.ConstantTimeCompare([]byte(record.OperationID), []byte(operationID)) != 1 {
			return Fault("activation_journal_conflict", "only exact fully recovered rule trial can be cleared")
		}
		if err := trialDisposableContext(); err != nil {
			return err
		}
		rule, err := trialSingleRule(record)
		if err != nil {
			return err
		}
		rows, err := trialNativeRules()
		if err != nil {
			return err
		}
		present, err := trialRulePresence(rows, rule)
		if err != nil {
			return err
		}
		if present {
			return Fault("trial_resource_conflict", "cannot clear journal while trial rule exists")
		}
		if record.Version == 3 {
			route, err := trialSingleRoute(record)
			if err != nil {
				return err
			}
			present, err := trialNativeRoutePresence(route)
			if err != nil {
				return err
			}
			if present {
				return Fault("trial_resource_conflict", "cannot clear journal while route exists")
			}
		}
		return store.removeJournal(id)
	})
}

// Installer holds the exact Manager .lock before invoking this privileged
// validator. Do not let a disabled timer or unsupported journal orphan a
// pending experiment by removing its recovery binary or systemd units.
func (m *Manager) InstallerCheckGuardClear() error {
	if os.Geteuid() != 0 {
		return Fault("ownership_required", "root required for installer guard check")
	}
	raw, err := readRegular(filepath.Join(m.Dir, activationJournalFilename))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return Fault("activation_journal_invalid", "cannot inspect existing private recovery journal")
	}
	if _, err := decodeTrialJournal(raw); err == nil {
		return Fault("guard_pending", "clear the exact recovered rule trial before update or uninstall")
	}
	if err := strictActivationJournalJSON(raw); err != nil {
		return Fault("activation_journal_invalid", "unsupported activation journal blocks installer")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var record activationJournal
	if err := decoder.Decode(&record); err != nil || validateActivationJournal(record) != nil {
		return Fault("activation_journal_invalid", "unsupported activation journal blocks installer")
	}
	if record.Phase != "prepared" {
		return Fault("guard_pending", "uncertain activation journal blocks installer")
	}
	return nil
}
