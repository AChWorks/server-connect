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
	trialIntentType     = "guarded_rule_trial_v2"
	trialProtocol       = "247"
	trialRecoveryUnit   = "server-connect-activation-recover.service"
	trialRecoveryTimer  = "server-connect-activation-recover.timer"
	trialGuardUnitDir   = "/etc/systemd/system/"
	trialRuntimeUnitDir = "/run/systemd/system/"
)

var trialBootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var trialJournalFields = map[string]bool{
	"version": true, "revision": true, "operation_id": true, "phase": true,
	"created_unix": true, "observation_sha256": true, "plan_sha256": true,
	"intent_type": true, "selective": true, "changes": true,
	"boot_id": true, "deadline_uptime_sec": true,
}

type trialJournal struct {
	activationJournal
	BootID            string `json:"boot_id"`
	DeadlineUptimeSec int64  `json:"deadline_uptime_sec"`
}

type TrialReceipt struct {
	OperationID        string `json:"operation_id"`
	Revision           uint64 `json:"revision"`
	Phase              string `json:"phase"`
	ExperimentOnly     bool   `json:"experiment_only"`
	GuardScheduled     bool   `json:"guard_scheduled"`
	ActivationReady    bool   `json:"activation_ready"`
	VPNVerified        bool   `json:"vpn_verified"`
	RecoveryVerified   bool   `json:"recovery_verified"`
	TrialRuleRecovered bool   `json:"trial_rule_recovered"`
}

func trialReceipt(record trialJournal, scheduled, recovered bool) TrialReceipt {
	return TrialReceipt{OperationID: record.OperationID, Revision: record.Revision, Phase: record.Phase,
		ExperimentOnly: true, GuardScheduled: scheduled, TrialRuleRecovered: recovered}
}

// The v1 record is retained in full, including before=absence and exact plan
// bindings. v2 only permits one IPv4 rule, an otherwise empty selected table,
// and no route/interface mutation. Unknown/corrupt fields fail closed.
func validateTrialJournal(record trialJournal) error {
	if record.Version != 2 || (record.Phase != "trial_pending" && record.Phase != "trial_recovered") ||
		(record.Phase == "trial_pending" && record.Revision != 2) ||
		(record.Phase == "trial_recovered" && record.Revision != 3) ||
		record.IntentType != trialIntentType || !trialBootIDPattern.MatchString(record.BootID) ||
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
	if err := requireExactJournalKeys(raw, trialJournalFields); err != nil {
		return record, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return record, activationJournalError("guard trial root invalid")
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

// This verifies both installed unit provenance and the live independent timer
// rather than trusting a cached service result or a PATH-selected systemctl.
func trialGuardScheduled() error {
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
		cmd, err := trustedSystemctlCommand(ctx, "show", name, "-p", "LoadState", "-p", "FragmentPath", "-p", "DropInPaths", "-p", "Transient", "-p", "ActiveState", "-p", "UnitFileState", "-p", "Unit")
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
		// The installed oneshot has no [Install] section and must stay
		// static. Runtime overrides are checked separately because /etc
		// has higher precedence and show may still report loaded/static.
		if name == trialRecoveryUnit && fields["UnitFileState"] != "static" {
			return Fault("guard_unavailable", "independent recovery service no longer static and available")
		}
		if name == trialRecoveryTimer && (fields["ActiveState"] != "active" || fields["UnitFileState"] != "enabled" || fields["Unit"] != trialRecoveryUnit) {
			return Fault("guard_unavailable", "independent recovery timer not enabled and running")
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
	case "apply":
		if point == "before-journal" || point == "after-journal" || point == "after-add" {
			return nil
		}
	case "recover":
		if point == "after-delete" || point == "before-recovered-journal" {
			return nil
		}
	}
	return Fault("invalid_arguments", "unsupported rule-trial QA crash boundary")
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
		return Fault("trial_kernel_error", "bounded native RPDB mutation failed")
	}
	return nil
}

// Activation is deliberately unavailable. This experimental path only adds a
// route-less RPDB rule to an otherwise unused table, then MUST expire. A
// successful trial is NOT a working tunnel, safe production activation, or
// evidence of live foreign transport.
func (m *Manager) BeginGuardedRuleTrial(operationID string, revision uint64, ttlSeconds int, qaCrashPoint string) (TrialReceipt, error) {
	// The fixed independent systemd unit has exactly one private state root.
	// A custom --state-dir would arm a watchdog that can never find this
	// transaction, leaving a real kernel rule unowned after controller death.
	if m.Dir != DefaultDir {
		return TrialReceipt{}, Fault("trial_unsupported", "guarded trial requires the installed default private state directory")
	}
	if err := trialValidateQACrashPoint("apply", qaCrashPoint); err != nil {
		return TrialReceipt{}, err
	}
	if !journalHex32.MatchString(operationID) || revision != 1 || ttlSeconds < 4 || ttlSeconds > 600 {
		return TrialReceipt{}, Fault("invalid_arguments", "exact staged revision and trial deadline (4-600s) required")
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
		if err := trialRunIP("-4", "rule", "add", "pref", strconv.Itoa(rule.Priority), "to", rule.Destination,
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
func (m *Manager) RecoverGuardedRuleTrial(qaCrashPoint string) (TrialReceipt, error) {
	if m.Dir != DefaultDir {
		return TrialReceipt{}, Fault("trial_unsupported", "guard recovery requires the installed default private state directory")
	}
	if err := trialValidateQACrashPoint("recover", qaCrashPoint); err != nil {
		return TrialReceipt{}, err
	}
	var receipt TrialReceipt
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record, id, err := loadTrialLocked(store)
		if errors.Is(err, os.ErrNotExist) {
			receipt = TrialReceipt{Phase: "absent", ExperimentOnly: true}
			return nil
		}
		if err != nil {
			// A valid v1 unarmed PREPARED intent is an expected no-op for
			// the always-independent watchdog. Corrupt/future/uncertain
			// state is never silently accepted as safe.
			legacy, _, legacyErr := loadActivationJournalLocked(store)
			if legacyErr == nil && legacy.Version == 1 && legacy.Phase == "prepared" {
				receipt = TrialReceipt{Phase: "unarmed_prepared", ExperimentOnly: true}
				return nil
			}
			return err
		}
		if record.Phase == "trial_recovered" {
			if err := trialVerifyRecoveredNative(record); err != nil {
				return err
			}
			receipt = trialReceipt(record, false, true)
			return nil
		}
		if err := trialDisposableContext(); err != nil {
			return err
		}
		boot, err := trialBootIdentity()
		if err != nil {
			return err
		}
		uptime, err := trialUptime()
		if err != nil {
			return err
		}
		if boot == record.BootID && uptime < record.DeadlineUptimeSec {
			// The timer may have been stopped/masked since application. A
			// pending return must NEVER claim a scheduled guard from journal
			// intent alone, even when the rule is still within its deadline.
			if err := trialGuardScheduled(); err != nil {
				return err
			}
			receipt = trialReceipt(record, true, false)
			return nil
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
			// This narrowly identifies our exact protocol/table/destination/priority
			// rather than deleting any rule at the occupied priority.
			if err := trialRunIP("-4", "rule", "del", "pref", strconv.Itoa(rule.Priority), "to", rule.Destination,
				"table", strconv.Itoa(rule.Table), "protocol", trialProtocol); err != nil {
				return err
			}
			if err := trialQAKillAt("after-delete", qaCrashPoint); err != nil {
				return err
			}
		}
		after, err := trialNativeRules()
		if err != nil {
			return err
		}
		remains, err := trialRulePresence(after, rule)
		if err != nil {
			return err
		}
		if remains {
			return Fault("trial_recovery_uncertain", "guarded rule persists after recovery")
		}
		if err := trialQAKillAt("before-recovered-journal", qaCrashPoint); err != nil {
			return err
		}
		record.Phase, record.Revision = "trial_recovered", 3
		if err := writeTrialLocked(store, record, &id); err != nil {
			return err
		}
		receipt = trialReceipt(record, false, true)
		return nil
	})
	if err != nil {
		return TrialReceipt{}, err
	}
	return receipt, nil
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
