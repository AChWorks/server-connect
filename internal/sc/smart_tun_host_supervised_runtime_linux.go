//go:build linux

package sc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"syscall"
	"time"
)

func (m *Manager) installedHostSupervisor() error {
	if m == nil || m.Dir != DefaultDir || m.Core != DefaultCore || os.Geteuid() != 0 {
		return Fault("trial_unsupported", "host supervision requires the installed root manager")
	}
	return nil
}

// No new records are created here. A valid legacy v9 preparation retains its
// immediate-Off semantics and cannot be promoted by invoking a health command.
func (m *Manager) hostRouteHealthDispatch() (version int, found bool, err error) {
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		raw, _, err := store.readJournal()
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := rejectAmbiguousJournalJSON(raw); err != nil {
			return err
		}
		var marker struct {
			Version int `json:"version"`
		}
		if json.Unmarshal(raw, &marker) != nil {
			return activationJournalError("health journal version invalid")
		}
		if marker.Version <= 0 {
			return activationJournalError("health journal version invalid")
		}
		version = marker.Version
		if version != hostRouteJournalVersion {
			return nil
		}
		r, err := decodeHostRouteJournal(raw)
		if err != nil {
			return err
		}
		found = hostRouteSupervised(r)
		return nil
	})
	return version, found, err
}

// During an active lease, keep the same ownership/foreign-owner checks used
// at preparation. The preparation deadline only authorizes unconfirmed work;
// it is never extended or rewritten to keep confirmed operation running.
func verifyHostRouteActivePolicy(r hostRouteJournal) error {
	i := r.Progress.Ingress
	if r.Route.State != "observed" || r.Native.StopReason != "" || !r.Native.StartupVerified {
		return Fault("trial_recovery_uncertain", "host routed policy is not fully active")
	}
	if err := hostIngressNamespace(i); err != nil {
		return err
	}
	if err := hostIngressUnderlay(i); err != nil {
		return err
	}
	if err := hostIngressMarkBoundary(i); err != nil {
		return err
	}
	if v, err := readHostIngressSysctl(); err != nil || v != 1 {
		return ingressFault("host socket mark inheritance changed")
	}
	if err := verifyHostNetworkBarrierReleased(r.Progress.Barrier); err != nil {
		return err
	}
	// V9 is IPv4-only. Newly appearing public IPv6 cannot silently acquire
	// an unsupported Direct bypass while the operation is being supervised.
	if err := nativeIPv4OnlyIPv6Current(nativeIPJSON); err != nil {
		return err
	}
	native := r.nativeView()
	link, err := nativeTUNObserveLink(native)
	if err != nil {
		return err
	}
	if !link.Present || r.Native.LinkStage != "observed" {
		return nativeTUNUncertain("host routed link disappeared")
	}
	if err := nativeTUNVerifyLink(native, link); err != nil {
		return err
	}
	for _, kind := range []string{"fallback", "route", "rule"} {
		present, digest, err := nativeTUNObserveResource(native, 4, kind)
		if err != nil {
			return err
		}
		receipt := nativeTUNResource(&r.Native, 4, kind)
		if !present || receipt.Stage != "observed" || digest != receipt.SHA256 {
			return nativeTUNUncertain("host routed policy receipt changed")
		}
	}
	observed, err := hostRouteNFTObserver(&r)(native)
	if err != nil {
		return err
	}
	if !nativeTUNNFTReceiptCovers(native, observed, true) {
		return nativeTUNConflict("host routed containment changed")
	}
	return nil
}

func hostRouteCredentialPlanMatches(raw []byte, r hostRouteJournal) bool {
	if sha256Hex(raw) != r.Core.ConfigSHA256 || rejectAmbiguousJournalJSON(raw) != nil {
		return false
	}
	var cfg struct {
		Outbounds []struct {
			Tag    string `json:"tag"`
			Type   string `json:"type"`
			Server string `json:"server"`
			Port   int    `json:"server_port"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return false
	}
	found := 0
	for _, o := range cfg.Outbounds {
		if o.Tag != "upstream" {
			continue
		}
		found++
		if o.Type != "vless" || o.Server != r.Core.PinnedEndpoint || o.Port != r.Supervision.Plans[0].EndpointPort {
			return false
		}
	}
	return found == 1
}

func inspectHostRouteRuntime(store *activationJournalDir, r hostRouteJournal) string {
	boot, err := trialBootIdentity()
	if err != nil {
		return "boot_unavailable"
	}
	now, err := smartTUNUptimeMillis()
	if err != nil {
		return "clock_unavailable"
	}
	if reason := hostRouteRuntimeDeadline(r, boot, now); reason != "" {
		return reason
	}
	raw, _, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
	if err != nil || !hostRouteCredentialPlanMatches(raw, r) {
		return "credential_conflict"
	}
	unit, err := observeSmartTUNTrialUnit(context.Background())
	if err != nil {
		return "core_identity_unavailable"
	}
	if unit.activeState != "active" || unit.subState != "running" || unit.mainPID == 0 || unit.result != "success" {
		return "core_unavailable"
	}
	process, err := readManagementProcess(int(unit.mainPID))
	if err != nil || unit.mainPID != r.Supervision.CorePID || process.StartTicks != r.Supervision.CoreStartTicks {
		return "core_generation_changed"
	}
	if trialGuardScheduled() != nil {
		return "recovery_executor_unavailable"
	}
	if _, err := smartTUNHealthUnits(true, &r.Supervision.Roles); err != nil {
		return "supervisor_unavailable"
	}
	path, err := observeGeneralHostSSHPath(r.Supervision.ManagementPeer, r.Progress.Ingress.Underlay)
	if err != nil || path.Local.String() != r.Supervision.Plans[0].IPv4.UnderlaySource ||
		path.Index != r.Native.UnderlayIndex {
		return "management_path_changed"
	}
	if verifyHostRouteActivePolicy(r) != nil {
		return "native_resource_conflict"
	}
	// Observations are bounded, but still consume lease time. Recheck the
	// monotonic authority after the final independent native observation.
	now, err = smartTUNUptimeMillis()
	if err != nil {
		return "clock_unavailable"
	}
	return hostRouteRuntimeDeadline(r, boot, now)
}

func hostRouteDisarmHealth(r hostRouteJournal) error {
	return disarmSmartTUNHealthTimer(smartTUNTrialJournal{Supervised: &smartTUNSupervision{Roles: r.Supervision.Roles}})
}

func hostRouteFinishOffLocked(store *activationJournalDir, r *hostRouteJournal, reason string) (TrialReceipt, error) {
	if r == nil || !hostRouteSupervised(*r) || !hostRouteSupervisionReason(reason) || reason == "" {
		return TrialReceipt{}, Fault("activation_journal_conflict", "exact supervised host Off authority required")
	}
	if r.Route.State != "removed" && r.Route.State != "off_pending" {
		next := *r
		next.Route.State, next.Native.StopReason = "off_pending", "guard"
		next.Supervision.State, next.Supervision.ReconnectStage = "stopped", "none"
		next.Supervision.Reason = reason
		next.Supervision.Generation++
		if err := persistHostRouteParent(store, r, next); err != nil {
			return TrialReceipt{}, err
		}
	}
	result, err := recoverHostRouteJournalLocked(store, r, defaultHostCoreRecoveryServices())
	if err != nil {
		return result, err
	}
	if !result.RecoveryVerified {
		return result, Fault("trial_recovery_uncertain", "host Off not independently verified")
	}
	// Never stop a possibly running Health service: it may be this caller.
	// Its bounded process will exit; disable only its exact owned timer.
	if err := hostRouteDisarmHealth(*r); err != nil {
		return result, err
	}
	return result, nil
}

func recoverHostSupervisedRouteLocked(store *activationJournalDir, r *hostRouteJournal) (TrialReceipt, error) {
	if r == nil || validateHostRouteJournal(*r) != nil || !hostRouteSupervised(*r) {
		return TrialReceipt{}, activationJournalError("invalid supervised host recovery selection")
	}
	if r.Route.State == "off_pending" || r.Route.State == "removed" {
		return hostRouteFinishOffLocked(store, r, "recovery_requested")
	}
	if reason := inspectHostRouteRuntime(store, *r); reason != "" {
		return hostRouteFinishOffLocked(store, r, reason)
	}
	// This independent executor verifies the Health role and lease; it
	// does not renew that lease itself or fabricate selected-path health.
	return TrialReceipt{OperationID: r.Progress.Ingress.OperationID, Phase: "host_route_" + r.Supervision.State,
		ExperimentOnly: true, GuardScheduled: true}, nil
}

func hostRouteCurrentReceipt(r hostRouteJournal, now int64) HostRouteSupervisionReceipt {
	result := hostRouteSupervisionReceipt(r)
	result.GuardScheduled = true
	healthy, _ := hostRouteHealthSummary(r.Supervision.Plans, r.Supervision.Evidence)
	result.IPv4SelectedVerified = r.Route.State == "observed" && r.Native.StopReason == "" &&
		(r.Supervision.State == "healthy" || r.Supervision.State == "awaiting_confirmation") && healthy && r.Supervision.Rounds > 0 &&
		now >= r.Supervision.LastProbeMS && now-r.Supervision.LastProbeMS <= int64(r.Supervision.Options.IntervalSeconds+5)*1000
	return result
}

func (m *Manager) InspectHostRouteSupervision() (HostRouteSupervisionReceipt, error) {
	result := HostRouteSupervisionReceipt{Phase: "absent", ExperimentOnly: true, IPv6: "not_supported", DomesticGeography: "not_verified", DNSRouting: "not_verified"}
	if err := m.installedHostSupervisor(); err != nil {
		return result, err
	}
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		r, _, err := loadHostRouteJournal(store)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !hostRouteSupervised(r) {
			return Fault("trial_unsupported", "host preparation has no supervised lifecycle")
		}
		result = hostRouteSupervisionReceipt(r)
		if r.Route.State == "removed" {
			if err := hostRouteVerifyOff(store, r, defaultHostCoreRecoveryServices()); err != nil {
				return err
			}
			result.RecoveryVerified = true
			return nil
		}
		if reason := inspectHostRouteRuntime(store, r); reason != "" {
			result.Phase, result.Reason, result.IPv4SelectedVerified = "host_route_uncertain", reason, false
			return Fault("trial_recovery_uncertain", reason)
		}
		now, err := smartTUNUptimeMillis()
		if err != nil {
			return err
		}
		result = hostRouteCurrentReceipt(r, now)
		return nil
	})
	return result, err
}

func (m *Manager) DisconnectHostRouteSupervision(op string) (HostRouteSupervisionReceipt, error) {
	var result HostRouteSupervisionReceipt
	if err := m.installedHostSupervisor(); err != nil {
		return result, err
	}
	if !journalHex32.MatchString(op) {
		return result, Fault("invalid_arguments", "exact host operation ID required")
	}
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		r, _, err := loadHostRouteJournal(store)
		if err != nil {
			return err
		}
		if !hostRouteSupervised(r) || r.Progress.Ingress.OperationID != op {
			return Fault("activation_journal_conflict", "host Disconnect operation does not match")
		}
		recovered, err := hostRouteFinishOffLocked(store, &r, "operator_disconnect")
		result = hostRouteSupervisionReceipt(r)
		result.RecoveryVerified = recovered.RecoveryVerified
		return err
	})
	return result, err
}

func probeHostRouteHealth(ctx context.Context, plans [2]HostHealthPlan) [2]HostHealthEvidence {
	type sample struct {
		index    int
		evidence HostHealthEvidence
	}
	answers := make(chan sample, 2)
	for i, plan := range plans {
		go func(index int, plan HostHealthPlan) { answers <- sample{index, ProbeHostHealth(ctx, plan)} }(i, plan)
	}
	var result [2]HostHealthEvidence
	for range plans {
		answer := <-answers
		result[answer.index] = answer.evidence
	}
	return result
}

func (m *Manager) RunHostRouteHealthRound() (HostRouteSupervisionReceipt, error) {
	result := HostRouteSupervisionReceipt{Phase: "absent", ExperimentOnly: true}
	if err := m.installedHostSupervisor(); err != nil {
		return result, err
	}
	var snapshot hostRouteJournal
	measure := false
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		r, _, err := loadHostRouteJournal(store)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !hostRouteSupervised(r) {
			return Fault("trial_unsupported", "legacy host preparation cannot acquire a health lease")
		}
		if reason := inspectHostRouteRuntime(store, r); reason != "" {
			off, err := hostRouteFinishOffLocked(store, &r, reason)
			result = hostRouteSupervisionReceipt(r)
			result.RecoveryVerified = off.RecoveryVerified
			return err
		}
		now, err := smartTUNUptimeMillis()
		if err != nil {
			return err
		}
		if now < r.Supervision.NextProbeMS {
			next := r
			next.Supervision.Generation++
			next.Supervision.HeartbeatMS, next.Supervision.LeaseDeadlineMS = now, now+smartTUNHealthLeaseMS
			if err := persistHostRouteParent(store, &r, next); err != nil {
				return err
			}
			result = hostRouteCurrentReceipt(r, now)
			return nil
		}
		snapshot, measure = r, true
		return nil
	})
	if err != nil || !measure {
		return result, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), smartTUNHealthRoundTimeout)
	evidence := probeHostRouteHealth(ctx, hostRouteHealthPlans(snapshot, snapshot.Supervision.Rounds+1))
	cancel()
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		r, _, err := loadHostRouteJournal(store)
		if errors.Is(err, os.ErrNotExist) {
			result.Phase = "absent"
			return nil
		}
		if err != nil {
			return err
		}
		if r != snapshot {
			result = hostRouteSupervisionReceipt(r)
			result.Reason, result.IPv4SelectedVerified = "stale_health_result_discarded", false
			return nil
		}
		if reason := inspectHostRouteRuntime(store, r); reason != "" {
			off, err := hostRouteFinishOffLocked(store, &r, reason)
			result = hostRouteSupervisionReceipt(r)
			result.RecoveryVerified = off.RecoveryVerified
			return err
		}
		now, err := smartTUNUptimeMillis()
		if err != nil {
			return err
		}
		next, action, err := advanceHostRouteHealth(r, evidence, now)
		if err != nil {
			return err
		}
		if err := persistHostRouteParent(store, &r, next); err != nil {
			return err
		}
		if action == "stop" {
			off, err := hostRouteFinishOffLocked(store, &r, r.Supervision.Reason)
			result = hostRouteSupervisionReceipt(r)
			result.RecoveryVerified = off.RecoveryVerified
			return err
		}
		if action == "reconnect" {
			if err := reconnectHostRouteCore(store, &r); err != nil {
				off, stopErr := hostRouteFinishOffLocked(store, &r, "reconnect_failed")
				result = hostRouteSupervisionReceipt(r)
				result.RecoveryVerified = off.RecoveryVerified
				if stopErr != nil {
					return stopErr
				}
				return err
			}
		}
		now, err = smartTUNUptimeMillis()
		if err != nil {
			return err
		}
		result = hostRouteCurrentReceipt(r, now)
		return nil
	})
	return result, err
}

func hostRouteReconnectBudget(r hostRouteJournal, now int64) (time.Duration, error) {
	s := r.Supervision
	if !s.Confirmed || r.Route.State != "observed" || r.Native.StopReason != "" ||
		s.RecoveryDeadlineMS == 0 || now >= s.RecoveryDeadlineMS ||
		now < s.HeartbeatMS || now >= s.LeaseDeadlineMS || s.Attempts > s.Options.MaxAttempts {
		return 0, Fault("trial_recovery_uncertain", "host reconnect authority or bounded budget expired")
	}
	budget := s.RecoveryDeadlineMS - now
	if lease := s.LeaseDeadlineMS - now; lease < budget {
		budget = lease
	}
	// Fits inside the installed Health executor's 20s hard timeout, including
	// the preceding four-second path round. The lease is never extended here.
	if budget > 12000 {
		budget = 12000
	}
	return time.Duration(budget) * time.Millisecond, nil
}
func hostRouteCoreCommand(ctx context.Context, store *activationJournalDir, action string) error {
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
		return Fault("trial_recovery_uncertain", "bounded host Core operation outcome unavailable")
	}
	return nil
}

func reconnectHostRouteCore(store *activationJournalDir, r *hostRouteJournal) error {
	if r == nil || r.Supervision.Attempts >= r.Supervision.Options.MaxAttempts {
		return Fault("trial_recovery_uncertain", "host reconnect attempt budget exhausted")
	}
	if reason := inspectHostRouteRuntime(store, *r); reason != "" {
		return Fault("trial_recovery_uncertain", reason)
	}
	now, err := smartTUNUptimeMillis()
	if err != nil {
		return err
	}
	budget, err := hostRouteReconnectBudget(*r, now)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	unit, err := observeSmartTUNTrialUnit(ctx)
	if err != nil {
		return err
	}
	next := *r
	next.Supervision.Attempts++
	next.Supervision.Generation++
	next.Supervision.State, next.Supervision.ReconnectStage = "reconnecting", "stop_requested"
	if err := persistHostRouteParent(store, r, next); err != nil {
		return err
	}
	if err := stopSmartTUNTrialCoreWith(unit, true, true,
		func() (smartTUNTrialUnitObservation, error) { return observeSmartTUNTrialUnit(ctx) },
		func(action string) error { return hostRouteCoreCommand(ctx, store, action) }); err != nil {
		return err
	}
	next = *r
	next.Supervision.Generation++
	next.Supervision.ReconnectStage = "stopped"
	if err := persistHostRouteParent(store, r, next); err != nil {
		return err
	}
	if err := verifyHostRouteActivePolicy(*r); err != nil {
		return err
	}
	watch, err := nativeTUNWatchStart(r.nativeView())
	if err != nil {
		return err
	}
	defer watch.close()
	now, err = smartTUNUptimeMillis()
	if err != nil {
		return err
	}
	if _, err := hostRouteReconnectBudget(*r, now); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return Fault("trial_recovery_uncertain", "host reconnect command deadline expired")
	}
	next = *r
	next.Supervision.Generation++
	next.Supervision.ReconnectStage = "start_requested"
	if err := persistHostRouteParent(store, r, next); err != nil {
		return err
	}
	if err := hostRouteCoreCommand(ctx, store, "start"); err != nil {
		return err
	}
	if err := watch.verify(r.nativeView()); err != nil {
		return err
	}
	started, err := observeSmartTUNTrialUnit(ctx)
	if err != nil || started.activeState != "active" || started.mainPID == 0 ||
		started.identity != unit.identity {
		return Fault("trial_recovery_uncertain", "reconnected host Core identity unavailable")
	}
	process, err := readManagementProcess(int(started.mainPID))
	if err != nil {
		return err
	}
	next = *r
	next.Supervision.Generation++
	next.Supervision.CorePID, next.Supervision.CoreStartTicks = started.mainPID, process.StartTicks
	next.Supervision.State, next.Supervision.ReconnectStage = "degraded", "none"
	next.Supervision.Reason = "reconnect_awaiting_fresh_paths"
	if err := persistHostRouteParent(store, r, next); err != nil {
		return err
	}
	now, err = smartTUNUptimeMillis()
	if err != nil {
		return err
	}
	if _, err := hostRouteReconnectBudget(*r, now); err != nil {
		return err
	}
	next = *r
	next.Supervision.Generation++
	next.Supervision.HeartbeatMS, next.Supervision.LeaseDeadlineMS = now, now+smartTUNHealthLeaseMS
	next.Supervision.NextProbeMS = now + int64(next.Supervision.Attempts)*5000
	return persistHostRouteParent(store, r, next)
}

var errHostRouteConfirmRefresh = errors.New("host health renewed while fresh confirmation was measured")

func hostRouteConfirmHealthOnlyRefresh(before, after hostRouteJournal) bool {
	if !hostRouteSupervised(before) || !hostRouteSupervised(after) || before.Route.State != "observed" ||
		after.Route.State != "observed" || before.Supervision.Confirmed || after.Supervision.Confirmed ||
		before.Supervision.State != "awaiting_confirmation" || after.Supervision.State != "awaiting_confirmation" {
		return false
	}
	a, b := before.Supervision, after.Supervision
	if b.Generation <= a.Generation || b.Generation > a.Generation+2 || b.HeartbeatMS < a.HeartbeatMS ||
		b.LeaseDeadlineMS < a.LeaseDeadlineMS || b.Rounds < a.Rounds || b.Rounds > a.Rounds+1 {
		return false
	}
	next := before
	next.Supervision.Generation, next.Supervision.HeartbeatMS, next.Supervision.LeaseDeadlineMS = b.Generation, b.HeartbeatMS, b.LeaseDeadlineMS
	if b.Rounds == a.Rounds+1 {
		healthy, _ := hostRouteHealthSummary(b.Plans, b.Evidence)
		if !healthy || b.Reason != "selected_path_healthy" || b.Failures != 0 || b.RecoveryDeadlineMS != 0 || b.LastProbeMS < a.LastProbeMS {
			return false
		}
		next.Supervision.Rounds, next.Supervision.Evidence = b.Rounds, b.Evidence
		next.Supervision.LastProbeMS, next.Supervision.NextProbeMS, next.Supervision.Reason = b.LastProbeMS, b.NextProbeMS, b.Reason
	}
	return next == after
}

func (m *Manager) ConfirmHostRouteSupervision(op, challenge string) (HostRouteSupervisionReceipt, error) {
	if err := m.installedHostSupervisor(); err != nil {
		return HostRouteSupervisionReceipt{}, err
	}
	if !journalHex32.MatchString(op) || !journalHex64.MatchString(challenge) {
		return HostRouteSupervisionReceipt{}, Fault("invalid_arguments", "exact host operation and one-use challenge required")
	}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := m.confirmHostRouteOnce(op, challenge)
		if !errors.Is(err, errHostRouteConfirmRefresh) {
			return result, err
		}
	}
	return HostRouteSupervisionReceipt{}, Fault("confirmation_unavailable", "host health renewed during confirmation; original deadline still applies")
}
func (m *Manager) confirmHostRouteOnce(op, challenge string) (HostRouteSupervisionReceipt, error) {
	var result HostRouteSupervisionReceipt
	var snapshot hostRouteJournal
	var proof smartTUNManagementProof
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		r, _, err := loadHostRouteJournal(store)
		if err != nil {
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
		if !hostRouteConfirmMatches(r, op, challenge, boot, now) {
			return Fault("confirmation_rejected", "host confirmation is wrong, stale, replayed or expired")
		}
		if reason := inspectHostRouteRuntime(store, r); reason != "" {
			return Fault("confirmation_unavailable", reason)
		}
		proof, err = observeFreshGeneralHostSSH(r.Supervision.ManagementPeer, r.Progress.Ingress.Underlay, r.Supervision.ReadyAfterMS)
		if err != nil {
			return err
		}
		snapshot = r
		return nil
	})
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), smartTUNHealthRoundTimeout)
	evidence := probeHostRouteHealth(ctx, hostRouteHealthPlans(snapshot, snapshot.Supervision.Rounds+1))
	cancel()
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		current, _, err := loadHostRouteJournal(store)
		if err != nil {
			return err
		}
		if current != snapshot {
			if hostRouteConfirmHealthOnlyRefresh(snapshot, current) {
				return errHostRouteConfirmRefresh
			}
			return Fault("activation_journal_conflict", "host operation changed during confirmation")
		}
		if reason := inspectHostRouteRuntime(store, current); reason != "" {
			return Fault("confirmation_unavailable", reason)
		}
		again, err := observeFreshGeneralHostSSH(current.Supervision.ManagementPeer, current.Progress.Ingress.Underlay, current.Supervision.ReadyAfterMS)
		if err != nil {
			return err
		}
		if proof != again {
			return Fault("confirmation_rejected", "authenticated host SSH generation changed")
		}
		boot, err := trialBootIdentity()
		if err != nil {
			return err
		}
		now, err := smartTUNUptimeMillis()
		if err != nil {
			return err
		}
		if !hostRouteConfirmMatches(current, op, challenge, boot, now) {
			return Fault("confirmation_rejected", "host confirmation expired before publication")
		}
		next, action, err := advanceHostRouteHealth(current, evidence, now)
		if err != nil {
			return err
		}
		healthy, _ := hostRouteHealthSummary(next.Supervision.Plans, evidence)
		if action != "" || !healthy {
			return Fault("confirmation_unavailable", "fresh selected and protected host paths required")
		}
		next.Supervision.Confirmed, next.Supervision.ChallengeSHA256, next.Supervision.State = true, "", "healthy"
		next.Supervision.SessionSHA256, next.Supervision.SessionStartedMS = proof.SessionSHA256, proof.StartedUptimeMS
		next.Supervision.Reason = "confirmed_fresh_paths"
		if err := persistHostRouteParent(store, &current, next); err != nil {
			return err
		}
		result = hostRouteCurrentReceipt(current, now)
		return nil
	})
	return result, err
}

// Preserve the established installed timer command and its compact receipt;
// the explicit host status command exposes host-specific coverage boundaries.
func hostRouteTrialReceipt(r HostRouteSupervisionReceipt) SmartTUNTrialReceipt {
	return SmartTUNTrialReceipt{OperationID: r.OperationID, Phase: r.Phase, ExperimentOnly: true,
		GuardScheduled: r.GuardScheduled, RecoveryVerified: r.RecoveryVerified,
		SupervisionState: r.Phase, HealthReason: r.Reason, HealthRound: r.HealthRound,
		HealthLastUptimeMS: r.HealthLastUptimeMS, HealthFailures: r.Failures,
		ReconnectAttempts: r.ReconnectAttempts, RecoveryDeadlineUptimeMS: r.RecoveryDeadlineUptimeMS}
}
