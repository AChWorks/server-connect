//go:build linux

package sc

import (
	"context"
	"encoding/json"
	"path/filepath"
	"syscall"
)

func nativeRestartCanTry(s NativeHealthState, now int64) bool {
	return s.RestartLimit > 0 && s.RestartAttempts < s.RestartLimit &&
		s.RestartIncidentMS > 0 && now >= s.RestartNextMS &&
		now >= s.RestartIncidentMS && now < s.RestartIncidentMS+s.RestartDeadlineMS
}

func nativeRestartDelay(s NativeHealthState) int64 {
	delay := s.RestartBackoffMS
	for i := 1; i < s.RestartAttempts && delay < 30000; i++ {
		delay *= 2
	}
	if delay > 30000 {
		delay = 30000
	}
	return delay
}

// Reuse the *same* operation-bound startup plan to install a fresh exact
// nft barrier before deliberately terminating a working Core child. The
// original post-startup barrier was fully removed; that old handle is never
// authority to adopt a new table. Retain crash-consistent preparing/armed
// receipts so ExecStopPost can still recover either interrupted transition.
func (m *Manager) rearmNativeRestartBarrierLocked(session NativeSession) error {
	if session.StartupGuardName == "" || session.StartupGuardPhase != "released" {
		return Fault("guard_pending", "Core restart requires a fully released initial startup barrier")
	}
	plan, err := m.readNativeStartupPlan(session)
	if err != nil {
		return err
	}
	present, err := nativeStartupPresent(context.Background(), nativeSystemRunner{}, plan.Name)
	if err != nil || present {
		return Fault("service_conflict", "Core restart startup slot unexpectedly occupied")
	}
	session.StartupGuardPhase = "preparing"
	session.StartupGuardHandle = 0
	raw, err := json.Marshal(session)
	if err != nil {
		return err
	}
	if err := put(filepath.Join(m.Dir, nativeSessionFile), raw); err != nil {
		return err
	}
	handle, err := nativeStartupInstall(context.Background(), nativeSystemRunner{}, plan)
	if err != nil {
		return err
	}
	session.StartupGuardHandle = handle
	session.StartupGuardPhase = "armed"
	raw, err = json.Marshal(session)
	if err != nil {
		return err
	}
	return put(filepath.Join(m.Dir, nativeSessionFile), raw)
}

// Signal only the verified installed manager MainPID, not sing-box itself.
// A SIGUSR1 on its own has no authority: the parent rechecks the complete
// barrier and operation receipt before stopping its child.
func (m *Manager) requestNativeCoreReplacement(id string) error {
	return m.withNativeTransition(func() error {
		var parent int
		var original nativeCoreIdentity
		err := m.withLock(func() error {
			s, e := m.readNativeHealth()
			if e != nil {
				return e
			}
			claim, e := m.readNativeSession()
			if e != nil {
				return e
			}
			state, e := m.load()
			if e != nil {
				return e
			}
			now, e := nativeUptimeMillis()
			if e != nil {
				return e
			}
			if state.Desired != "smart" || s.Phase != "recovering" ||
				s.OperationID != id || s.OperationID != claim.HealthOperationID ||
				s.ConfigSHA256 != claim.ConfigSHA256 || !nativeRestartCanTry(s, now) ||
				!claim.CoreStartAttempted {
				return Fault("guard_pending", "native Core restart no longer belongs to pending health incident")
			}
			if err := m.validateNativeSessionConfig(claim); err != nil {
				return err
			}
			if err := nativeHealthGuardRoles(); err != nil {
				return err
			}
			if err := requireNativeReplyGuardClaim(context.Background(), nativeSystemRunner{},
				claim.ReplyGuardHandle, claim.ReplyGuardFingerprint); err != nil {
				return err
			}
			// A failed VPN peer is not proof that our kernel policy or Core
			// identity is safe to replace. Fatal ownership/guard loss goes Off.
			raw, err := readRegular(filepath.Join(m.Dir, nativeConfigFile))
			if err != nil {
				return err
			}
			targets, err := nativeHealthTargets(raw, s.ProbeScope)
			if err != nil {
				return err
			}
			if err := inspectNativeHealthPolicy(context.Background(), nativeHealthKernelReader{}, claim.recoveryScope(), targets); err != nil {
				return err
			}
			original, parent, err = m.nativeCoreChildIdentity()
			if err != nil {
				return err
			}
			if err := m.rearmNativeRestartBarrierLocked(claim); err != nil {
				return err
			}
			s.RestartAttempts++
			s.RestartOriginalPID = original.PID
			s.RestartInFlight = true
			s.RestartResult = "restart_requested"
			s.Reason = "core_restart_in_progress"
			s.HeartbeatMS = now
			return m.saveNativeHealth(s)
		})
		if err != nil {
			return err
		}
		identity, nextParent, err := m.nativeCoreChildIdentity()
		if err != nil || identity != original || nextParent != parent {
			return Fault("guard_pending", "supervised Core identity changed before restart request")
		}
		return syscall.Kill(parent, syscall.SIGUSR1)
	})
}

// Hold the shared transition lock across Core replacement observation,
// barrier release and selected-path publication. A concurrent operator
// Disconnect must not interleave stop-hook cleanup with nft removal.
func (m *Manager) nativeRestartWaitOrVerify(s NativeHealthState, claim NativeSession, targets []nativeProbeTarget, now int64) (NativeHealthState, error) {
	var next NativeHealthState
	err := m.withNativeTransition(func() error {
		var e error
		next, e = m.nativeRestartWaitOrVerifyUnlocked(s, claim, targets, now)
		return e
	})
	return next, err
}

func (m *Manager) nativeRestartWaitOrVerifyUnlocked(s NativeHealthState, claim NativeSession, targets []nativeProbeTarget, now int64) (NativeHealthState, error) {
	if err := m.withLock(func() error {
		current, e := m.readNativeSession()
		if e != nil || current != claim {
			return Fault("guard_pending", "Core restart session changed before guarded release")
		}
		state, e := m.load()
		if e != nil || state.Desired != "smart" {
			return Fault("guard_pending", "Core restart is no longer authorized to be routed")
		}
		latest, e := m.readNativeHealth()
		if e != nil || latest != s {
			return Fault("guard_pending", "Core restart health generation changed")
		}
		return nil
	}); err != nil {
		return s, err
	}
	plan, err := m.readNativeStartupPlan(claim)
	if err != nil {
		return s, err
	}
	if claim.StartupGuardPhase != "armed" {
		return s, Fault("guard_unavailable", "Core restart barrier not committed")
	}
	if err := requireNativeStartupGuardClaim(context.Background(), nativeSystemRunner{}, plan, claim.StartupGuardHandle); err != nil {
		return s, err
	}
	newCore, _, err := m.nativeCoreChildIdentity()
	if err != nil || newCore.PID == s.RestartOriginalPID {
		// Parent may still be replacing its child. The barrier, independent
		// guard roles and incident deadline remain the only temporary safety.
		if now >= s.RestartIncidentMS+s.RestartDeadlineMS {
			return s, Fault("guard_unavailable", "bounded Core restart timed out")
		}
		previous := s
		s.HeartbeatMS, s.Rounds = now, s.Rounds+1
		s.RestartResult = "waiting_for_fresh_core"
		err = m.withLock(func() error {
			latest, e := m.readNativeHealth()
			if e != nil || latest != previous {
				return Fault("guard_pending", "native Core retry belongs to a superseded health operation")
			}
			current, e := m.readNativeSession()
			if e != nil || current != claim {
				return Fault("guard_pending", "native Core retry ownership changed during wait")
			}
			return m.saveNativeHealth(s)
		})
		return s, err
	}
	if err := m.nativeReadyKernelPolicy(claim, s.ProbeScope); err != nil {
		// A child exists but may still be rebuilding TUN and redirect.
		previous := s
		s.HeartbeatMS, s.Rounds = now, s.Rounds+1
		s.RestartResult = "waiting_for_kernel_policy"
		err = m.withLock(func() error {
			latest, e := m.readNativeHealth()
			if e != nil || latest != previous {
				return Fault("guard_pending", "Core policy readiness belongs to a superseded restart")
			}
			current, e := m.readNativeSession()
			if e != nil || current != claim {
				return Fault("guard_pending", "Core policy receipt changed during restart")
			}
			return m.saveNativeHealth(s)
		})
		return s, err
	}
	// The exact new process and kernel interception are independently
	// established before removing the temporary OUTPUT barrier.
	if err := m.releaseNativeStartupAfterReady(claim); err != nil {
		return s, err
	}
	if err := m.finishNativeStartupRelease(claim); err != nil {
		return s, err
	}
	outcome := runNativeHealthProbes(context.Background(), claim.InterfaceName, s.ProbeScope, targets, probeNativeHTTPS)
	after, _, err := m.nativeCoreChildIdentity()
	if err != nil || after != newCore {
		return s, Fault("guard_unavailable", "Core changed again during selected-path reproof")
	}
	now, err = nativeUptimeMillis()
	if err != nil {
		return s, err
	}
	err = m.withLock(func() error {
		latest, e := m.readNativeHealth()
		if e != nil {
			return e
		}
		current, e := m.readNativeSession()
		if e != nil {
			return e
		}
		if latest != s || latest.OperationID != current.HealthOperationID ||
			current.StartupGuardPhase != "released" {
			return Fault("guard_pending", "native selected recovery result belongs to old operation")
		}
		if e := nativeHealthGuardRoles(); e != nil {
			return e
		}
		if e := inspectNativeHealthPolicy(context.Background(), nativeHealthKernelReader{}, claim.recoveryScope(), targets); e != nil {
			return e
		}
		latest.HeartbeatMS, latest.LastProbeMS = now, now
		latest.Rounds++
		latest.RestartInFlight = false
		latest.RestartFromPID = latest.RestartOriginalPID
		latest.RestartToPID = newCore.PID
		latest.RestartToStarted = newCore.Started
		latest.RestartOriginalPID = 0
		if outcome.OK {
			latest.Phase, latest.Reason, latest.Failures = "healthy", "selected_https_verified", 0
			latest.RestartIncidentMS = 0
			latest.RestartResult = "fresh_core_selected_path_verified"
		} else {
			latest.Phase, latest.Reason = "recovering", outcome.Reason
			latest.UnhealthyRounds++
			if latest.Failures < latest.FailureThreshold {
				latest.Failures++
			}
			latest.RestartNextMS = now + nativeRestartDelay(latest)
			latest.RestartResult = "fresh_core_selected_path_unavailable"
		}
		s = latest
		return m.saveNativeHealth(latest)
	})
	return s, err
}

func (m *Manager) advanceNativeCoreRecovery(s NativeHealthState, claim NativeSession, targets []nativeProbeTarget) (NativeHealthState, error) {
	// Every in-flight restart remains subject to the independent timer and
	// operation-wide deadline, including between process exit and new TUN.
	now, err := nativeUptimeMillis()
	if err != nil {
		return s, err
	}
	boot, err := trialBootIdentity()
	if err != nil || s.BootID != boot || now < s.StartedMS {
		return m.failNativeCoreRecovery(s, "native_boot_identity_changed")
	}
	if err := nativeHealthGuardRoles(); err != nil {
		return m.failNativeCoreRecovery(s, "runtime_guard_unavailable")
	}
	if now >= s.RestartIncidentMS+s.RestartDeadlineMS {
		return m.failNativeCoreRecovery(s, "core_restart_deadline_exhausted")
	}
	if s.RestartInFlight {
		next, err := m.nativeRestartWaitOrVerify(s, claim, targets, now)
		if err != nil {
			return m.failNativeCoreRecovery(s, "core_restart_guard_or_policy_unverified")
		}
		if next.Phase == "healthy" {
			return next, nil
		}
		if next.RestartInFlight {
			return next, nil
		}
		s = next
	}
	if s.RestartAttempts >= s.RestartLimit || s.RestartLimit == 0 {
		return m.failNativeCoreRecovery(s, "core_restart_attempts_exhausted")
	}
	if now < s.RestartNextMS {
		// A live Core in its own verified policy continues protecting all
		// VPN-required traffic between bounded retry attempts.
		if _, _, err := m.nativeCoreChildIdentity(); err != nil {
			return m.failNativeCoreRecovery(s, "native_core_unavailable")
		}
		if err := inspectNativeHealthPolicy(context.Background(), nativeHealthKernelReader{}, claim.recoveryScope(), targets); err != nil {
			return m.failNativeCoreRecovery(s, "native_policy_unverified")
		}
		previous := s
		s.HeartbeatMS, s.Rounds = now, s.Rounds+1
		if err := m.withLock(func() error {
			latest, e := m.readNativeHealth()
			if e != nil || latest != previous {
				return Fault("guard_pending", "recovery backoff superseded")
			}
			current, e := m.readNativeSession()
			if e != nil || current != claim {
				return Fault("guard_pending", "recovery backoff ownership changed")
			}
			return m.saveNativeHealth(s)
		}); err != nil {
			return s, err
		}
		return s, nil
	}
	if err := m.requestNativeCoreReplacement(s.OperationID); err != nil {
		return m.failNativeCoreRecovery(s, "core_restart_request_failed")
	}
	next, err := m.readNativeHealth()
	if err != nil {
		return s, err
	}
	return next, nil
}

func (m *Manager) failNativeCoreRecovery(s NativeHealthState, reason string) (NativeHealthState, error) {
	stopped, err := m.stopNativeHealthOperation(s.OperationID, reason)
	if err != nil {
		return s, err
	}
	if !stopped {
		return s, Fault("guard_pending", "native recovery belongs to superseded Core operation")
	}
	s.Phase, s.Reason, s.RestartResult = "off", reason, reason
	s.RestartInFlight = false
	s.RestartOriginalPID = 0
	return s, nil
}

// Kept as a deterministic policy boundary for fault/flap/backoff tests.
func nativeEnterCoreRecovery(s NativeHealthState, now int64) (NativeHealthState, bool) {
	if s.RestartLimit == 0 || s.RestartAttempts >= s.RestartLimit {
		return s, false
	}
	if s.RestartIncidentMS == 0 {
		s.RestartIncidentMS = now
		s.RestartNextMS = now
	}
	if now >= s.RestartIncidentMS+s.RestartDeadlineMS {
		return s, false
	}
	s.Phase, s.Reason = "recovering", "selected_path_restart_pending"
	return s, true
}
