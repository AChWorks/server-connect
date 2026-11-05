//go:build linux

package sc

// This private bridge coordinates the journalable ingress and kernel-grace
// primitives. It DOES NOT create a general-host operation, start a core,
// change capture routes, or authorize ACTIVE_VERIFIED. A future caller must
// first own one durable enclosing activation journal, an independently
// functioning recovery executor, and the complete native routing ledger.
//
// The single parent-progress persistence callback must compare the FULL old
// enclosing operation and fsync the replacement BEFORE returning success.
// Two independent journal writers are deliberately not accepted.

type hostCaptureGateProgress struct {
	Ingress hostIngressStage   `json:"ingress"`
	Barrier hostNetworkBarrier `json:"barrier"`
}

type hostCaptureGatePersist func(previous, next hostCaptureGateProgress) error

func validateHostCaptureGatePair(ingress hostIngressStage, barrier hostNetworkBarrier) error {
	if err := validateHostIngressStage(ingress); err != nil {
		return err
	}
	if err := validateHostNetworkBarrier(barrier); err != nil {
		return err
	}
	if ingress.OperationID != barrier.OperationID || ingress.BootID != barrier.BootID ||
		ingress.NamespaceDev != barrier.NamespaceDev || ingress.NamespaceIno != barrier.NamespaceIno {
		return ingressFault("host capture gate crosses operation, boot or network namespace ownership")
	}
	return nil
}

// A fresh plan requires the host to ALREADY have TCP mark inheritance
// enabled. Linux does not expose a scalar sysctl generation/CAS; changing
// tcp_fwmark_accept on a shared host cannot be safely attributed.
// The standalone 0->1 ingress experiment remains confined to native QA.
func newHostCaptureGateProgress(underlay string, deadlineSeconds int) (hostCaptureGateProgress, error) {
	ingress, err := newHostIngressStage(underlay, deadlineSeconds)
	if err != nil {
		return hostCaptureGateProgress{}, err
	}
	if ingress.SysctlBefore != 1 {
		return hostCaptureGateProgress{}, ingressFault("shared host requires preexisting tcp_fwmark_accept=1")
	}
	barrier, err := newHostNetworkBarrier(ingress.OperationID)
	if err != nil {
		return hostCaptureGateProgress{}, err
	}
	if err := validateHostCaptureGatePair(ingress, barrier); err != nil {
		return hostCaptureGateProgress{}, err
	}
	return hostCaptureGateProgress{Ingress: ingress, Barrier: barrier}, nil
}

// Both native primitives receive adapters to the EXACT SAME full-parent
// persistence function. Every previous-stage comparison and next-stage write
// remains bound to the original ingress/barrier pair. These adapters can be
// reconstructed from an independently decoded enclosing journal to recover
// the exact owned ingress stage after an interrupted operation.
func hostCaptureIngressPersistence(current *hostCaptureGateProgress, persist hostCaptureGatePersist) hostIngressPersist {
	return func(previous *hostIngressStage, next hostIngressStage) error {
		if current == nil || persist == nil {
			return Fault("guard_unavailable", "single parent host capture persistence is required")
		}
		if previous == nil {
			if current.Ingress != next {
				return Fault("activation_journal_conflict", "new ingress does not match durable parent")
			}
		} else if current.Ingress != *previous {
			return Fault("activation_journal_conflict", "ingress parent snapshot changed")
		}
		after := *current
		after.Ingress = next
		if err := validateHostCaptureGatePair(after.Ingress, after.Barrier); err != nil {
			return err
		}
		if err := persist(*current, after); err != nil {
			return err
		}
		*current = after
		return nil
	}
}

func hostCaptureBarrierPersistence(current *hostCaptureGateProgress, persist hostCaptureGatePersist) hostNetworkBarrierPersist {
	return func(previous, next hostNetworkBarrier) error {
		if current == nil || persist == nil {
			return Fault("guard_unavailable", "single parent host capture persistence is required")
		}
		if current.Barrier != previous {
			return Fault("activation_journal_conflict", "barrier parent snapshot changed")
		}
		after := *current
		after.Barrier = next
		if err := validateHostCaptureGatePair(after.Ingress, after.Barrier); err != nil {
			return err
		}
		if err := persist(*current, after); err != nil {
			return err
		}
		*current = after
		return nil
	}
}

// runHostCaptureGateLocked stages only the two owned prerequisites.
// The caller must hold the shared activation lock, have independently armed
// recovery, and persist initial progress in one durable enclosing journal.
// An error may leave ingress applied: the caller MUST retain the parent for
// independent recovery, never infer Off from a failed return. A successful
// return is a fleeting observation, NOT admission to publish capture; the
// eventual native transaction must revalidate all identities immediately
// before changing routes/policy and retain active Runtime Health Guard.
func runHostCaptureGateLocked(
	store *activationJournalDir,
	current *hostCaptureGateProgress,
	guard func() error,
	persist hostCaptureGatePersist,
) error {
	if store == nil || current == nil || guard == nil || persist == nil {
		return Fault("guard_unavailable", "one independently recoverable host capture operation is required")
	}
	if err := validateHostCaptureGatePair(current.Ingress, current.Barrier); err != nil {
		return err
	}
	if current.Ingress.SysctlBefore != 1 ||
		current.Ingress.Phase != "pending" || current.Ingress.SysctlStage != "planned" ||
		current.Ingress.NFTStage != "planned" || current.Barrier.Stage != "planned" {
		return ingressFault("host capture requires a fresh, preenabled, unmodified ingress and barrier")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if err := hostIngressBeforeDeadline(current.Ingress); err != nil {
		return err
	}
	if err := hostIngressNamespace(current.Ingress); err != nil {
		return err
	}
	if err := hostIngressUnderlay(current.Ingress); err != nil {
		return err
	}
	if err := hostNetworkBarrierContext(current.Barrier); err != nil {
		return err
	}
	// Preexisting reserved socket marks are another owner's state. Run this
	// BEFORE staging creates intentionally bypass-marked accepted sockets.
	if err := observeReservedHostSocketMarks(); err != nil {
		return err
	}
	if err := applyHostIngressStageWithPersistLocked(store, &current.Ingress, guard,
		hostCaptureIngressPersistence(current, persist)); err != nil {
		return err
	}
	// Userspace drain first, independently journaled kernel grace next,
	// in-kernel filtered socket query last. No snapshot is a reservation.
	if err := hostIngressDrainBarrier(current.Ingress, guard); err != nil {
		return err
	}
	if err := runHostNetworkBarrierLocked(store, &current.Barrier, guard,
		hostCaptureBarrierPersistence(current, persist)); err != nil {
		return err
	}
	if err := observeHostIngressKernelQuiescence(current.Ingress, guard); err != nil {
		return err
	}
	if err := hostIngressStageIntact(current.Ingress); err != nil {
		return err
	}
	if err := verifyHostNetworkBarrierReleased(current.Barrier); err != nil {
		return err
	}
	if err := validateHostCaptureGatePair(current.Ingress, current.Barrier); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	return hostIngressBeforeDeadline(current.Ingress)
}

// recoverHostCaptureGateLocked is the bounded Off helper for an interrupted
// ingress/grace prerequisite, not the complete native TUN recovery handler.
// The enclosing independent executor must have already selected/validated
// this exact full operation under the SAME manager lock. A failed barrier
// lifetime cannot be replayed or promoted to "closed" from interface absence.
// Recovery may remove only the journaled ingress table and may never invent
// authority over an unowned sysctl. A partial/ambiguous restoration retains
// the parent for another exact-operation recovery attempt.
func recoverHostCaptureGateLocked(
	store *activationJournalDir,
	current *hostCaptureGateProgress,
	persist hostCaptureGatePersist,
) (HostIngressStageReceipt, error) {
	if store == nil || current == nil || persist == nil {
		return HostIngressStageReceipt{}, Fault("guard_unavailable", "single parent host capture recovery is required")
	}
	if err := validateHostCaptureGatePair(current.Ingress, current.Barrier); err != nil {
		return HostIngressStageReceipt{}, err
	}
	if err := store.ensureLockIdentity(); err != nil {
		return HostIngressStageReceipt{}, err
	}
	// A create_possible record is NOT a completed grace barrier. The
	// absence check is only an ownership/release proof for the helper FD;
	// no synchronized-capture receipt is minted during recovery.
	boot, err := trialBootIdentity()
	if err != nil {
		return HostIngressStageReceipt{}, err
	}
	if boot == current.Barrier.BootID {
		if err := hostNetworkBarrierContext(current.Barrier); err != nil {
			return HostIngressStageReceipt{}, err
		}
	}
	// Across reboot, there is no FD lifetime to continue and no previous
	// namespace/handle may be mutated. In both cases require current absence
	// of this exact helper name, never synthesize a closed receipt.
	if err := verifyHostNetworkBarrierReleased(current.Barrier); err != nil {
		return HostIngressStageReceipt{}, err
	}
	result, err := recoverHostIngressStageWithPersistLocked(store, &current.Ingress, true,
		hostCaptureIngressPersistence(current, persist))
	if err != nil {
		return result, err
	}
	if !result.RecoveryVerified || current.Ingress.Phase != "recovered" {
		return result, ingressFault("host ingress recovery was not independently verified")
	}
	if err := verifyHostNetworkBarrierReleased(current.Barrier); err != nil {
		result.RecoveryVerified = false
		return result, err
	}
	if err := validateHostCaptureGatePair(current.Ingress, current.Barrier); err != nil {
		result.RecoveryVerified = false
		return result, err
	}
	return result, nil
}
