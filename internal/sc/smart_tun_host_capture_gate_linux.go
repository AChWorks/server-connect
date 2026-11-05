//go:build linux

package sc

// This is an internal, non-admitting bridge between the independently
// journalable ingress and kernel-grace primitives. It does NOT create a
// general-host operation, start a core, install capture routes, or authorize
// ACTIVE_VERIFIED. A future caller must first own one durable enclosing
// activation journal and an independently functioning recovery executor.
//
// Every callback is required to persist its portion of the SAME enclosing
// operation with compare-and-swap on the full previous record. Mixing two
// journals, operations, boot epochs or network namespaces is forbidden.

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

// A fresh staging plan requires the host to ALREADY have TCP mark inheritance
// enabled. Linux does not expose a scalar sysctl generation/CAS; changing
// tcp_fwmark_accept on a real shared host cannot be safely attributed.
// The standalone 0->1 ingress experiment remains confined to native QA.
func newHostCaptureGatePair(underlay string, deadlineSeconds int) (hostIngressStage, hostNetworkBarrier, error) {
	ingress, err := newHostIngressStage(underlay, deadlineSeconds)
	if err != nil {
		return hostIngressStage{}, hostNetworkBarrier{}, err
	}
	if ingress.SysctlBefore != 1 {
		return hostIngressStage{}, hostNetworkBarrier{}, ingressFault("shared host requires preexisting tcp_fwmark_accept=1")
	}
	barrier, err := newHostNetworkBarrier(ingress.OperationID)
	if err != nil {
		return hostIngressStage{}, hostNetworkBarrier{}, err
	}
	if err := validateHostCaptureGatePair(ingress, barrier); err != nil {
		return hostIngressStage{}, hostNetworkBarrier{}, err
	}
	return ingress, barrier, nil
}

// runHostCaptureGateLocked prepares only the two exact owned prerequisites.
// It must be called with the shared activation lock held, with recovery
// independently armed, and with both persistence adapters wired to ONE durable
// parent journal. On any error the caller must keep that journal for its
// independent recovery role: a partially staged ingress is never a safe
// absence claim. A successful return is a snapshot, NOT authorization to
// publish capture; the parent must revalidate every mutable identity and
// completed phase immediately before any subsequent native mutation.
func runHostCaptureGateLocked(
	store *activationJournalDir,
	ingress *hostIngressStage,
	barrier *hostNetworkBarrier,
	guard func() error,
	persistIngress hostIngressPersist,
	persistBarrier hostNetworkBarrierPersist,
) error {
	if store == nil || ingress == nil || barrier == nil ||
		guard == nil || persistIngress == nil || persistBarrier == nil {
		return Fault("guard_unavailable", "one independently recoverable host capture operation is required")
	}
	if err := validateHostCaptureGatePair(*ingress, *barrier); err != nil {
		return err
	}
	if ingress.SysctlBefore != 1 ||
		ingress.Phase != "pending" || ingress.SysctlStage != "planned" ||
		ingress.NFTStage != "planned" || barrier.Stage != "planned" {
		return ingressFault("host capture requires a fresh, preenabled, unmodified ingress and barrier")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if err := hostIngressBeforeDeadline(*ingress); err != nil {
		return err
	}
	if err := hostIngressNamespace(*ingress); err != nil {
		return err
	}
	if err := hostIngressUnderlay(*ingress); err != nil {
		return err
	}
	if err := hostNetworkBarrierContext(*barrier); err != nil {
		return err
	}
	// Existing reserved socket marks are another owner's state, not
	// permission to mark or exempt that process. This check must run
	// BEFORE this operation creates intentionally bypass-marked sockets.
	if err := observeReservedHostSocketMarks(); err != nil {
		return err
	}
	if err := applyHostIngressStageWithPersistLocked(store, ingress, guard, persistIngress); err != nil {
		return err
	}
	// A two-sided userspace snapshot alone is never the final admission
	// proof; it first eliminates obvious old-generation and foreign marks.
	if err := hostIngressDrainBarrier(*ingress, guard); err != nil {
		return err
	}
	// Completion of the creating TUN's final FD close provides the kernel
	// grace interval. Its progress and close receipt are durable in the
	// SAME operation journal as the ingress stage.
	if err := runHostNetworkBarrierLocked(store, barrier, guard, persistBarrier); err != nil {
		return err
	}
	if err := observeHostIngressKernelQuiescence(*ingress, guard); err != nil {
		return err
	}
	if err := hostIngressStageIntact(*ingress); err != nil {
		return err
	}
	if err := verifyHostNetworkBarrierReleased(*barrier); err != nil {
		return err
	}
	if err := validateHostCaptureGatePair(*ingress, *barrier); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	return hostIngressBeforeDeadline(*ingress)
}
