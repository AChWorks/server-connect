//go:build linux

package sc

// observeHostIngressKernelQuiescence is a guarded, *non-authorizing* snapshot.
// Run it only after the same operation has durably staged accepted-socket
// marks and completed an independently journaled kernel grace barrier.
// Its strict in-kernel inet_diag mark predicates avoid pagination omissions
// under socket churn. Successful observation is NOT a socket reservation,
// persistent activation receipt, proof of foreign-owner cooperation, or
// permission to begin general-host capture. The final enclosing activation
// transaction and runtime guard must independently enforce those boundaries.
func observeHostIngressKernelQuiescence(r hostIngressStage, guard func() error) error {
	if guard == nil {
		return Fault("guard_unavailable", "independent ingress recovery is required")
	}
	if err := guard(); err != nil {
		return err
	}
	if err := hostIngressStageIntact(r); err != nil {
		return err
	}
	ports, before, err := hostIngressRawSnapshot()
	if err != nil {
		return err
	}
	if before != r.RawSHA256 || len(ports) == 0 {
		return ingressFault("verified NOTRACK sources changed or are absent")
	}
	// Check listener SO_MARK first: a foreign listener's nonzero mark can
	// override inherited SYN/ACK protection even if prior replies drained.
	if err := observeForeignMarkedListeners(ports); err != nil {
		return err
	}
	// Returned request and TIME_WAIT generations with no userspace inode are
	// still unsafe; the kernel-filtered query must refuse them as present.
	if err := observeUnmarkedHostIngress(ports); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if err := hostIngressStageIntact(r); err != nil {
		return err
	}
	_, after, err := hostIngressRawSnapshot()
	if err != nil {
		return err
	}
	if after != before {
		return ingressFault("foreign NOTRACK policy drifted around kernel socket observation")
	}
	return nil
}
