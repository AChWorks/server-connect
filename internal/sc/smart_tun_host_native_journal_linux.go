//go:build linux

package sc

// v7 is a separate, deliberately limited native-LINK preparation journal.
// It owns one host ingress + kernel grace barrier + one exclusive native TUN.
// It NEVER starts sing-box, adds policy routes/rules/nft capture, or claims
// general-host routing. Real Apply requires a further reviewed transaction
// with complete native policy, core, health and independently bounded Off.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
)

const (
	hostNativeJournalVersion = 7
	hostNativeJournalIntent  = "host_native_link_preparation_v1"
)

type hostNativeJournal struct {
	Version         int                     `json:"version"`
	Intent          string                  `json:"intent_type"`
	Progress        hostCaptureGateProgress `json:"progress"`
	TunnelInterface string                  `json:"tunnel_interface"`
	Native          smartTUNNativeLedger    `json:"native"`
}

func validateHostNativeJournal(r hostNativeJournal) error {
	bad := func() error {
		return activationJournalError("host native preparation identity or resource state invalid")
	}
	if r.Version != hostNativeJournalVersion || r.Intent != hostNativeJournalIntent ||
		validateHostCaptureGatePair(r.Progress.Ingress, r.Progress.Barrier) != nil ||
		r.Progress.Ingress.SysctlBefore != 1 ||
		!smartTUNDeviceName.MatchString(r.TunnelInterface) ||
		r.TunnelInterface == "lo" || r.TunnelInterface == r.Progress.Ingress.Underlay ||
		r.TunnelInterface == r.Progress.Barrier.Name {
		return bad()
	}
	i, n := r.Progress.Ingress, r.Native
	if n.Version != 1 || n.NamespaceDev != i.NamespaceDev || n.NamespaceIno != i.NamespaceIno ||
		n.UnderlayIndex != i.UnderlayIndex || n.NFTName != "scnt_"+i.OperationID ||
		n.IPv4.Address != "172.31.99.1/30" || n.IPv4.Table != nativeTUNTable4 ||
		n.IPv6.Address != "" || n.IPv6.Table != nativeTUNTable6 ||
		n.DNSResolverIPv4 != "" || n.DNSStage != "" || n.DNSSHA256 != "" ||
		n.StartupVerified || n.StopReason != "" ||
		n.NFT.Stage != "planned" || n.NFT.SHA256 != "" || n.NFTHandle != 0 || n.NFTCount != 0 ||
		n.NFTObjects != ([24]smartTUNNativeNFTIdentity{}) {
		return bad()
	}
	for _, f := range []smartTUNNativeFamily{n.IPv4, n.IPv6} {
		if f.Rule.Stage != "planned" || f.Route.Stage != "planned" || f.Fallback.Stage != "planned" ||
			f.Rule.SHA256 != "" || f.Route.SHA256 != "" || f.Fallback.SHA256 != "" {
			return bad()
		}
	}
	switch n.LinkStage {
	case "planned", "create_possible":
		if n.LinkIndex != 0 || n.LinkSHA256 != "" || n.AddressSHA256 != "" ||
			n.IPv4.DependentSHA256 != "" || n.IPv6.DependentSHA256 != "" {
			return bad()
		}
	case "bound", "persist_possible", "observed", "remove_requested", "removed":
		if n.LinkStage == "removed" && n.LinkIndex == 0 {
			if n.LinkSHA256 != "" || n.AddressSHA256 != "" ||
				n.IPv4.DependentSHA256 != "" || n.IPv6.DependentSHA256 != "" {
				return bad()
			}
		} else if n.LinkIndex < 2 || n.LinkIndex == n.UnderlayIndex ||
			!journalHex64.MatchString(n.LinkSHA256) || !journalHex64.MatchString(n.AddressSHA256) ||
			!journalHex64.MatchString(n.IPv4.DependentSHA256) || !journalHex64.MatchString(n.IPv6.DependentSHA256) {
			return bad()
		}
	default:
		return bad()
	}
	if n.LinkStage != "planned" && n.LinkStage != "removed" &&
		(i.Phase != "pending" || i.SysctlStage != "observed" || i.NFTStage != "observed" ||
			r.Progress.Barrier.Stage != "closed") {
		return bad()
	}
	if i.Phase == "recovered" && n.LinkStage != "removed" {
		return bad()
	}
	if i.Phase == "pending" && r.Progress.Barrier.Stage != "planned" && i.NFTStage != "observed" {
		return bad()
	}
	return nil
}

func decodeHostNativeJournal(raw []byte) (hostNativeJournal, error) {
	var r hostNativeJournal
	if err := rejectAmbiguousJournalJSON(raw); err != nil {
		return r, err
	}
	if err := requireExactJournalKeys(raw, map[string]bool{
		"version": true, "intent_type": true, "progress": true, "tunnel_interface": true, "native": true,
	}); err != nil {
		return r, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return r, activationJournalError("host native parent JSON invalid")
	}
	for _, v := range fields {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return r, activationJournalError("null host native parent member")
		}
	}
	if err := requireExactJournalKeys(fields["progress"], map[string]bool{"ingress": true, "barrier": true}); err != nil {
		return r, err
	}
	var nested map[string]json.RawMessage
	if json.Unmarshal(fields["progress"], &nested) != nil {
		return r, activationJournalError("host native progress invalid")
	}
	ingress, err := decodeHostIngressStage(nested["ingress"])
	if err != nil {
		return r, err
	}
	barrier, err := decodeHostNetworkBarrier(nested["barrier"])
	if err != nil {
		return r, err
	}
	if err := strictSmartTUNNativeJSON(fields["native"]); err != nil {
		return r, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil {
		return hostNativeJournal{}, activationJournalError("host native parent schema invalid")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return hostNativeJournal{}, activationJournalError("host native parent trailing content")
	}
	if r.Progress.Ingress != ingress || r.Progress.Barrier != barrier {
		return hostNativeJournal{}, activationJournalError("host native parent changed typed progress")
	}
	return r, validateHostNativeJournal(r)
}

func loadHostNativeJournal(store *activationJournalDir) (hostNativeJournal, activationJournalFileIdentity, error) {
	raw, id, err := store.readJournal()
	if err != nil {
		return hostNativeJournal{}, id, err
	}
	r, err := decodeHostNativeJournal(raw)
	return r, id, err
}
func writeHostNativeJournal(store *activationJournalDir, r hostNativeJournal, old *activationJournalFileIdentity) error {
	if err := validateHostNativeJournal(r); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return activationJournalError("cannot encode host native parent")
	}
	return store.writeJournal(append(raw, '\n'), old)
}
func hostNativeSame(a, b hostNativeJournal) bool { return a == b }

// All native and host ingress mutations have one pinned full-parent CAS and
// readback. This adapter never reads/writes a second v4 journal.
func persistHostNativeParent(store *activationJournalDir, current *hostNativeJournal, next hostNativeJournal) error {
	if store == nil || current == nil {
		return Fault("guard_unavailable", "missing enclosing host native journal")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	actual, id, err := loadHostNativeJournal(store)
	if err != nil {
		return err
	}
	if !hostNativeSame(actual, *current) {
		return Fault("activation_journal_conflict", "host native parent changed")
	}
	if err := writeHostNativeJournal(store, next, &id); err != nil {
		return err
	}
	readback, _, err := loadHostNativeJournal(store)
	if err != nil {
		return err
	}
	if !hostNativeSame(readback, next) {
		return Fault("activation_journal_conflict", "host native parent readback mismatch")
	}
	*current = next
	return nil
}
func hostNativeCapturePersist(store *activationJournalDir, r *hostNativeJournal) hostCaptureGatePersist {
	return func(before, after hostCaptureGateProgress) error {
		if r == nil || r.Progress != before {
			return Fault("activation_journal_conflict", "host native ingress parent changed")
		}
		next := *r
		next.Progress = after
		return persistHostNativeParent(store, r, next)
	}
}
func (r hostNativeJournal) nativeView() smartTUNTrialJournal {
	n := r.Native
	return smartTUNTrialJournal{OperationID: r.Progress.Ingress.OperationID, BootID: r.Progress.Ingress.BootID,
		UnderlayInterface: r.Progress.Ingress.Underlay, TunnelInterface: r.TunnelInterface, Native: &n}
}
func hostNativeLinkPersist(store *activationJournalDir, r *hostNativeJournal) nativeTUNRecordPersist {
	return func(before, after smartTUNTrialJournal) error {
		if r == nil || !sameSmartTUNTrial(r.nativeView(), before) {
			return Fault("activation_journal_conflict", "host native link parent changed")
		}
		fixed := r.nativeView()
		fixed.Native = nil
		changed := cloneSmartTUNTrial(after)
		changed.Native = nil
		if fixed != changed || after.Native == nil {
			return Fault("activation_journal_conflict", "host native operation metadata changed")
		}
		next := *r
		next.Native = *after.Native
		return persistHostNativeParent(store, r, next)
	}
}

// No core/start authority is recorded or invented by this native-link-only
// journal. The independently verified installed TUN service must be idle.
func hostNativeCoreIdle() error {
	observed, err := observeSmartTUNTrialUnit(context.Background())
	if err != nil {
		return err
	}
	if !observed.stopped() {
		return Fault("service_conflict", "native-link preparation cannot own a live sing-box core")
	}
	return nil
}

// Only the actual independent executor may select v7 under the shared lock.
// Test-only injection of idle verification never changes that selection.
func recoverHostNativeJournalLocked(store *activationJournalDir, r *hostNativeJournal, idle func() error) (TrialReceipt, error) {
	if r == nil {
		return TrialReceipt{}, Fault("guard_unavailable", "missing host native recovery record")
	}
	receipt := TrialReceipt{OperationID: r.Progress.Ingress.OperationID, Phase: "host_native_uncertain", ExperimentOnly: true}
	if err := validateHostNativeJournal(*r); err != nil {
		return receipt, err
	}
	if store == nil || idle == nil {
		return receipt, Fault("guard_unavailable", "host native independent recovery not available")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return receipt, err
	}
	if err := idle(); err != nil {
		return receipt, err
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return receipt, err
	}
	if boot == r.Progress.Ingress.BootID {
		native := r.nativeView()
		if err := nativeTUNCheckRecoveryGraph(native); err != nil {
			return receipt, err
		}
		if err := nativeTUNRemoveLinkWithPersist(store, &native, "", hostNativeLinkPersist(store, r)); err != nil {
			return receipt, err
		}
	} else {
		if err := hostNativeOldBootLinkAbsent(*r); err != nil {
			return receipt, err
		}
		next := *r
		next.Native.LinkStage = "removed"
		if err := persistHostNativeParent(store, r, next); err != nil {
			return receipt, err
		}
	}
	if err := hostNativeVerifyLinkAbsent(*r, boot); err != nil {
		return receipt, err
	}
	result, err := recoverHostCaptureGateLocked(store, &r.Progress, hostNativeCapturePersist(store, r))
	if err != nil {
		return receipt, err
	}
	if !result.RecoveryVerified {
		return receipt, Fault("trial_recovery_uncertain", "host native ingress recovery was not verified")
	}
	if err := hostNativeVerifyLinkAbsent(*r, boot); err != nil {
		return receipt, err
	}
	receipt.Phase, receipt.RecoveryVerified = "host_native_recovered", true
	return receipt, nil
}

func hostNativeVerifyLinkAbsent(r hostNativeJournal, boot string) error {
	if boot != r.Progress.Ingress.BootID {
		return hostNativeOldBootLinkAbsent(r)
	}
	native := r.nativeView()
	if err := nativeTUNCheckRecoveryGraph(native); err != nil {
		return err
	}
	if r.Native.LinkStage != "removed" {
		return Fault("trial_recovery_uncertain", "owned TUN link not durably removed")
	}
	link, err := nativeTUNObserveLink(native)
	if err != nil {
		return err
	}
	if link.Present {
		return Fault("trial_resource_conflict", "owned TUN link remains")
	}
	return nil
}
func hostNativeOldBootLinkAbsent(r hostNativeJournal) error {
	// A prior-boot identity is never deletion authority. A name collision or
	// reserved policy slot retains uncertainty, not a restored claim.
	rows, err := nativeTUNRows("-d", "-j", "link", "show")
	if err != nil {
		return err
	}
	for _, row := range rows {
		if selectiveText(row["ifname"]) == r.TunnelInterface {
			return Fault("trial_resource_conflict", "old-boot native TUN name is occupied")
		}
	}
	native := r.nativeView()
	for _, family := range []int{4, 6} {
		for _, kind := range []string{"rule", "route", "fallback"} {
			present, _, err := nativeTUNObserveResource(native, family, kind)
			if err != nil {
				return err
			}
			if present {
				return Fault("trial_resource_conflict", "old-boot native policy slot occupied")
			}
		}
	}
	nft, err := nativeTUNObserveNFT(native)
	if err != nil {
		return err
	}
	if nft.Present {
		return Fault("trial_resource_conflict", "old-boot native nft name occupied")
	}
	return nil
}

// No standalone unlock, no guessed Direct mode, no automatic resource removal
// from invalid or non-terminating journal phases.
func clearRecoveredHostNativeLocked(store *activationJournalDir, op string, idle func() error) error {
	if !journalHex32.MatchString(op) || idle == nil {
		return Fault("invalid_arguments", "exact recovered host native operation and idle proof required")
	}
	r, id, err := loadHostNativeJournal(store)
	if err != nil {
		return err
	}
	if r.Progress.Ingress.OperationID != op || r.Progress.Ingress.Phase != "recovered" || r.Native.LinkStage != "removed" {
		return Fault("activation_journal_conflict", "host native operation is not independently recovered")
	}
	if err := idle(); err != nil {
		return err
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return err
	}
	if err := hostNativeVerifyLinkAbsent(r, boot); err != nil {
		return err
	}
	if err := verifyHostNetworkBarrierReleased(r.Progress.Barrier); err != nil {
		return err
	}
	if err := verifyHostCapturePreparationOff(hostCaptureJournal{Version: hostCaptureJournalVersion, Intent: hostCaptureJournalIntent, Progress: r.Progress}); err != nil {
		return err
	}
	latest, identity, err := loadHostNativeJournal(store)
	if err != nil {
		return err
	}
	if id != identity || latest != r {
		return Fault("activation_journal_conflict", "host native parent changed before clear")
	}
	if err := hostNativeVerifyLinkAbsent(latest, boot); err != nil {
		return err
	}
	return store.removeJournal(identity)
}
