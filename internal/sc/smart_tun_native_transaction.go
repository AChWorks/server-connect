package sc

import (
	"errors"
	"net/netip"
	"os"
	"strings"
)

func nativeTUNQAKillValid(point string, apply bool) bool {
	if apply {
		switch point {
		case "after-native-link-bind", "after-native-persist", "after-native-route-effect", "after-native-rule-effect", "after-native-nft-effect", "after-native-capture":
			return true
		}
	}
	if !apply {
		switch point {
		case "after-native-nft-remove", "after-native-rule-remove", "after-native-route-remove", "after-native-link-remove":
			return true
		}
	}
	return false
}

func nativeTUNAdmission(options SmartTUNCandidateOptions, host HostPreflight) (smartTUNNativeLedger, error) {
	dev, ino, err := nativeTUNNamespace()
	if err != nil {
		return smartTUNNativeLedger{}, err
	}
	rows, err := selectiveRows(host.Links)
	if err != nil {
		return smartTUNNativeLedger{}, err
	}
	underlay := 0
	for _, row := range rows {
		if selectiveText(row["ifname"]) == options.UnderlayInterface {
			underlay, _ = selectiveInt(row["ifindex"])
		}
	}
	if underlay < 2 {
		return smartTUNNativeLedger{}, nativeTUNConflict("native underlay index unavailable")
	}
	n := smartTUNNativeLedger{Version: 1, NamespaceDev: dev, NamespaceIno: ino, UnderlayIndex: underlay, LinkStage: "planned",
		IPv4: nativeTUNPlannedFamily(options.TunnelIPv4, nativeTUNTable4), IPv6: nativeTUNPlannedFamily(options.TunnelIPv6, nativeTUNTable6), NFT: smartTUNNativeObject{Stage: "planned"}}
	// The actual operation name is bound after the second admission. This
	// placeholder authorizes only observations; exclusive nft creation is later.
	record := smartTUNTrialJournal{OperationID: strings.Repeat("0", 32), TunnelInterface: options.TunnelInterface, UnderlayInterface: options.UnderlayInterface, Native: &n}
	n.NFTName = "scnt_" + record.OperationID
	link, err := nativeTUNObserveLink(record)
	if err != nil {
		return smartTUNNativeLedger{}, err
	}
	if link.Present {
		return smartTUNNativeLedger{}, nativeTUNConflict("native TUN name is already occupied")
	}
	for _, family := range []int{4, 6} {
		for _, kind := range []string{"rule", "route", "fallback"} {
			present, _, err := nativeTUNObserveResource(record, family, kind)
			if err != nil {
				return smartTUNNativeLedger{}, err
			}
			if present {
				return smartTUNNativeLedger{}, nativeTUNConflict("native route or rule slot is already occupied")
			}
		}
	}
	nft, err := nativeTUNObserveNFT(record)
	if err != nil {
		return smartTUNNativeLedger{}, err
	}
	if nft.Present {
		return smartTUNNativeLedger{}, nativeTUNConflict("native nft operation name is already occupied")
	}
	n.NFTName = ""
	return n, nil
}

// Every transition revalidates the complete previous record, publishes one
// fsynced replacement, and verifies all next contents before refreshing inode.
func nativeTUNAdvance(store *activationJournalDir, record *smartTUNTrialJournal, next smartTUNTrialJournal) error {
	identity, err := reloadSmartTUNTrialLocked(store, *record)
	if err != nil {
		return err
	}
	if err := writeSmartTUNTrialLocked(store, next, &identity); err != nil {
		return err
	}
	if _, err := reloadSmartTUNTrialLocked(store, next); err != nil {
		return err
	}
	*record = cloneSmartTUNTrial(next)
	return nil
}

func nativeTUNPrepareLink(store *activationJournalDir, record *smartTUNTrialJournal, qaPoint string) error {
	if err := nativeTUNCheckNamespace(*record); err != nil {
		return err
	}
	next := cloneSmartTUNTrial(*record)
	next.Native.LinkStage = "create_possible"
	if err := nativeTUNAdvance(store, record, next); err != nil {
		return err
	}
	file, link, err := nativeTUNCreateEphemeral(store, *record)
	if err != nil {
		return err
	}
	defer file.Close()
	next = cloneSmartTUNTrial(*record)
	next.Native.LinkIndex = link.Index
	next.Native.LinkStage = "bound"
	next.Native.LinkSHA256 = link.LinkSHA256
	next.Native.AddressSHA256 = link.AddressSHA256
	next.Native.IPv4.DependentSHA256 = link.Dependent4
	next.Native.IPv6.DependentSHA256 = link.Dependent6
	if err := nativeTUNAdvance(store, record, next); err != nil {
		return err
	}
	if err := trialQAKillAt("after-native-link-bind", qaPoint); err != nil {
		return err
	}
	// Persistence is the first operation that can outlive this FD/process.
	// Its exact parent/children receipt is already durable, even if the next
	// ioctl succeeds and the process dies before an observed flag is written.
	next = cloneSmartTUNTrial(*record)
	next.Native.LinkStage = "persist_possible"
	if err := nativeTUNAdvance(store, record, next); err != nil {
		return err
	}
	if err := nativeTUNPersist(file); err != nil {
		return err
	}
	if err := trialQAKillAt("after-native-persist", qaPoint); err != nil {
		return err
	}
	observed, err := nativeTUNObserveLink(*record)
	if err != nil {
		return err
	}
	if !observed.Present || !observed.Persistent {
		return nativeTUNUncertain("created TUN persistence was not observed")
	}
	if err := nativeTUNVerifyLink(*record, observed); err != nil {
		return err
	}
	next = cloneSmartTUNTrial(*record)
	next.Native.LinkStage = "observed"
	return nativeTUNAdvance(store, record, next)
}

func nativeTUNResource(ledger *smartTUNNativeLedger, family int, kind string) *smartTUNNativeObject {
	f := nativeFamily(ledger, family)
	switch kind {
	case "rule":
		return &f.Rule
	case "fallback":
		return &f.Fallback
	default:
		return &f.Route
	}
}

func nativeTUNApplyPolicy(store *activationJournalDir, record *smartTUNTrialJournal, qaPoint string) error {
	if err := nativeTUNCheckNamespace(*record); err != nil {
		return err
	}
	link, err := nativeTUNObserveLink(*record)
	if err != nil {
		return err
	}
	if !link.Present || !link.Persistent {
		return nativeTUNConflict("core did not retain the manager-created persistent TUN")
	}
	if err := nativeTUNVerifyLink(*record, link); err != nil {
		return err
	}
	for _, family := range []int{4, 6} {
		if nativeFamily(record.Native, family).Address == "" {
			continue
		}
		for _, kind := range []string{"fallback", "route", "rule"} {
			present, _, err := nativeTUNObserveResource(*record, family, kind)
			if err != nil {
				return err
			}
			if present {
				return nativeTUNConflict("native slot changed before exclusive addition")
			}
			next := cloneSmartTUNTrial(*record)
			nativeTUNResource(next.Native, family, kind).Stage = "effect_possible"
			if err := nativeTUNAdvance(store, record, next); err != nil {
				return err
			}
			if err := nativeTUNRunIP(store, nativeRouteArgs(*record, family, kind, "add")...); err != nil {
				return err
			}
			if family == 4 && kind == "route" {
				if err := trialQAKillAt("after-native-route-effect", qaPoint); err != nil {
					return err
				}
			}
			if family == 4 && kind == "rule" {
				if err := trialQAKillAt("after-native-rule-effect", qaPoint); err != nil {
					return err
				}
			}
			present, hash, err := nativeTUNObserveResource(*record, family, kind)
			if err != nil {
				return err
			}
			if !present {
				return nativeTUNUncertain("acknowledged native addition was not observed")
			}
			next = cloneSmartTUNTrial(*record)
			*nativeTUNResource(next.Native, family, kind) = smartTUNNativeObject{Stage: "observed", SHA256: hash}
			if err := nativeTUNAdvance(store, record, next); err != nil {
				return err
			}
		}
	}
	before, err := nativeTUNObserveNFT(*record)
	if err != nil {
		return err
	}
	if before.Present {
		return nativeTUNConflict("native nft name changed before exclusive creation")
	}
	next := cloneSmartTUNTrial(*record)
	next.Native.NFT.Stage = "effect_possible"
	if err := nativeTUNAdvance(store, record, next); err != nil {
		return err
	}
	program, err := nativeNFTCreateJSON(*record)
	if err != nil {
		return err
	}
	if _, err := nativeTUNRunNFT(store, program, "-j", "-f", "-"); err != nil {
		return err
	}
	if err := trialQAKillAt("after-native-nft-effect", qaPoint); err != nil {
		return err
	}
	observed, err := nativeTUNObserveNFT(*record)
	if err != nil {
		return err
	}
	if !observed.Present || !observed.Matches {
		return nativeTUNConflict("created nft graph differs from exact intended policy")
	}
	next = cloneSmartTUNTrial(*record)
	next.Native.NFT = smartTUNNativeObject{Stage: "observed", SHA256: observed.SHA256}
	next.Native.NFTHandle = observed.Handle
	next.Native.NFTCount, next.Native.NFTObjects = observed.Count, observed.Objects
	if err := nativeTUNAdvance(store, record, next); err != nil {
		return err
	}
	return nil
}

// An exact-looking post-effect object is not a receipt. Kernel generations
// do not authenticate route/rule ownership, and a lost nft creation receipt
// cannot be reconstructed by adopting the current table handle.
func nativeTUNObjectRecovery(object smartTUNNativeObject, present bool, hash string) error {
	if !present {
		return nil
	}
	if object.Stage == "effect_possible" {
		return nativeTUNUncertain("native effect is present without a durable ownership receipt")
	}
	if (object.Stage != "observed" && object.Stage != "remove_requested") || object.SHA256 != hash {
		return nativeTUNConflict("native object is new, replaced or modified")
	}
	return nil
}

func nativeTUNVerifyPending(record smartTUNTrialJournal) error {
	if err := nativeTUNCheckNamespace(record); err != nil {
		return err
	}
	n := record.Native
	if n.LinkStage != "observed" || n.NFT.Stage != "observed" || n.StopReason != "" || !n.StartupVerified {
		return nativeTUNUncertain("native activation was not completely receipted")
	}
	link, err := nativeTUNObserveLink(record)
	if err != nil {
		return err
	}
	if !link.Present {
		return nativeTUNUncertain("native TUN disappeared")
	}
	if err := nativeTUNVerifyLink(record, link); err != nil {
		return err
	}
	for _, family := range []int{4, 6} {
		if nativeFamily(n, family).Address == "" {
			continue
		}
		for _, kind := range []string{"fallback", "route", "rule"} {
			object := *nativeTUNResource(n, family, kind)
			present, hash, err := nativeTUNObserveResource(record, family, kind)
			if err != nil {
				return err
			}
			if object.Stage != "observed" || !present || hash != object.SHA256 {
				return nativeTUNUncertain("native capture route or rule changed")
			}
		}
	}
	nft, err := nativeTUNObserveNFT(record)
	if err != nil {
		return err
	}
	if !nativeTUNNFTReceiptCovers(record, nft, true) {
		return nativeTUNConflict("native capture or independent guard graph changed")
	}
	return nil
}

func nativeTUNCheckRecoveryGraph(record smartTUNTrialJournal) error {
	if err := nativeTUNCheckNamespace(record); err != nil {
		return err
	}
	link, err := nativeTUNObserveLink(record)
	if err != nil {
		return err
	}
	if err := nativeTUNVerifyLink(record, link); err != nil {
		return err
	}
	if link.Present && record.Native.LinkStage == "removed" {
		return nativeTUNConflict("native TUN reappeared after removal")
	}
	remaining := cloneSmartTUNTrial(record)
	if !link.Present {
		remaining.Native.LinkStage = "removed"
	}
	for _, family := range []int{4, 6} {
		for _, kind := range []string{"fallback", "route", "rule"} {
			present, hash, err := nativeTUNObserveResource(record, family, kind)
			if err != nil {
				return err
			}
			if err := nativeTUNObjectRecovery(*nativeTUNResource(record.Native, family, kind), present, hash); err != nil {
				return err
			}
			if !present {
				nativeTUNResource(remaining.Native, family, kind).Stage = "removed"
			}
		}
	}
	nft, err := nativeTUNObserveNFT(record)
	if err != nil {
		return err
	}
	if nft.Present {
		if record.Native.NFT.Stage == "effect_possible" {
			return nativeTUNUncertain("native nft creation receipt was not durable")
		}
		if (record.Native.NFT.Stage != "observed" && record.Native.NFT.Stage != "remove_requested") || !nativeTUNNFTReceiptCovers(record, nft, false) {
			return nativeTUNConflict("native nft graph contains foreign or replaced objects")
		}
	}
	if err := nativeTUNRecoveryContainment(remaining, nft); err != nil {
		return err
	}
	return nil
}

func nativeTUNRecoveryContainment(record smartTUNTrialJournal, observed nativeTUNNFTObservation) error {
	n := record.Native
	if n.NFT.Stage == "planned" || n.NFT.Stage == "effect_possible" {
		// The pre-policy exception requires fresh absence. RemoveResource
		// reobserves here after the initial graph check; a newly present
		// exact-looking table still has no durable ownership receipt.
		if observed.Present {
			return nativeTUNUncertain("unreceipted native nft graph appeared before routing cleanup")
		}
		return nil
	}
	complete := n.LinkStage == "removed"
	for _, f := range []smartTUNNativeFamily{n.IPv4, n.IPv6} {
		if f.Address != "" && (f.Rule.Stage != "removed" || f.Route.Stage != "removed" || f.Fallback.Stage != "removed") {
			complete = false
		}
	}
	if complete {
		return nil
	}
	if !nativeTUNGuardIntact(record, observed) {
		return nativeTUNUncertain("native guard is incomplete; routing containment and evidence retained")
	}
	return nil
}

func nativeTUNRemoveResource(store *activationJournalDir, record *smartTUNTrialJournal, family int, kind, qaPoint string) error {
	object := *nativeTUNResource(record.Native, family, kind)
	present, hash, err := nativeTUNObserveResource(*record, family, kind)
	if err != nil {
		return err
	}
	if err := nativeTUNObjectRecovery(object, present, hash); err != nil {
		return err
	}
	if present {
		next := cloneSmartTUNTrial(*record)
		nativeTUNResource(next.Native, family, kind).Stage = "remove_requested"
		if err := nativeTUNAdvance(store, record, next); err != nil {
			return err
		}
		// Reobserve immediately after the durable deletion intent. No broad
		// table/priority deletion and no mutation on a mismatching selector.
		present, hash, err = nativeTUNObserveResource(*record, family, kind)
		if err != nil {
			return err
		}
		if err := nativeTUNObjectRecovery(*nativeTUNResource(record.Native, family, kind), present, hash); err != nil {
			return err
		}
		guard, err := nativeTUNObserveNFT(*record)
		if err != nil {
			return err
		}
		if err := nativeTUNRecoveryContainment(*record, guard); err != nil {
			return err
		}
		if present {
			if err := nativeTUNRunIP(store, nativeRouteArgs(*record, family, kind, "del")...); err != nil {
				return err
			}
		}
		point := "after-native-route-remove"
		if kind == "rule" {
			point = "after-native-rule-remove"
		}
		if err := trialQAKillAt(point, qaPoint); err != nil {
			return err
		}
		present, _, err = nativeTUNObserveResource(*record, family, kind)
		if err != nil {
			return err
		}
		if present {
			return nativeTUNUncertain("native deletion was not observed")
		}
	}
	next := cloneSmartTUNTrial(*record)
	nativeTUNResource(next.Native, family, kind).Stage = "removed"
	return nativeTUNAdvance(store, record, next)
}

func nativeTUNRemoveLink(store *activationJournalDir, record *smartTUNTrialJournal, qaPoint string) error {
	link, err := nativeTUNObserveLink(*record)
	if err != nil {
		return err
	}
	if err := nativeTUNVerifyLink(*record, link); err != nil {
		return err
	}
	if link.Present {
		if record.Native.LinkStage == "removed" {
			return nativeTUNConflict("removed TUN was replaced")
		}
		next := cloneSmartTUNTrial(*record)
		next.Native.LinkStage = "remove_requested"
		if err := nativeTUNAdvance(store, record, next); err != nil {
			return err
		}
		// Includes ALL addresses, attached routes and foreign rule/nft/link
		// dependencies. The earlier whole-host hash is never deletion authority.
		if err := nativeTUNCheckRecoveryGraph(*record); err != nil {
			return err
		}
		link, err = nativeTUNObserveLink(*record)
		if err != nil {
			return err
		}
		if err := nativeTUNVerifyLink(*record, link); err != nil {
			return err
		}
		if link.Present {
			if err := nativeTUNDeleteLink(link.Index); err != nil {
				return err
			}
		}
		if err := trialQAKillAt("after-native-link-remove", qaPoint); err != nil {
			return err
		}
		link, err = nativeTUNObserveLink(*record)
		if err != nil {
			return err
		}
		if link.Present {
			return nativeTUNUncertain("native link deletion was not observed")
		}
	}
	next := cloneSmartTUNTrial(*record)
	next.Native.LinkStage = "removed"
	return nativeTUNAdvance(store, record, next)
}

func nativeTUNRemoveNFT(store *activationJournalDir, record *smartTUNTrialJournal, qaPoint string) error {
	for attempt := 0; attempt < 3; attempt++ {
		observed, err := nativeTUNObserveNFT(*record)
		if err != nil {
			return err
		}
		if !observed.Present {
			next := cloneSmartTUNTrial(*record)
			next.Native.NFT.Stage = "removed"
			return nativeTUNAdvance(store, record, next)
		}
		if (record.Native.NFT.Stage != "observed" && record.Native.NFT.Stage != "remove_requested") || !nativeTUNNFTReceiptCovers(*record, observed, false) {
			return nativeTUNConflict("foreign nft objects prevent native final deactivation")
		}
		next := cloneSmartTUNTrial(*record)
		next.Native.NFT.Stage = "remove_requested"
		if err := nativeTUNAdvance(store, record, next); err != nil {
			return err
		}
		// A generation-conditioned kernel batch makes this prior full graph
		// observation a real precondition. A new foreign child must survive.
		err = nativeNFTDeleteTableCAS(observed.Handle, observed.Generation)
		if errors.Is(err, errNativeNFTGenerationChanged) {
			continue
		}
		if err != nil {
			return nativeTUNUncertain("native nft deletion outcome is unresolved")
		}
		if err := trialQAKillAt("after-native-nft-remove", qaPoint); err != nil {
			return err
		}
		after, err := nativeTUNObserveNFT(*record)
		if err != nil {
			return err
		}
		if after.Present {
			return nativeTUNConflict("nft table exists after acknowledged removal")
		}
		next = cloneSmartTUNTrial(*record)
		next.Native.NFT.Stage = "removed"
		return nativeTUNAdvance(store, record, next)
	}
	return nativeTUNUncertain("nft reconciliation exceeded bounded generation retries")
}

func nativeTUNVerifyRestored(record smartTUNTrialJournal) error {
	// A different boot cannot authenticate reused native IDs. Kernel objects
	// normally vanish at reboot; only observed absence is accepted here.
	dev, ino, err := nativeTUNNamespace()
	if err != nil {
		return err
	}
	if dev != record.Native.NamespaceDev || ino != record.Native.NamespaceIno {
		return nativeTUNConflict("native recovery namespace changed")
	}
	link, err := nativeTUNObserveLink(record)
	if err != nil {
		return err
	}
	if link.Present {
		return nativeTUNConflict("native TUN remains or was replaced")
	}
	for _, family := range []int{4, 6} {
		for _, kind := range []string{"fallback", "route", "rule"} {
			present, _, err := nativeTUNObserveResource(record, family, kind)
			if err != nil {
				return err
			}
			if present {
				return nativeTUNConflict("native policy remains or was replaced")
			}
		}
	}
	nft, err := nativeTUNObserveNFT(record)
	if err != nil {
		return err
	}
	if nft.Present {
		return nativeTUNConflict("native nft graph remains or was replaced")
	}
	for _, target := range []string{record.EndpointIP, record.ManagementPeerIP} {
		lookup, err := lookupHostRoute(netip.MustParseAddr(target))
		if err != nil || lookup == nil {
			return nativeTUNUncertain("protected underlay route unavailable")
		}
		rows, err := selectiveRows(lookup.KernelRoute)
		if err != nil || len(rows) != 1 || selectiveText(rows[0]["dev"]) != record.UnderlayInterface {
			return nativeTUNUncertain("protected underlay route changed")
		}
	}
	return nil
}

func recoverSmartTUNNativeLocked(store *activationJournalDir, record *smartTUNTrialJournal, qaPoint string) (SmartTUNTrialReceipt, error) {
	if err := trialDisposableContext(); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	status, err := smartTUNTrialUnitState()
	if err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if record.Phase == "trial_recovered" || record.Phase == "trial_cleanup_pending" {
		if status != "inactive" {
			return SmartTUNTrialReceipt{}, nativeTUNUncertain("recovered native operation has active core")
		}
		if err := nativeTUNVerifyRestored(*record); err != nil {
			return SmartTUNTrialReceipt{}, err
		}
		return smartTUNReceipt(*record, false, true), nil
	}
	data, _, credentialErr := store.readSmartTUNFile(smartTUNTrialConfigFile)
	present := credentialErr == nil
	valid := present && sha256Hex(data) == record.ConfigSHA256
	if record.Phase == "trial_pending" {
		boot, bootErr := trialBootIdentity()
		uptime, upErr := trialUptime()
		if bootErr == nil && upErr == nil && smartTUNTrialMayRemainPending(*record, status, valid, boot == record.BootID, uptime) && trialGuardScheduled() == nil && nativeTUNVerifyPending(*record) == nil {
			return smartTUNReceipt(*record, true, false), nil
		}
	}
	// Deactivation intent is durable before containing the exact core. A
	// credential/ownership conflict keeps native capture and the independent
	// POSTROUTING guard, never a silently Direct but still-pending operation.
	if record.Native.StopReason == "" {
		next := cloneSmartTUNTrial(*record)
		reason := "guard"
		if record.Phase == "trial_stop_requested" {
			reason = "off"
		}
		next.Native.StopReason = reason
		next.Phase, next.Revision = "trial_stop_requested", 2
		if err := nativeTUNAdvance(store, record, next); err != nil {
			return SmartTUNTrialReceipt{}, err
		}
	}
	previousStatus := status
	if err := smartTUNTrialSystemctl("stop", smartTUNTrialUnit); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	status, err = smartTUNTrialUnitState()
	if err != nil || status != "inactive" {
		return SmartTUNTrialReceipt{}, nativeTUNUncertain("native core did not stop")
	}
	if credentialErr != nil && !errors.Is(credentialErr, os.ErrNotExist) {
		return SmartTUNTrialReceipt{}, nativeTUNConflict("native credential cannot be inspected; containment retained")
	}
	if err := smartTUNTrialCredentialRecoveryCheck(*record, previousStatus, present, valid); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if record.CoreStartAttempted && !record.Native.StartupVerified {
		return SmartTUNTrialReceipt{}, nativeTUNUncertain("native core attach was not durably verified; generation uncertainty retained")
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	if boot != record.BootID {
		if err := nativeTUNVerifyRestored(*record); err != nil {
			return SmartTUNTrialReceipt{}, err
		}
	} else {
		if err := nativeTUNCheckRecoveryGraph(*record); err != nil {
			return SmartTUNTrialReceipt{}, err
		}
		for _, family := range []int{4, 6} {
			if nativeFamily(record.Native, family).Address == "" {
				continue
			}
			for _, kind := range []string{"rule", "route", "fallback"} {
				if err := nativeTUNRemoveResource(store, record, family, kind, qaPoint); err != nil {
					return SmartTUNTrialReceipt{}, err
				}
			}
		}
		if err := nativeTUNRemoveLink(store, record, qaPoint); err != nil {
			return SmartTUNTrialReceipt{}, err
		}
		// Keep capture and the independently classified leak guard until all
		// native routing/link cleanup is conclusive; nft is the final barrier.
		if err := nativeTUNRemoveNFT(store, record, qaPoint); err != nil {
			return SmartTUNTrialReceipt{}, err
		}
		if err := nativeTUNVerifyRestored(*record); err != nil {
			return SmartTUNTrialReceipt{}, err
		}
	}
	next := cloneSmartTUNTrial(*record)
	next.Native.LinkStage = "removed"
	next.Native.NFT.Stage = "removed"
	for _, family := range []int{4, 6} {
		if nativeFamily(next.Native, family).Address != "" {
			for _, kind := range []string{"rule", "route", "fallback"} {
				nativeTUNResource(next.Native, family, kind).Stage = "removed"
			}
		}
	}
	next.Phase, next.Revision = "trial_recovered", 2
	if next.Native.StopReason == "off" {
		next.Revision = 3
	}
	if err := nativeTUNAdvance(store, record, next); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	return smartTUNReceipt(*record, false, true), nil
}
