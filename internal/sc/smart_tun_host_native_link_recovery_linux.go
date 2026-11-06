//go:build linux

package sc

// LINK-ONLY v7 cleanup deliberately does not inherit the disconnected v4
// native policy guard's blanket ban on third-party NAT. The v7 journal can
// own no RPDB/FIB/nft route capture at all. It independently verifies that
// limitation and the current exact Docker/NOTRACK ingress boundary BEFORE
// touching only its receipted TUN ifindex. Unknown/overlapping owners still
// fail closed, retaining the operation rather than deleting foreign state.

import (
	"strings"
)

func hostNativeCheckNoPolicy(r hostNativeJournal) error {
	native := r.nativeView()
	if err := nativeTUNCheckNamespace(native); err != nil {
		return err
	}
	for _, family := range []int{4, 6} {
		for _, kind := range []string{"rule", "route", "fallback"} {
			present, _, err := nativeTUNObserveResource(native, family, kind)
			if err != nil {
				return err
			}
			if present {
				return Fault("trial_resource_conflict", "host native link-only preparation has reserved policy effects")
			}
		}
	}
	// Revalidate foreign raw, Docker NAT and active ingress ownership using
	// current kernel state. The check must not treat foreign NAT as our delta.
	if err := hostIngressMarkBoundary(r.Progress.Ingress); err != nil {
		return err
	}
	for attempt := 0; attempt < 3; attempt++ {
		before, err := nativeNFTGeneration()
		if err != nil {
			return err
		}
		raw, err := nativeTUNRunNFT(nil, nil, "-n", "-j", "-a", "list", "ruleset")
		if err != nil {
			return err
		}
		after, err := nativeNFTGeneration()
		if err != nil {
			return err
		}
		if before == 0 || before != after {
			continue
		}
		objects, err := nativeTUNNftObjects(raw)
		if err != nil {
			return err
		}
		if err := hostIngressForeignNATBoundary(r.Progress.Ingress, objects); err != nil {
			return err
		}
		if err := hostIngressForeignNFTBoundary(r.Progress.Ingress, native, objects); err != nil {
			return err
		}
		if err := hostNativeNoOwnedPolicyNFT(objects); err != nil {
			return err
		}
		return nil
	}
	return Fault("trial_recovery_uncertain", "host native nft generation changed during link-only verification")
}

func hostNativeNoOwnedPolicyNFT(objects []map[string]any) error {
	for _, row := range objects {
		for kind, value := range row {
			fields, ok := value.(map[string]any)
			if !ok {
				return Fault("trial_recovery_uncertain", "uninspectable host native nft object")
			}
			if kind == "table" {
				name, ok := fields["name"].(string)
				if !ok {
					return Fault("trial_recovery_uncertain", "native nft table name uninspectable")
				}
				if strings.HasPrefix(name, "scnt_") {
					return Fault("trial_resource_conflict", "reserved native nft table remains or is foreign")
				}
			}
			{
				if name, ok := fields["table"].(string); ok && strings.HasPrefix(name, "scnt_") {
					return Fault("trial_resource_conflict", "reserved native nft child remains")
				}
			}
		}
	}
	return nil
}

func hostNativeRemoveLinkLocked(store *activationJournalDir, r *hostNativeJournal) error {
	return hostNativeRemoveLinkWithPersist(store, r, hostNativeLinkPersist(store, r))
}

// Reuse the exactly owned link removal with an enclosing v8 core parent.
// Both v7 and v8 must persist the effect intent into their same parent.
func hostNativeRemoveLinkWithPersist(store *activationJournalDir, r *hostNativeJournal, persist nativeTUNRecordPersist) error {
	if store == nil || r == nil || persist == nil {
		return Fault("guard_unavailable", "host native link removal requires owning parent")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	if err := hostNativeCheckNoPolicy(*r); err != nil {
		return err
	}
	native := r.nativeView()
	link, err := nativeTUNObserveLink(native)
	if err != nil {
		return err
	}
	if err := nativeTUNVerifyLink(native, link); err != nil {
		return err
	}
	if link.Present && r.Native.LinkStage == "removed" {
		return Fault("trial_resource_conflict", "removed host native link was replaced")
	}
	if link.Present {
		next := cloneSmartTUNTrial(native)
		next.Native.LinkStage = "remove_requested"
		if err := nativeTUNAdvanceWithPersist(&native, next, persist); err != nil {
			return err
		}
		// Durably record remove intent first, then fresh reobservations of owned
		// link, all dependent routes and foreign firewall immediately before RTM_DELLINK.
		if err := hostNativeCheckNoPolicy(*r); err != nil {
			return err
		}
		link, err = nativeTUNObserveLink(r.nativeView())
		if err != nil {
			return err
		}
		if err := nativeTUNVerifyLink(r.nativeView(), link); err != nil {
			return err
		}
		if link.Present {
			if err := nativeTUNDeleteLink(link.Index); err != nil {
				return err
			}
		}
	}
	if err := hostNativeCheckNoPolicy(*r); err != nil {
		return err
	}
	link, err = nativeTUNObserveLink(r.nativeView())
	if err != nil {
		return err
	}
	if link.Present {
		return Fault("trial_recovery_uncertain", "host native link removal not confirmed")
	}
	next := r.nativeView()
	next.Native.LinkStage = "removed"
	return nativeTUNAdvanceWithPersist(&native, next, persist)
}
