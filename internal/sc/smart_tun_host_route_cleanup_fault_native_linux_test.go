//go:build linux

package sc

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
)

// Reuses the existing isolated v9 kernel fixture and the existing argument-local
// netlink transport seam. Only the exact Core unit is simulated, as in the
// surrounding host-route kernel tests. No production fault knob is introduced.
func TestHostRouteV9LostDeleteACKReloadRequiresPositiveAbsence(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_ROUTE_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: isolated root network namespace required")
	}
	guard, base := prepareHostNativeKernelFixture(t)
	before := hostNativeKernelSnapshot(t)
	r := hostRouteKernelExample(t)
	r.Progress, r.Native = base.Progress, base.Native
	r.Native.NFTName = "scnt_" + r.Progress.Ingress.OperationID
	var err error
	r.Route.PolicySHA256, err = hostRoutePolicyPlanSHA256(r)
	if err != nil {
		t.Fatal(err)
	}
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	idle := smartTUNCoreObservationExample("inactive")
	services := hostCoreRecoveryServices{
		observe: func() (smartTUNTrialUnitObservation, error) { return idle, nil },
		stop: func(_ smartTUNTrialUnitObservation, started, valid bool) error {
			if !started || !valid {
				return errors.New("native cleanup fixture lacked exact Core authority")
			}
			return nil
		},
	}
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := hostRouteKernelReady(t, store, &r, guard, []byte(`{"simulated":"host-route-v9"}`)); err != nil {
			return err
		}
		native := r.nativeView()
		observe := hostRouteNFTObserver(&r)
		persist := hostRouteNativePersist(store, &r)
		if err := nativeTUNApplyGuardFirstWithObserver(store, &native, "", persist, observe); err != nil {
			return err
		}
		if err := hostRoutePhasePersist(store, &r, "observed"); err != nil {
			return err
		}
		if err := hostRoutePhasePersist(store, &r, "off_pending"); err != nil {
			return err
		}
		if err := hostCoreStopWith(store, &r.Core, func(stage string) error { return hostRouteCoreStagePersist(store, &r, stage) }, services); err != nil {
			return err
		}

		// Reach the actual last native cleanup boundary using the same owned
		// deletion helpers. RPDB/FIB/TUN effects are gone before guard removal.
		native = r.nativeView()
		for _, kind := range []string{"rule", "route", "fallback"} {
			if err := nativeTUNRemoveResourceWithObserver(store, &native, 4, kind, "", persist, observe); err != nil {
				return err
			}
		}
		if err := nativeTUNRemoveLinkWithObserver(store, &native, "", persist, observe); err != nil {
			return err
		}
		live, err := observe(native)
		if err != nil || !live.Present || !nativeTUNNFTReceiptCovers(native, live, false) {
			return fmt.Errorf("final deletion lost the actual owned graph receipt: %v", err)
		}
		next := cloneSmartTUNTrial(native)
		next.Native.NFT.Stage = "remove_requested"
		if err := nativeTUNAdvanceWithPersist(&native, next, persist); err != nil {
			return err
		}
		connection, err := openNativeNFTSocket()
		if err != nil {
			return err
		}
		// Send the real generation-conditioned delete; suppress only receive.
		err = nativeNFTDeleteTableUsing(nativeNFTLostTestReplies{connection}, connection.portID, live.Handle, live.Generation)
		_ = syscall.Close(connection.fd)
		if !errors.Is(err, errNativeNFTOutcomeUnknown) || !errors.Is(err, syscall.ETIMEDOUT) {
			return fmt.Errorf("committed delete/lost reply was not reported unknown: %v", err)
		}
		absent, err := observe(native)
		if err != nil || absent.Present {
			return fmt.Errorf("kernel did not perform the lost-ACK delete: %v", err)
		}
		retained, _, err := loadHostRouteJournal(store)
		if err != nil || retained != r || retained.Native.NFT.Stage != "remove_requested" || retained.Route.State != "off_pending" {
			return errors.New("unknown deletion falsely published terminal parent")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("HOST_ROUTE_V9_REAL_DELETE_LOST_ACK_RETAINED_PARENT=PASS")

	runner := New(m.Dir, DefaultCore, DefaultPort)
	err = runner.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		loaded, _, err := loadHostRouteJournal(store)
		if err != nil {
			return err
		}
		raw, id, err := store.readJournal()
		if err != nil {
			return err
		}
		view := loaded.nativeView()
		unknown := errors.New("test-only independent nft observation unavailable")
		err = nativeTUNRemoveNFTWithObserver(store, &view, "", hostRouteNativePersist(store, &loaded),
			func(smartTUNTrialJournal) (nativeTUNNFTObservation, error) { return nativeTUNNFTObservation{}, unknown })
		after, afterID, readErr := store.readJournal()
		if !errors.Is(err, unknown) || readErr != nil || id != afterID || !bytes.Equal(raw, after) || loaded != r {
			return errors.New("unknown post-delete observation was mistaken for positive absence")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("HOST_ROUTE_V9_LOST_ACK_UNKNOWN_OBSERVATION_RETAINS_INTENT=PASS")

	// Another explicit fixture owner now reuses the exact name. The retained
	// original handle must not authorize its deletion during fresh recovery.
	replacement := createNativeNFTTestTable(t, r.Native.NFTName)
	if replacement.observed.handle == r.Native.NFTHandle {
		t.Fatal("fixture replacement reused the original handle")
	}
	receipt, err := runner.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, selected trialRecoverySelection) (TrialReceipt, error) {
		if selected.version != hostRouteJournalVersion {
			return TrialReceipt{}, errors.New("lost-ACK retry selected the wrong parent")
		}
		return recoverHostRouteJournalLocked(store, &selected.hostRoute, services)
	})
	if err == nil || receipt.RecoveryVerified {
		t.Fatalf("replacement table allowed successful Off: %+v %v", receipt, err)
	}
	replacement.requireUnchanged(t)
	err = runner.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		retained, _, err := loadHostRouteJournal(store)
		if err != nil || retained.Native.NFT.Stage != "remove_requested" || retained.Route.State != "off_pending" {
			return errors.New("foreign replacement discarded uncertain deletion parent")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	replacement.cleanup(t) // Only its explicit test owner can remove it.
	replacement.requireAbsent(t)
	fmt.Println("HOST_ROUTE_V9_LOST_ACK_FOREIGN_REPLACEMENT_PRESERVED=PASS")

	receipt, err = runner.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, selected trialRecoverySelection) (TrialReceipt, error) {
		if selected.version != hostRouteJournalVersion || selected.hostRoute.Native.NFT.Stage != "remove_requested" {
			return TrialReceipt{}, errors.New("fresh retry lost durable final deletion intent")
		}
		return recoverHostRouteJournalLocked(store, &selected.hostRoute, services)
	})
	if err != nil || !receipt.RecoveryVerified {
		t.Fatalf("positively absent lost-ACK recovery failed: %+v %v", receipt, err)
	}
	err = runner.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		return clearRecoveredHostRouteLocked(store, r.Progress.Ingress.OperationID, services)
	})
	if err != nil {
		t.Fatal(err)
	}
	if hostNativeKernelSnapshot(t) != before {
		t.Fatal("lost-ACK retry altered foreign/baseline kernel state")
	}
	fmt.Println("HOST_ROUTE_V9_LOST_ACK_RELOAD_POSITIVE_ABSENCE_EXACT_OFF=PASS")
}
