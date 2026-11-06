//go:build linux

package sc

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
)

// The Test Server executes this real-kernel test as root inside a newly
// isolated netns. No systemd service is started; its idle identity is
// injected only at the independent core boundary. The actual link/ingress,
// journal CAS and rollback are the same code as installed execution.
func TestHostCoreCompositeParentRealKernelWithoutCore(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_CORE_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: isolated root network namespace required")
	}
	guard, base := prepareHostNativeKernelFixture(t)
	before := hostNativeKernelSnapshot(t)
	base.Version, base.Intent = hostCoreJournalVersion, hostCoreJournalIntent
	r := hostCoreJournal{hostNativeJournal: base, Core: hostCoreLedger{
		ProfileID: "abcdef0123456789", ConfigSHA256: sha256Hex([]byte(`{"test":"v8"}`)),
		PinnedEndpoint: "8.8.8.8", Stage: "planned",
	}}
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostCoreJournal(store, r, nil); err != nil {
			return err
		}
		if err := runHostCaptureGateLocked(store, &r.Progress, guard, hostCoreCapturePersist(store, &r)); err != nil {
			return err
		}
		native := r.nativeBase().nativeView()
		if err := nativeTUNPrepareLinkWithPersist(store, &native, "", hostCoreNativePersist(store, &r)); err != nil {
			return err
		}
		if r.Native.LinkStage != "observed" || r.Progress.Barrier.Stage != "closed" {
			return errors.New("v8 parent never durably owned real host resources")
		}
		if err := hostCoreAdvance(store, &r, "credential_possible"); err != nil {
			return err
		}
		if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, []byte(`{"test":"v8"}`), nil); err != nil {
			return err
		}
		return hostCoreAdvance(store, &r, "credential_staged")
	})
	if err != nil {
		t.Fatal(err)
	}
	idle := smartTUNCoreObservationExample("inactive")
	services := hostCoreRecoveryServices{
		observe: func() (smartTUNTrialUnitObservation, error) { return idle, nil },
		stop: func(smartTUNTrialUnitObservation, bool, bool) error {
			return errors.New("unstarted core cannot be stopped")
		},
	}
	result, err := m.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, s trialRecoverySelection) (TrialReceipt, error) {
		if s.version != hostCoreJournalVersion || s.hostCore.Core.Stage != "credential_staged" {
			return TrialReceipt{}, errors.New("independent executor selected wrong v8 owner")
		}
		return recoverHostCoreJournalLocked(store, &s.hostCore, services)
	})
	if err != nil || !result.RecoveryVerified || result.Phase != "host_core_recovered" {
		t.Fatalf("v8 kernel recovery failed: %+v %v", result, err)
	}
	fmt.Println("HOST_CORE_V8_LINK_INGRESS_CORE_ONE_PARENT_RECOVERED=PASS")
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		return clearRecoveredHostCoreLocked(store, r.Progress.Ingress.OperationID, services)
	})
	if err != nil {
		t.Fatal(err)
	}
	if after := hostNativeKernelSnapshot(t); after != before {
		t.Fatal("v8 core preparation changed Docker NAT or foreign FIB/RPDB across owned Off")
	}
	fmt.Println("HOST_CORE_V8_DOCKER_NAT_AND_FIB_RPDB_IDENTICAL=PASS")
}

func TestHostCoreCompositeStartRequestedRecoveryKernel(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_CORE_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: isolated root network namespace required")
	}
	guard, base := prepareHostNativeKernelFixture(t)
	before := hostNativeKernelSnapshot(t)
	base.Version, base.Intent = hostCoreJournalVersion, hostCoreJournalIntent
	secret := []byte(`{"simulated":"unit-bound-v8"}`)
	r := hostCoreJournal{hostNativeJournal: base, Core: hostCoreLedger{
		ProfileID: "abcdef0123456789", ConfigSHA256: sha256Hex(secret), PinnedEndpoint: "8.8.8.8", Stage: "planned",
	}}
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostCoreJournal(store, r, nil); err != nil {
			return err
		}
		if err := runHostCaptureGateLocked(store, &r.Progress, guard, hostCoreCapturePersist(store, &r)); err != nil {
			return err
		}
		native := r.nativeBase().nativeView()
		if err := nativeTUNPrepareLinkWithPersist(store, &native, "", hostCoreNativePersist(store, &r)); err != nil {
			return err
		}
		if err := hostCoreAdvance(store, &r, "credential_possible"); err != nil {
			return err
		}
		if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, secret, nil); err != nil {
			return err
		}
		if err := hostCoreAdvance(store, &r, "credential_staged"); err != nil {
			return err
		}
		return hostCoreAdvance(store, &r, "start_requested")
	})
	if err != nil {
		t.Fatal(err)
	}
	// These callbacks simulate only a separately owned exact unit; the kernel
	// effects and parent lifecycle are real. A wrong order would leave the
	// real link present and the callback witnesses would fail.
	state := smartTUNCoreObservationExample("active")
	inactive := smartTUNCoreObservationExample("inactive")
	inactive.identity = state.identity
	called := false
	service := hostCoreRecoveryServices{
		observe: func() (smartTUNTrialUnitObservation, error) { return state, nil },
		stop: func(_ smartTUNTrialUnitObservation, attempted, valid bool) error {
			if !attempted || !valid {
				return errors.New("core lacked durable authority or valid credential")
			}
			// /sys/class/net reflects the caller's mount namespace, which
			// can differ from the isolated NETLINK namespace under unshare.
			// Observe this exact TUN by rtnetlink instead of assuming sysfs.
			link, err := nativeTUNObserveLink(r.nativeBase().nativeView())
			if err != nil || !link.Present || !link.Persistent {
				return errors.New("native link deleted before owned core stop")
			}
			called = true
			state = inactive
			return nil
		},
	}
	result, err := m.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, s trialRecoverySelection) (TrialReceipt, error) {
		return recoverHostCoreJournalLocked(store, &s.hostCore, service)
	})
	if err != nil || !result.RecoveryVerified || !called {
		t.Fatalf("core-first native cleanup not verified: %+v %v", result, err)
	}
	fmt.Println("HOST_CORE_V8_START_REQUESTED_STOP_BEFORE_NATIVE_DELETE=PASS")
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		return clearRecoveredHostCoreLocked(store, r.Progress.Ingress.OperationID, service)
	})
	if err != nil {
		t.Fatal(err)
	}
	if hostNativeKernelSnapshot(t) != before {
		t.Fatal("v8 simulated-start recovery changed Docker NAT or foreign routes")
	}
	fmt.Println("HOST_CORE_V8_RESTARTABLE_STOP_EXACT_CREDENTIAL_CLEANUP=PASS")
}
