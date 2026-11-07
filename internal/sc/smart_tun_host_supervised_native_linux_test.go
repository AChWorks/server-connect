//go:build linux

package sc

// Real kernel regression for the active-policy verifier. The existing v9
// fixture simulates Core solely to isolate RPDB/FIB/nft verification. This
// test never starts an installed service or claims selected VPN delivery.
import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
)

func TestHostSupervisorNativeActivePolicyOwnsCaptureAndRejectsDrift(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_SUPERVISION_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: isolated root network namespace required")
	}
	guard, base := prepareHostNativeKernelFixture(t)
	before := hostNativeKernelSnapshot(t)
	r := hostRouteKernelExample(t)
	r.Progress, r.Native = base.Progress, base.Native
	r.Native.NFTName = "scnt_" + r.Progress.Ingress.OperationID
	digest, err := hostRoutePolicyPlanSHA256(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = digest
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := hostRouteKernelReady(t, store, &r, guard, []byte(`{"simulated":"host-route-v9"}`)); err != nil {
			return err
		}
		native := r.nativeView()
		if err := nativeTUNApplyGuardFirstWithObserver(store, &native, "", hostRouteNativePersist(store, &r), hostRouteNFTObserver(&r)); err != nil {
			return err
		}
		return hostRoutePhasePersist(store, &r, "observed")
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := hostIngressMarkBoundary(r.Progress.Ingress); err == nil {
		t.Fatal("preparation gate must still refuse the occupied capture rule")
	}
	if err := verifyHostRouteActivePolicy(r); err != nil {
		t.Fatalf("active verification rejected its own durably observed RPDB/FIB/nft policy: %v", err)
	}
	for name, change := range map[string]func(*hostRouteJournal){
		"boot":          func(r *hostRouteJournal) { r.Progress.Ingress.BootID = "22222222-2222-3333-4444-555555555555" },
		"namespace":     func(r *hostRouteJournal) { r.Progress.Ingress.NamespaceIno++ },
		"underlay":      func(r *hostRouteJournal) { r.Progress.Ingress.UnderlayIndex++ },
		"rule receipt":  func(r *hostRouteJournal) { r.Native.IPv4.Rule.SHA256 = sha256Hex([]byte("foreign")) },
		"route receipt": func(r *hostRouteJournal) { r.Native.IPv4.Route.SHA256 = sha256Hex([]byte("foreign")) },
		"nft receipt":   func(r *hostRouteJournal) { r.Native.NFTHandle++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if verifyHostRouteActivePolicy(changed) == nil {
				t.Fatal("active authority drift accepted")
			}
		})
	}
	ingressNativeCommand(t, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.tcp_fwmark_accept=0")
	if verifyHostRouteActivePolicy(r) == nil {
		t.Fatal("sysctl drift accepted")
	}
	ingressNativeCommand(t, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.tcp_fwmark_accept=1")
	mark := fmt.Sprintf("0x%x/0x%x", nativeTUNBypassMark, nativeTUNMarkMask)
	ingressNativeCommand(t, "/usr/sbin/ip", "-4", "rule", "add", "priority", "1000", "fwmark", mark, "table", "main")
	if verifyHostRouteActivePolicy(r) == nil {
		t.Fatal("foreign IPv4 reserved-mark policy accepted")
	}
	ingressNativeCommand(t, "/usr/sbin/ip", "-4", "rule", "del", "priority", "1000", "fwmark", mark, "table", "main")
	ingressNativeCommand(t, "/usr/sbin/ip", "-6", "rule", "add", "priority", "1000", "table", "main")
	if verifyHostRouteActivePolicy(r) == nil {
		t.Fatal("foreign IPv6 policy accepted")
	}
	ingressNativeCommand(t, "/usr/sbin/ip", "-6", "rule", "del", "priority", "1000", "table", "main")
	table := fmt.Sprint(nativeTUNTable4)
	ingressNativeCommand(t, "/usr/sbin/ip", "-4", "route", "add", "9.8.7.6/32", "dev", "scv7edge0", "table", table)
	if verifyHostRouteActivePolicy(r) == nil {
		t.Fatal("foreign route in the owned FIB table accepted")
	}
	ingressNativeCommand(t, "/usr/sbin/ip", "-4", "route", "del", "9.8.7.6/32", "dev", "scv7edge0", "table", table)
	ingressNativeCommand(t, "/usr/sbin/nft", "add", "table", "inet", "sc_supervisor_foreign")
	ingressNativeCommand(t, "/usr/sbin/nft", "add", "chain", "inet", "sc_supervisor_foreign", "output", "{ type route hook output priority -150; policy accept; }")
	ingressNativeCommand(t, "/usr/sbin/nft", "add", "rule", "inet", "sc_supervisor_foreign", "output", "meta", "mark", "set", fmt.Sprintf("0x%x", nativeTUNBypassMark))
	if verifyHostRouteActivePolicy(r) == nil {
		t.Fatal("foreign nft mark mutation accepted")
	}
	ingressNativeCommand(t, "/usr/sbin/nft", "delete", "table", "inet", "sc_supervisor_foreign")
	if err := verifyHostRouteActivePolicy(r); err != nil {
		t.Fatalf("exact active policy did not recover after test-owned drift cleanup: %v", err)
	}

	state := smartTUNCoreObservationExample("active")
	inactive := smartTUNCoreObservationExample("inactive")
	inactive.identity = state.identity
	stopped := false
	services := hostCoreRecoveryServices{
		observe: func() (smartTUNTrialUnitObservation, error) { return state, nil },
		stop: func(_ smartTUNTrialUnitObservation, started, valid bool) error {
			present, _, err := nativeTUNObserveResource(r.nativeView(), 4, "rule")
			if err != nil || !present || !started || !valid {
				return errors.New("native containment disappeared before Core-first stop")
			}
			stopped, state = true, inactive
			return nil
		},
	}
	receipt, err := m.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, selection trialRecoverySelection) (TrialReceipt, error) {
		return recoverHostRouteJournalLocked(store, &selection.hostRoute, services)
	})
	if err != nil || !receipt.RecoveryVerified || !stopped {
		t.Fatalf("active verifier regression Off failed: %v %+v", err, receipt)
	}
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		return clearRecoveredHostRouteLocked(store, r.Progress.Ingress.OperationID, services)
	}); err != nil {
		t.Fatal(err)
	}
	if after := hostNativeKernelSnapshot(t); after != before {
		t.Fatal("native regression failed exact foreign/kernel baseline preservation")
	}
	fmt.Println("HOST_SUPERVISOR_ACTIVE_OWNER_AND_FOREIGN_DRIFT_REFUSAL=PASS")
}
