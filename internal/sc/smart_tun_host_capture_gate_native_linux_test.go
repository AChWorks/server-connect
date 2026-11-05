//go:build linux

package sc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Native QA uses the SAME strict v6 journal and full-parent CAS as the
// installed independent recovery dispatcher, never a permissive test-only
// JSON parent. The fixture itself still has no generic-host TUN Apply API.
func TestHostCaptureGateOneJournalAndOwnedOffNative(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_CAPTURE_GATE_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: explicit isolated network namespace required")
	}
	self := requireNativeQANetworkNamespace(t)
	guard := func() error {
		current, err := os.Stat("/proc/self/ns/net")
		if err != nil || !os.SameFile(current, self) {
			return errors.New("isolated QA network namespace changed")
		}
		return nil
	}
	// This test owns only a fresh network namespace, never real host routes,
	// systemd guards, or an installed core. Shared-host source code requires
	// preexisting mark inheritance; the fixture sets it only in its own netns.
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "lo", "up")
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "add", "scgate0", "type", "veth", "peer", "name", "scgate1")
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "scgate0", "up")
	for _, binary := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"} {
		ingressNativeCommand(t, binary, "-t", "raw", "-A", "PREROUTING", "-p", "tcp", "--dport", "28997", "-j", "NOTRACK")
		ingressNativeCommand(t, binary, "-t", "raw", "-A", "OUTPUT", "-p", "tcp", "--sport", "28997", "-j", "NOTRACK")
	}
	// A disconnected guest shares the hosted runner kernel. Its IPv6
	// iptables-legacy raw table may be absent even if the nft backend works.
	// This exact unsupported condition is a negative admission proof, not a
	// positive composite gate test. No operation journal has been created.
	if _, _, err := hostIngressRawSnapshot(); err != nil {
		legacy4, err4 := exec.Command("/usr/sbin/iptables-legacy", "-t", "raw", "-S").CombinedOutput()
		legacy6, err6 := exec.Command("/usr/sbin/ip6tables-legacy", "-t", "raw", "-S").CombinedOutput()
		var unavailable *exec.ExitError
		knownMissing := ErrorCode(err) == "host_ingress_unverified" &&
			strings.Contains(err.Error(), "legacy raw backend inventory unavailable") &&
			err4 == nil && strictEmptyLegacyRawPolicy(legacy4) &&
			errors.As(err6, &unavailable) && unavailable.ExitCode() == 3 &&
			len(legacy6) < 512 &&
			strings.Contains(string(legacy6), "can't initialize ip6tables table `raw': Table does not exist")
		if knownMissing {
			if _, e := newHostCaptureGateProgress("scgate0", 90); ErrorCode(e) != "host_ingress_unverified" ||
				!strings.Contains(e.Error(), "legacy raw backend inventory unavailable") {
				t.Fatalf("unsupported kernel unexpectedly admitted composite gate: %v", e)
			}
			fmt.Println("HOST_CAPTURE_UNSUPPORTED_LEGACY_IPV6_REFUSES_BEFORE_JOURNAL=PASS")
			t.Skip("NOT_RUN: runner kernel lacks IPv6 legacy raw; composite positive requires supported kernel")
		}
		t.Fatalf("composite ingress prerequisites unavailable for an unrecognized reason: %v", err)
	}
	// An unowned 0->1 sysctl transition is prohibited on real hosts. Prove
	// the preflight refusal before creating any activation journal or nft
	// ingress table, then prepare the supported preenabled QA fixture.
	ingressNativeCommand(t, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.tcp_fwmark_accept=0")
	if _, err := newHostCaptureGateProgress("scgate0", 90); ErrorCode(err) != "host_ingress_unverified" {
		t.Fatalf("unowned mark inheritance mutation was admitted: %v", err)
	}
	fmt.Println("HOST_CAPTURE_PREEXISTING_SYSCTL_REQUIRED=PASS")
	ingressNativeCommand(t, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.tcp_fwmark_accept=1")
	routesAndRules := func() string {
		var out []string
		for _, family := range []string{"-4", "-6"} {
			for _, kind := range []string{"route", "rule"} {
				args := []string{family, "-j", kind, "show"}
				if kind == "route" {
					args = append(args, "table", "all")
				}
				out = append(out, ingressNativeCommand(t, "/usr/sbin/ip", args...))
			}
		}
		return strings.Join(out, "\x00")
	}
	baseline := routesAndRules()
	rawBaseline := ingressNativeCommand(t, "/usr/sbin/nft", "-j", "list", "ruleset")
	progress, err := newHostCaptureGateProgress("scgate0", 90)
	if err != nil {
		t.Fatal(err)
	}
	if progress.Ingress.SysctlBefore != 1 {
		t.Fatal("fixture did not start with preenabled mark inheritance")
	}
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record := hostCaptureJournal{Version: hostCaptureJournalVersion, Intent: hostCaptureJournalIntent, Progress: progress}
		if err := writeHostCaptureJournal(store, record, nil); err != nil {
			return err
		}
		get := func() (hostCaptureJournal, activationJournalFileIdentity, error) {
			return loadHostCaptureJournal(store)
		}
		save := func(saved hostCaptureJournal, id activationJournalFileIdentity) error {
			return writeHostCaptureJournal(store, saved, &id)
		}
		persist := hostCaptureJournalPersist(store, &record)
		// A failed durable intent MUST NOT permit the first kernel effect.
		// Retrying is allowed only because the exact pending parent is
		// unchanged and no effect has yet been attempted.
		durabilityFault := errors.New("synthetic enclosing journal fsync failure")
		failIntent := func(previous, next hostCaptureGateProgress) error {
			if previous.Ingress.SysctlStage == "planned" && next.Ingress.SysctlStage == "effect_possible" {
				return durabilityFault
			}
			return persist(previous, next)
		}
		if err := runHostCaptureGateLocked(store, &progress, guard, failIntent); !errors.Is(err, durabilityFault) {
			return fmt.Errorf("unacknowledged parent write did not stop staging: %v", err)
		}
		uncommitted, _, err := get()
		if err != nil || uncommitted.Progress != progress ||
			progress.Ingress.SysctlStage != "planned" || progress.Ingress.NFTStage != "planned" {
			return errors.New("failed durable intent advanced ingress parent")
		}
		if observed, err := observeHostIngressNFT(progress.Ingress); err != nil || observed.Present {
			return errors.New("unacknowledged ingress intent created nft effects")
		}
		fmt.Println("HOST_CAPTURE_FAILED_INTENT_HAS_NO_KERNEL_EFFECT=PASS")
		if err := runHostCaptureGateLocked(store, &progress, guard, persist); err != nil {
			return err
		}
		saved, _, err := get()
		if err != nil || saved.Progress != progress || progress.Barrier.Stage != "closed" ||
			progress.Ingress.NFTStage != "observed" || progress.Ingress.Phase != "pending" {
			return fmt.Errorf("gate did not persist both exact owned prerequisites: %v", err)
		}
		fmt.Println("HOST_CAPTURE_COMMON_JOURNAL_STAGED_AND_BARRIER_CLOSED=PASS")
		// Replaying a completed barrier cannot mint another synchronization
		// receipt or acquire an arbitrary overlapping ingress mark.
		if err := runHostCaptureGateLocked(store, &progress, guard, persist); err == nil {
			return errors.New("completed gate was replayed")
		}
		replayed, _, err := get()
		if err != nil || replayed != saved {
			return errors.New("replayed gate changed the durable journal")
		}
		// The parent still owns only the ingress stage. The independent
		// recovery adapter can release that exact stage while preserving
		// foreign raw rules and the preexisting inherited-mark sysctl.
		recovered, err := recoverHostCaptureGateLocked(store, &progress, persist)
		if err != nil || !recovered.RecoveryVerified || progress.Ingress.Phase != "recovered" {
			return fmt.Errorf("owned ingress recovery not verified: %v", err)
		}
		if err := verifyHostNetworkBarrierReleased(progress.Barrier); err != nil {
			return err
		}
		off, _, err := get()
		if err != nil || off.Progress != progress {
			return errors.New("owned recovery not durably recorded in same operation")
		}
		fmt.Println("HOST_CAPTURE_COMMON_JOURNAL_OWNED_OFF=PASS")

		// Start a second strictly owned QA operation only AFTER the first
		// operation is durably recovered and its ephemeral barrier absent.
		// Simulate loss of the durable acknowledgement AFTER the kernel
		// grace lifetime closes: neither a "closed" receipt nor active
		// capture is allowed to be inferred from helper disappearance.
		replacement, err := newHostCaptureGateProgress("scgate0", 90)
		if err != nil {
			return err
		}
		prior, priorID, err := get()
		if err != nil || prior.Progress != progress || progress.Ingress.Phase != "recovered" {
			return errors.New("prior capture gate is not verified Off")
		}
		if err := save(hostCaptureJournal{Version: hostCaptureJournalVersion, Intent: hostCaptureJournalIntent, Progress: replacement}, priorID); err != nil {
			return err
		}
		progress = replacement
		record = hostCaptureJournal{Version: hostCaptureJournalVersion, Intent: hostCaptureJournalIntent, Progress: replacement}
		closeReceiptFault := errors.New("synthetic final-FD receipt fsync failure")
		faultReached := false
		failAfterBarrierClose := func(previous, next hostCaptureGateProgress) error {
			if previous.Barrier.Stage == "create_possible" && next.Barrier.Stage == "closed" {
				faultReached = true
				return closeReceiptFault
			}
			return persist(previous, next)
		}
		if err := runHostCaptureGateLocked(store, &progress, guard, failAfterBarrierClose); !errors.Is(err, closeReceiptFault) || !faultReached {
			return fmt.Errorf("interrupted kernel grace receipt not detected: %v", err)
		}
		interrupted, _, err := get()
		if err != nil || interrupted.Progress != progress ||
			progress.Barrier.Stage != "create_possible" || progress.Ingress.NFTStage != "observed" {
			return errors.New("partial ingress/grace operation was not durably retained")
		}
		if err := verifyHostNetworkBarrierReleased(progress.Barrier); err != nil {
			return err
		}
		if observed, err := observeHostIngressNFT(progress.Ingress); err != nil || !observed.Present ||
			!observed.Matches || observed.Handle != progress.Ingress.NFTHandle {
			return errors.New("interrupted barrier did not retain exact owned ingress evidence")
		}
		if err := runHostCaptureGateLocked(store, &progress, guard, persist); err == nil {
			return errors.New("interrupted barrier was replayed as fresh capture")
		}
		// The recovery helper must never upgrade create_possible into
		// closed. Decode the independently selected full parent as if the
		// initiating process had died, then release only its exact owned
		// ingress with the installed CAS adapter.
		selected, err := selectTrialRecoveryLocked(store, "", "")
		if err != nil || selected.version != hostCaptureJournalVersion || selected.capture.Progress != progress {
			return fmt.Errorf("installed independent recovery selection lost exact operation: %v", err)
		}
		// Call the EXACT dispatcher used by the installed oneshot, not
		// a test-local invocation of a narrower native cleanup helper.
		independentReceipt, err := recoverSelectedTrialLocked(store, selected, "", "")
		if err != nil || !independentReceipt.RecoveryVerified ||
			independentReceipt.Phase != "recovered" ||
			independentReceipt.OperationID != progress.Ingress.OperationID {
			return fmt.Errorf("independent v6 dispatcher failed owned recovery: %v", err)
		}
		reconciled, _, err := get()
		if err != nil || reconciled.Progress.Ingress.Phase != "recovered" ||
			reconciled.Progress.Barrier.Stage != "create_possible" {
			return errors.New("independent dispatcher lost journal progress or fabricated barrier receipt")
		}
		record = reconciled
		progress = record.Progress
		persist = hostCaptureJournalPersist(store, &record)
		if observed, err := observeHostIngressNFT(progress.Ingress); err != nil || observed.Present {
			return errors.New("interrupted ingress rollback retained owned nft effects")
		}
		fmt.Println("HOST_CAPTURE_FAILED_BARRIER_RECEIPT_OWNED_OFF=PASS")

		// Simulate a journal surviving a REAL boot epoch change, while
		// executing only in this disposable namespace (no host reboot).
		// Old handles/namespace IDs are never accepted as delete authority.
		oldBoot, err := newHostCaptureGateProgress("scgate0", 90)
		if err != nil {
			return err
		}
		oldBootID := "11111111-2222-3333-4444-555555555555"
		if oldBootID == oldBoot.Ingress.BootID {
			oldBootID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		}
		oldBoot.Ingress.BootID, oldBoot.Barrier.BootID = oldBootID, oldBootID
		oldBoot.Ingress.SysctlStage = "observed"
		oldBoot.Ingress.NFTStage = "observed"
		oldBoot.Ingress.NFTHandle = 123456
		oldBoot.Ingress.NFTSHA256 = strings.Repeat("c", 64)
		oldBoot.Barrier.Stage = "create_possible"
		if err := validateHostCaptureGatePair(oldBoot.Ingress, oldBoot.Barrier); err != nil {
			return err
		}
		prior, priorID, err = get()
		if err != nil || prior.Progress != progress || progress.Ingress.Phase != "recovered" {
			return errors.New("cannot enter old-boot QA without verified prior Off")
		}
		if err := save(hostCaptureJournal{Version: hostCaptureJournalVersion, Intent: hostCaptureJournalIntent, Progress: oldBoot}, priorID); err != nil {
			return err
		}
		progress = oldBoot
		record = hostCaptureJournal{Version: hostCaptureJournalVersion, Intent: hostCaptureJournalIntent, Progress: oldBoot}

		refusedRecoveryCode := func(value *hostCaptureGateProgress) string {
			_, err := recoverHostCaptureGateLocked(store, value, persist)
			return ErrorCode(err)
		}
		// A previous 0->1 sysctl operation has no old-boot CAS authority.
		unowned := progress
		unowned.Ingress.SysctlBefore = 0
		expectedRefused := unowned
		if code := refusedRecoveryCode(&unowned); code != "host_ingress_unverified" {
			return fmt.Errorf("old-boot sysctl write acquired restoration authority: %s", code)
		}
		if unowned != expectedRefused {
			return errors.New("refused old-boot sysctl recovery mutated memory")
		}

		// Even an exact-looking table name on the current boot belongs to
		// an unknown owner and must be retained, not deleted by old handles.
		foreignName := "scin_" + progress.Ingress.OperationID
		ingressNativeCommand(t, "/usr/sbin/nft", "add", "table", "inet", foreignName)
		if code := refusedRecoveryCode(&progress); code != "host_ingress_unverified" {
			return fmt.Errorf("reused nft table name bypassed old-boot admission: %s", code)
		}
		if observed, err := observeHostIngressNFT(progress.Ingress); err != nil || !observed.Present {
			return errors.New("old-boot recovery deleted a foreign same-name table")
		}
		ingressNativeCommand(t, "/usr/sbin/nft", "delete", "table", "inet", foreignName)

		// A changed sysctl or occupied helper interface also forbids a
		// successful old-boot Off receipt.
		ingressNativeCommand(t, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.tcp_fwmark_accept=0")
		if code := refusedRecoveryCode(&progress); code != "host_ingress_unverified" {
			return fmt.Errorf("sysctl drift bypassed old-boot refusal: %s", code)
		}
		ingressNativeCommand(t, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.tcp_fwmark_accept=1")
		ingressNativeCommand(t, "/usr/sbin/ip", "link", "add", progress.Barrier.Name, "type", "dummy")
		if code := refusedRecoveryCode(&progress); code != "host_ingress_unverified" {
			return fmt.Errorf("foreign helper name bypassed old-boot refusal: %s", code)
		}
		ingressNativeCommand(t, "/usr/sbin/ip", "link", "del", progress.Barrier.Name)
		unchanged, _, err := get()
		if err != nil || unchanged.Progress != progress {
			return errors.New("refused old-boot collision mutated parent journal")
		}

		// With independent proof that the helper and table are absent and
		// the original sysctl was preenabled, the actual installed
		// dispatcher must perform JOURNAL-ONLY recovery on a fresh read.
		oldBootSelected, err := selectTrialRecoveryLocked(store, "", "")
		if err != nil || oldBootSelected.version != hostCaptureJournalVersion ||
			oldBootSelected.capture.Progress != progress {
			return fmt.Errorf("old-boot recovery selector lost complete journal: %v", err)
		}
		independentReceipt, err = recoverSelectedTrialLocked(store, oldBootSelected, "", "")
		if err != nil || !independentReceipt.RecoveryVerified ||
			independentReceipt.Phase != "recovered" ||
			independentReceipt.OperationID != progress.Ingress.OperationID {
			return fmt.Errorf("absence-only old-boot dispatcher did not recover: %v", err)
		}
		finalRecord, _, err := get()
		if err != nil || finalRecord.Progress.Ingress.Phase != "recovered" ||
			finalRecord.Progress.Barrier.Stage != "create_possible" {
			return errors.New("old-boot absence-only recovery not durable")
		}
		progress, record = finalRecord.Progress, finalRecord
		fmt.Println("HOST_CAPTURE_OLD_BOOT_NO_FOREIGN_MUTATION_AND_OWNED_OFF=PASS")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// A second fresh v6 operation is owned by a real subprocess, which is
	// deliberately SIGKILLed AFTER its first kernel effect and durable
	// parent receipt. Recovery runs in the surviving parent under a NEW
	// activation lock and selection, not the initiator's memory.
	crashDir := privateJournalTempDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHostCaptureNativeCrashHelper$", "-test.v", "-test.timeout=30s")
	child.Env = append(os.Environ(), "SC_TEST_HOST_CAPTURE_CRASH_HELPER=isolated-netns", "SC_TEST_HOST_CAPTURE_CRASH_DIR="+crashDir)
	childOut, childErr := child.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("native crash subprocess exceeded bounded deadline: %v", ctx.Err())
	}
	var killed *exec.ExitError
	if !errors.As(childErr, &killed) || !killed.ProcessState.Sys().(syscall.WaitStatus).Signaled() ||
		killed.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL ||
		!strings.Contains(string(childOut), "HOST_CAPTURE_CHILD_DURABLE_INGRESS_EFFECT_BEFORE_SIGKILL=PASS") {
		t.Fatalf("native crash subprocess was not exact post-effect SIGKILL: err=%v output=%q", childErr, childOut)
	}
	crashed := New(crashDir, DefaultCore, DefaultPort)
	// This is the same typed handler as the installed systemd independent
	// recovery role, selected afresh inside the shared Manager lock.
	result, err := crashed.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, selected trialRecoverySelection) (TrialReceipt, error) {
		if selected.version != hostCaptureJournalVersion || selected.capture.Progress.Ingress.NFTStage != "observed" ||
			selected.capture.Progress.Barrier.Stage != "planned" {
			return TrialReceipt{}, errors.New("killed process did not leave a strict v6 owned operation")
		}
		return recoverSelectedTrialLocked(store, selected, "", "")
	})
	if err != nil || !result.RecoveryVerified || result.Phase != "recovered" {
		t.Fatalf("surviving independent dispatcher could not restore exact owned ingress: receipt=%+v err=%v", result, err)
	}
	err = crashed.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record, _, err := loadHostCaptureJournal(store)
		if err != nil || record.Progress.Ingress.Phase != "recovered" ||
			record.Progress.Ingress.NFTStage != "removed" || record.Progress.Barrier.Stage != "planned" {
			return errors.New("SIGKILL recovery did not persist complete owned Off without fabricated barrier")
		}
		if observed, err := observeHostIngressNFT(record.Progress.Ingress); err != nil || observed.Present {
			return errors.New("SIGKILL recovery retained owned ingress table")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("HOST_CAPTURE_REAL_SIGKILL_INDEPENDENT_DISPATCH_OWNED_OFF=PASS")
	if after := routesAndRules(); after != baseline {
		t.Fatal("host capture gate modified foreign route/rule state")
	}
	if after := ingressNativeCommand(t, "/usr/sbin/nft", "-j", "list", "ruleset"); after != rawBaseline {
		t.Fatal("host capture gate modified foreign raw/NFT baseline")
	}
	if value, err := readHostIngressSysctl(); err != nil || value != 1 {
		t.Fatal("preexisting mark-inheritance sysctl was changed")
	}
	t.Log("HOST_CAPTURE_COMMON_JOURNAL_FOREIGN_NETWORK_PRESERVED=PASS")
}

// TestHostCaptureNativeCrashHelper is a separate process that is intentionally
// killed AFTER the v6 parent durably owns an ingress NFT effect. Its default
// invocation is inert, and the root scenario is restricted to a fresh netns.
// It never attempts a TUN/core/host capture Apply.
func TestHostCaptureNativeCrashHelper(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_CAPTURE_CRASH_HELPER") != "isolated-netns" {
		t.Skip("NOT_RUN: crash subprocess requires explicit isolated-netns QA")
	}
	requireNativeQANetworkNamespace(t)
	dir := os.Getenv("SC_TEST_HOST_CAPTURE_CRASH_DIR")
	if dir == "" || os.Getppid() == 1 {
		t.Fatal("isolated parent-owned journal or parent process missing")
	}
	m := New(dir, DefaultCore, DefaultPort)
	progress, err := newHostCaptureGateProgress("scgate0", 90)
	if err != nil {
		t.Fatal(err)
	}
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record := hostCaptureJournal{Version: hostCaptureJournalVersion, Intent: hostCaptureJournalIntent, Progress: progress}
		if err := writeHostCaptureJournal(store, record, nil); err != nil {
			return err
		}
		guard := func() error {
			if os.Getppid() == 1 {
				return errors.New("isolated QA parent watchdog disappeared")
			}
			return nil
		}
		return applyHostIngressStageWithPersistLocked(store, &progress.Ingress, guard,
			hostCaptureIngressPersistence(&record.Progress, hostCaptureJournalPersist(store, &record)))
	})
	if err != nil || progress.Ingress.NFTStage != "observed" {
		t.Fatalf("crash child failed to stage owned ingress: %v", err)
	}
	if result, err := observeHostIngressNFT(progress.Ingress); err != nil || !result.Present ||
		result.Handle != progress.Ingress.NFTHandle || !result.Matches {
		t.Fatalf("crash child did not verify exact owned nft effect: %v", err)
	}
	fmt.Println("HOST_CAPTURE_CHILD_DURABLE_INGRESS_EFFECT_BEFORE_SIGKILL=PASS")
	if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
		t.Fatalf("expected SIGKILL failed: %v", err)
	}
	t.Fatal("SIGKILL unexpectedly returned")
}
