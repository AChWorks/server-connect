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

func prepareHostNativeKernelFixture(t *testing.T) (func() error, hostNativeJournal) {
	t.Helper()
	self := requireNativeQANetworkNamespace(t)
	guard := func() error {
		now, err := os.Stat("/proc/self/ns/net")
		if err != nil || !os.SameFile(self, now) {
			return errors.New("native QA left its isolated network namespace")
		}
		return nil
	}
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "lo", "up")
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "add", "scv7edge0", "type", "veth", "peer", "name", "scv7edge1")
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "scv7edge0", "up")
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "add", "docker0", "type", "bridge")
	ingressNativeCommand(t, "/usr/sbin/ip", "address", "add", "172.17.0.1/16", "dev", "docker0")
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "docker0", "up")
	if _, err := os.Stat("/usr/sbin/iptables-nft"); err == nil {
		for _, args := range [][]string{
			{"-t", "nat", "-N", "DOCKER"},
			{"-t", "nat", "-A", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "DOCKER"},
			{"-t", "nat", "-A", "OUTPUT", "!", "-d", "127.0.0.0/8", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "DOCKER"},
			{"-t", "nat", "-A", "POSTROUTING", "-s", "172.17.0.0/16", "!", "-o", "docker0", "-j", "MASQUERADE"},
			{"-t", "nat", "-A", "DOCKER", "-i", "docker0", "-j", "RETURN"},
		} {
			ingressNativeCommand(t, "/usr/sbin/iptables-nft", args...)
		}
	} else {
		t.Log("iptables-nft unavailable: isolated bridge and native ownership still tested; Docker NAT coexistence verified on Test Server")
	}
	// Preserve representative foreign raw/NOTRACK owners, including both
	// families, to exercise the same admitted ingress contract as v6.
	for _, binary := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"} {
		if _, err := os.Stat(binary); err != nil {
			continue
		}
		ingressNativeCommand(t, binary, "-t", "raw", "-A", "PREROUTING", "-p", "tcp", "--dport", "28997", "-j", "NOTRACK")
		ingressNativeCommand(t, binary, "-t", "raw", "-A", "OUTPUT", "-p", "tcp", "--sport", "28997", "-j", "NOTRACK")
	}
	ingressNativeCommand(t, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.tcp_fwmark_accept=1")
	progress, err := newHostCaptureGateProgress("scv7edge0", 90)
	if err != nil {
		t.Fatal(err)
	}
	if err := hostIngressMarkBoundary(progress.Ingress); err != nil {
		t.Fatal(err)
	}
	r := hostNativeExample()
	r.Progress = progress
	r.TunnelInterface = "sctunv70"
	r.Native.NamespaceDev = progress.Ingress.NamespaceDev
	r.Native.NamespaceIno = progress.Ingress.NamespaceIno
	r.Native.UnderlayIndex = progress.Ingress.UnderlayIndex
	r.Native.NFTName = "scnt_" + progress.Ingress.OperationID
	if err := validateHostNativeJournal(r); err != nil {
		t.Fatal(err)
	}
	return guard, r
}

func hostNativeKernelSnapshot(t *testing.T) string {
	t.Helper()
	var lines []string
	for _, family := range []string{"-4", "-6"} {
		lines = append(lines, ingressNativeCommand(t, "/usr/sbin/ip", family, "-N", "-j", "route", "show", "table", "all"))
		lines = append(lines, ingressNativeCommand(t, "/usr/sbin/ip", family, "-N", "-j", "rule", "show"))
	}
	lines = append(lines, ingressNativeCommand(t, "/usr/sbin/nft", "-j", "list", "ruleset"))
	return strings.Join(lines, "\x00")
}

func TestHostNativeJournalOneKernelLinkAndOwnedOff(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_NATIVE_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: isolated network namespace is required")
	}
	guard, r := prepareHostNativeKernelFixture(t)
	before := hostNativeKernelSnapshot(t)
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostNativeJournal(store, r, nil); err != nil {
			return err
		}
		if err := runHostCaptureGateLocked(store, &r.Progress, guard, hostNativeCapturePersist(store, &r)); err != nil {
			return err
		}
		if r.Progress.Barrier.Stage != "closed" || r.Progress.Ingress.NFTStage != "observed" {
			return errors.New("host ingress/barrier were not durably staged")
		}
		native := r.nativeView()
		if err := nativeTUNPrepareLinkWithPersist(store, &native, "", hostNativeLinkPersist(store, &r)); err != nil {
			return err
		}
		if r.Native.LinkStage != "observed" || r.Native.LinkIndex < 2 {
			return errors.New("native TUN was not durably observed in same v7 journal")
		}
		link, err := nativeTUNObserveLink(r.nativeView())
		if err != nil || !link.Present || !link.Persistent {
			return fmt.Errorf("native persisted link not observed: %v", err)
		}
		fmt.Println("HOST_NATIVE_V7_ONE_PARENT_INGRESS_BARRIER_TUN=PASS")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	runner := New(m.Dir, DefaultCore, DefaultPort)
	result, err := runner.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, selected trialRecoverySelection) (TrialReceipt, error) {
		if selected.version != hostNativeJournalVersion || selected.hostNative.Native.LinkStage != "observed" {
			return TrialReceipt{}, errors.New("independent selector lost persisted native link")
		}
		return recoverHostNativeJournalLocked(store, &selected.hostNative, guard)
	})
	if err != nil || !result.RecoveryVerified || result.Phase != "host_native_recovered" {
		t.Fatalf("native independent recovery: %+v %v", result, err)
	}
	fmt.Println("HOST_NATIVE_V7_INDEPENDENT_OWNED_OFF=PASS")
	// A different owner reusing the name must not be removed or mistaken for
	// recovery. The journal remains until the foreign collision disappears.
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "add", "sctunv70", "type", "dummy")
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if ErrorCode(clearRecoveredHostNativeLocked(store, r.Progress.Ingress.OperationID, guard)) == "" {
			return errors.New("foreign same-name link was cleared")
		}
		if _, _, err := loadHostNativeJournal(store); err != nil {
			return errors.New("clear removed foreign collision evidence")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "del", "sctunv70")
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := clearRecoveredHostNativeLocked(store, r.Progress.Ingress.OperationID, guard); err != nil {
			return err
		}
		if _, _, err := store.readJournal(); !errors.Is(err, os.ErrNotExist) {
			return errors.New("verified native recovery still retained parent")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if after := hostNativeKernelSnapshot(t); after != before {
		t.Fatal("v7 native ingress/Off changed foreign or baseline kernel resources")
	}
	fmt.Println("HOST_NATIVE_V7_FOREIGN_COLLISION_RETAINED_AND_EXACT_CLEAR=PASS")
	fmt.Println("HOST_NATIVE_V7_DOCKER_NAT_AND_FIB_RPDB_PRESERVED=PASS")
}

func TestHostNativeKernelCrashHelper(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_NATIVE_CRASH_HELPER") != "isolated-netns" {
		t.Skip("NOT_RUN: authorized isolated subprocess only")
	}
	guard, r := prepareHostNativeKernelFixture(t)
	dir := os.Getenv("SC_TEST_HOST_NATIVE_CRASH_DIR")
	if dir == "" {
		t.Fatal("missing crash directory")
	}
	m := New(dir, DefaultCore, DefaultPort)
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostNativeJournal(store, r, nil); err != nil {
			return err
		}
		if err := runHostCaptureGateLocked(store, &r.Progress, guard, hostNativeCapturePersist(store, &r)); err != nil {
			return err
		}
		// The real native syscall persists the link before the next journal write.
		// An actual process SIGKILL exercises the independent recoverer, not a mock.
		native := r.nativeView()
		return nativeTUNPrepareLinkWithPersist(store, &native, "after-native-persist", hostNativeLinkPersist(store, &r))
	})
	t.Fatalf("native crash helper returned instead of terminating: %v", err)
}

func TestHostNativeKernelCrashAfterPersistentLink(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_NATIVE_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: isolated network namespace is required")
	}
	requireNativeQANetworkNamespace(t)
	dir := privateJournalTempDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHostNativeKernelCrashHelper$", "-test.v", "-test.timeout=30s")
	child.Env = append(os.Environ(), "SC_TEST_HOST_NATIVE_CRASH_HELPER=isolated-netns", "SC_TEST_HOST_NATIVE_CRASH_DIR="+dir)
	out, err := child.CombinedOutput()
	var killed *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &killed) || !killed.ProcessState.Sys().(syscall.WaitStatus).Signaled() ||
		killed.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("native crash did not SIGKILL after persistent effect: %v %s", err, out)
	}
	m := New(dir, DefaultCore, DefaultPort)
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		r, _, err := loadHostNativeJournal(store)
		if err != nil {
			return err
		}
		if r.Native.LinkStage != "persist_possible" || r.Progress.Barrier.Stage != "closed" {
			return errors.New("crash did not retain exact native persistence intent")
		}
		link, err := nativeTUNObserveLink(r.nativeView())
		if err != nil || !link.Present || !link.Persistent {
			return errors.New("native link did not survive initiator SIGKILL")
		}
		fmt.Println("HOST_NATIVE_V7_REAL_SIGKILL_AFTER_PERSISTENT_LINK=PASS")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, s trialRecoverySelection) (TrialReceipt, error) {
		if s.version != hostNativeJournalVersion {
			return TrialReceipt{}, errors.New("independent v7 selection missing")
		}
		return recoverHostNativeJournalLocked(store, &s.hostNative, func() error { return nil })
	})
	if err != nil || !result.RecoveryVerified {
		t.Fatalf("independent post-SIGKILL native recovery failed: %+v %v", result, err)
	}
	fmt.Println("HOST_NATIVE_V7_REAL_SIGKILL_INDEPENDENT_OFF=PASS")
}
