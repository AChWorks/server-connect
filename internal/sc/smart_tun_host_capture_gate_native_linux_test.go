//go:build linux

package sc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
)

// This intentionally uses a test-only journal discriminator. It must not be
// dispatched by the installed recovery service: native QA is executed only in
// a disposable isolated netns, and no general-host Apply entrypoint exists.
// The production host transaction needs its own fully recoverable journal
// with the native TUN ledger, runtime health and one independent guard.
type hostCaptureNativeTestParent struct {
	Version int                `json:"version"`
	Ingress hostIngressStage   `json:"ingress"`
	Barrier hostNetworkBarrier `json:"barrier"`
}

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
	ingressNativeCommand(t, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.tcp_fwmark_accept=1")
	for _, binary := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"} {
		ingressNativeCommand(t, binary, "-t", "raw", "-A", "PREROUTING", "-p", "tcp", "--dport", "28997", "-j", "NOTRACK")
		ingressNativeCommand(t, binary, "-t", "raw", "-A", "OUTPUT", "-p", "tcp", "--sport", "28997", "-j", "NOTRACK")
	}
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
	ingress, barrier, err := newHostCaptureGatePair("scgate0", 90)
	if err != nil {
		t.Fatal(err)
	}
	if ingress.SysctlBefore != 1 {
		t.Fatal("fixture did not start with preenabled mark inheritance")
	}
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		initial := hostCaptureNativeTestParent{Version: 600, Ingress: ingress, Barrier: barrier}
		raw, err := json.Marshal(initial)
		if err != nil {
			return err
		}
		if err := store.writeJournal(append(raw, '\n'), nil); err != nil {
			return err
		}
		get := func() (hostCaptureNativeTestParent, activationJournalFileIdentity, error) {
			var saved hostCaptureNativeTestParent
			raw, id, err := store.readJournal()
			if err != nil {
				return saved, id, err
			}
			if err = json.Unmarshal(raw, &saved); err != nil {
				return saved, id, err
			}
			if saved.Version != 600 || validateHostCaptureGatePair(saved.Ingress, saved.Barrier) != nil {
				return saved, id, errors.New("enclosing test journal identity changed")
			}
			return saved, id, nil
		}
		save := func(saved hostCaptureNativeTestParent, id activationJournalFileIdentity) error {
			raw, err := json.Marshal(saved)
			if err != nil {
				return err
			}
			return store.writeJournal(append(raw, '\n'), &id)
		}
		persistIngress := func(previous *hostIngressStage, next hostIngressStage) error {
			saved, id, err := get()
			if err != nil {
				return err
			}
			// The first call acknowledges an already durably created parent;
			// subsequent calls must CAS against exact previous ingress bytes.
			if previous == nil {
				if saved.Ingress != next || saved.Barrier != barrier {
					return errors.New("ingress insertion changed parent")
				}
			} else if saved.Ingress != *previous || saved.Barrier != barrier {
				return errors.New("ingress progress attempted against changed parent")
			}
			saved.Ingress = next
			return save(saved, id)
		}
		persistBarrier := func(previous, next hostNetworkBarrier) error {
			saved, id, err := get()
			if err != nil {
				return err
			}
			if saved.Ingress != ingress || saved.Barrier != previous {
				return errors.New("barrier progress attempted against changed parent")
			}
			saved.Barrier = next
			return save(saved, id)
		}
		if err := runHostCaptureGateLocked(store, &ingress, &barrier, guard, persistIngress, persistBarrier); err != nil {
			return err
		}
		saved, _, err := get()
		if err != nil || saved.Ingress != ingress || saved.Barrier != barrier || barrier.Stage != "closed" ||
			ingress.NFTStage != "observed" || ingress.Phase != "pending" {
			return fmt.Errorf("gate did not persist both exact owned prerequisites: %v", err)
		}
		fmt.Println("HOST_CAPTURE_COMMON_JOURNAL_STAGED_AND_BARRIER_CLOSED=PASS")
		// Replaying a completed barrier cannot mint another synchronization
		// receipt or acquire an arbitrary overlapping ingress mark.
		if err := runHostCaptureGateLocked(store, &ingress, &barrier, guard, persistIngress, persistBarrier); err == nil {
			return errors.New("completed gate was replayed")
		}
		replayed, _, err := get()
		if err != nil || replayed != saved {
			return errors.New("replayed gate changed the durable journal")
		}
		// The parent still owns only the ingress stage. The independent
		// recovery adapter can release that exact stage while preserving
		// foreign raw rules and the preexisting inherited-mark sysctl.
		recovered, err := recoverHostIngressStageWithPersistLocked(store, &ingress, true, persistIngress)
		if err != nil || !recovered.RecoveryVerified || ingress.Phase != "recovered" {
			return fmt.Errorf("owned ingress recovery not verified: %v", err)
		}
		if err := verifyHostNetworkBarrierReleased(barrier); err != nil {
			return err
		}
		off, _, err := get()
		if err != nil || off.Ingress != ingress || off.Barrier != barrier {
			return errors.New("owned recovery not durably recorded in same operation")
		}
		fmt.Println("HOST_CAPTURE_COMMON_JOURNAL_OWNED_OFF=PASS")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
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
