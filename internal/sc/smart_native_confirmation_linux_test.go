//go:build linux

package sc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
)

func TestNativeConfirmationOneUseToken(t *testing.T) {
	first, digest, err := newNativeConfirmationToken()
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := newNativeConfirmationToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 48 || len(digest) != 64 || first == second {
		t.Fatalf("bad random confirmation identity")
	}
	check := sha256.Sum256([]byte(first))
	if hex.EncodeToString(check[:]) != digest {
		t.Fatal("hash does not bind token")
	}
}

func TestNativeConfirmationBoundedExpiry(t *testing.T) {
	session := NativeSession{ConfirmationTokenSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ConfirmationBootID: "boot"}
	health := NativeHealthState{BootID: "boot", StartedMS: 1000}
	if got := nativeConfirmationTimeoutReason(session, health, "boot", 21000); got != "" {
		t.Fatal(got)
	}
	if got := nativeConfirmationTimeoutReason(session, health, "boot", 21001); got != "activation_confirmation_not_issued" {
		t.Fatal(got)
	}
	session.ConfirmationIssuedMS = 3000
	session.ConfirmationDeadlineMS = 603000
	if got := nativeConfirmationTimeoutReason(session, health, "boot", 602999); got != "" {
		t.Fatal(got)
	}
	if got := nativeConfirmationTimeoutReason(session, health, "boot", 603000); got != "activation_confirmation_expired" {
		t.Fatal(got)
	}
	if got := nativeConfirmationTimeoutReason(session, health, "other", 10000); got != "activation_confirmation_boot_changed" {
		t.Fatal(got)
	}
	session.ConfirmationAccepted = true
	session.ConfirmationTokenSHA256 = ""
	if got := nativeConfirmationTimeoutReason(session, health, "boot", 700000); got != "" {
		t.Fatal(got)
	}
}

func TestNativeSSHAncestorMustBeginAfterIssuedTime(t *testing.T) {
	// Child shell or sudo can be new, but an older sshd login is not.
	type entry struct {
		parent int
		start  uint64
		sshd   bool
	}
	data := map[int]entry{33: {22, 9000, false}, 22: {10, 8500, false}, 10: {1, 7000, true}}
	read := func(pid int) (int, uint64, error) {
		v, ok := data[pid]
		if !ok {
			return 0, 0, errors.New("missing")
		}
		return v.parent, v.start, nil
	}
	sshd := func(pid int) bool { return data[pid].sshd }
	good, err := nativeFreshSSHAncestry(33, 80000, 100, read, sshd) // issued at tick 8000
	if err != nil || good {
		t.Fatalf("old sshd ancestor accepted: %v %v", good, err)
	}
	data[10] = entry{1, 8010, true}
	good, err = nativeFreshSSHAncestry(33, 80000, 100, read, sshd)
	if err != nil || !good {
		t.Fatalf("new SSH ancestor rejected: %v %v", good, err)
	}
	data[10] = entry{1, 8000, true}
	good, err = nativeFreshSSHAncestry(33, 80000, 100, read, sshd)
	if err != nil || good {
		t.Fatal("same instant is not a proven fresh session")
	}
	data[10] = entry{1, 9000, false}
	good, err = nativeFreshSSHAncestry(33, 80000, 100, read, sshd)
	if err != nil || good {
		t.Fatal("no trusted SSH process accepted")
	}
	data[22] = entry{10, 9000, false}
	delete(data, 10)
	good, err = nativeFreshSSHAncestry(33, 80000, 100, read, sshd)
	if err == nil || good {
		t.Fatal("unreadable ancestry must fail")
	}
}

func TestNativeLinuxClockSource(t *testing.T) {
	hz, err := nativeClockTicks()
	if err != nil || hz < 10 {
		t.Fatalf("kernel auxv clock: hz=%d err=%v", hz, err)
	}
}

func TestNativeConfirmationInFlightHealthProbeCompatibility(t *testing.T) {
	pending := NativeSession{
		Version: 1, Selected: "provider", InterfaceName: "sc0", UnderlayIF: "eth0",
		HealthOperationID: "operation-1", ConfigSHA256: "config-1",
		ConfirmationTokenSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ConfirmationIssuedMS:    1000, ConfirmationDeadlineMS: 601000,
		ConfirmationBootID: "boot-1", StartupGuardName: "sc-output", StartupGuardHandle: 44,
	}
	confirmed := pending
	confirmed.ConfirmationAccepted = true
	confirmed.ConfirmationTokenSHA256 = ""
	// A synthetic in-flight result snapshots pending before a legal new-SSH
	// receipt is atomically committed. Its later publication must still match.
	started := make(chan struct{})
	resume := make(chan NativeSession)
	done := make(chan bool, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		snapshot := pending
		close(started)
		current := <-resume
		done <- nativeConfirmationOnlyUpgrade(snapshot, current)
	}()
	<-started
	resume <- confirmed
	if !<-done {
		t.Fatal("valid SSH confirmation invalidated in-flight Health probe")
	}
	wg.Wait()
	if pending == confirmed || !nativeConfirmationOnlyUpgrade(pending, confirmed) {
		t.Fatal("confirmation generation not treated as compatible")
	}
	changed := confirmed
	changed.ConfigSHA256 = "foreign-config"
	if nativeConfirmationOnlyUpgrade(pending, changed) {
		t.Fatal("foreign config adopted")
	}
	changed = confirmed
	changed.HealthOperationID = "new-operation"
	if nativeConfirmationOnlyUpgrade(pending, changed) {
		t.Fatal("new Health operation adopted")
	}
	changed = confirmed
	changed.StartupGuardHandle++
	if nativeConfirmationOnlyUpgrade(pending, changed) {
		t.Fatal("new kernel guard adopted")
	}
	changed = confirmed
	changed.ConfirmationDeadlineMS++
	if nativeConfirmationOnlyUpgrade(pending, changed) {
		t.Fatal("tampered expiry adopted")
	}
	changed = confirmed
	changed.ConfirmationAccepted = false
	if nativeConfirmationOnlyUpgrade(pending, changed) {
		t.Fatal("unconfirmed session accepted")
	}
}

func TestNativeConfirmationStaleSupervisorExpiryRecheck(t *testing.T) {
	health := NativeHealthState{OperationID: "op-1", ConfigSHA256: "sha", BootID: "boot-1", StartedMS: 1000}
	pending := NativeSession{HealthOperationID: "op-1", ConfigSHA256: "sha", ConfirmationBootID: "boot-1",
		ConfirmationIssuedMS: 2000, ConfirmationDeadlineMS: 602000,
		ConfirmationTokenSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	staleReason := nativeConfirmationTimeoutReason(pending, health, "boot-1", 602000)
	if staleReason != "activation_confirmation_expired" {
		t.Fatalf("initial expiry not visible: %s", staleReason)
	}
	confirmed := pending
	confirmed.ConfirmationTokenSHA256 = ""
	confirmed.ConfirmationAccepted = true
	if now := nativeConfirmationTimeoutReason(confirmed, health, "boot-1", 602001); now == staleReason || now != "" {
		t.Fatalf("a legal confirmation must invalidate a stale stop proposal: %s", now)
	}
	if now := nativeConfirmationTimeoutReason(pending, health, "boot-1", 602002); now != staleReason {
		t.Fatal("genuinely expired pending operation must still stop")
	}
	replaced := health
	replaced.OperationID = "op-2"
	if replaced.OperationID == pending.HealthOperationID {
		t.Fatal("foreign operation unexpectedly matched")
	}
}
