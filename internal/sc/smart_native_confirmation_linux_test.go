//go:build linux

package sc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
