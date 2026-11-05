//go:build linux

package sc

// Native kernel tests must not run in the initial host network namespace.
// An unprivileged user+net namespace may be unable to stat /proc/1/ns/net;
// in that case, prove the current net namespace is owned by the process's
// subordinate user namespace via the kernel NS_GET_USERNS ioctl. A user
// namespace alone (-Ur without -n) does NOT satisfy this gate.
import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const qaNSGetUserns = 0xb701 // _IO(0xb7, 0x1), linux/nsfs.h

func requireNativeQANetworkNamespace(t *testing.T) os.FileInfo {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("native QA requires effective root inside a separate network namespace")
	}
	self, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		t.Fatal("native QA network namespace unavailable:", err)
	}
	pid1, pid1Err := os.Stat("/proc/1/ns/net")
	if pid1Err == nil {
		if os.SameFile(self, pid1) {
			t.Fatal("native QA refuses PID 1 host network namespace")
		}
		return self
	}
	if !errors.Is(pid1Err, os.ErrPermission) {
		t.Fatal("native QA cannot prove host namespace separation:", pid1Err)
	}

	// In an unprivileged namespace, ptrace/namespace checks may deny
	// /proc/1/ns/net. Only accept a single non-root host UID mapping.
	// This is insufficient alone: -Ur can still share the host netns.
	mapping, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		t.Fatal("native QA cannot inspect user namespace mapping:", err)
	}
	fields := strings.Fields(string(mapping))
	if len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		t.Fatal("native QA requires a single subordinate user namespace mapping")
	}
	mappedHostUID, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil || mappedHostUID == 0 {
		t.Fatal("native QA user namespace is not subordinate to the host")
	}
	fd, err := syscall.Open("/proc/self/ns/net", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("native QA cannot open current network namespace:", err)
	}
	defer syscall.Close(fd)
	ownerFD, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), qaNSGetUserns, 0)
	if errno != 0 {
		t.Fatal("native QA cannot verify owning user namespace:", errno)
	}
	owner := os.NewFile(ownerFD, "network-namespace-user-owner")
	defer owner.Close()
	owningUserNS, err := owner.Stat()
	if err != nil {
		t.Fatal("native QA cannot stat network namespace owner:", err)
	}
	currentUserNS, err := os.Stat("/proc/self/ns/user")
	if err != nil || !os.SameFile(owningUserNS, currentUserNS) {
		t.Fatal("native QA netns is not owned by subordinate current userns")
	}
	return self
}
