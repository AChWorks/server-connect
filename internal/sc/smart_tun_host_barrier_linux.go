//go:build linux

package sc

import (
	"encoding/binary"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// hostNetworkBarrier records an independently guarded, ephemeral TUN lifetime.
// Unlike a persistent dummy selected later by name, only the creating FD can
// authorize the normal close. No route, address, RPDB, sysctl or UP transition
// belongs to this interface. It is not the traffic-carrying TUN.
//
// The intended synchronization boundary is the trusted Linux TUN driver's
// last nonpersistent queue close -> unregister_netdevice -> network grace
// period. Source: Linux v6.1 drivers/net/tun.c tun_chr_close, tun_detach,
// __tun_detach (synchronize_net before unregister); net/core/dev.c
// unregister_netdevice_many (flush_all_backlogs and synchronize_net).
// https://github.com/torvalds/linux/blob/v6.1/drivers/net/tun.c
// https://github.com/torvalds/linux/blob/v6.1/net/core/dev.c
// Calling nft, waiting, or observing link absence alone is NOT this
// boundary. General-host Apply must additionally revalidate the staging
// policy and use the kernel-filtered socket absence queries, not a paginated
// diagnostic snapshot. This primitive alone never grants capture authority.
type hostNetworkBarrier struct {
	Version      int    `json:"version"`
	OperationID  string `json:"operation_id"`
	BootID       string `json:"boot_id"`
	NamespaceDev uint64 `json:"namespace_dev"`
	NamespaceIno uint64 `json:"namespace_ino"`
	Name         string `json:"name"`
	Stage        string `json:"stage"`
}

type hostNetworkBarrierPersist func(previous, next hostNetworkBarrier) error

func newHostNetworkBarrier(operationID string) (hostNetworkBarrier, error) {
	var b hostNetworkBarrier
	if !journalHex32.MatchString(operationID) {
		return b, ingressFault("network barrier operation identity invalid")
	}
	dev, ino, err := nativeTUNNamespace()
	if err != nil {
		return b, err
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return b, err
	}
	b = hostNetworkBarrier{Version: 1, OperationID: operationID, BootID: boot, NamespaceDev: dev, NamespaceIno: ino,
		Name: "scq" + operationID[:12], Stage: "planned"}
	return b, validateHostNetworkBarrier(b)
}
func validateHostNetworkBarrier(b hostNetworkBarrier) error {
	if b.Version != 1 || !journalHex32.MatchString(b.OperationID) || !trialBootIDPattern.MatchString(b.BootID) ||
		b.NamespaceDev == 0 || b.NamespaceIno == 0 || b.Name != "scq"+b.OperationID[:12] {
		return ingressFault("network barrier identity invalid")
	}
	switch b.Stage {
	case "planned", "create_possible", "closed":
		return nil
	default:
		return ingressFault("network barrier progress invalid")
	}
}
func hostNetworkBarrierContext(b hostNetworkBarrier) error {
	if err := validateHostNetworkBarrier(b); err != nil {
		return err
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return err
	}
	dev, ino, err := nativeTUNNamespace()
	if err != nil {
		return err
	}
	if boot != b.BootID || dev != b.NamespaceDev || ino != b.NamespaceIno {
		return ingressFault("network barrier boot or namespace changed")
	}
	return nil
}
func hostNetworkBarrierAbsent(name string) error {
	rows, err := nativeTUNRows("-j", "link", "show")
	if err != nil {
		return err
	}
	for _, row := range rows {
		if selectiveText(row["ifname"]) == name {
			return ingressFault("network barrier name occupied or retained")
		}
	}
	return nil
}
func advanceHostNetworkBarrier(current *hostNetworkBarrier, next hostNetworkBarrier, persist hostNetworkBarrierPersist) error {
	if persist == nil {
		return Fault("guard_unavailable", "network barrier requires enclosing durable journal")
	}
	previous := *current
	if previous.OperationID != next.OperationID || previous.BootID != next.BootID ||
		previous.NamespaceDev != next.NamespaceDev || previous.NamespaceIno != next.NamespaceIno || previous.Name != next.Name {
		return ingressFault("network barrier identity changed")
	}
	if err := validateHostNetworkBarrier(next); err != nil {
		return err
	}
	if !((previous.Stage == "planned" && next.Stage == "create_possible") ||
		(previous.Stage == "create_possible" && next.Stage == "closed")) {
		return ingressFault("network barrier transition invalid")
	}
	if err := persist(previous, next); err != nil {
		return err
	}
	*current = next
	return nil
}
func closeHostNetworkBarrierTUN(name string) error {
	// The exported Go syscall fork lock excludes transient inherited references
	// until last-close executes. Do not run guard callbacks, os/exec, or helpers
	// that reacquire ForkLock within this small lifetime. No FD is exposed/duped.
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return ingressFault("network barrier TUN device unavailable")
	}
	defer func() {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
	}()
	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil {
		return ingressFault("network barrier TUN device cannot be inspected")
	}
	if info.Mode&syscall.S_IFMT != syscall.S_IFCHR || info.Rdev != uint64(10<<8|200) {
		return ingressFault("network barrier TUN device identity invalid")
	}
	request := make([]byte, 40)
	copy(request[:16], name)
	binary.NativeEndian.PutUint16(request[16:18], 0x0001|0x1000|0x8000) // TUN | NO_PI | TUN_EXCL
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&request[0])))
	if errno != 0 {
		return ingressFault("exclusive network barrier TUN creation failed")
	}
	if strings.TrimRight(string(request[:16]), "\x00") != name {
		return ingressFault("kernel changed network barrier name")
	}
	// Linux close may release the FD even if it reports EINTR. Never retry
	// close on the numeric descriptor, which could already have been reused.
	closing := fd
	fd = -1
	if err := syscall.Close(closing); err != nil {
		return ingressFault("network barrier close outcome uncertain")
	}
	return nil
}

// runHostNetworkBarrierLocked is intentionally internal and requires one
// enclosing journal's held lock and independently verified guard. A closed
// receipt is published only after the creating FD closes successfully. An
// interrupted caller cannot resume into capture from create_possible.
func runHostNetworkBarrierLocked(store *activationJournalDir, current *hostNetworkBarrier, guard func() error, persist hostNetworkBarrierPersist) error {
	if current == nil || guard == nil || persist == nil {
		return Fault("guard_unavailable", "guarded enclosing network barrier is required")
	}
	if err := hostNetworkBarrierContext(*current); err != nil {
		return err
	}
	if current.Stage != "planned" {
		return ingressFault("network barrier is not a fresh planned lifetime")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if err := hostNetworkBarrierAbsent(current.Name); err != nil {
		return err
	}
	next := *current
	next.Stage = "create_possible"
	if err := advanceHostNetworkBarrier(current, next, persist); err != nil {
		return err
	}
	// Journal durability is established before opening the exclusive lifetime.
	if err := guard(); err != nil {
		return err
	}
	if err := hostNetworkBarrierContext(*current); err != nil {
		return err
	}
	if err := closeHostNetworkBarrierTUN(current.Name); err != nil {
		return err
	}
	if err := hostNetworkBarrierContext(*current); err != nil {
		return err
	}
	if err := hostNetworkBarrierAbsent(current.Name); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	next = *current
	next.Stage = "closed"
	return advanceHostNetworkBarrier(current, next, persist)
}

// Recovery does not manufacture a synchronization receipt. A killed caller
// has no right to continue its activation; its pending enclosing operation
// must recover Off. Absence can establish no retained helper, never that the
// old caller observed a successful grace period.
func verifyHostNetworkBarrierReleased(b hostNetworkBarrier) error {
	if err := validateHostNetworkBarrier(b); err != nil {
		return err
	}
	if err := hostNetworkBarrierAbsent(b.Name); err != nil {
		return err
	}
	return nil
}
