//go:build linux

package sc

// A one-use initial activation receipt is tied to the actual native session.
// The independent existing health/recovery timers enforce expiry; this is not
// an authentication scheme or a replacement for host network safety guards.
import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const nativeConfirmationTTLMS int64 = 600000

func newNativeConfirmationToken() (string, string, error) {
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		return "", "", err
	}
	token := hex.EncodeToString(secret)
	digest := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(digest[:]), nil
}

// A zero issued time exists only while the original connect-smart is still
// starting the Core. If it never completes, the normal starting grace wins.
func nativeConfirmationTimeoutReason(s NativeSession, h NativeHealthState, boot string, now int64) string {
	if s.ConfirmationAccepted || s.ConfirmationTokenSHA256 == "" {
		return ""
	}
	if boot != h.BootID || boot != s.ConfirmationBootID || now < h.StartedMS {
		return "activation_confirmation_boot_changed"
	}
	if s.ConfirmationIssuedMS == 0 {
		if now > h.StartedMS+nativeHealthGraceMS {
			return "activation_confirmation_not_issued"
		}
		return ""
	}
	if now >= s.ConfirmationDeadlineMS {
		return "activation_confirmation_expired"
	}
	return ""
}

// Linux /proc/self/auxv is the kernel-provided clock tick rate. Avoid guessing
// HZ or shelling out to a potentially absent getconf during emergency access.
func nativeClockTicks() (uint64, error) {
	raw, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return 0, err
	}
	for off := 0; off+16 <= len(raw); off += 16 {
		key := binary.LittleEndian.Uint64(raw[off : off+8])
		if key == 17 { // AT_CLKTCK on Linux/amd64
			ticks := binary.LittleEndian.Uint64(raw[off+8 : off+16])
			if ticks == 0 || ticks > 1000000 {
				return 0, fmt.Errorf("invalid kernel clock tick rate")
			}
			return ticks, nil
		}
		if key == 0 {
			break
		}
	}
	return 0, fmt.Errorf("kernel clock tick rate unavailable")
}

func nativeProcParentAndStart(pid int) (int, uint64, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0, err
	}
	// The comm field may contain ')' and spaces. The last ')' precedes state.
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0, 0, errors.New("invalid process stat")
	}
	parts := strings.Fields(string(raw[end+1:]))
	if len(parts) <= 19 {
		return 0, 0, errors.New("truncated process stat")
	}
	parent, err := strconv.Atoi(parts[1]) // field 4: PPID
	if err != nil {
		return 0, 0, err
	}
	start, err := strconv.ParseUint(parts[19], 10, 64) // field 22: starttime
	return parent, start, err
}

func nativeSSHDExecutable(pid int) bool {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false
	}
	return path == "/usr/sbin/sshd" || path == "/usr/lib/openssh/sshd-session"
}

// Inspect the real SSH server ancestor, not SSH_CONNECTION/SSH_TTY strings
// that the operator's shell can inherit or spoof. An existing SSH login that
// starts a new shell or sudo AFTER activation still has an old sshd ancestor.
func nativeFreshSSHAncestry(pid int, issuedMS int64, hz uint64,
	process func(int) (int, uint64, error), isSSHD func(int) bool) (bool, error) {
	if issuedMS <= 0 || hz == 0 {
		return false, errors.New("invalid clock or activation time")
	}
	seen := make(map[int]bool)
	for depth := 0; depth < 64 && pid > 1 && !seen[pid]; depth++ {
		seen[pid] = true
		parent, start, err := process(pid)
		if err != nil {
			return false, err
		}
		if isSSHD(pid) {
			return start > uint64(issuedMS)*hz/1000, nil
		}
		pid = parent
	}
	return false, nil
}

func nativeFreshSSHSession(issuedMS int64) error {
	hz, err := nativeClockTicks()
	if err != nil {
		return Fault("confirmation_unavailable", "cannot verify SSH session kernel clock")
	}
	good, err := nativeFreshSSHAncestry(os.Getppid(), issuedMS, hz, nativeProcParentAndStart, nativeSSHDExecutable)
	if err != nil {
		return Fault("confirmation_unavailable", "cannot verify SSH process ancestry")
	}
	if !good {
		return Fault("confirmation_requires_new_ssh", "open a new SSH connection after activation; an existing login or local shell cannot confirm")
	}
	return nil
}

// A Health round may snapshot a pending confirmation, perform a network probe,
// and then publish after the SSH acknowledgement. That acknowledgement is not
// a new Core, policy, boot or Health generation. All other session changes
// must continue invalidating in-flight observations.
func nativeConfirmationOnlyUpgrade(before, after NativeSession) bool {
	if before.ConfirmationAccepted || before.ConfirmationTokenSHA256 == "" ||
		before.ConfirmationIssuedMS <= 0 || after.ConfirmationTokenSHA256 != "" ||
		!after.ConfirmationAccepted || after.ConfirmationIssuedMS != before.ConfirmationIssuedMS ||
		after.ConfirmationDeadlineMS != before.ConfirmationDeadlineMS ||
		after.ConfirmationBootID != before.ConfirmationBootID {
		return false
	}
	before.ConfirmationTokenSHA256 = ""
	before.ConfirmationAccepted = true
	return before == after
}

func (m *Manager) issueNativeConfirmation(tokenHash string) (int64, error) {
	var remaining int64
	err := m.withLock(func() error {
		s, err := m.readNativeSession()
		if err != nil {
			return err
		}
		h, err := m.readNativeHealth()
		if err != nil {
			return err
		}
		boot, err := trialBootIdentity()
		if err != nil {
			return err
		}
		now, err := nativeUptimeMillis()
		if err != nil {
			return err
		}
		if s.ConfirmationTokenSHA256 != tokenHash || s.ConfirmationAccepted ||
			s.HealthOperationID != h.OperationID || boot != h.BootID ||
			s.ConfirmationBootID != boot || s.ConfirmationIssuedMS != 0 {
			return Fault("guard_pending", "native confirmation belongs to a different operation")
		}
		state, err := m.load()
		if err != nil {
			return err
		}
		if state.Desired != "smart" {
			return Fault("guard_pending", "native activation is no longer Smart")
		}
		s.ConfirmationIssuedMS = now
		s.ConfirmationDeadlineMS = now + nativeConfirmationTTLMS
		raw, err := json.Marshal(s)
		if err != nil {
			return err
		}
		if err := put(filepath.Join(m.Dir, nativeSessionFile), raw); err != nil {
			return err
		}
		remaining = nativeConfirmationTTLMS / 1000
		return nil
	})
	return remaining, err
}

func (m *Manager) ConfirmNativeSmartRouting(token string) error {
	if len(token) != 48 {
		return Fault("invalid_arguments", "expected the one-use confirmation token from connect-smart")
	}
	if _, err := hex.DecodeString(token); err != nil {
		return Fault("invalid_arguments", "invalid confirmation token")
	}
	err := m.nativeUnitOwnership()
	if err != nil {
		return err
	}
	return m.withNativeTransition(func() error {
		return m.withLock(func() error {
			session, err := m.readNativeSession()
			if err != nil {
				return err
			}
			h, err := m.readNativeHealth()
			if err != nil {
				return err
			}
			state, err := m.load()
			if err != nil {
				return err
			}
			boot, err := trialBootIdentity()
			if err != nil {
				return err
			}
			now, err := nativeUptimeMillis()
			if err != nil {
				return err
			}
			if state.Desired != "smart" || session.HealthOperationID != h.OperationID ||
				session.ConfigSHA256 != h.ConfigSHA256 || session.ConfirmationAccepted ||
				session.ConfirmationTokenSHA256 == "" || session.ConfirmationIssuedMS == 0 ||
				session.ConfirmationBootID != boot || h.BootID != boot ||
				now < session.ConfirmationIssuedMS || now >= session.ConfirmationDeadlineMS ||
				h.Phase == "off" || h.Phase == "stopping" {
				return Fault("confirmation_expired", "activation is not pending or has expired; check native-status and restore Direct before retrying")
			}
			digest := sha256.Sum256([]byte(token))
			want, err := hex.DecodeString(session.ConfirmationTokenSHA256)
			if err != nil || subtle.ConstantTimeCompare(digest[:], want) != 1 {
				return Fault("confirmation_invalid", "confirmation token does not match this activation")
			}
			if err := nativeFreshSSHSession(session.ConfirmationIssuedMS); err != nil {
				return err
			}
			if err := nativeHealthGuardRoles(); err != nil {
				return err
			}
			activity, err := m.nativeActivity()
			if err != nil || activity != "active" {
				return Fault("guard_pending", "native Core is not active")
			}
			if err := m.verifyNativeLiveOutputGuard(session); err != nil {
				return err
			}
			if err := requireNativeReplyGuardClaim(context.Background(), nativeSystemRunner{}, session.ReplyGuardHandle, session.ReplyGuardFingerprint); err != nil {
				return err
			}
			if _, _, err := m.nativeCoreChildIdentity(); err != nil {
				return err
			}
			if err := m.nativeReadyKernelPolicy(session, h.ProbeScope); err != nil {
				return err
			}
			session.ConfirmationAccepted = true
			session.ConfirmationTokenSHA256 = "" // no replay after durable commit
			raw, err := json.Marshal(session)
			if err != nil {
				return err
			}
			return put(filepath.Join(m.Dir, nativeSessionFile), raw)
		})
	})
}
