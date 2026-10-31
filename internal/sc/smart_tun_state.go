package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
)

const smartTUNSavedPolicyFile = "smart-tun-policy.json"

// The policy and transient credential share the journal's pinned directory
// and lifecycle lock. Existing entries are untrusted: reject links, devices,
// FIFOs, foreign owners and oversized data before reading any bytes.
func (store *activationJournalDir) openSmartTUNFile(name string) (*os.File, activationJournalFileIdentity, error) {
	var identity activationJournalFileIdentity
	if name != smartTUNSavedPolicyFile && name != smartTUNTrialConfigFile && name != smartRoutingRulesFilename {
		return nil, identity, journalFSUnavailable("unsupported TUN state filename")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return nil, identity, err
	}
	fd, err := syscall.Openat(int(store.dir.Fd()), name,
		syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, identity, os.ErrNotExist
	}
	if err != nil {
		return nil, identity, Fault("trial_resource_conflict", "private TUN state is unavailable or substituted")
	}
	file := os.NewFile(uintptr(fd), "private-tun-state")
	info, err := journalStat(fd)
	if err != nil || !journalPrivateFile(info) || info.Size <= 0 || info.Size > activationJournalMaxBytes {
		_ = file.Close()
		return nil, identity, Fault("trial_resource_conflict", "private TUN state type, owner, mode, link count or size is invalid")
	}
	return file, activationJournalFileIdentity{dev: uint64(info.Dev), ino: info.Ino}, nil
}

func (store *activationJournalDir) readSmartTUNFile(name string) ([]byte, activationJournalFileIdentity, error) {
	file, identity, err := store.openSmartTUNFile(name)
	if err != nil {
		return nil, identity, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, activationJournalMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > activationJournalMaxBytes {
		return nil, identity, Fault("trial_resource_conflict", "private TUN state cannot be read within size bound")
	}
	return data, identity, nil
}

func (store *activationJournalDir) checkSmartTUNFile(name string, expected *activationJournalFileIdentity) error {
	file, found, err := store.openSmartTUNFile(name)
	if errors.Is(err, os.ErrNotExist) && expected == nil {
		return nil
	}
	if err != nil {
		return Fault("trial_resource_conflict", "private TUN state identity disappeared or became untrusted")
	}
	_ = file.Close()
	if expected == nil || found != *expected {
		return Fault("trial_resource_conflict", "private TUN state identity changed while locked")
	}
	return nil
}

func (store *activationJournalDir) writeSmartTUNFile(name string, data []byte, expected *activationJournalFileIdentity) error {
	if len(data) == 0 || len(data) > activationJournalMaxBytes {
		return Fault("trial_resource_conflict", "private TUN state exceeds size bound")
	}
	if err := store.checkSmartTUNFile(name, expected); err != nil {
		return err
	}
	random, err := randomHex(12)
	if err != nil {
		return journalFSUnavailable("cannot select private TUN temporary filename")
	}
	temporary := ".sc-tun-" + random
	fd, err := syscall.Openat(int(store.dir.Fd()), temporary,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return journalFSUnavailable("cannot create private TUN temporary file")
	}
	defer syscall.Unlinkat(int(store.dir.Fd()), temporary)
	file := os.NewFile(uintptr(fd), "private-tun-temporary")
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return journalFSUnavailable("cannot set private TUN state mode")
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return journalFSUnavailable("cannot write private TUN state")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return journalFSUnavailable("cannot sync private TUN state")
	}
	if err := file.Close(); err != nil {
		return journalFSUnavailable("cannot close private TUN state")
	}
	if err := store.checkSmartTUNFile(name, expected); err != nil {
		return err
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	if err := syscall.Renameat(int(store.dir.Fd()), temporary, int(store.dir.Fd()), name); err != nil {
		return journalFSUnavailable("cannot publish private TUN state")
	}
	if err := store.dir.Sync(); err != nil {
		return journalFSUnavailable("private TUN state durability is uncertain")
	}
	return nil
}

// Keep the exact-operation durability prerequisite next to the unlink so
// every attempt, including a visible-cleanup retry, must pass it. The same
// barrier also persists an earlier uncertain unlink when already absent.
// directorySync is only an argument-scoped filesystem failure seam.
func (store *activationJournalDir) removeSmartTUNCredential(journalIdentity activationJournalFileIdentity, record smartTUNTrialJournal, credential *activationJournalFileIdentity, directorySync func(int) error) error {
	if err := syncSmartTUNCleanupLocked(store, journalIdentity, record, directorySync); err != nil {
		return err
	}
	data, found, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
	if credential == nil && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || credential == nil || found != *credential || sha256Hex(data) != record.ConfigSHA256 {
		return Fault("trial_resource_conflict", "TUN credential identity or bytes changed before removal")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	if err := syscall.Unlinkat(int(store.dir.Fd()), smartTUNTrialConfigFile); err != nil {
		return journalFSUnavailable("cannot remove exact TUN credential")
	}
	if err := directorySync(int(store.dir.Fd())); err != nil {
		return journalFSUnavailable("TUN credential removal durability is uncertain")
	}
	return nil
}

// This record contains only non-secret routing configuration. In particular,
// it contains neither a profile/outbound nor an activation operation ID.
type smartTUNSavedPolicy struct {
	Version          int                      `json:"version"`
	ManagementPeerIP string                   `json:"management_peer_ip"`
	Options          SmartTUNCandidateOptions `json:"options"`
}

type SmartTUNSavedPolicyStatus struct {
	Present          bool                      `json:"present"`
	ExperimentOnly   bool                      `json:"experiment_only"`
	Version          int                       `json:"version,omitempty"`
	SHA256           string                    `json:"sha256,omitempty"`
	ManagementPeerIP string                    `json:"management_peer_ip,omitempty"`
	Options          *SmartTUNCandidateOptions `json:"options,omitempty"`
}

type smartTUNSavedPolicyBinding struct {
	identity activationJournalFileIdentity
	digest   string
}

var smartTUNSavedPolicyFields = map[string]bool{
	"version": true, "management_peer_ip": true, "options": true,
}

var smartTUNSavedOptionsFields = map[string]bool{
	"tunnel_interface": true, "underlay_interface": true,
	"tunnel_ipv4": true, "tunnel_ipv6": true,
	"protected_cidrs": true, "protected_ipv6_cidrs": true,
	"domestic_cidrs": true, "domestic_ipv6_cidrs": true,
	"exceptions": true, "ipv6_exceptions": true, "domain_exceptions": true,
}

func decodeSavedSmartTUNPolicy(data []byte) (smartTUNSavedPolicy, error) {
	var policy smartTUNSavedPolicy
	invalid := func() (smartTUNSavedPolicy, error) {
		return smartTUNSavedPolicy{}, Fault("saved_policy_invalid", "saved TUN policy is malformed or outside supported disposable fixtures")
	}
	if rejectAmbiguousJournalJSON(data) != nil || requireExactJournalKeys(data, smartTUNSavedPolicyFields) != nil {
		return invalid()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || requireExactJournalKeys(fields["options"], smartTUNSavedOptionsFields) != nil {
		return invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&policy) != nil || policy.Version != 1 ||
		policy.ManagementPeerIP != "10.254.72.2" || !smartTUNTrialFixturePolicySupported(policy.Options) {
		return invalid()
	}
	// Nested exception names must also be exact, not encoding/json's
	// case-insensitive aliases. Null/unknown data never widens fixture scope.
	var options map[string]json.RawMessage
	_ = json.Unmarshal(fields["options"], &options)
	for _, field := range []string{"tunnel_interface", "underlay_interface", "tunnel_ipv4", "tunnel_ipv6"} {
		raw := bytes.TrimSpace(options[field])
		if len(raw) < 2 || raw[0] != '"' {
			return invalid()
		}
	}
	for _, field := range []string{"exceptions", "ipv6_exceptions"} {
		var rows []json.RawMessage
		if json.Unmarshal(options[field], &rows) != nil {
			return invalid()
		}
		for _, row := range rows {
			if requireExactJournalKeys(row, map[string]bool{"cidr": true, "via": true}) != nil {
				return invalid()
			}
		}
	}
	return policy, nil
}

// With no expected binding this still refuses a corrupted existing policy
// before prearm. --saved additionally pins the inode and bytes through BOTH
// admissions, so a replaced saved record cannot be applied as stale input.
func checkSavedSmartTUNPolicyLocked(store *activationJournalDir, expected *smartTUNSavedPolicyBinding) error {
	data, identity, err := store.readSmartTUNFile(smartTUNSavedPolicyFile)
	if errors.Is(err, os.ErrNotExist) && expected == nil {
		return nil
	}
	if err != nil {
		return Fault("saved_policy_invalid", "saved TUN policy is absent or untrusted")
	}
	if _, err := decodeSavedSmartTUNPolicy(data); err != nil {
		return err
	}
	if expected != nil && (identity != expected.identity || sha256Hex(data) != expected.digest) {
		return Fault("saved_policy_conflict", "saved TUN policy changed during activation admission")
	}
	return nil
}

func saveSmartTUNPolicyLocked(store *activationJournalDir, options SmartTUNCandidateOptions, managementPeer string) error {
	data, err := json.Marshal(smartTUNSavedPolicy{Version: 1, ManagementPeerIP: managementPeer, Options: options})
	if err != nil {
		return Fault("saved_policy_invalid", "cannot encode saved TUN policy")
	}
	data = append(data, '\n')
	if _, err := decodeSavedSmartTUNPolicy(data); err != nil {
		return err
	}
	old, identity, err := store.readSmartTUNFile(smartTUNSavedPolicyFile)
	if errors.Is(err, os.ErrNotExist) {
		return store.writeSmartTUNFile(smartTUNSavedPolicyFile, data, nil)
	}
	if err != nil {
		return err
	}
	if _, err := decodeSavedSmartTUNPolicy(old); err != nil {
		return err
	}
	if bytes.Equal(old, data) {
		return nil // unchanged settings retain their exact inode and bytes
	}
	return store.writeSmartTUNFile(smartTUNSavedPolicyFile, data, &identity)
}

func (m *Manager) InspectSavedSmartTUNTrialPolicy() (SmartTUNSavedPolicyStatus, error) {
	status := SmartTUNSavedPolicyStatus{ExperimentOnly: true}
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		data, _, err := store.readSmartTUNFile(smartTUNSavedPolicyFile)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		policy, err := decodeSavedSmartTUNPolicy(data)
		if err != nil {
			return err
		}
		status.Present, status.Version, status.SHA256 = true, policy.Version, sha256Hex(data)
		status.ManagementPeerIP, status.Options = policy.ManagementPeerIP, &policy.Options
		return nil
	})
	return status, err
}

func (m *Manager) BeginSavedSmartTUNTrial(deadlineSeconds int, qaKillPoint string) (SmartTUNTrialReceipt, error) {
	if m.Dir != DefaultDir || m.Core != DefaultCore {
		return SmartTUNTrialReceipt{}, Fault("trial_unsupported", "installed trial paths required")
	}
	if err := nativeTrialApplyPlatform(); err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	var policy smartTUNSavedPolicy
	var binding smartTUNSavedPolicyBinding
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		data, identity, err := store.readSmartTUNFile(smartTUNSavedPolicyFile)
		if err != nil {
			return Fault("saved_policy_invalid", "saved TUN policy is absent or untrusted")
		}
		policy, err = decodeSavedSmartTUNPolicy(data)
		if err != nil {
			return err
		}
		binding = smartTUNSavedPolicyBinding{identity: identity, digest: sha256Hex(data)}
		return nil
	})
	if err != nil {
		return SmartTUNTrialReceipt{}, err
	}
	return m.beginSmartTUNTrial(policy.Options, policy.ManagementPeerIP, deadlineSeconds, qaKillPoint, &binding, nil)
}
