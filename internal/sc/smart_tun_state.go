package sc

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// The policy and transient credential share the journal's pinned directory
// and lifecycle lock. Existing entries are untrusted: reject links, devices,
// FIFOs, foreign owners and oversized data before reading any bytes.
func (store *activationJournalDir) openSmartTUNFile(name string) (*os.File, activationJournalFileIdentity, error) {
	var identity activationJournalFileIdentity
	if name != smartRoutingRulesFilename {
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
