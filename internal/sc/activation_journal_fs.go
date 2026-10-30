package sc

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Journal I/O is Linux-only, as are the product's routing and systemd
// acceptance targets. Never resolve the private state through a path-based
// Lstat/Open/Remove sequence. All journal and lock accesses use pinned,
// no-follow directory descriptors and the SAME .lock inode as Manager.withLock.
type activationJournalLink struct {
	parent *os.File
	child  *os.File
	name   string
}

type activationJournalDir struct {
	links []activationJournalLink // retain each ancestor, not only the leaf
	dir   *os.File
	lock  *os.File
}

type activationJournalFileIdentity struct {
	dev uint64
	ino uint64
}

func journalFSUnavailable(message string) error {
	return Fault("activation_journal_unavailable", message)
}

func journalStat(fd int) (syscall.Stat_t, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return stat, journalFSUnavailable("cannot verify private journal descriptor")
	}
	return stat, nil
}

func journalTrustedAncestor(stat syscall.Stat_t) bool {
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return false
	}
	if stat.Uid != 0 && int(stat.Uid) != os.Geteuid() {
		return false
	}
	// A root-owned sticky /tmp-style directory permits tests and the
	// supported Linux sticky-bit rule: an unprivileged non-owner cannot
	// replace an entry owned by the journal process. All other writable
	// ancestor directories are rejected.
	mode := stat.Mode & 07777
	if mode&0022 != 0 {
		return stat.Uid == 0 && mode == 01777
	}
	return true
}

func journalPrivateDir(stat syscall.Stat_t) bool {
	return stat.Mode&syscall.S_IFMT == syscall.S_IFDIR &&
		stat.Mode&07777 == 0700 && int(stat.Uid) == os.Geteuid()
}

func journalPrivateFile(stat syscall.Stat_t) bool {
	return stat.Mode&syscall.S_IFMT == syscall.S_IFREG &&
		stat.Mode&07777 == 0600 && int(stat.Uid) == os.Geteuid() &&
		stat.Nlink == 1
}

func journalSameInode(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino
}

// openActivationJournalDir opens every ancestor with O_DIRECTORY|O_NOFOLLOW.
// The only created component is the leaf state directory. Fsync its *parent*
// even when the leaf already exists: a prior failed sync cannot become a
// successful acknowledgment just because the directory is visible in RAM.
// Parent fsync injection is a test seam, never an operator-controlled setting.
func openActivationJournalDir(path string, parentSync func(int) error) (_ *activationJournalDir, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" ||
		parentSync == nil {
		return nil, journalFSUnavailable("state directory requires a clean absolute private path")
	}
	root, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, journalFSUnavailable("cannot open trusted filesystem root")
	}
	rootFile := os.NewFile(uintptr(root), "journal-root")
	opened := []*os.File{rootFile}
	retained := false
	defer func() {
		if !retained {
			for i := len(opened) - 1; i >= 0; i-- {
				_ = opened[i].Close()
			}
		}
	}()
	current := rootFile
	links := []activationJournalLink{}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, name := range segments {
		if name == "" || name == "." || name == ".." {
			return nil, journalFSUnavailable("invalid private state directory component")
		}
		parentInfo, statErr := journalStat(int(current.Fd()))
		if statErr != nil || !journalTrustedAncestor(parentInfo) {
			return nil, journalFSUnavailable("untrusted state directory ancestor or permissions")
		}
		flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		fd, openErr := syscall.Openat(int(current.Fd()), name, flags, 0)
		last := i == len(segments)-1
		if last && errors.Is(openErr, syscall.ENOENT) {
			if createErr := syscall.Mkdirat(int(current.Fd()), name, 0700); createErr != nil &&
				!errors.Is(createErr, syscall.EEXIST) {
				return nil, journalFSUnavailable("cannot create private state directory")
			}
			fd, openErr = syscall.Openat(int(current.Fd()), name, flags, 0)
		}
		if openErr != nil {
			return nil, journalFSUnavailable("state directory component is absent, substituted or untrusted")
		}
		child := os.NewFile(uintptr(fd), "journal-state-path-component")
		opened = append(opened, child)
		info, statErr := journalStat(fd)
		if statErr != nil || (last && !journalPrivateDir(info)) ||
			(!last && !journalTrustedAncestor(info)) {
			return nil, journalFSUnavailable("private state directory component ownership or mode is untrusted")
		}
		links = append(links, activationJournalLink{parent: current, child: child, name: name})
		if last {
			// Always retry parent fsync even if the directory already exists
			// after an earlier failed attempt in the same boot.
			if syncErr := parentSync(int(current.Fd())); syncErr != nil {
				return nil, journalFSUnavailable("state directory parent fsync failed; no PREPARED acknowledgment")
			}
			store := &activationJournalDir{links: links, dir: child}
			if err := store.ensureLinked(); err != nil {
				return nil, err
			}
			retained = true
			return store, nil
		}
		current = child
	}
	return nil, journalFSUnavailable("no private state directory component")
}

func (store *activationJournalDir) close() {
	if store.lock != nil {
		_ = syscall.Flock(int(store.lock.Fd()), syscall.LOCK_UN)
		_ = store.lock.Close()
		store.lock = nil
	}
	if len(store.links) > 0 {
		for i := len(store.links) - 1; i >= 0; i-- {
			_ = store.links[i].child.Close()
		}
		_ = store.links[0].parent.Close() // root handle
		store.links = nil
	}
	store.dir = nil
}

// Validate every component's parent->child link, not merely the private leaf.
// The path cannot silently redirect to another ancestor while this operation
// continues with descriptors pinned to its original subtree.
func (store *activationJournalDir) ensureLinked() error {
	for i, link := range store.links {
		fd, err := syscall.Openat(int(link.parent.Fd()), link.name,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return journalFSUnavailable("state directory ancestry was replaced or disconnected")
		}
		linked, err := journalStat(fd)
		_ = syscall.Close(fd)
		if err != nil {
			return err
		}
		pinned, err := journalStat(int(link.child.Fd()))
		if err != nil || !journalSameInode(linked, pinned) {
			return journalFSUnavailable("state directory ancestor inode changed while locked")
		}
		if (i == len(store.links)-1 && !journalPrivateDir(linked)) ||
			(i < len(store.links)-1 && !journalTrustedAncestor(linked)) {
			return journalFSUnavailable("state directory ancestry became untrusted")
		}
	}
	return nil
}

func (store *activationJournalDir) lockSharedManager() error {
	if err := store.ensureLinked(); err != nil {
		return err
	}
	fd, err := syscall.Openat(int(store.dir.Fd()), ".lock",
		syscall.O_RDWR|syscall.O_CREAT|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return journalFSUnavailable("cannot open trusted shared manager lock")
	}
	store.lock = os.NewFile(uintptr(fd), "journal-shared-manager-lock")
	stat, err := journalStat(int(store.lock.Fd()))
	if err != nil || !journalPrivateFile(stat) {
		return journalFSUnavailable("shared manager lock ownership, link count or mode is untrusted")
	}
	if err := syscall.Flock(int(store.lock.Fd()), syscall.LOCK_EX); err != nil {
		return journalFSUnavailable("cannot acquire shared manager lifecycle lock")
	}
	return store.ensureLockIdentity()
}

func (store *activationJournalDir) ensureLockIdentity() error {
	if err := store.ensureLinked(); err != nil {
		return err
	}
	fd, err := syscall.Openat(int(store.dir.Fd()), ".lock",
		syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return journalFSUnavailable("shared manager lock path was replaced")
	}
	defer syscall.Close(fd)
	linked, err := journalStat(fd)
	if err != nil || !journalPrivateFile(linked) {
		return journalFSUnavailable("shared manager lock path is untrusted")
	}
	pinned, err := journalStat(int(store.lock.Fd()))
	if err != nil || !journalSameInode(linked, pinned) {
		return journalFSUnavailable("shared manager lock inode diverged from the acquired lock")
	}
	return nil
}

// Existing on-disk entries are untrusted even when their mode looks private:
// O_NOFOLLOW alone does not reject FIFOs and blocking devices. Every
// descriptor opened on a preexisting journal or .lock entry uses O_NONBLOCK,
// and Fstat verifies the regular-file type before reading or taking flock.
// Creating a new temporary file with O_EXCL is separate and safe.
//
// This uses the exact existing .lock inode, rather than a separate journal
// lock. All journal filesystem operations happen while it is held.
func (m *Manager) withActivationJournalLock(parentSync func(int) error, fn func(*activationJournalDir) error) error {
	store, err := openActivationJournalDir(m.Dir, parentSync)
	if err != nil {
		return err
	}
	defer store.close()
	if err := store.lockSharedManager(); err != nil {
		return err
	}
	return fn(store)
}

func (store *activationJournalDir) openJournal() (_ *os.File, identity activationJournalFileIdentity, err error) {
	if err := store.ensureLockIdentity(); err != nil {
		return nil, identity, err
	}
	fd, err := syscall.Openat(int(store.dir.Fd()), activationJournalFilename,
		syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, identity, os.ErrNotExist
	}
	if err != nil {
		return nil, identity, activationJournalError("private activation journal is a symlink or unavailable")
	}
	file := os.NewFile(uintptr(fd), "journal-record")
	info, err := journalStat(fd)
	if err != nil || !journalPrivateFile(info) || info.Size <= 0 ||
		info.Size > activationJournalMaxBytes {
		_ = file.Close()
		return nil, identity, activationJournalError("private activation journal ownership, mode or size is invalid")
	}
	return file, activationJournalFileIdentity{dev: uint64(info.Dev), ino: info.Ino}, nil
}

func (store *activationJournalDir) readJournal() ([]byte, activationJournalFileIdentity, error) {
	file, id, err := store.openJournal()
	if err != nil {
		return nil, id, err
	}
	defer file.Close()
	// A bounded read *after* descriptor verification. No path reopen, and
	// size changes after fstat cannot make the read unbounded.
	data, err := io.ReadAll(io.LimitReader(file, activationJournalMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > activationJournalMaxBytes {
		return nil, id, activationJournalError("private activation journal cannot be read within size limit")
	}
	return data, id, nil
}

func (store *activationJournalDir) checkTarget(expected *activationJournalFileIdentity) error {
	file, found, err := store.openJournal()
	if errors.Is(err, os.ErrNotExist) {
		if expected != nil {
			return Fault("activation_journal_conflict", "previous journal identity disappeared")
		}
		return nil
	}
	if err != nil {
		return err
	}
	_ = file.Close()
	if expected == nil || found != *expected {
		return Fault("activation_journal_conflict", "journal identity changed during locked operation")
	}
	return nil
}

// writeJournal is bounded, no-follow and fd-relative throughout. It never
// rewrites any existing record that was not read under this exact lock.
// Temp file fsync precedes rename; directory fsync follows it. A post-rename
// sync failure returns an error and intentionally retains uncertain evidence.
func (store *activationJournalDir) writeJournal(data []byte, expected *activationJournalFileIdentity) error {
	return store.writeJournalWithDirSync(data, expected, syscall.Fsync)
}

// The directory-only sync argument is a narrow failure seam, like the
// parent sync in openActivationJournalDir; production always uses Fsync.
func (store *activationJournalDir) writeJournalWithDirSync(data []byte, expected *activationJournalFileIdentity, directorySync func(int) error) error {
	if len(data) == 0 || len(data) > activationJournalMaxBytes {
		return activationJournalError("activation journal record exceeds size bound")
	}
	if directorySync == nil {
		return journalFSUnavailable("activation journal directory sync is unavailable")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	random, err := randomHex(12)
	if err != nil {
		return journalFSUnavailable("cannot select private journal temporary filename")
	}
	name := ".sc-journal-" + random
	fd, err := syscall.Openat(int(store.dir.Fd()), name,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return journalFSUnavailable("cannot create private journal temporary file")
	}
	defer syscall.Unlinkat(int(store.dir.Fd()), name)
	file := os.NewFile(uintptr(fd), "journal-temporary")
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return journalFSUnavailable("cannot set private journal mode")
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return journalFSUnavailable("cannot write activation journal")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return journalFSUnavailable("activation journal file fsync failed")
	}
	if err := file.Close(); err != nil {
		return journalFSUnavailable("cannot close durable activation journal file")
	}
	if err := store.checkTarget(expected); err != nil {
		return err
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	if err := syscall.Renameat(int(store.dir.Fd()), name, int(store.dir.Fd()), activationJournalFilename); err != nil {
		return journalFSUnavailable("cannot atomically publish activation journal")
	}
	if err := directorySync(int(store.dir.Fd())); err != nil {
		return journalFSUnavailable("activation journal directory fsync failed; persisted state is uncertain")
	}
	return nil
}

func (store *activationJournalDir) removeJournal(expected activationJournalFileIdentity) error {
	if err := store.checkTarget(&expected); err != nil {
		return err
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	if err := syscall.Unlinkat(int(store.dir.Fd()), activationJournalFilename); err != nil {
		return journalFSUnavailable("cannot unlink the expected prepared journal")
	}
	if err := syscall.Fsync(int(store.dir.Fd())); err != nil {
		return journalFSUnavailable("cannot persist prepared journal removal")
	}
	return nil
}
