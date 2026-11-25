// Package transfer copies files between client and host (PLAN.md 4.8).
package transfer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"witnesshell/internal/launch"
	"witnesshell/internal/view"
)

// Stage makes a file without a name in dir, so that nothing but this process
// can reach it and a crash removes it.
func Stage(dir string) (*os.File, error) {
	fd, err := unix.Open(dir, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "stage", Path: dir, Err: err}
	}
	return os.NewFile(uintptr(fd), "staged"), nil
}

// Fill copies exactly size bytes from r to f and returns their hash.
func Fill(f *os.File, r io.Reader, size int64) (string, error) {
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, size))
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
	}
	return hex.EncodeToString(h.Sum(nil)), err
}

// Dest is a destination on the host as it was when looked at.
type Dest struct {
	Dir    string // resolved
	Name   string
	Exists bool
	Size   int64
	SHA256 string // of the existing file; empty if the user cannot read it

	stat unix.Stat_t
}

// Path returns the whole path.
func (d *Dest) Path() string {
	if d.Dir == "/" {
		return "/" + d.Name
	}
	return d.Dir + "/" + d.Name
}

// ErrChanged means that the destination is not what was approved.
var ErrChanged = errors.New("the destination changed after it was approved")

// Look examines a destination as u. name may be relative to base.
func Look(u launch.User, base, name string) (*Dest, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return nil, errors.New("no destination")
	}
	if !strings.HasPrefix(name, "/") {
		name = base + "/" + name
	}
	i := strings.LastIndexByte(name, '/')
	d := &Dest{Name: name[i+1:]}
	if d.Name == "" || d.Name == "." || d.Name == ".." {
		return nil, errors.New("the destination must be a file, not a directory")
	}
	err := launch.AsUser(u, func() error {
		dir, err := d.open(name[:i+1])
		if err != nil {
			return err
		}
		defer unix.Close(dir)
		return d.look(dir)
	})
	if err != nil {
		return nil, err
	}
	if view.Escape(d.Path()) != d.Path() {
		return nil, errors.New("the destination has hidden or control characters")
	}
	return d, nil
}

// open opens the directory and notes where it really is.
func (d *Dest) open(path string) (int, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil || fs.Type == unix.PROC_SUPER_MAGIC {
		_ = unix.Close(fd)
		return -1, errors.New("files in /proc are not allowed here")
	}
	if d.Dir, err = os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (d *Dest) look(dir int) error {
	err := unix.Fstatat(dir, d.Name, &d.stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return &os.PathError{Op: "stat", Path: d.Path(), Err: err}
	}
	if d.stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%s is not a regular file", d.Path())
	}
	d.Exists, d.Size = true, d.stat.Size
	fd, err := unix.Openat(dir, d.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil // replacing needs no permission to read
	}
	f := os.NewFile(uintptr(fd), d.Name)
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	d.SHA256 = hex.EncodeToString(h.Sum(nil))
	return nil
}

func same(a, b *unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mtim == b.Mtim && a.Mode == b.Mode
}

// Place writes size bytes of src, which must have the given hash, to the
// destination as u. The result is never executable. A replaced file's other
// permissions are kept.
func Place(u launch.User, d *Dest, src *os.File, size int64, hash string, umask uint32) error {
	return launch.AsUser(u, func() (err error) {
		now := *d
		dir, err := now.open(d.Dir)
		if err != nil {
			return err
		}
		defer unix.Close(dir)
		if now.Dir != d.Dir {
			return ErrChanged
		}
		var r [8]byte
		if _, err := rand.Read(r[:]); err != nil {
			return err
		}
		tmp := ".witsh-" + hex.EncodeToString(r[:])
		fd, err := unix.Openat(dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return &os.PathError{Op: "create", Path: d.Path(), Err: err}
		}
		f := os.NewFile(uintptr(fd), tmp)
		defer f.Close()
		placed := false
		defer func() {
			if !placed {
				err = errors.Join(err, unix.Unlinkat(dir, tmp, 0))
			}
		}()
		got, err := Fill(f, io.NewSectionReader(src, 0, size), size)
		if err != nil {
			return err
		}
		if got != hash {
			return errors.New("the staged file is damaged")
		}
		mode := 0o666 &^ umask
		if d.Exists {
			mode = d.stat.Mode & 0o666
		}
		if err := unix.Fchmod(fd, mode&0o666); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		if !d.Exists {
			err := unix.Renameat2(dir, tmp, dir, d.Name, unix.RENAME_NOREPLACE)
			if errors.Is(err, unix.EEXIST) {
				return ErrChanged
			}
			placed = err == nil
			return err
		}
		// Exchange the two, then see what it was that was replaced. If it is not
		// what was approved, undo it.
		if err := unix.Renameat2(dir, tmp, dir, d.Name, unix.RENAME_EXCHANGE); err != nil {
			if errors.Is(err, unix.ENOENT) {
				return ErrChanged
			}
			return err
		}
		var old unix.Stat_t
		if err := unix.Fstatat(dir, tmp, &old, unix.AT_SYMLINK_NOFOLLOW); err != nil || !same(&old, &d.stat) {
			return errors.Join(ErrChanged, unix.Renameat2(dir, tmp, dir, d.Name, unix.RENAME_EXCHANGE))
		}
		placed = true
		return unix.Unlinkat(dir, tmp, 0)
	})
}
