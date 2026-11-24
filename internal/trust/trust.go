// Package trust decides whether an actor could modify a file (D18).
package trust

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Actor is the user whose write access matters.
type Actor struct {
	UID  uint32
	GIDs []uint32 // all groups, primary included
}

// File is a resolved file. Close it when done.
type File struct {
	Path    string // fully resolved
	Trusted bool
	Reason  string // why it is not trusted
	Stat    unix.Stat_t
	fd      int
}

// Close releases the file.
func (f *File) Close() { _ = unix.Close(f.fd) }

// Regular reports whether it is a regular file.
func (f *File) Regular() bool { return f.Stat.Mode&unix.S_IFMT == unix.S_IFREG }

// Open opens the resolved file itself for reading, with no path lookup that
// could be raced. Only regular files can be opened.
func (f *File) Open() (*os.File, error) {
	if !f.Regular() {
		return nil, fmt.Errorf("%s: not a regular file", f.Path)
	}
	return os.OpenFile(procPath(f.fd), os.O_RDONLY, 0)
}

func procPath(fd int) string { return "/proc/self/fd/" + strconv.Itoa(fd) }

const maxLinks = 40

// Resolve walks an absolute path one component at a time. The file is trusted
// if the actor can modify neither it nor any directory used to reach it.
func Resolve(name string, a Actor) (*File, error) {
	if !path.IsAbs(name) {
		return nil, fmt.Errorf("%s: not an absolute path", name)
	}
	f := &File{Trusted: true, fd: -1}
	if a.UID == 0 {
		f.distrust("actor is root")
	}
	var dir int
	toRoot := func() (err error) {
		dir, err = unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		f.Path = "/"
		return err
	}
	if err := toRoot(); err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dir) }()
	if err := f.inspect(dir, "/", a); err != nil {
		return nil, err
	}
	todo := strings.Split(name, "/")
	links := 0
	for len(todo) > 0 {
		c := todo[0]
		todo = todo[1:]
		if c == "" || c == "." {
			continue
		}
		next, err := unix.Openat(dir, c, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: name, Err: err}
		}
		var st unix.Stat_t
		if err := unix.Fstat(next, &st); err != nil {
			_ = unix.Close(next)
			return nil, err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			// proc's links depend on who follows them.
			err := f.rejectProc(next)
			var target string
			if err == nil {
				target, err = readlink(next)
			}
			_ = unix.Close(next)
			if err != nil {
				return nil, err
			}
			if links++; links > maxLinks {
				return nil, &os.PathError{Op: "open", Path: name, Err: unix.ELOOP}
			}
			if path.IsAbs(target) {
				_ = unix.Close(dir)
				if err := toRoot(); err != nil {
					return nil, err
				}
			}
			todo = append(strings.Split(target, "/"), todo...)
			continue
		}
		_ = unix.Close(dir)
		dir = next
		f.Path = path.Join(f.Path, c) // ".." is physical: links are resolved
		if err := f.inspect(dir, f.Path, a); err != nil {
			return nil, err
		}
	}
	fd, err := unix.FcntlInt(uintptr(dir), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f.fd = fd
	return f, unix.Fstat(fd, &f.Stat)
}

func readlink(fd int) (string, error) {
	b := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(fd, "", b)
	if err != nil {
		return "", err
	}
	if n == 0 || n == len(b) {
		return "", unix.ENAMETOOLONG
	}
	return string(b[:n]), nil
}

func (f *File) distrust(format string, args ...any) {
	if f.Trusted {
		f.Trusted = false
		f.Reason = fmt.Sprintf(format, args...)
	}
}

func (f *File) rejectProc(fd int) error {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if fs.Type == unix.PROC_SUPER_MAGIC {
		f.distrust("path goes through /proc")
	}
	return nil
}

func (f *File) inspect(fd int, name string, a Actor) error {
	if err := f.rejectProc(fd); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	w, err := Writable(procPath(fd), &st, a)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if w {
		f.distrust("%s can be modified by the actor", name)
	}
	return nil
}

// Writable reports whether the actor owns or may write the file at p, whose
// status is st. It errs towards true: ACL masks and sticky bits are ignored.
func Writable(p string, st *unix.Stat_t, a Actor) (bool, error) {
	if a.UID == 0 || st.Uid == a.UID || st.Mode&0o002 != 0 {
		return true, nil
	}
	if st.Mode&0o020 != 0 && slices.Contains(a.GIDs, st.Gid) {
		return true, nil
	}
	b := make([]byte, 4096)
	n, err := unix.Getxattr(p, "system.posix_acl_access", b)
	switch {
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ENOTSUP):
		return false, nil
	case errors.Is(err, unix.ERANGE):
		return true, nil // absurdly long ACL
	case err != nil:
		return true, err
	}
	return aclWritable(b[:n], a), nil
}

// aclWritable parses the kernel's ACL format: a 4-byte version, then entries
// of tag, permissions (16 bits each) and id (32 bits).
func aclWritable(b []byte, a Actor) bool {
	const aclUser, aclGroup, write = 0x02, 0x08, 2
	if len(b) < 4 || (len(b)-4)%8 != 0 || binary.LittleEndian.Uint32(b) != 2 {
		return true
	}
	for b = b[4:]; len(b) > 0; b = b[8:] {
		id := binary.LittleEndian.Uint32(b[4:])
		if binary.LittleEndian.Uint16(b[2:])&write == 0 {
			continue
		}
		switch binary.LittleEndian.Uint16(b) {
		case aclUser:
			if id == a.UID {
				return true
			}
		case aclGroup:
			if slices.Contains(a.GIDs, id) {
				return true
			}
		case 0x04: // owning group; st.Mode shows the mask instead of this
			// Covered by the caller only if the mask has write. If it does
			// not, the entry is ineffective.
		}
	}
	return false
}
