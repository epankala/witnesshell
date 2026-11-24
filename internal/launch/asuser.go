package launch

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// AsUser runs f on a thread that accesses files as u and has no capabilities.
// The thread is discarded afterwards. The process as a whole stays root, so u
// can neither signal nor trace it. f must not start goroutines or programs.
func AsUser(u User, f func() error) error {
	if os.Getuid() != 0 {
		if uint32(os.Getuid()) == u.UID { // unprivileged tests
			return f()
		}
		return errors.New("must be root")
	}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with us
		if err := fsDrop(u); err != nil {
			done <- err
			return
		}
		done <- f()
	}()
	return <-done
}

func fsDrop(u User) error {
	if u.UID == 0 || u.GID == 0 {
		return errors.New("refusing to act as root")
	}
	groups := append([]uint32{u.GID}, u.Groups...)
	if _, _, e := unix.RawSyscall(unix.SYS_SETGROUPS, uintptr(len(groups)), uintptr(unsafe.Pointer(&groups[0])), 0); e != 0 {
		return fmt.Errorf("setgroups: %w", e)
	}
	// These report the previous value, so a second call verifies the first.
	for _, c := range [][2]uintptr{{unix.SYS_SETFSGID, uintptr(u.GID)}, {unix.SYS_SETFSUID, uintptr(u.UID)}} {
		_, _, _ = unix.RawSyscall(c[0], c[1], 0, 0)
		if got, _, _ := unix.RawSyscall(c[0], c[1], 0, 0); got != c[1] {
			return errors.New("could not take on the user's file access")
		}
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("drop capabilities: %w", err)
	}
	return nil
}

// OpenAs opens name, relative to dir, as u would. Links in /proc such as
// /dev/stdin are refused, since they would mean this process's files; so is
// everything else in /proc. Opening never blocks.
func OpenAs(u User, dir, name string, flags int) (f *os.File, err error) {
	err = AsUser(u, func() error {
		d, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return &os.PathError{Op: "open", Path: dir, Err: err}
		}
		defer unix.Close(d)
		how := unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY), Resolve: unix.RESOLVE_NO_MAGICLINKS}
		if flags&unix.O_CREAT != 0 {
			how.Mode = 0o666 // narrowed by the caller's umask
		}
		fd, err := unix.Openat2(d, name, &how)
		if err != nil {
			return &os.PathError{Op: "open", Path: name, Err: err}
		}
		var fs unix.Statfs_t
		if err := unix.Fstatfs(fd, &fs); err != nil || fs.Type == unix.PROC_SUPER_MAGIC {
			_ = unix.Close(fd)
			return &os.PathError{Op: "open", Path: name, Err: errors.New("files in /proc are not allowed here")}
		}
		if flags&unix.O_PATH == 0 {
			if err := unix.SetNonblock(fd, false); err != nil {
				_ = unix.Close(fd)
				return err
			}
		}
		f = os.NewFile(uintptr(fd), name)
		return nil
	})
	return f, err
}
