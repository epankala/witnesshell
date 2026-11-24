// Package pty opens pseudo-terminals.
package pty

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Open returns the two sides of a new terminal. Reads from the master can be
// interrupted by closing it.
func Open(rows, cols uint16) (master, slave *os.File, err error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open ptmx: %w", err)
	}
	master = os.NewFile(uintptr(fd), "ptmx")
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		_ = master.Close()
		return nil, nil, fmt.Errorf("unlock pty: %w", err)
	}
	s, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCGPTPEER, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC)
	if e != 0 {
		_ = master.Close()
		return nil, nil, fmt.Errorf("open pty peer: %w", e)
	}
	slave = os.NewFile(s, "pts")
	if err := Resize(master, rows, cols); err != nil {
		_, _ = master.Close(), slave.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

// Resize sets the terminal size.
func Resize(master *os.File, rows, cols uint16) error {
	rc, err := master.SyscallConn() // Fd() would make the file blocking
	if err != nil {
		return err
	}
	var e error
	if err := rc.Control(func(fd uintptr) {
		e = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols})
	}); err != nil {
		return err
	}
	return e
}
