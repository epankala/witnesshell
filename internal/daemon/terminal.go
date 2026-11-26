package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"

	"witnesshell/internal/launch"
	"witnesshell/internal/pty"
)

// TerminalArg is the hidden argument that makes the binary run Terminal.
const TerminalArg = "__terminal"

// Terminal is the first stage of a session's process. It hides all other
// terminals from the session, so that its programs can neither read nor write
// those of the same user's other logins, such as one that witnesses. It opens
// the session's own terminal, hands the other side to the daemon through the
// socket on descriptor 5, and becomes the leader. It returns only on failure.
func Terminal() error {
	if os.Getuid() != 0 {
		return errors.New("must be root")
	}
	// A mount namespace belongs to a thread; exec keeps this one.
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare: %w", err)
	}
	// What is mounted over /dev/pts must not propagate to the host, where later
	// logins would use it. Everything else should: "sudo mount" must work.
	if err := unix.Mount("", "/dev/pts", "", unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make /dev/pts private: %w", err)
	}
	if err := unix.Mount("devpts", "/dev/pts", "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620,gid=5"); err != nil {
		return fmt.Errorf("mount devpts: %w", err)
	}
	if err := ptmxDevice(); err != nil {
		return err
	}
	ptm, pts, err := pty.Open(24, 80)
	if err != nil {
		return err
	}
	if err := unix.Sendmsg(5, []byte{1}, unix.UnixRights(int(ptm.Fd())), nil, 0); err != nil {
		return fmt.Errorf("hand over terminal: %w", err)
	}
	_ = ptm.Close()
	if err := unix.IoctlSetInt(int(pts.Fd()), unix.TIOCSCTTY, 0); err != nil {
		return fmt.Errorf("controlling terminal: %w", err)
	}
	for fd := range 3 {
		if err := unix.Dup3(int(pts.Fd()), fd, 0); err != nil {
			return err
		}
	}
	_ = unix.Close(5)
	return syscall.Exec("/proc/self/exe", []string{"witsh", LeaderArg}, launch.ChildEnv())
}

// ptmxDevice makes sure that /dev/ptmx opens the new instance. The usual
// device node and the link to pts/ptmx both do.
func ptmxDevice() error {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("/dev/ptmx: %w", err)
	}
	defer unix.Close(fd)
	peer, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCGPTPEER, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC)
	if e == unix.EIO { // still locked
		if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
			return err
		}
		peer, _, e = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCGPTPEER, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC)
	}
	if e != 0 {
		return fmt.Errorf("/dev/ptmx: %w", e)
	}
	defer unix.Close(int(peer))
	var a, b unix.Stat_t
	if err := errors.Join(unix.Fstat(int(peer), &a), unix.Stat("/dev/pts", &b)); err != nil {
		return err
	}
	if a.Dev != b.Dev {
		return errors.New("/dev/ptmx does not open the session's own terminals")
	}
	return nil
}

// receiveTerminal gets the terminal that Terminal sends.
func receiveTerminal(c *net.UnixConn) (*os.File, error) {
	b, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	_, n, _, _, err := c.ReadMsgUnix(b, oob)
	if err != nil {
		return nil, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:n])
	if err != nil || len(msgs) != 1 {
		return nil, errors.New("no terminal received")
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		return nil, errors.New("no terminal received")
	}
	unix.CloseOnExec(fds[0])
	if err := unix.SetNonblock(fds[0], true); err != nil { // so that deadlines work
		return nil, err
	}
	return os.NewFile(uintptr(fds[0]), "ptmx"), nil
}
