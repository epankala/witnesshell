// Package shell runs an actor's bash so that it takes commands only from a
// private socket and never from the terminal. See PLAN.md section 4.3.
package shell

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	ErrBusy   = errors.New("shell is busy")
	ErrExited = errors.New("shell has exited")
)

// Config describes the bash process to start.
type Config struct {
	Path       string // path to bash
	Args       []string
	Dir        string
	Env        []string
	Credential *syscall.Credential // nil keeps the caller's identity
	Rows, Cols uint16
}

// Shell is a running bash. Methods are safe for concurrent use.
type Shell struct {
	mu      sync.Mutex // serializes Run, Idle and Close
	cmd     *exec.Cmd
	ptm     *os.File // terminal, our side
	pts     *os.File // terminal, shell's side; kept for flushing
	ctl     *os.File // commands, our side
	ctlPeer *os.File // commands, shell's side; kept to count unread bytes
	done    chan struct{}
	closed  bool
}

// Start launches bash. Wait for Idle before the first Run.
func Start(c Config) (s *Shell, err error) {
	s = &Shell{done: make(chan struct{})}
	defer func() {
		if err != nil {
			s.closeFiles()
		}
	}()
	if err = s.openPTY(c); err != nil {
		return nil, err
	}
	// A socket, not a pipe: /proc/PID/fd/N can reopen a pipe for writing,
	// which would let any program inject commands.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair: %w", err)
	}
	s.ctl = os.NewFile(uintptr(fds[0]), "ctl")
	s.ctlPeer = os.NewFile(uintptr(fds[1]), "ctl-peer")

	// Interactive, so Ctrl-C returns bash to its command loop. Without line
	// editing, so that it waits in a plain read(2), which Idle recognizes.
	s.cmd = exec.Command(c.Path, append([]string{"--noediting"}, append(c.Args, "-i")...)...)
	s.cmd.Dir, s.cmd.Env = c.Dir, c.Env
	s.cmd.Stdin, s.cmd.Stdout, s.cmd.Stderr = s.ctlPeer, s.pts, s.pts
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 1, Credential: c.Credential}
	if err = s.cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		_ = s.cmd.Wait()
		close(s.done)
	}()
	// Queued after startup files: no history expansion (approved text must
	// run as shown), no history file entries, no automatic logout.
	if _, err = s.ctl.WriteString("set +H; set +o history; unset TMOUT\n"); err != nil {
		_ = s.cmd.Process.Kill()
		return nil, err
	}
	return s, nil
}

func (s *Shell) openPTY(c Config) error {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open ptmx: %w", err)
	}
	s.ptm = os.NewFile(uintptr(fd), "ptmx") // non-blocking: Close interrupts Read
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		return fmt.Errorf("unlock pty: %w", err)
	}
	pfd, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCGPTPEER,
		unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC)
	if e != 0 {
		return fmt.Errorf("open pty peer: %w", e)
	}
	s.pts = os.NewFile(pfd, "pts")
	if c.Credential != nil {
		if err := unix.Fchown(int(pfd), int(c.Credential.Uid), -1); err != nil {
			return fmt.Errorf("chown pty: %w", err)
		}
		if err := unix.Fchmod(int(pfd), 0o600); err != nil {
			return fmt.Errorf("chmod pty: %w", err)
		}
	}
	return s.Resize(c.Rows, c.Cols)
}

// Run executes text, which must be approved, as one unit. It fails with
// ErrBusy unless bash is waiting for a command.
func (s *Shell) Run(text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idle, err := s.idle()
	if err != nil {
		return err
	}
	if !idle {
		return ErrBusy
	}
	// Drop leftover typing so it cannot feed this command. The gate passes
	// no keys while idle, so nothing can arrive behind the flush.
	if err := unix.IoctlSetInt(int(s.pts.Fd()), unix.TCFLSH, unix.TCIFLUSH); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	// eval keeps incomplete syntax from swallowing the next command.
	_, err = s.ctl.WriteString(`\builtin eval ` + quote(text) + " </dev/tty\n")
	return err
}

// Idle reports whether bash is blocked reading its command socket with
// nothing unread. The kernel answers, so terminal output cannot fake it.
func (s *Shell) Idle() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.idle()
}

func (s *Shell) idle() (bool, error) {
	if s.closed {
		return false, ErrExited
	}
	select {
	case <-s.done:
		return false, ErrExited
	default:
	}
	n, err := unix.IoctlGetInt(int(s.ctlPeer.Fd()), unix.TIOCINQ)
	if err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	proc := "/proc/" + strconv.Itoa(s.cmd.Process.Pid)
	b, err := os.ReadFile(proc + "/syscall")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			return false, ErrExited
		}
		return false, err // e.g. no permission: must not look like idle
	}
	f := strings.Fields(string(b)) // "nr arg0 ..." or "running"
	if len(f) < 2 || f[0] != strconv.Itoa(unix.SYS_READ) {
		return false, nil
	}
	fd, err := strconv.ParseUint(strings.TrimPrefix(f[1], "0x"), 16, 31)
	if err != nil {
		return false, nil
	}
	var have, want unix.Stat_t
	if unix.Stat(proc+"/fd/"+strconv.FormatUint(fd, 10), &have) != nil {
		return false, nil
	}
	if err := unix.Fstat(int(s.ctlPeer.Fd()), &want); err != nil {
		return false, err
	}
	return have.Dev == want.Dev && have.Ino == want.Ino, nil
}

// Read returns terminal output.
func (s *Shell) Read(p []byte) (int, error) { return s.ptm.Read(p) }

// Write sends keystrokes to the running program. Callers must do so only
// while an approved command runs.
func (s *Shell) Write(p []byte) (int, error) { return s.ptm.Write(p) }

// Resize sets the terminal size.
func (s *Shell) Resize(rows, cols uint16) error {
	rc, err := s.ptm.SyscallConn()
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

// Done is closed when bash exits.
func (s *Shell) Done() <-chan struct{} { return s.done }

// Close hangs up the terminal and kills bash, like a lost ssh connection.
func (s *Shell) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	_ = s.cmd.Process.Signal(unix.SIGHUP)
	s.closeFiles() // closing the terminal sends SIGHUP to the foreground job
	_ = s.cmd.Process.Kill()
	<-s.done
}

func (s *Shell) closeFiles() {
	for _, f := range []*os.File{s.ctl, s.ctlPeer, s.pts, s.ptm} {
		if f != nil {
			_ = f.Close()
		}
	}
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
