package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"witnesshell/internal/launch"
	"witnesshell/internal/pty"
	"witnesshell/internal/runner"
	"witnesshell/internal/sign"
)

// LeaderArg is the hidden argument that makes the binary run Leader.
const LeaderArg = "__session"

// The leader is a root process per session that leads the terminal's session
// and runs the shell. It talks to the daemon over pipes on descriptors 3, 4.

type leaderConfig struct {
	User     launch.User
	StoreDir string
	Keys     sign.KeyDir
	ExecDirs []string
	Free     []string // free_commands
}

type leaderReq struct {
	Run  uint64 // run the line prepared with this serial; 0 means prepare Text
	Text string
}

type leaderResp struct {
	Err      string
	Serial   uint64
	Details  []string
	Warnings []string
	Free     bool
	Status   int
	Dir      string
	Exited   bool
	SHA256   string // of the file that was looked at
	Umask    int
}

// Leader is the body of the leader process.
func Leader() error {
	in, out := os.NewFile(3, "in"), os.NewFile(4, "out")
	unix.CloseOnExec(3)
	unix.CloseOnExec(4)
	if os.Getuid() != 0 {
		return errors.New("must be root")
	}
	if err := errors.Join(watchDaemon(), notProtected()); err != nil {
		return err
	}
	dec, enc := json.NewDecoder(in), json.NewEncoder(out)
	var c leaderConfig
	if err := dec.Decode(&c); err != nil {
		return err
	}
	// Programs such as tty and mesg expect the user to own the terminal.
	if err := errors.Join(unix.Fchown(0, int(c.User.UID), -1), unix.Fchmod(0, 0o600)); err != nil {
		return err
	}
	store := &sign.Store{Dir: c.StoreDir, Keys: c.Keys, LookupUID: launch.LookupUID}
	free := map[string]bool{}
	for _, n := range c.Free {
		if err := launch.CheckFree(n); err != nil {
			return err
		}
		free[n] = true
	}
	s, err := runner.New(runner.Config{User: c.User, Policy: &launch.Policy{Store: store}, ExecDirs: c.ExecDirs,
		TTY: os.Stdin, Dir: c.User.Home, Free: free})
	if err != nil {
		return err
	}
	defer s.Close()
	if err := enc.Encode(leaderResp{Dir: s.Dir()}); err != nil {
		return err
	}
	var last *runner.Prepared
	var serial uint64
	for {
		var q leaderReq
		if err := dec.Decode(&q); err != nil {
			return nil // the daemon ended the session
		}
		var r leaderResp
		if q.Run == 0 {
			serial++
			last, err = s.Prepare(q.Text)
			if err == nil {
				r.Serial, r.Details, r.Warnings, r.Free = serial, last.Describe(), last.Warnings(), last.Free()
			}
		} else {
			err = errors.New("internal error: wrong command")
			if last != nil && q.Run == serial {
				r.Status, err = s.Run(last)
				r.SHA256 = s.Inspected()
				last = nil
			}
		}
		if err != nil {
			r.Err = err.Error()
		}
		r.Dir, r.Exited, r.Umask = s.Dir(), s.Exited(), s.Umask()
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
}

// watchDaemon ends the session if the daemon, the leader's parent, ends
// without ending it: nothing may run that is not logged. The daemon kills old
// sessions when it starts again, but it may not start again, and the leader
// does not hear from it while a program runs. So the leader watches it, and
// kills its own cgroup, itself included.
func watchDaemon() error {
	parent := os.Getppid()
	pidfd, err := unix.PidfdOpen(parent, 0)
	if err != nil {
		return fmt.Errorf("watching the daemon: %w", err)
	}
	if os.Getppid() != parent { // it ended before it was watched
		return errors.New("the daemon has ended")
	}
	kill, err := ownCgroupKill()
	if err != nil {
		return err
	}
	// The terminal hangs up when the daemon dies, which would end the leader
	// first: the hangup must end the session the same way. A hangup means
	// the session is over anyway.
	over := make(chan os.Signal, 2)
	signal.Notify(over, unix.SIGHUP)
	go func() {
		fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		for {
			if _, err := unix.Poll(fds, -1); err != unix.EINTR {
				break
			}
		}
		over <- unix.SIGKILL
	}()
	go func() {
		<-over
		_, _ = kill.WriteString("1")
		os.Exit(1)
	}()
	return nil
}

// notProtected gives up the daemon's protection from the OOM killer, which
// children inherit (OOMScoreAdjust in the systemd unit). The daemon ending
// ends all sessions, so a session that uses too much memory must be killed
// instead.
func notProtected() error {
	return os.WriteFile("/proc/self/oom_score_adj", []byte("0"), 0)
}

// ownCgroupKill opens cgroup.kill of the session's cgroup, the one this
// process is in.
func ownCgroupKill() (*os.File, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil, err
	}
	p, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "0::")
	if !ok || !strings.HasPrefix(p, cgroupName+"/") || strings.Contains(p, "\n") || strings.Contains(p, "..") {
		return nil, fmt.Errorf("not in a session's cgroup: %q", b)
	}
	return os.OpenFile(cgroupRoot+p+"/cgroup.kill", os.O_WRONLY, 0)
}

// leader is the daemon's handle on a leader process.
type leader struct {
	mu   sync.Mutex
	in   *os.File
	enc  *json.Encoder
	dec  *json.Decoder
	cmd  *exec.Cmd
	done chan struct{}
}

// startLeader starts the process and returns the session's terminal.
func startLeader(c leaderConfig, cgroup *os.File, rows, cols uint16) (*leader, *os.File, string, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, "", err
	}
	ours, theirs := os.NewFile(uintptr(fds[0]), "tty"), os.NewFile(uintptr(fds[1]), "tty")
	defer ours.Close()
	conn, err := net.FileConn(ours)
	if err != nil {
		_ = theirs.Close()
		return nil, nil, "", err
	}
	defer conn.Close()
	inR, inW, err := os.Pipe()
	if err != nil {
		_ = theirs.Close()
		return nil, nil, "", err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_, _, _ = inR.Close(), inW.Close(), theirs.Close()
		return nil, nil, "", err
	}
	cmd := exec.Command("/proc/self/exe", TerminalArg)
	cmd.Env = launch.ChildEnv()
	cmd.Dir = "/"
	cmd.Stderr = os.Stderr // until there is a terminal
	cmd.ExtraFiles = []*os.File{inR, outW, theirs}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
	err = cmd.Start()
	_, _, _ = inR.Close(), outW.Close(), theirs.Close()
	if err != nil {
		_, _ = inW.Close(), outR.Close()
		return nil, nil, "", err
	}
	l := &leader{in: inW, enc: json.NewEncoder(inW), dec: json.NewDecoder(outR), cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(l.done)
	}()
	var r leaderResp
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	ptm, err := receiveTerminal(conn.(*net.UnixConn))
	if err == nil {
		err = pty.Resize(ptm, rows, cols)
	}
	if err == nil {
		err = l.enc.Encode(c)
	}
	if err == nil {
		err = l.dec.Decode(&r)
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = inW.Close()
		if ptm != nil {
			_ = ptm.Close()
		}
		return nil, nil, "", fmt.Errorf("session process: %w", err)
	}
	return l, ptm, r.Dir, nil
}

// call sends a request and waits for the answer, which for Run comes when the
// command is over.
func (l *leader) call(q leaderReq) (r leaderResp, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.enc.Encode(q); err != nil {
		return r, err
	}
	return r, l.dec.Decode(&r)
}
