package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
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
}

// Leader is the body of the leader process.
func Leader() error {
	in, out := os.NewFile(3, "in"), os.NewFile(4, "out")
	unix.CloseOnExec(3)
	unix.CloseOnExec(4)
	if os.Getuid() != 0 {
		return errors.New("must be root")
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
	s, err := runner.New(runner.Config{User: c.User, Policy: &launch.Policy{Store: store}, ExecDirs: c.ExecDirs,
		TTY: os.Stdin, Dir: c.User.Home})
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
		r.Dir, r.Exited = s.Dir(), s.Exited()
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
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
	cmd.Env = []string{}
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
