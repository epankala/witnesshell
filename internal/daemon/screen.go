package daemon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"witnesshell/internal/screen"
	"witnesshell/internal/wire"
)

// ScreenArg is the hidden argument that makes the binary run Screen.
const ScreenArg = "__screen"

const (
	nobody = 65534
	// stuck is how long the process may take over a piece of output.
	stuck    = 10 * time.Second
	maxFrame = 16 << 20
)

// Screen is the body of the process that emulates a session's terminal.
func Screen() error {
	if os.Getuid() == 0 {
		return errors.New("must not be root")
	}
	if err := errors.Join(unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0), unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)); err != nil {
		return err
	}
	return screen.Serve(os.Stdin, os.Stdout)
}

// screenProc is the daemon's handle on that process. A new one is started
// when it dies or hangs, with an empty screen.
type screenProc struct {
	cgroup  string
	onFrame func(*wire.Frame)
	onLost  func(error)
	size    func() (rows, cols uint16)

	mu     sync.Mutex // taken before the session's lock
	in     *os.File
	cmd    *exec.Cmd
	closed bool
}

// start launches the process. Lock held.
func (p *screenProc) start() error {
	inR, inW, err := os.Pipe()
	if err != nil {
		return err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_, _ = inR.Close(), inW.Close()
		return err
	}
	// What waits in the pipe delays the effect of Ctrl-C on the screen. Not by
	// Fd, which would make the file blocking and deadlines useless.
	if rc, err := inW.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) { _, _ = unix.FcntlInt(fd, unix.F_SETPIPE_SZ, 4096) })
	}
	cg, err := os.Open(p.cgroup)
	if err != nil {
		_, _, _, _ = inR.Close(), inW.Close(), outR.Close(), outW.Close()
		return err
	}
	defer cg.Close()
	cmd := exec.Command("/proc/self/exe", ScreenArg)
	cmd.Env, cmd.Dir = []string{}, "/"
	cmd.Stdin, cmd.Stdout = inR, outW
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, UseCgroupFD: true, CgroupFD: int(cg.Fd()),
		Credential: &syscall.Credential{Uid: nobody, Gid: nobody}}
	err = cmd.Start()
	_, _ = inR.Close(), outW.Close()
	if err != nil {
		_, _ = inW.Close(), outR.Close()
		return err
	}
	p.in, p.cmd = inW, cmd
	go func() {
		defer outR.Close()
		for {
			var f wire.Frame
			if err := wire.Read(outR, maxFrame, &f); err != nil || checkFrame(&f) != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return
			}
			p.onFrame(&f)
		}
	}()
	return p.send(screen.MsgResize, p.dimensions())
}

func (p *screenProc) dimensions() []byte {
	rows, cols := p.size()
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, rows), cols)
}

func checkFrame(f *wire.Frame) error {
	if f.Rows < 1 || f.Rows > 300 || f.Cols < 1 || f.Cols > 500 || len(f.Lines) > f.Rows || f.CX < 0 || f.CX >= f.Cols || f.CY < 0 || f.CY >= f.Rows {
		return errors.New("bad frame")
	}
	for _, l := range f.Lines {
		if l.Y < 0 || l.Y >= f.Rows || len(l.Runs) > f.Cols {
			return errors.New("bad frame")
		}
	}
	return nil
}

// send writes a message. Lock held.
func (p *screenProc) send(typ byte, b []byte) error {
	_ = p.in.SetWriteDeadline(time.Now().Add(stuck))
	_, err := p.in.Write(screen.Message(typ, b))
	return err
}

// deliver sends a message, replacing a process that does not take it.
func (p *screenProc) deliver(typ byte, b []byte) {
	if p.closed {
		return
	}
	err := p.send(typ, b)
	if err == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_ = p.in.Close()
	p.onLost(fmt.Errorf("screen process: %w", err))
	if err := p.start(); err != nil {
		p.onLost(err)
		p.closed = true // rather than trying for every bit of output
	}
}

func (p *screenProc) output(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deliver(screen.MsgOutput, b)
}

// resize tells the process the current size.
func (p *screenProc) resize() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deliver(screen.MsgResize, p.dimensions())
}

func (p *screenProc) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.in != nil {
		_ = p.in.Close()
	}
}

// screenState is the current screen. Each row remembers the version in which
// it last changed, so that each client gets exactly what it lacks.
type screenState struct {
	frame wire.Frame // without Lines
	rows  [][]wire.Run
	vers  []uint64
	ver   uint64
}

func (s *screenState) apply(f *wire.Frame) {
	s.ver++
	if f.Rows != s.frame.Rows || f.Cols != s.frame.Cols {
		s.rows, s.vers = make([][]wire.Run, f.Rows), make([]uint64, f.Rows)
		for y := range s.vers {
			s.vers[y] = s.ver
		}
	}
	for _, l := range f.Lines {
		s.rows[l.Y], s.vers[l.Y] = l.Runs, s.ver
	}
	s.frame = *f
	s.frame.Lines = nil
}

// since returns what changed after version v; 0 means everything.
func (s *screenState) since(v uint64) (*wire.Frame, uint64) {
	f := s.frame
	for y, rv := range s.vers {
		if rv > v {
			f.Lines = append(f.Lines, wire.Line{Y: y, Runs: s.rows[y]})
		}
	}
	return &f, s.ver
}
