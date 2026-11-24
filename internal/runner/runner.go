// Package runner is the shell proper: it prepares command lines for approval
// and runs approved ones with job control. It runs as root in a process that
// leads the terminal's session. Files are accessed as the actor.
package runner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"witnesshell/internal/lang"
	"witnesshell/internal/launch"
)

var (
	ErrStale  = errors.New("the shell's state changed after this command was prepared")
	ErrExited = errors.New("the shell has exited")
)

// Config describes a shell.
type Config struct {
	User     launch.User
	Policy   *launch.Policy
	ExecDirs []string
	TTY      *os.File // the controlling terminal
	Dir      string
}

// Shell is one actor's shell. Run must not be called concurrently with
// itself or Prepare.
type Shell struct {
	c        Config
	dir      string
	vars     map[string]string
	exported map[string]bool
	umask    int
	status   int
	gen      uint64 // changes with every Run; see ErrStale
	exited   bool
	termios  *unix.Termios

	mu      sync.Mutex
	changed *sync.Cond // some job's state changed
	jobs    []*job
}

type procState uint8

const (
	running procState = iota
	stopped
	ended
)

type job struct {
	id      int // 0 until listed
	pgid    int
	text    string
	pids    []int
	state   map[int]procState
	last    unix.WaitStatus // of the last command in the pipeline
	termios *unix.Termios   // saved when it stopped
}

// status must be called with the lock held.
func (j *job) status() procState {
	out := ended
	for _, s := range j.state {
		if s == running {
			return running
		}
		if s == stopped {
			out = stopped
		}
	}
	return out
}

// New sets up the shell. The calling process must lead the terminal's session.
func New(c Config) (*Shell, error) {
	s := &Shell{c: c, dir: c.Dir, vars: map[string]string{}, exported: map[string]bool{}, umask: 0o022}
	s.changed = sync.NewCond(&s.mu)
	unix.Umask(s.umask)
	// Caught rather than ignored: ignored signals would be inherited.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGINT, unix.SIGQUIT, unix.SIGTSTP, unix.SIGTTIN, unix.SIGTTOU)
	go func() {
		for range ch {
		}
	}()
	t, err := unix.IoctlGetTermios(int(c.TTY.Fd()), unix.TCGETS)
	if err != nil {
		return nil, fmt.Errorf("terminal: %w", err)
	}
	s.termios = t
	if s.dir, err = s.resolveDir(c.Dir); err != nil {
		s.dir = "/"
	}
	return s, nil
}

// Dir returns the current directory.
func (s *Shell) Dir() string { return s.dir }

// Exited reports whether the actor has left the shell.
func (s *Shell) Exited() bool { return s.exited }

// Var, Home and ReadDir implement lang.Env.
func (s *Shell) Var(n string) (string, bool) {
	switch n {
	case "?":
		return strconv.Itoa(s.status), true
	case "HOME":
		return s.c.User.Home, true
	case "USER", "LOGNAME":
		return s.c.User.Name, true
	case "PWD":
		return s.dir, true
	case "PATH":
		return launch.SearchPath, true
	}
	v, ok := s.vars[n]
	return v, ok
}

func (s *Shell) Home() string { return s.c.User.Home }

func (s *Shell) ReadDir(dir string) ([]lang.DirEntry, error) {
	if dir == "" {
		dir = "."
	}
	f, err := launch.OpenAs(s.c.User, s.dir, dir, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	es, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	sort.Slice(es, func(i, j int) bool { return es[i].Name() < es[j].Name() })
	out := make([]lang.DirEntry, 0, len(es))
	for _, e := range es {
		d := e.IsDir()
		if e.Type()&os.ModeSymlink != 0 {
			if t, err := launch.OpenAs(s.c.User, s.dir, dir+"/"+e.Name(), unix.O_PATH|unix.O_DIRECTORY); err == nil {
				d = true
				_ = t.Close()
			}
		}
		out = append(out, lang.DirEntry{Name: e.Name(), Dir: d})
	}
	return out, nil
}

// Prepared is a command line ready for approval. Exactly this will run.
type Prepared struct {
	Text    string
	Steps   []Step
	builtin []string // set instead of Steps
	assigns []lang.Assign
	gen     uint64
}

// Builtin returns a shell builtin's words, if that is what the line is.
func (p *Prepared) Builtin() []string { return p.builtin }

// Step is one pipeline.
type Step struct {
	Op         lang.Op
	Cmds       []Cmd
	Background bool
}

// Cmd is one program start.
type Cmd struct {
	Plan   *launch.Plan
	Redirs []lang.Redir
}

// Warnings returns all warnings for witnesses.
func (p *Prepared) Warnings() []string {
	var out []string
	for _, st := range p.Steps {
		for _, c := range st.Cmds {
			for _, w := range c.Plan.Warnings {
				if !slices.Contains(out, w) {
					out = append(out, w)
				}
			}
		}
	}
	return out
}

// Builtins change the shell itself, so later words on the same line could not
// be expanded in advance. Each needs a line of its own.
var builtins = map[string]func(s *Shell, args []string) (int, error){
	"cd": (*Shell).cd, "export": (*Shell).export, "unset": (*Shell).unset, "umask": (*Shell).setUmask,
	"jobs": (*Shell).listJobs, "fg": (*Shell).fg, "bg": (*Shell).bg, "kill": (*Shell).kill, "exit": (*Shell).exit,
}

// Names that bash would treat as builtins. The program of the same name, if
// any, behaves differently, so they are refused.
var unsupported = map[string]bool{
	".": true, "source": true, "eval": true, "exec": true, "set": true, "shopt": true, "trap": true, "alias": true, "unalias": true,
	"command": true, "builtin": true, "type": true, "hash": true, "read": true, "mapfile": true, "readarray": true, "wait": true,
	"disown": true, "suspend": true, "ulimit": true, "shift": true, "return": true, "break": true, "continue": true, "local": true,
	"pushd": true, "popd": true, "dirs": true, "history": true, "fc": true, "bind": true, "complete": true, "compgen": true,
	"getopts": true, "enable": true, "logout": true, "caller": true, "times": true, "let": true, ":": true, "coproc": true,
}

// Prepare parses, expands and checks text without running anything.
func (s *Shell) Prepare(text string) (*Prepared, error) {
	if s.exited {
		return nil, ErrExited
	}
	line, err := lang.Parse(text, s)
	if err != nil {
		return nil, err
	}
	p := &Prepared{Text: text, gen: s.gen}
	if len(line) == 0 {
		return nil, errors.New("nothing to run")
	}
	for _, pl := range line {
		st := Step{Op: pl.Op, Background: pl.Background}
		for _, c := range pl.Cmds {
			alone := len(line) == 1 && len(pl.Cmds) == 1 && !pl.Background && len(c.Redirs) == 0
			if len(c.Argv) == 0 {
				if !alone {
					return nil, errors.New("an assignment needs a line of its own")
				}
				for _, a := range c.Assigns {
					if !launch.EnvAllowed(a.Name) {
						return nil, fmt.Errorf("variable %s may not be set", a.Name)
					}
				}
				p.assigns = c.Assigns
				return p, nil
			}
			name := c.Argv[0]
			if _, ok := builtins[name]; ok {
				if !alone || len(c.Assigns) > 0 {
					return nil, fmt.Errorf("%s needs a line of its own", name)
				}
				if name == "export" || name == "unset" {
					for _, a := range c.Argv[1:] {
						if n, _, _ := strings.Cut(a, "="); !launch.EnvAllowed(n) {
							return nil, fmt.Errorf("variable %s may not be changed", n)
						}
					}
				}
				p.builtin = c.Argv
				return p, nil
			}
			if unsupported[name] {
				return nil, fmt.Errorf("the shell builtin %q is not supported", name)
			}
			env := map[string]string{}
			for n := range s.exported {
				if v, ok := s.vars[n]; ok {
					env[n] = v
				}
			}
			for _, a := range c.Assigns {
				env[a.Name] = a.Value
			}
			req := launch.Request{Argv: c.Argv, Cwd: s.dir, Env: env, User: s.c.User, Umask: s.umask}
			for _, r := range c.Redirs {
				if r.Kind == lang.Read {
					if req.Stdin != "" {
						return nil, errors.New("more than one input redirection")
					}
					req.Stdin = r.Path
				}
			}
			plan, err := s.c.Policy.Plan(req)
			if err != nil {
				return nil, err
			}
			st.Cmds = append(st.Cmds, Cmd{plan, c.Redirs})
		}
		p.Steps = append(p.Steps, st)
	}
	return p, nil
}

// Run executes an approved line and returns when no foreground job is left.
func (s *Shell) Run(p *Prepared) (int, error) {
	if s.exited {
		return 0, ErrExited
	}
	if p.gen != s.gen {
		return 0, ErrStale
	}
	s.gen++
	// Leftover typing must not feed this command. No keys are passed to the
	// terminal while no command runs, so nothing can arrive behind the flush.
	if err := unix.IoctlSetInt(int(s.c.TTY.Fd()), unix.TCFLSH, unix.TCIFLUSH); err != nil {
		return 0, err
	}
	if len(p.assigns) > 0 {
		for _, a := range p.assigns {
			s.vars[a.Name] = a.Value
		}
		s.status = 0
		return 0, nil
	}
	if p.builtin != nil {
		st, err := builtins[p.builtin[0]](s, p.builtin[1:])
		if err != nil {
			fmt.Fprintf(s.out(), "%s: %v\n", p.builtin[0], err)
		}
		s.status = st
		return st, nil
	}
	for _, st := range p.Steps {
		if st.Op == lang.And && s.status != 0 || st.Op == lang.Or && s.status == 0 {
			continue
		}
		goOn, err := s.pipeline(st, p.Text)
		if err != nil {
			fmt.Fprintf(s.out(), "%v\n", err)
			s.status = 1
		}
		if !goOn {
			break
		}
	}
	return s.status, nil
}

func (s *Shell) out() io.Writer { return s.c.TTY }

// pipeline starts a step; unless in the background it waits. It reports
// whether the rest of the line should run.
func (s *Shell) pipeline(st Step, text string) (bool, error) {
	var files []*os.File
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	// Open everything first, so that nothing starts if a file is missing.
	fds := make([][3]*os.File, len(st.Cmds))
	for i := range st.Cmds {
		fds[i] = [3]*os.File{s.c.TTY, s.c.TTY, s.c.TTY}
	}
	for i := 0; i+1 < len(st.Cmds); i++ {
		r, w, err := os.Pipe()
		if err != nil {
			return false, err
		}
		files = append(files, r, w)
		fds[i][1], fds[i+1][0] = w, r
	}
	for i, c := range st.Cmds {
		for _, r := range c.Redirs {
			if r.Kind == lang.Dup {
				fds[i][r.FD] = fds[i][r.Source]
				continue
			}
			f, err := s.open(c.Plan, r)
			if err != nil {
				return true, err // like bash, the line goes on with status 1
			}
			files = append(files, f)
			fds[i][r.FD] = f
		}
	}
	j := &job{text: text, state: map[int]procState{}}
	var startErr error
	for i, c := range st.Cmds {
		attr := &syscall.SysProcAttr{Setpgid: true, Pgid: j.pgid}
		if i == 0 && !st.Background {
			attr.Foreground, attr.Ctty = true, int(s.c.TTY.Fd())
		}
		cmd, err := launch.Start(c.Plan, launch.Options{Stdin: fds[i][0], Stdout: fds[i][1], Stderr: fds[i][2],
			ExecDirs: s.c.ExecDirs, SysProcAttr: attr})
		if err != nil {
			startErr = err
			break
		}
		pid := cmd.Process.Pid
		_ = cmd.Process.Release() // reaped by s.reap
		if j.pgid == 0 {
			j.pgid = pid
		}
		j.pids = append(j.pids, pid)
		j.state[pid] = running
	}
	for _, f := range files {
		_ = f.Close()
	}
	files = nil
	// Reaping starts only now: an unreaped first process keeps the group alive
	// for the others to join.
	for _, pid := range j.pids {
		go s.reap(j, pid)
	}
	if startErr != nil {
		if j.pgid != 0 {
			_ = unix.Kill(-j.pgid, unix.SIGKILL)
			s.wait(j)
		}
		return false, startErr
	}
	if st.Background {
		s.mu.Lock()
		s.list(j)
		s.mu.Unlock()
		fmt.Fprintf(s.out(), "[%d] %d\n", j.id, j.pgid)
		s.status = 0
		return true, nil
	}
	return s.wait(j), nil
}

func (s *Shell) open(p *launch.Plan, r lang.Redir) (*os.File, error) {
	flags, name := unix.O_RDONLY, r.Path
	switch r.Kind {
	case lang.Read:
		name = p.Stdin
	case lang.Write:
		flags = unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC
	case lang.Append:
		flags = unix.O_WRONLY | unix.O_CREAT | unix.O_APPEND
	}
	f, err := launch.OpenAs(s.c.User, s.dir, name, flags)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() && st.Mode()&os.ModeCharDevice == 0 {
		err = fmt.Errorf("%s: not a regular file or character device", name)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// reap follows one process until it ends.
func (s *Shell) reap(j *job, pid int) {
	for {
		var ws unix.WaitStatus
		_, err := unix.Wait4(pid, &ws, unix.WUNTRACED|unix.WCONTINUED, nil)
		if err == unix.EINTR {
			continue
		}
		s.mu.Lock()
		switch {
		case err != nil || ws.Exited() || ws.Signaled():
			j.state[pid] = ended
			if pid == j.pids[len(j.pids)-1] {
				j.last = ws
			}
		case ws.Stopped():
			j.state[pid] = stopped
		case ws.Continued():
			j.state[pid] = running
		}
		done := j.state[pid] == ended
		s.changed.Broadcast()
		s.mu.Unlock()
		if done {
			return
		}
	}
}

// wait follows a foreground job until it ends or stops, then takes the
// terminal back. It reports whether the rest of the line should run.
func (s *Shell) wait(j *job) bool {
	s.mu.Lock()
	for j.status() == running {
		s.changed.Wait()
	}
	st, last := j.status(), j.last
	if st == stopped {
		s.list(j)
	} else {
		s.unlist(j)
	}
	s.mu.Unlock()
	if st == stopped {
		j.termios, _ = unix.IoctlGetTermios(int(s.c.TTY.Fd()), unix.TCGETS)
	}
	s.foreground(unix.Getpgrp(), s.termios)
	switch {
	case st == stopped:
		s.status = 128 + int(unix.SIGTSTP)
		fmt.Fprintf(s.out(), "\n[%d] Stopped  %s\n", j.id, j.text)
		return false
	case last.Signaled():
		s.status = 128 + int(last.Signal())
		return last.Signal() != unix.SIGINT && last.Signal() != unix.SIGQUIT
	}
	s.status = last.ExitStatus()
	return true
}

// foreground gives the terminal to a process group.
func (s *Shell) foreground(pgid int, t *unix.Termios) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		// A background process doing this is stopped by SIGTTOU unless it is
		// blocked. The thread is not reused, so neither is the mask.
		lockThreadBlocking(unix.SIGTTOU)
		fd := int(s.c.TTY.Fd())
		_ = unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, pgid)
		if t != nil {
			_ = unix.IoctlSetTermios(fd, unix.TCSETSW, t)
		}
	}()
	<-done
}

// list and unlist must be called with the lock held.
func (s *Shell) list(j *job) {
	if j.id != 0 {
		return
	}
	j.id = 1
	for _, o := range s.jobs {
		j.id = max(j.id, o.id+1)
	}
	s.jobs = append(s.jobs, j)
}

func (s *Shell) unlist(j *job) {
	s.jobs = slices.DeleteFunc(s.jobs, func(o *job) bool { return o == j })
}

// Close hangs up all jobs.
func (s *Shell) Close() {
	s.exited = true
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		s.signal(j, unix.SIGHUP)
		s.signal(j, unix.SIGCONT)
	}
}

// signal must be called with the lock held. A job whose processes have all
// been reaped is left alone: its id may belong to someone else by now.
func (s *Shell) signal(j *job, sig unix.Signal) bool {
	if j.status() == ended {
		return false
	}
	return unix.Kill(-j.pgid, sig) == nil
}

func (s *Shell) resolveDir(dir string) (string, error) {
	if !filepath.IsAbs(dir) {
		dir = s.dir + "/" + dir
	}
	var out string
	err := launch.AsUser(s.c.User, func() (err error) {
		if out, err = filepath.EvalSymlinks(dir); err != nil {
			return err
		}
		// "/." needs permission to enter the directory.
		fd, err := unix.Open(out+"/.", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return &os.PathError{Op: "cd", Path: dir, Err: err}
		}
		return unix.Close(fd)
	})
	return out, err
}

func (s *Shell) cd(args []string) (int, error) {
	if len(args) > 1 {
		return 1, errors.New("too many arguments")
	}
	to := s.c.User.Home
	if len(args) == 1 {
		to = args[0]
	}
	if to == "" || strings.HasPrefix(to, "-") {
		return 1, errors.New("want a directory")
	}
	d, err := s.resolveDir(to)
	if err != nil {
		return 1, err
	}
	s.dir = d
	return 0, nil
}

func (s *Shell) export(args []string) (int, error) {
	if len(args) == 0 {
		names := make([]string, 0, len(s.exported))
		for n := range s.exported {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			fmt.Fprintf(s.out(), "export %s=%q\n", n, s.vars[n])
		}
	}
	for _, a := range args {
		n, v, set := strings.Cut(a, "=")
		if set {
			s.vars[n] = v
		}
		s.exported[n] = true
	}
	return 0, nil
}

func (s *Shell) unset(args []string) (int, error) {
	for _, a := range args {
		delete(s.vars, a)
		delete(s.exported, a)
	}
	return 0, nil
}

func (s *Shell) setUmask(args []string) (int, error) {
	if len(args) == 0 {
		fmt.Fprintf(s.out(), "%04o\n", s.umask)
		return 0, nil
	}
	m, err := strconv.ParseUint(args[0], 8, 16)
	if err != nil || len(args) > 1 || m > 0o777 {
		return 1, errors.New("want an octal mask")
	}
	s.umask = int(m)
	unix.Umask(s.umask) // for files that redirections create
	return 0, nil
}

func (s *Shell) listJobs(args []string) (int, error) {
	if len(args) > 0 {
		return 1, errors.New("takes no arguments")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range slices.Clone(s.jobs) {
		name := "Running"
		switch j.status() {
		case stopped:
			name = "Stopped"
		case ended:
			name = "Done"
			s.unlist(j)
		}
		fmt.Fprintf(s.out(), "[%d] %-8s %s\n", j.id, name, j.text)
	}
	return 0, nil
}

// find returns the job named by "%N", or the latest. Lock held.
func (s *Shell) find(args []string) (*job, error) {
	if len(args) > 1 {
		return nil, errors.New("want one job")
	}
	for i := len(s.jobs) - 1; i >= 0; i-- {
		j := s.jobs[i]
		if j.status() != ended && (len(args) == 0 || args[0] == "%"+strconv.Itoa(j.id)) {
			return j, nil
		}
	}
	return nil, errors.New("no such job")
}

func (s *Shell) resume(args []string, fg bool) (*job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, err := s.find(args)
	if err != nil {
		return nil, err
	}
	if fg {
		s.foreground(j.pgid, j.termios)
	}
	for pid, st := range j.state {
		if st == stopped {
			j.state[pid] = running
		}
	}
	s.signal(j, unix.SIGCONT)
	fmt.Fprintf(s.out(), "%s\n", j.text)
	return j, nil
}

func (s *Shell) fg(args []string) (int, error) {
	j, err := s.resume(args, true)
	if err != nil {
		return 1, err
	}
	s.wait(j)
	return s.status, nil
}

func (s *Shell) bg(args []string) (int, error) {
	if _, err := s.resume(args, false); err != nil {
		return 1, err
	}
	return 0, nil
}

var signals = map[string]unix.Signal{"-TERM": unix.SIGTERM, "-15": unix.SIGTERM, "-KILL": unix.SIGKILL, "-9": unix.SIGKILL,
	"-INT": unix.SIGINT, "-2": unix.SIGINT, "-HUP": unix.SIGHUP, "-1": unix.SIGHUP, "-STOP": unix.SIGSTOP, "-CONT": unix.SIGCONT}

// kill signals jobs only; for processes there is /bin/kill, which runs as the
// actor. This process is root and must not signal anything else.
func (s *Shell) kill(args []string) (int, error) {
	sig := unix.SIGTERM
	if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		var ok bool
		if sig, ok = signals[args[0]]; !ok {
			return 1, errors.New("unknown signal")
		}
		args = args[1:]
	}
	if len(args) != 1 || !strings.HasPrefix(args[0], "%") {
		return 1, errors.New("want a job such as %1; use /bin/kill for processes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	j, err := s.find(args)
	if err != nil {
		return 1, err
	}
	s.signal(j, sig)
	if sig == unix.SIGTERM || sig == unix.SIGHUP {
		s.signal(j, unix.SIGCONT) // a stopped job cannot act on it
	}
	return 0, nil
}

func (s *Shell) exit(args []string) (int, error) {
	if len(args) > 0 {
		return 1, errors.New("takes no arguments")
	}
	s.Close()
	return 0, nil
}
