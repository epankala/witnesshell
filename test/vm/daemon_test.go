//go:build vmtest

package vm

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/vt"
	"golang.org/x/sys/unix"

	"witnesshell/internal/launch"
	"witnesshell/internal/pty"
	"witnesshell/internal/wire"
)

const (
	binary = "/usr/local/bin/witsh"
	sock   = "/run/witnesshell.sock"
)

// startDaemon runs the real daemon.
func startDaemon(t *testing.T, config string) *bytes.Buffer {
	t.Helper()
	must(os.WriteFile("/etc/witnesshell/config.toml", []byte(config), 0o644))
	var log bytes.Buffer
	cmd := exec.Command(binary, "daemon")
	cmd.Stderr = &log
	must(cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("daemon log:\n%s", log.String())
		}
		if out, _ := exec.Command("pgrep", "-f", "__session|__terminal|__screen").Output(); len(out) != 0 {
			t.Errorf("session processes left: %s", out)
		}
	})
	for range 100 {
		if c, err := net.Dial("unix", sock); err == nil {
			_ = c.Close()
			return &log
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("daemon did not start: %s", log.String())
	return nil
}

// window is a user's terminal running witsh attach.
type window struct {
	t    *testing.T
	name string
	ptm  *os.File
	cmd  *exec.Cmd
	mu   sync.Mutex
	em   *vt.Emulator
	raw  bytes.Buffer
}

func attach(t *testing.T, u launch.User, args ...string) *window {
	t.Helper()
	cmd := exec.Command(binary, append([]string{"attach"}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: u.UID, Gid: u.GID, Groups: u.Groups}}
	return open(t, u, cmd)
}

// open runs a command in a terminal of its own.
func open(t *testing.T, u launch.User, cmd *exec.Cmd) *window {
	t.Helper()
	ptm, pts, err := pty.Open(30, 110)
	must(err)
	w := &window{t: t, name: u.Name, ptm: ptm, em: vt.NewEmulator(110, 30)}
	w.cmd = cmd
	cmd.Env = []string{"TERM=xterm-256color", "PATH=/usr/bin", "HOME=/root"}
	cmd.Dir = "/"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pts, pts, pts
	must(unix.Fchown(int(pts.Fd()), int(u.UID), -1))
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid, cmd.SysProcAttr.Setctty = true, true
	must(w.cmd.Start())
	_ = pts.Close()
	go func() { _, _ = io.Copy(io.Discard, w.em) }()
	go func() {
		b := make([]byte, 8192)
		for {
			n, err := ptm.Read(b)
			w.mu.Lock()
			w.raw.Write(b[:n])
			_, _ = w.em.Write(b[:n])
			w.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(w.close)
	return w
}

func (w *window) close() {
	_ = w.cmd.Process.Kill()
	_ = w.cmd.Wait()
	_ = w.ptm.Close()
}

func (w *window) screen() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.em.String()
}

func (w *window) has(s string) bool { return strings.Contains(w.screen(), s) }

func (w *window) wait(s string) {
	w.t.Helper()
	for end := time.Now().Add(150 * time.Second); !w.has(s); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(end) {
			w.t.Fatalf("%s does not see %q:\n%s", w.name, s, w.screen())
		}
	}
}

func (w *window) typ(s string) {
	w.t.Helper()
	_, err := w.ptm.WriteString(s)
	must(err)
}

// approve waits until the request is shown and approves it.
func (w *window) approve(s string) {
	w.t.Helper()
	w.wait(s)
	w.wait("[a]pprove")
	time.Sleep(time.Second)
	w.typ("a")
}

func TestDaemonSession(t *testing.T) {
	harden(t)
	fixtures(t)
	log := startDaemon(t, "approvals_required = 1\n")
	a := attach(t, alice)
	a.wait("ACTOR alice  PROMPT")
	a.wait("no witness")
	b := attach(t, bob)
	b.wait("[1] witness the session of alice")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.wait("witnesses: bob")

	// Nothing runs without approval; the draft is visible.
	a.typ("touch MARK")
	b.wait("typing: touch MARK")
	a.typ("\r")
	a.wait("PENDING 0/1")
	b.wait(`/touch"`)
	b.wait(`arguments: "touch" "MARK"`)
	clean(t)
	b.typ("a\x03xyz\r") // too quick to count, and not the actor's keys
	b.wait("very quick")
	clean(t)

	// Rejection needs a comment and gives the text back.
	b.typ("r")
	b.wait("reject, because:")
	b.typ("\r")
	time.Sleep(300 * time.Millisecond)
	clean(t)
	b.typ("wrong host\r")
	a.wait("rejected by bob: wrong host")
	a.wait("$ touch MARK")
	clean(t)

	// Resubmit a corrected command.
	a.typ("2; echo O''K\r")
	b.approve(`"touch" "MARK2"`)
	a.wait("OK")
	b.wait("OK")
	a.wait("PROMPT")
	if !exists(home+"/MARK2") || exists(marker) {
		t.Error("wrong command ran")
	}

	// Cancel, then a late vote has nothing to hit.
	a.typ("touch MARK\r")
	b.wait("PENDING")
	a.typ("\x03")
	a.wait("cancelled")
	b.typ("a")
	b.wait("nothing to approve")
	a.typ("\x03")
	clean(t)

	// Interactive program: input is free while it runs, then gated again.
	a.typ("cat\r")
	b.approve(`/cat"`)
	a.wait("RUNNING")
	a.typ("hello\r")
	b.wait("hello")
	a.typ("\x04touch MARK\r") // typed ahead: thrown away
	a.wait("PROMPT")
	clean(t)
	a.typ("touch MARK\r")
	a.wait("PENDING 0/1")
	clean(t)
	a.typ("\x03")
	a.wait("cancelled")
	a.typ("\x03")

	// Warnings, free commands, refusals.
	a.typ("sh -c true\r")
	b.wait("WARNING: this allows unsigned code")
	a.typ("\x03")
	a.wait("cancelled")
	a.typ("\x03")
	a.typ("./s.sh\r")
	a.wait("not signed by a witness")
	a.typ("\x03checksig s.sh\r")
	a.wait("trusted  no")
	a.typ("view s.sh\r")
	a.wait("touch /home/alice/MARK")
	clean(t)

	// The witness looks at the file and signs it.
	sh(t, "chmod 750 /home/alice")
	b.typ("v")
	b.wait("view file:")
	b.typ("s.sh\r")
	b.wait("permission denied") // a private home stays private
	sh(t, "chmod 755 /home/alice")
	b.typ("v")
	b.wait("view file:")
	b.typ("s.sh\r")
	b.wait("[S]ign")
	b.typ("S")
	b.wait("sign exactly this content")
	b.typ("y")
	b.wait("signed")
	b.typ("s")
	b.wait("check signature of:")
	b.typ("s.sh\r")
	b.wait("signed   by uid")
	b.typ("q")
	b.wait("WITNESS of alice")
	a.typ("./s.sh\r")
	b.approve("signed by uid")
	a.wait("PROMPT")
	time.Sleep(500 * time.Millisecond)
	if !exists(marker) {
		t.Error("signed script did not run")
	}
	_ = os.Remove(marker)

	// Paste of several lines is one request.
	a.typ("\x1b[200~echo one\recho two\x1b[201~\r")
	b.wait("echo one")
	b.approve("echo two")
	a.wait("two")
	a.wait("PROMPT")

	// The actor's connection is lost and comes back; the request survives.
	a.typ("touch MARK\r")
	b.wait("PENDING")
	a.close()
	b.wait("actor is away")
	a = attach(t, alice)
	a.wait("return to your session")
	a.typ("1\r")
	a.wait("PENDING 0/1")
	b.approve("MARK")
	a.wait("PROMPT")
	time.Sleep(300 * time.Millisecond)
	if !exists(marker) {
		t.Error("did not run after reattach")
	}

	// Logout ends everything that the session started.
	a.typ("setsid nohup sleep 4321\r")
	b.approve("4321")
	time.Sleep(1500 * time.Millisecond)
	a.typ("\x1a\x03")
	a.wait("PROMPT")
	a.typ("\x04")
	b.wait("the actor logged out")
	time.Sleep(2 * time.Second)
	if out, _ := exec.Command("pgrep", "-f", "sleep 4321").Output(); len(out) != 0 {
		t.Errorf("program outlived the session: %s", out)
	}
	if !strings.Contains(log.String(), "session ended") {
		t.Error("not logged")
	}
}

func TestDaemonWitnessMovesOn(t *testing.T) {
	harden(t)
	fixtures(t)
	startDaemon(t, "allow_weak_host = true\n") // carol is not prepared as an actor
	a := attach(t, alice)
	a.wait("ACTOR alice  PROMPT")
	c := attach(t, carolUser(), "-new")
	c.wait("ACTOR carol  PROMPT")
	b := attach(t, bob)
	b.wait("[2] witness the session of carol")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.typ("touch MARK\r")
	b.wait("[a]pprove")
	// Keys typed as the session ends must not choose anything.
	a.typ("\x03")
	a.wait("cancelled")
	a.typ("\x03")
	time.Sleep(300 * time.Millisecond)
	a.typ("\x04")
	for range 5 {
		b.typ("1\r")
		time.Sleep(100 * time.Millisecond)
	}
	b.wait("the actor logged out")
	b.wait("[1] witness the session of carol")
	if b.has("witness the session of alice") && strings.Count(b.screen(), "session of alice") > 1 {
		t.Errorf("ended session offered:\n%s", b.screen())
	}
	time.Sleep(700 * time.Millisecond)
	if b.has("WITNESS of") {
		t.Errorf("joined by accident:\n%s", b.screen())
	}
	b.typ("1\r")
	b.wait("WITNESS of carol")
	c.wait("witnesses: bob")
	c.typ("echo o''k\r")
	b.approve(`"echo" "ok"`)
	c.wait("PROMPT")
	c.typ("\x04")
	b.wait("there is no session to witness")
	a = attach(t, alice)
	a.wait("ACTOR alice  PROMPT")
	b.typ("r\r")
	b.wait("[1] witness the session of alice")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	b.typ("q")
	b.wait("detached")
	if err := b.cmd.Wait(); err != nil {
		t.Error(err)
	}
}

func TestDaemonSpoofing(t *testing.T) {
	harden(t)
	fixtures(t)
	startDaemon(t, "")
	must(os.WriteFile(home+"/spoof", []byte("\x1b]0;TITLE\x07\x1b]52;c;ZXZpbA==\x07\x1b[r\x1b[999;1H\x1b[2K FAKE [a]pprove\x1b[30;1HFAKE2\x1bc\x1b[6n\x1b[c\x1bP+q544e\x1b\\\x1b[?1049h\x1b[?1000h\x1b[5iEND\n"), 0o644))
	a := attach(t, alice)
	a.wait("PROMPT")
	b := attach(t, bob)
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.typ("cat spoof\r")
	b.approve("spoof")
	b.wait("END")
	a.wait("PROMPT")
	for _, w := range []*window{a, b} {
		lines := strings.Split(w.screen(), "\n")
		panel := strings.Join(lines[len(lines)-3:], "\n")
		if strings.Contains(panel, "FAKE") || !strings.Contains(panel, "alice") {
			t.Errorf("%s: panel overwritten:\n%s", w.name, panel)
		}
		w.mu.Lock()
		raw := w.raw.String()
		w.mu.Unlock()
		for _, bad := range []string{"\x1b]", "\x1bc", "\x1bP", "\x1b[6n", "\x1b[c", "\x1b[?1000h", "\x1b[5i", "\x1b[r"} {
			if strings.Contains(raw, bad) {
				t.Errorf("%s: terminal got %q", w.name, bad)
			}
		}
	}
	// Answers to queries must not have become input.
	if d := a.screen(); strings.Contains(d, "$ [") || strings.Contains(d, "R$") {
		t.Errorf("input injected:\n%s", d)
	}
	// A flood must not stall or kill the session.
	a.typ("timeout 3 yes\r")
	b.approve("yes")
	a.wait("RUNNING")
	a.wait("exit status 124")
	b.wait("PROMPT")
	a.typ("echo ali''ve\r")
	b.approve("alive")
	a.wait("PROMPT")
}

// dialAs connects with another user's credentials.
func dialAs(u launch.User) net.Conn {
	ch := make(chan int)
	go func() {
		runtime.LockOSThread() // the thread ends with the goroutine
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		must(err)
		_, _, e := unix.RawSyscall(unix.SYS_SETRESUID, uintptr(u.UID), uintptr(u.UID), 0)
		if e != 0 {
			panic(e)
		}
		must(unix.Connect(fd, &unix.SockaddrUnix{Name: sock}))
		ch <- fd
	}()
	fd := <-ch
	f := os.NewFile(uintptr(fd), "sock")
	defer f.Close()
	c, err := net.FileConn(f)
	must(err)
	return c
}

func say(c net.Conn, q wire.Request) {
	q.Version = wire.Version
	_ = wire.Write(c, q)
}

// hear returns the next reply of a type, or an error or end.
func hear(t *testing.T, c net.Conn, typ string) wire.Reply {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Second))
	for {
		var r wire.Reply
		if err := wire.Read(c, wire.MaxReply, &r); err != nil {
			return wire.Reply{Type: "closed", Text: err.Error()}
		}
		if r.Type == typ || r.Type == wire.Error || r.Type == wire.End {
			return r
		}
	}
}

// scr is a screen made of frames.
type scr map[int]string

func (s scr) add(r wire.Reply) {
	if r.Frame == nil {
		return
	}
	for _, l := range r.Frame.Lines {
		s[l.Y] = ""
		for _, run := range l.Runs {
			s[l.Y] += run.T
		}
	}
}

func (s scr) text() string {
	out := ""
	for y := range 300 {
		if s[y] != "" {
			out += s[y] + "\n"
		}
	}
	return out
}

// until waits for a state.
func until(t *testing.T, c net.Conn, f func(*wire.State) bool) *wire.State {
	t.Helper()
	for {
		r := hear(t, c, wire.StateType)
		if r.Type != wire.StateType {
			t.Fatalf("got %s %q", r.Type, r.Text)
		}
		if f(r.State) {
			return r.State
		}
	}
}

func carolUser() launch.User { return mustUser("carol") }

func phase(p wire.Phase) func(*wire.State) bool {
	return func(s *wire.State) bool { return s.Phase == p }
}

func TestDaemonProtocol(t *testing.T) {
	harden(t)
	fixtures(t)
	startDaemon(t, "approvals_required = 2\nmax_sessions = 1\n")
	carol := carolUser()
	a := dialAs(alice)
	defer a.Close()
	say(a, wire.Request{Type: wire.Actor, Rows: 24, Cols: 80})
	id := until(t, a, phase(wire.Prompt)).Session

	refuse := func(what string, u launch.User, q wire.Request) {
		t.Helper()
		c := dialAs(u)
		defer c.Close()
		say(c, q)
		if r := hear(t, c, wire.StateType); r.Type != wire.Error && r.Type != "closed" {
			t.Errorf("%s: %+v", what, r)
		}
	}
	refuse("witness own session", alice, wire.Request{Type: wire.Witness, Session: id})
	refuse("act in another's session", bob, wire.Request{Type: wire.Actor, Session: id})
	refuse("second session", bob, wire.Request{Type: wire.Actor})
	refuse("unknown session", bob, wire.Request{Type: wire.Witness, Session: "x"})
	refuse("witness nothing", bob, wire.Request{Type: wire.Witness})
	refuse("vote without joining", bob, wire.Request{Type: wire.Vote, ID: 1, Approve: true})
	refuse("bad hash", bob, wire.Request{Type: wire.Sign, Text: "../../etc/passwd"})
	for _, raw := range []string{"\xff\xff\xff\xff", "\x00\x00\x00\x01x", "\x00\x00\x00\x00", "GET / HTTP/1.0\r\n\r\n"} {
		c := dialAs(bob)
		_, _ = c.Write([]byte(raw))
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		if _, err := io.ReadAll(c); os.IsTimeout(err) {
			t.Errorf("%q: not closed: %v", raw, err)
		}
		_ = c.Close()
	}

	join := func(u launch.User) net.Conn {
		c := dialAs(u)
		t.Cleanup(func() { _ = c.Close() })
		say(c, wire.Request{Type: wire.Witness, Session: id})
		until(t, c, phase(wire.Prompt))
		return c
	}
	b, c := join(bob), join(carol)
	typ := func(s string) { say(a, wire.Request{Type: wire.Key, Data: []byte(s)}) }
	vote := func(w net.Conn, id uint64, ok bool, why string) {
		say(w, wire.Request{Type: wire.Vote, ID: id, Approve: ok, Text: why})
	}
	mark := func(want bool, what string) {
		t.Helper()
		time.Sleep(700 * time.Millisecond)
		if exists(marker) != want {
			t.Errorf("%s: ran=%v", what, !want)
		}
		_ = os.Remove(marker)
	}
	expectError := func(w net.Conn, want string) {
		t.Helper()
		for {
			r := hear(t, w, wire.Error)
			if r.Type == wire.Error {
				if !strings.Contains(r.Text, want) {
					t.Errorf("got %q, want %q", r.Text, want)
				}
				return
			}
			if r.Type == "closed" {
				t.Fatalf("closed, want %q", want)
			}
		}
	}

	say(b, wire.Request{Type: wire.Key, Data: []byte("touch MARK\r")})
	expectError(b, "not allowed")
	say(a, wire.Request{Type: wire.Vote, ID: 1, Approve: true})
	expectError(a, "not allowed")

	// Two approvals are needed, from different users, of this request.
	typ("touch MARK\r")
	p := until(t, b, phase(wire.Pending))
	vote(b, p.ID, true, "")
	vote(b, p.ID, true, "")
	expectError(b, "already approved")
	b2 := join2(t, bob, id)
	vote(b2, p.ID, true, "")
	expectError(b2, "already approved")
	mark(false, "one user, three votes")
	vote(c, p.ID+1, true, "")
	expectError(c, "different request")
	mark(false, "stale vote")
	// A witness who leaves keeps their vote.
	_, _ = b.Close(), b2.Close()
	vote(c, p.ID, true, "")
	mark(true, "two approvals")
	until(t, a, phase(wire.Prompt))

	// Veto.
	b = join(bob)
	typ("touch MARK\r")
	p = until(t, b, phase(wire.Pending))
	vote(b, p.ID, true, "")
	vote(c, p.ID, false, " ")
	expectError(c, "needs a comment")
	vote(c, p.ID, false, "no")
	until(t, a, func(s *wire.State) bool { return strings.Contains(s.Notice, "rejected by carol: no") })
	vote(c, p.ID, true, "")
	expectError(c, "no request")
	mark(false, "vetoed")

	// Viewing uses the witness's own permissions.
	sh(t, "install -m 600 -o alice /dev/null /home/alice/private; chmod 755 /home/alice")
	for _, f := range []string{"private", "/etc/shadow", "/root/secret", "/proc/self/environ", "/proc/1/environ", "/dev/zero", "/dev/stdin"} {
		say(b, wire.Request{Type: wire.View, Text: f})
		expectError(b, "")
		say(b, wire.Request{Type: wire.Checksig, Text: f})
		expectError(b, "")
	}
	say(b, wire.Request{Type: wire.View, Text: "s.sh"}) // relative to the actor
	if r := hear(t, b, wire.Doc); r.Doc == nil || len(r.Doc.Lines) != 2 {
		t.Errorf("%+v", r)
	}

	// A program in the session cannot use the daemon as its user.
	typ("\x03")
	prog := `import socket,struct,json
def go(**q):
    s=socket.socket(socket.AF_UNIX); s.connect("` + sock + `"); q["Version"]=1; b=json.dumps(q).encode()
    s.sendall(struct.pack(">I",len(b))+b); h=s.recv(4); print(s.recv(4000).decode())
go(Type="list")
go(Type="sign",Text="00"*32)
`
	must(os.WriteFile("/usr/local/lib/inside.py", []byte(prog), 0o644))
	run := func(line string) {
		t.Helper()
		typ(line + "\r")
		p := until(t, c, phase(wire.Pending))
		vote(b, p.ID, true, "")
		vote(c, p.ID, true, "")
	}
	out := ""
	got := make(chan struct{})
	go func() {
		defer close(got)
		_ = a.SetReadDeadline(time.Now().Add(60 * time.Second))
		sc := scr{}
		for strings.Count(out, "inside a session") < 4 {
			var r wire.Reply
			if wire.Read(a, wire.MaxReply, &r) != nil {
				return
			}
			sc.add(r)
			out = sc.text()
		}
	}()
	run("python3 /usr/local/lib/inside.py")
	until(t, c, phase(wire.Running))
	until(t, c, phase(wire.Prompt))
	run("setsid -f sh -c 'sleep 1; python3 /usr/local/lib/inside.py'")
	<-got
	if strings.Count(out, "inside a session") != 4 || strings.Contains(out, `"ok"`) || strings.Contains(out, `"sessions"`) {
		t.Errorf("daemon answered a program in the session: %q", out)
	}
}

func join2(t *testing.T, u launch.User, id string) net.Conn {
	t.Helper()
	c := dialAs(u)
	t.Cleanup(func() { _ = c.Close() })
	say(c, wire.Request{Type: wire.Witness, Session: id})
	until(t, c, func(*wire.State) bool { return true })
	return c
}

func TestDaemonLongRequestMustBeRead(t *testing.T) {
	harden(t)
	fixtures(t)
	startDaemon(t, "")
	a := attach(t, alice)
	a.wait("PROMPT")
	b := attach(t, bob)
	b.typ("1\r")
	b.wait("WITNESS of alice")
	line := "true"
	for i := range 30 {
		line += fmt.Sprintf("; echo %d", i)
	}
	a.typ("\x1b[200~" + line + "; touch MARK\x1b[201~\r")
	b.wait("MORE: space")
	time.Sleep(time.Second)
	b.typ("a")
	b.wait("read to the end first")
	clean(t)
	for range 20 {
		b.typ(" ")
		time.Sleep(100 * time.Millisecond)
	}
	b.wait(`"touch" "MARK"`)
	b.typ("a")
	a.wait("PROMPT")
	time.Sleep(1500 * time.Millisecond)
	if !exists(marker) {
		t.Error("did not run")
	}
}

func TestDaemonTimeoutsAndHost(t *testing.T) {
	harden(t)
	fixtures(t)
	log := startDaemon(t, "detach_timeout = \"2s\"\n")
	a := dialAs(alice)
	say(a, wire.Request{Type: wire.Actor, Rows: 24, Cols: 80})
	until(t, a, phase(wire.Prompt))
	say(a, wire.Request{Type: wire.Key, Data: []byte("touch MARK\r")})
	until(t, a, phase(wire.Pending))
	_ = a.Close()
	time.Sleep(5 * time.Second)
	if !strings.Contains(log.String(), "request purged") || !strings.Contains(log.String(), "away too long") {
		t.Error("session not ended after the actor left")
	}
	sh(t, "sysctl -qw vm.memfd_noexec=0")
	defer harden(t)
	a = dialAs(alice)
	defer a.Close()
	say(a, wire.Request{Type: wire.Actor, Rows: 24, Cols: 80})
	if r := hear(t, a, wire.StateType); r.Type != wire.Error || !strings.Contains(r.Text, "memfd_noexec") {
		t.Errorf("weak host accepted: %+v", r)
	}
}

func TestDaemonWeakHostIsShown(t *testing.T) {
	harden(t)
	fixtures(t)
	startDaemon(t, "allow_weak_host = true\n")
	sh(t, "sysctl -qw vm.memfd_noexec=0")
	defer harden(t)
	a := attach(t, alice)
	a.wait("WEAK HOST")
}

func TestDaemonConfigStrict(t *testing.T) {
	for _, c := range []string{"approvals_required = 0", "nonsense = 1", "detach_timeout = \"x\"", "exec_dirs = [\"rel\"]", "max_sessions = -1", "udp_port = 70000", "record_dir = \"x\"", "approvals_required = \"2\""} {
		must(os.WriteFile("/etc/witnesshell/config.toml", []byte(c), 0o644))
		cmd := exec.Command("timeout", "3", binary, "daemon")
		if err := cmd.Run(); err == nil || cmd.ProcessState.ExitCode() == 124 {
			t.Errorf("accepted %q", c)
		}
	}
	must(os.Remove("/etc/witnesshell/config.toml"))
}
