//go:build vmtest

package vm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"witnesshell/internal/pty"
	"witnesshell/internal/runner"
)

// The shell must lead a terminal's session, so it runs in a child process
// that takes lines on descriptor 3 and answers on descriptor 4.
const leaderArg = "__leader"

type reply struct {
	Err      string // from Prepare: refused
	RunErr   string
	Status   int
	Dir      string
	Exited   bool
	Warnings []string
}

func leader() {
	in, out := os.NewFile(3, "in"), os.NewFile(4, "out")
	syscall.CloseOnExec(3)
	syscall.CloseOnExec(4)
	s, err := runner.New(runner.Config{User: alice, Policy: policy, ExecDirs: execDirs, TTY: os.Stdin, Dir: home})
	must(err)
	dec, enc := json.NewDecoder(in), json.NewEncoder(out)
	var stale *runner.Prepared
	for {
		var line string
		if dec.Decode(&line) != nil {
			s.Close()
			os.Exit(0)
		}
		var r reply
		if line == "\x00stale" {
			_, err := s.Run(stale)
			r.RunErr = fmt.Sprint(err)
		} else if p, err := s.Prepare(line); err != nil {
			r.Err = err.Error()
		} else {
			stale = p
			r.Warnings = p.Warnings()
			if r.Status, err = s.Run(p); err != nil {
				r.RunErr = err.Error()
			}
		}
		r.Dir, r.Exited = s.Dir(), s.Exited()
		must(enc.Encode(r))
	}
}

type tsh struct {
	t   *testing.T
	ptm *os.File
	in  *json.Encoder
	out chan reply
	mu  sync.Mutex
	buf bytes.Buffer
}

func shell(t *testing.T) *tsh {
	t.Helper()
	ptm, pts, err := pty.Open(24, 200)
	must(err)
	inR, inW, err := os.Pipe()
	must(err)
	outR, outW, err := os.Pipe()
	must(err)
	cmd := exec.Command("/proc/self/exe", leaderArg)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pts, pts, pts
	cmd.ExtraFiles = []*os.File{inR, outW}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	must(cmd.Start())
	_, _, _ = pts.Close(), inR.Close(), outW.Close()
	s := &tsh{t: t, ptm: ptm, in: json.NewEncoder(inW), out: make(chan reply, 1)}
	go func() {
		dec := json.NewDecoder(outR)
		for {
			var r reply
			if dec.Decode(&r) != nil {
				close(s.out)
				return
			}
			s.out <- r
		}
	}()
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := ptm.Read(b)
			s.mu.Lock()
			s.buf.Write(b[:n])
			s.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = inW.Close()
		time.Sleep(50 * time.Millisecond)
		_ = ptm.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return s
}

func (s *tsh) begin(line string) {
	s.t.Helper()
	s.mu.Lock()
	s.buf.Reset()
	s.mu.Unlock()
	must(s.in.Encode(line))
	time.Sleep(1200 * time.Millisecond) // generous: the VM may be emulated
}

func (s *tsh) busy() {
	s.t.Helper()
	select {
	case r := <-s.out:
		s.t.Fatalf("finished early: %+v %q", r, s.text())
	default:
	}
}

func (s *tsh) end() reply {
	s.t.Helper()
	select {
	case r := <-s.out:
		time.Sleep(50 * time.Millisecond)
		return r
	case <-time.After(30 * time.Second):
		s.t.Fatalf("no prompt; output %q", s.text())
	}
	panic("unreachable")
}

func (s *tsh) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *tsh) run(line string) reply {
	s.t.Helper()
	s.mu.Lock()
	s.buf.Reset()
	s.mu.Unlock()
	must(s.in.Encode(line))
	return s.end()
}

func (s *tsh) key(k string) {
	s.t.Helper()
	_, err := s.ptm.WriteString(k)
	must(err)
}

// expect runs a line and checks output and status.
func (s *tsh) expect(line, want string, status int) {
	s.t.Helper()
	r := s.run(line)
	if r.Err != "" || r.RunErr != "" || r.Status != status || !strings.Contains(s.text(), want) {
		s.t.Errorf("%q: %+v output %q, want %q status %d", line, r, s.text(), want, status)
	}
}

func (s *tsh) refused(line string) {
	s.t.Helper()
	if r := s.run(line); r.Err == "" {
		s.t.Errorf("%q not refused: %+v %q", line, r, s.text())
	}
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func clean(t *testing.T) {
	t.Helper()
	time.Sleep(400 * time.Millisecond)
	if exists(marker) {
		t.Error("UNAPPROVED COMMAND RAN")
	}
}

func TestShellBasics(t *testing.T) {
	harden(t)
	fixtures(t)
	sh(t, "cd /home/alice && rm -rf d o e secret && mkdir d && touch d/1 d/2 && chown -R alice: d && install -m 600 /dev/null /root/secret")
	s := shell(t)
	s.expect("id -un", "alice", 0)
	s.expect("tty", "/dev/pts/", 0)
	s.expect("stty size", "24 200", 0)
	s.expect("false", "", 1)
	s.expect("echo rc=$?", "rc=1", 0)
	s.refused("false; echo $?")
	s.expect("printf 'a\\nb\\n' | grep b | tr b c", "c\r\n", 0)
	s.expect("false && echo NO || echo yes", "yes", 0)
	s.expect("true || echo NO; echo two", "two", 0)
	s.expect("echo d/*", "d/1 d/2", 0)
	s.expect("X='a b'", "", 0)
	s.expect(`echo "[$X]"`, "[a b]", 0)
	s.expect("printenv X", "", 1)
	s.expect("export X", "", 0)
	s.expect("printenv X", "a b", 0)
	s.expect("Y=1 printenv Y", "1", 0)
	s.expect("unset X", "", 0)
	s.refused(`echo "$X"`)
	if r := s.run("cd d"); r.Dir != home+"/d" {
		t.Errorf("%+v", r)
	}
	s.expect("pwd", home+"/d", 0)
	s.expect("cd nope", "no such", 1)
	s.expect("cd /root", "denied", 1)
	s.expect("pwd", home+"/d", 0)
	s.expect("cd", "", 0)
	s.expect("umask 077", "", 0)
	s.expect("echo hi >o 2>e", "", 0)
	s.expect("stat -c '%a %U' o", "600 alice", 0)
	s.expect("echo more >>o", "", 0)
	s.expect("cat <o", "hi\r\nmore", 0)
	s.expect("ls /nope &>o", "", 2)
	s.expect("grep -c nope o", "1", 0)
	s.expect("cat </root/secret", "denied", 1)
	s.expect("echo x >/etc/x", "denied", 1)
	s.expect("echo x >/root/x", "denied", 1)
	s.expect("nice -n 1 nosuch", "", 127)
	s.refused("nosuch")
	s.refused("./s.sh")
	s.refused("echo $(id)")
	s.refused("eval id")
	s.refused("exec id")
	s.expect("cd d && echo * $PWD", "1 2 "+home+"/d", 0)
	s.expect("cd .. && pwd && false || pwd", home+"\r\n"+home, 0)
	s.refused("cd nope && ls")
	s.refused("cd d; ls")
	s.refused("cd d || ls")
	s.refused("ls && cd d")
	s.refused("cd d && cd ..")
	s.refused("cd d && export A=1")
	s.refused("cd d && ./s.sh")
	s.refused("cd d && sh ../s.sh")
	s.refused("X=1; echo a")
	s.refused("X=1 cd d")
	s.refused("cd d | cat")
	s.refused("jobs >o")
	s.refused("LD_PRELOAD=/x ls")
	s.refused("PATH=/x")
	s.refused("export PATH=/x")
	s.refused("unset HOME")
	s.refused("sh <s.sh")
	s.refused("ls /root/*")
	if r := s.run("sh -c true"); len(r.Warnings) != 1 {
		t.Errorf("no warning: %+v", r)
	}
	if r := s.run("\x00stale"); !strings.Contains(r.RunErr, "changed") {
		t.Errorf("same approval ran twice: %+v", r)
	}
	if r := s.run("exit"); !r.Exited {
		t.Errorf("%+v", r)
	}
	s.refused("id")
}

func TestShellOwnProcessUnreachable(t *testing.T) {
	// The shell is root: redirections must not reach its own files.
	harden(t)
	fixtures(t)
	s := shell(t)
	for _, c := range []string{"cat </proc/self/environ", "cat </proc/self/mem", "echo x >/proc/self/mem", "echo x >/proc/self/oom_score_adj",
		"cat </dev/fd/3", "cat </dev/stdin", "echo x >/dev/fd/4", "echo x >/proc/self/fd/4", "echo x >/proc/thread-self/comm"} {
		if r := s.run(c); r.Status == 0 && r.Err == "" {
			t.Errorf("%q allowed: %q", c, s.text())
		}
	}
	s.refused("echo /proc/self/fd/*")
	s.expect("python3 -c \"import os;print([l for l in open('/proc/%d/status'%os.getppid()) if l.startswith('Uid')])\"", `0\t0\t0\t0`, 0)
	for _, c := range []string{"mem", "environ", "fd/4"} {
		s.expect("cat /proc/self/status", "Uid", 0)
		s.expect("python3 -c \"import os;open('/proc/%d/"+c+"'%os.getppid())\"", "PermissionError", 1)
	}
	s.expect("python3 -c \"import os,signal;os.kill(os.getppid(),signal.SIGKILL)\"", "PermissionError", 1)
	s.expect("ls -l /proc/self/fd", "", 0)
	if strings.Contains(s.text(), "pipe:") || strings.Contains(s.text(), "socket:") {
		t.Errorf("descriptor leaked: %q", s.text())
	}
	s.expect("sh -c 'trap'", "", 0)
	s.expect("grep SigIgn /proc/self/status", "SigIgn:\t0000000000000000", 0)
	s.expect("grep SigBlk /proc/self/status", "SigBlk:\t0000000000000000", 0)
	s.expect("ps -o pgid=,tpgid= -p 1", "", 0)
}

func TestShellTypeAhead(t *testing.T) {
	harden(t)
	fixtures(t)
	s := shell(t)
	for range 3 {
		s.begin("sleep 2")
		s.busy()
		s.key("touch MARK\r")
		s.end()
		clean(t)
		s.begin("bash --norc -i") // leftovers must not feed the next command
		clean(t)
		s.key("exit\r")
		s.end()
	}
	s.begin("bash --norc -i")
	s.key("exit\rtouch MARK\r")
	s.end()
	clean(t)
	s.begin("bash --norc -i")
	s.key("suspend\r")
	s.end()
	s.key("touch MARK\r")
	clean(t)
}

func TestShellCtrlC(t *testing.T) {
	harden(t)
	fixtures(t)
	s := shell(t)
	for _, c := range []string{"sleep 60", "sleep 60 | cat", "cat", "sh -c 'while :; do :; done'", "sleep 60; touch MARK", "sleep 60 && touch MARK", "sleep 60 || touch MARK"} {
		s.begin(c)
		s.busy()
		s.key("\x03")
		if r := s.end(); r.Status != 130 {
			t.Errorf("%q: %+v", c, r)
		}
		clean(t)
		s.expect("echo alive", "alive", 0)
	}
	s.key("\x03") // at the prompt
	time.Sleep(300 * time.Millisecond)
	s.expect("echo alive", "alive", 0)
}

func TestShellJobs(t *testing.T) {
	harden(t)
	fixtures(t)
	s := shell(t)
	s.begin("sleep 4; touch MARK")
	s.key("\x1a")
	if r := s.end(); r.Status != 148 {
		t.Errorf("%+v", r)
	}
	clean(t)
	s.expect("jobs", "Stopped", 0)
	s.expect("fg", "sleep", 0)
	s.expect("jobs", "", 0)
	s.expect("sleep 60 &", "[1]", 0)
	s.expect("jobs", "Running", 0)
	s.expect("kill -KILL %1", "", 0)
	time.Sleep(300 * time.Millisecond)
	s.expect("jobs", "Done", 0)
	s.expect("kill %1", "no such job", 1)
	s.expect("kill 1", "want a job", 1)
	s.expect("fg", "no such job", 1)
	// Terminal settings must survive a stopped full-screen program.
	s.begin("vim -u NONE")
	s.busy()
	s.key("\x1a")
	if r := s.end(); r.Status != 148 {
		t.Errorf("%+v", r)
	}
	s.expect("stty -a", " icanon", 0)
	if strings.Contains(s.text(), "-icanon") || strings.Contains(s.text(), "-echo ") {
		t.Errorf("terminal left raw: %q", s.text())
	}
	s.begin("fg")
	s.key(":q!\r")
	s.end()
	s.expect("stty -a", " icanon", 0)
	// A background program gets no keys.
	s.begin("cat &")
	s.end()
	s.key("x\r")
	time.Sleep(300 * time.Millisecond)
	s.expect("jobs", "Stopped", 0)
}

func TestShellSudoPassword(t *testing.T) {
	harden(t)
	fixtures(t)
	s := shell(t)
	s.begin("sudo -k id -u")
	s.busy()
	s.key("test\r")
	if r := s.end(); r.Status != 0 || !strings.Contains(s.text(), "\n0\r\n") || strings.Contains(s.text(), "test\r") {
		t.Errorf("%+v %q", r, s.text())
	}
	s.begin("sudo -k sleep 60")
	s.key("test\r")
	time.Sleep(time.Second)
	s.busy()
	s.key("\x03")
	s.end()
	s.expect("echo alive", "alive", 0)
}

func TestShellHangup(t *testing.T) {
	harden(t)
	fixtures(t)
	s := shell(t)
	s.expect("sleep 4321 &", "[1]", 0)
	s.run("exit")
	time.Sleep(500 * time.Millisecond)
	if out, _ := exec.Command("pgrep", "-f", "sleep 4321").Output(); len(out) != 0 {
		t.Errorf("job survived logout: %s", out)
	}
}

func TestChecksigCommand(t *testing.T) {
	// The real command, as alice, with unlistable directories.
	harden(t)
	fixtures(t)
	bin := "/usr/local/bin/witnesshell"
	if !exists(bin) {
		t.Skip("binary not installed")
	}
	s := shell(t)
	s.expect("witnesshell checksig s.sh", "signed   no", 0)
	s.expect("witnesshell checksig /usr/bin/env", "trusted  yes", 0)
	s.expect("ls /var/lib/witnesshell/records", "denied", 2)
	signHere(t, home+"/s.sh", bob.UID)
	s.expect("witnesshell checksig s.sh", fmt.Sprintf(`by uid %d`, bob.UID), 0)
	s.expect("./s.sh", "", 0)
	if !exists(marker) {
		t.Error("signed script did not run")
	}
	signHere(t, home+"/s.sh", alice.UID)
	s.expect("witnesshell checksig s.sh", "does not count", 0)
	s.expect("witnesshell checksig /root/secret", "denied", 1)
}

func TestShellView(t *testing.T) {
	harden(t)
	fixtures(t)
	sh(t, "cd /home/alice && seq 1 500 >long && printf 'a\\033]0;x\\007b\\n' >esc && chown alice: long esc && install -m 600 /dev/null /root/secret")
	s := shell(t)
	s.expect("view esc", "a^[]0;x^Gb", 0)
	s.expect("view /etc/hostname", "witnesshell-vm", 0)
	s.expect("view /root/secret", "denied", 1)
	s.expect("view /proc/self/environ", "denied", 1)
	s.expect("view /dev/zero", "not a regular", 1)
	s.expect("checksig s.sh", "trusted  no", 0)
	s.expect("checksig /usr/bin/env", "trusted  yes", 0)
	s.expect("checksig /root/secret", "denied", 1)
	for _, c := range []string{"view esc | sh", "view esc >x", "view esc; id", "view esc && id", "view esc &", "A=1 view esc", "view $(id)"} {
		s.refused(c)
	}
	s.begin("view long")
	s.busy()
	s.key("!touch MARK\r\x1a\x1c")
	time.Sleep(300 * time.Millisecond)
	s.busy()
	s.key("Gqtouch MARK\r")
	if r := s.end(); r.Status != 0 || !strings.Contains(s.text(), "\r\n500") {
		t.Errorf("%+v", r)
	}
	clean(t)
	s.expect("stty -a", " icanon", 0)
}
