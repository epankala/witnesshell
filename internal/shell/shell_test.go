package shell

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type tsh struct {
	*Shell
	t   *testing.T
	dir string
	mu  sync.Mutex
	buf bytes.Buffer
}

func start(t *testing.T) *tsh {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	s := &tsh{t: t, dir: t.TempDir()}
	s.Shell, err = Start(Config{Path: bash, Args: []string{"--norc", "--noprofile"},
		Dir: s.dir, Env: append(os.Environ(), "PS1=$ "), Rows: 24, Cols: 200})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := s.Read(b)
			s.mu.Lock()
			s.buf.Write(b[:n])
			s.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	s.waitIdle()
	return s
}

func (s *tsh) waitIdle() {
	s.t.Helper()
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		ok, err := s.Idle()
		if err != nil {
			s.t.Fatal(err)
		}
		if ok {
			return
		}
	}
	s.t.Fatalf("never idle; output %q", s.out())
}

func (s *tsh) out() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// begin starts a command and lets it settle.
func (s *tsh) begin(c string) {
	s.t.Helper()
	if err := s.Run(c); err != nil {
		s.t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
}

func (s *tsh) do(c string) {
	s.t.Helper()
	if err := s.Run(c); err != nil {
		s.t.Fatal(err)
	}
	s.waitIdle()
}

func (s *tsh) expect(c, want string) {
	s.t.Helper()
	s.mu.Lock()
	s.buf.Reset()
	s.mu.Unlock()
	s.do(c)
	for end := time.Now().Add(2 * time.Second); !strings.Contains(s.out(), want); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			s.t.Fatalf("%q: output %q lacks %q", c, s.out(), want)
		}
	}
}

func (s *tsh) key(k string) {
	s.t.Helper()
	if _, err := s.Write([]byte(k)); err != nil {
		s.t.Fatal(err)
	}
}

func (s *tsh) busy() {
	s.t.Helper()
	if ok, _ := s.Idle(); ok {
		s.t.Fatal("reported idle while busy")
	}
	if err := s.Run("touch P"); !errors.Is(err, ErrBusy) {
		s.t.Fatalf("Run while busy: %v", err)
	}
}

// clean asserts that the unapproved command never ran.
func (s *tsh) clean() {
	s.t.Helper()
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(s.dir, "P")); err == nil {
		s.t.Fatal("UNAPPROVED COMMAND RAN")
	}
}

func TestSemantics(t *testing.T) {
	s := start(t)
	s.do("X=1; cd /; f(){ echo fn$X; }; alias q='echo al'")
	s.expect("pwd; f", "/\r\nfn1")
	s.expect("q", "al\r\n")
	s.do("false")
	s.expect("echo rc=$?", "rc=1")
	s.expect("for i in 1 2\ndo echo L$i\ndone\ncat <<E\nhere\nE", "L2\r\nhere")
	s.expect(`echo 'a!b' "c!!d" it\'s`, "a!b c!!d it's")
	s.expect("test -t 0 && echo ISTTY", "ISTTY")
	s.expect("exec </dev/null; echo X", "X\r\n")
	s.expect("stty size", "24 200")
	s.do("sleep 5 &")
	s.expect("jobs", "Running")
}

func TestIncompleteSyntaxDoesNotSwallowNext(t *testing.T) {
	s := start(t)
	for _, c := range []string{"if true", "echo 'x", "cat <<E", "echo \\", "f() {", "$(", "}; touch P"} {
		s.do(c)
		s.expect("echo OK", "OK\r\n")
	}
	s.clean()
}

func TestBusy(t *testing.T) {
	for _, c := range []string{
		"sleep 1", "sleep 1 | cat", `printf '\033]133;A\007$ '; sleep 1`,
		"read -t 1 v", "wait $(:) ; sleep 1", "SECONDS=0; while ((SECONDS<2)); do :; done",
	} {
		s := start(t)
		s.begin(c)
		s.busy()
		s.waitIdle()
		s.clean()
	}
}

func TestCtrlC(t *testing.T) {
	for _, c := range []string{"sleep 30", "while :; do :; done", "while :; do sleep .2; done", "read v", "cat"} {
		s := start(t)
		s.begin(c)
		s.key("\x03")
		s.waitIdle()
		s.expect("echo alive", "alive\r\n")
	}
	s := start(t)
	s.key("\x03") // at the prompt
	s.expect("echo alive", "alive\r\n")
}

func TestCtrlZ(t *testing.T) {
	s := start(t)
	s.begin("sleep 1")
	s.key("\x1a")
	s.waitIdle()
	s.expect("jobs", "Stopped")
	s.do("fg")
}

func TestTypeAheadDoesNotRun(t *testing.T) {
	for range 5 {
		s := start(t)
		s.begin("sleep .6")
		s.key("touch P\r")
		s.waitIdle()
		s.clean()
		s.begin("bash --norc -i") // must not inherit the leftovers either
		s.clean()
		s.key("exit\r")
		s.waitIdle()
	}
}

func TestNestedShell(t *testing.T) {
	s := start(t)
	s.begin("bash --norc -i")
	s.busy()
	s.key("touch N\r")
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(s.dir, "N")); err != nil {
		t.Fatal("nested shell got no input")
	}
	s.key("exit\rtouch P\r")
	s.waitIdle()
	s.clean()
	s.begin("bash --norc -i")
	s.key("suspend\r")
	s.waitIdle()
	s.key("touch P\r")
	s.clean()
}

func TestBackgroundReaderGetsNoKeys(t *testing.T) {
	s := start(t)
	s.do("(read v; touch P) &")
	s.key("x\r")
	s.clean()
}

func TestChannelNotReachable(t *testing.T) {
	s := start(t)
	s.expect("ls -l /proc/self/fd; echo END", "END")
	if strings.Contains(s.out(), "socket:") {
		t.Fatalf("socket leaked: %q", s.out())
	}
	s.do("for f in /proc/$$/fd/*; do (echo touch P >$f) 2>/dev/null; done")
	s.clean()
	s.do("cat >stolen & sleep .2")
	s.expect("echo mine", "mine\r\n")
}

func TestExit(t *testing.T) {
	s := start(t)
	if err := s.Run("exit"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("did not exit")
	}
	if err := s.Run("true"); !errors.Is(err, ErrExited) {
		t.Fatal(err)
	}
}

func TestLargeCommand(t *testing.T) {
	s := start(t)
	s.expect("v='"+strings.Repeat("a", 60000)+"'; echo ${#v}", "60000")
}

func TestCloseWhileRunning(t *testing.T) {
	s := start(t)
	s.begin("sleep 60")
	s.Close()
	s.Close()
	if _, err := s.Idle(); !errors.Is(err, ErrExited) {
		t.Fatal(err)
	}
}
