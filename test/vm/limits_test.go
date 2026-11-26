//go:build vmtest

package vm

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"witnesshell/internal/wire"
)

func TestLimitsRecording(t *testing.T) {
	// A full recording ends that session only.
	harden(t)
	fixtures(t)
	startDaemon(t, "max_recording = \"200KiB\"\nallow_weak_host = true\n") // carol is not prepared as an actor
	a := attach(t, alice)
	a.wait("PROMPT")
	o := attach(t, carolUser(), "-new") // somebody else's session
	o.wait("ACTOR carol  PROMPT")
	b := attach(t, bob)
	b.wait("witness the session of alice")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.typ("seq 1 1000000\r")
	b.approve("seq")
	a.wait("recording reached its limit")
	b.wait("witness the session of carol") // back to the list
	o.typ("echo st''ill\r")
	o.wait("PENDING") // carol's session goes on
	if out, err := exec.Command("sh", "-c", "ls -l /var/log/witnesshell/*-actor-alice.cast | awk '{print $5}' | sort -n | tail -1").Output(); err != nil || len(strings.TrimSpace(string(out))) == 0 {
		t.Error(err)
	} else if n := strings.TrimSpace(string(out)); len(n) > 6 {
		t.Errorf("recording of %s bytes", n)
	}
}

func TestDaemonKilled(t *testing.T) {
	// Nothing may run unlogged, even when the daemon dies without ending its
	// sessions and is not started again.
	harden(t)
	fixtures(t)
	startDaemon(t, "")
	a := attach(t, alice)
	a.wait("PROMPT")
	b := attach(t, bob)
	b.wait("witness the session of alice")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	// It ignores the hangup that ends a program when the terminal goes.
	a.typ(`python3 -c "import signal, time; signal.signal(signal.SIGHUP, signal.SIG_IGN); time.sleep(4242)"` + "\r")
	b.approve("python3")
	a.wait("RUNNING")
	// Until it really ignores the hangup; before that, the hangup alone would
	// end it and the test would prove nothing.
	for i := 0; !ignoresHangup("sleep.4242"); i++ {
		if i == 100 {
			t.Fatalf("not running:\n%s", sh(t, "ps -eo user,pid,ppid,comm,args"))
		}
		time.Sleep(100 * time.Millisecond)
	}
	must(daemonCmd.Process.Kill())
	_ = daemonCmd.Wait()
	for i := 0; ; i++ {
		out, _ := exec.Command("pgrep", "-f", "sleep.4242").Output()
		if len(out) == 0 {
			break
		}
		if i == 50 {
			t.Fatalf("still running after the daemon died: %s", sh(t, "ps -u alice -o pid,args"))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ignoresHangup tells whether alice's process whose command line matches
// pattern ignores SIGHUP.
func ignoresHangup(pattern string) bool {
	out, err := exec.Command("pgrep", "-u", "alice", "-f", pattern).Output()
	if err != nil {
		return false
	}
	b, err := os.ReadFile("/proc/" + strings.Fields(string(out))[0] + "/status")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "SigIgn:\t"); ok {
			n, err := strconv.ParseUint(v, 16, 64)
			return err == nil && n&(1<<(syscall.SIGHUP-1)) != 0
		}
	}
	return false
}

func TestOOMScore(t *testing.T) {
	// The daemon is protected from the OOM killer; sessions are not.
	harden(t)
	fixtures(t)
	startDaemon(t, "")
	a := attach(t, alice)
	a.wait("PROMPT")
	b := attach(t, bob)
	b.wait("witness the session of alice")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.typ("grep -H . /proc/self/oom_score_adj\r")
	b.approve("grep")
	a.wait("/proc/self/oom_score_adj:0")
	for what, want := range map[string]string{
		"daemon": fmt.Sprint(daemonCmd.Process.Pid), "leader": "$(pgrep -f ' __session$')", "screen": "$(pgrep -f ' __screen$')"} {
		got := strings.TrimSpace(sh(t, "cat /proc/"+want+"/oom_score_adj"))
		if what == "daemon" && got != "-900" || what != "daemon" && got != "0" {
			t.Errorf("%s: oom_score_adj %s", what, got)
		}
	}
}

func TestLimitsSessions(t *testing.T) {
	harden(t)
	fixtures(t)
	startDaemon(t, "")
	var conns []net.Conn
	for i := range 5 {
		c := dialAs(alice)
		conns = append(conns, c)
		say(c, wire.Request{Type: wire.Actor, Rows: 24, Cols: 80})
		r := hear(t, c, wire.StateType)
		if i < 4 && r.Type != wire.StateType {
			t.Fatalf("session %d: %+v", i, r)
		}
		if i == 4 && (r.Type != wire.Error || !strings.Contains(r.Text, "4 sessions already")) {
			t.Errorf("fifth session: %+v", r)
		}
	}
	for _, c := range conns {
		_ = c.Close()
	}
}

func TestLimitsTyping(t *testing.T) {
	harden(t)
	fixtures(t)
	startDaemon(t, "")
	a := dialAs(alice)
	defer a.Close()
	say(a, wire.Request{Type: wire.Actor, Rows: 24, Cols: 80})
	until(t, a, phase(wire.Prompt))
	// Each line is refused at once and logged, so the prompt comes back.
	for range 40 {
		say(a, wire.Request{Type: wire.Key, Data: []byte("echo $(x)\r")})
		time.Sleep(20 * time.Millisecond)
	}
	until(t, a, func(s *wire.State) bool { return strings.Contains(s.Notice, "too many lines") })
	time.Sleep(time.Second)
	out := sh(t, "cat $(ls -t /var/log/witnesshell/*-actor-alice.log | head -1)") // this session's
	if n := strings.Count(out, `"refused"`); n > 20 || n < 5 {
		t.Errorf("%d refusals logged, want at most 20", n)
	}
}
