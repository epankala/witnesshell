//go:build vmtest

package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"witnesshell/internal/transport"
	"witnesshell/internal/wire"
)

// ticketFor logs a user in over ssh, like connect does.
func ticketFor(t *testing.T, user string) []string {
	t.Helper()
	out := sh(t, "ssh "+strings.Join(sshOpts, " ")+" -T "+user+"@127.0.0.1 'quic 1'")
	m := regexp.MustCompile(`WITNESSHELL 1 (\d+) (\w+) (\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no ticket: %q", out)
	}
	return m[1:]
}

func dialQUIC(t *testing.T, k []string) (*transport.Client, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return transport.Dial(ctx, "127.0.0.1:"+k[0], k[1], wire.Request{Type: wire.Auth, Text: k[2]})
}

// onUDP checks that no ssh connection of the user is left.
func onUDP(t *testing.T, user string) {
	t.Helper()
	time.Sleep(500 * time.Millisecond)
	if out, _ := exec.Command("pgrep", "-fa", "sshd-session: "+user).Output(); len(out) != 0 {
		t.Errorf("ssh is still connected: %s", out)
	}
}

func TestQUICSession(t *testing.T) {
	harden(t)
	fixtures(t)
	sshKey(t)
	startDaemon(t, "")
	a := connectWith(t, alice)
	a.wait("ACTOR alice  PROMPT")
	onUDP(t, "alice")
	b := connectWith(t, bob)
	b.wait("[1] witness the session of alice")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.typ("id -un; touch MARK\r")
	b.approve("MARK")
	b.wait("alice")
	a.wait("PROMPT")
	time.Sleep(500 * time.Millisecond)
	if !exists(marker) {
		t.Error("did not run")
	}
	a.typ("seq 1 3000\r")
	b.approve("seq")
	a.wait("3000")
	b.wait("3000")
	a.wait("PROMPT")
	time.Sleep(time.Second)
	a.typ("cat\r")
	b.approve("/cat")
	a.wait("RUNNING")
	a.typ("over udp\r")
	b.wait("over udp")
	a.typ("\x04")
	a.wait("PROMPT")
	b.typ("v")
	b.wait("view file:")
	b.typ("/etc/hostname\r")
	b.wait("witnesshell-vm")
	b.typ("q")
	b.wait("WITNESS of alice")
	a.typ("\x04")
	b.wait("there is no session to witness")
	// The next session uses the same connection.
	a = connectWith(t, alice)
	a.wait("ACTOR alice  PROMPT")
	b.typ("r\r")
	b.wait("[1]")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.typ("echo se''cond\r")
	b.approve("second")
	b.wait("PROMPT")
}

func TestQUICLoss(t *testing.T) {
	harden(t)
	fixtures(t)
	sshKey(t)
	startDaemon(t, "")
	a := connectWith(t, alice)
	a.wait("ACTOR alice  PROMPT")
	b := connectWith(t, bob)
	b.wait("[1]")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	sh(t, "tc qdisc add dev lo root netem loss 30% delay 40ms 10ms")
	defer func() { _ = exec.Command("tc", "qdisc", "del", "dev", "lo", "root").Run() }()
	for i := range 5 {
		a.typ(fmt.Sprintf("echo lo''ss%d; seq 1 200\r", i))
		b.approve(fmt.Sprintf("loss%d", i))
		a.wait("PROMPT")
		a.wait("200")
	}
	a.typ("touch MARK\r")
	b.approve("MARK")
	a.wait("PROMPT")
	time.Sleep(time.Second)
	if !exists(marker) {
		t.Error("did not run")
	}
}

func TestQUICLogin(t *testing.T) {
	harden(t)
	fixtures(t)
	sshKey(t)
	log := startDaemon(t, "")
	k := ticketFor(t, "alice")
	c, err := dialQUIC(t, k)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := dialQUIC(t, k); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("token used twice: %v", err)
	}
	for _, tok := range []string{"", "x", strings.Repeat("A", 43)} {
		if _, err := dialQUIC(t, []string{k[0], k[1], tok}); err == nil {
			t.Errorf("token %q accepted", tok)
		}
	}
	old := ticketFor(t, "bob")
	time.Sleep(31 * time.Second)
	if _, err := dialQUIC(t, old); err == nil {
		t.Error("old token accepted")
	}
	if _, err := dialQUIC(t, append([]string{k[0], strings.Repeat("0", 64)}, ticketFor(t, "bob")[2])); err == nil {
		t.Error("wrong certificate accepted")
	}
	// The connection is alice, and only alice.
	st, err := c.Open()
	must(err)
	say(st, wire.Request{Type: wire.Actor, Rows: 24, Cols: 80})
	id := until(t, st, phase(wire.Prompt)).Session
	st2, err := c.Open()
	must(err)
	say(st2, wire.Request{Type: wire.Witness, Session: id})
	if r := hear(t, st2, wire.StateType); r.Type != wire.Error {
		t.Errorf("witnessed own session: %+v", r)
	}
	st3, err := c.Open()
	must(err)
	say(st3, wire.Request{Type: wire.Token})
	if r := hear(t, st3, wire.OK); r.Type != wire.Error {
		t.Errorf("token from a token: %+v", r)
	}
	// A program in the session cannot get a token.
	b, err := dialQUIC(t, ticketFor(t, "bob"))
	must(err)
	defer b.Close()
	w, err := b.Open()
	must(err)
	say(w, wire.Request{Type: wire.Witness, Session: id})
	until(t, w, phase(wire.Prompt))
	say(st, wire.Request{Type: wire.Key, Data: []byte("env SSH_ORIGINAL_COMMAND=x witnesshell bootstrap; env SSH_ORIGINAL_COMMAND='quic 1' witnesshell bootstrap\r")})
	p := until(t, w, phase(wire.Pending))
	say(w, wire.Request{Type: wire.Vote, ID: p.ID, Approve: true})
	out, sc := "", scr{}
	_ = st.SetReadDeadline(time.Now().Add(60 * time.Second))
	for !strings.Contains(out, "inside a session") {
		var r wire.Reply
		if err := wire.Read(st, wire.MaxReply, &r); err != nil {
			t.Fatalf("%v %q", err, out)
		}
		sc.add(r)
		out = sc.text()
	}
	if strings.Contains(out, "WITNESSHELL 1") {
		t.Errorf("token issued inside a session: %q", out)
	}
	// A client that vanishes is noticed, and its session waits.
	c.Close()
	until(t, w, func(s *wire.State) bool { return !s.ActorOnline })
	if strings.Contains(log.String(), k[2]) {
		t.Error("token in the log")
	}
}

// blockUDP drops what clients send until the returned function is called.
func blockUDP(t *testing.T) func() {
	t.Helper()
	sh(t, "nft add table inet wt && nft add chain inet wt in '{ type filter hook input priority 0; }' && nft add rule inet wt in udp dport 60001 drop && nft add rule inet wt in udp sport 60001 drop")
	open := func() { _ = exec.Command("nft", "delete", "table", "inet", "wt").Run() }
	t.Cleanup(open)
	return open
}

// same waits until two windows show the same screen above their panels.
func same(t *testing.T, a, b *window, rows int) {
	t.Helper()
	top := func(w *window) string {
		l := strings.Split(w.screen(), "\n")
		return strings.TrimRight(strings.Join(l[:min(rows, len(l))], "\n"), "\n ")
	}
	for end := time.Now().Add(60 * time.Second); top(a) != top(b); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("screens differ:\n%s\n----\n%s", top(a), top(b))
		}
	}
}

func TestQUICResume(t *testing.T) {
	harden(t)
	fixtures(t)
	sshKey(t)
	log := startDaemon(t, "")
	a := connectWith(t, alice)
	a.wait("ACTOR alice  PROMPT")
	b := connectWith(t, bob)
	b.wait("[1]")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	l := attach(t, carolUser()) // a witness whose connection does not break
	l.wait("[1]")
	l.typ("1\r")
	l.wait("WITNESS of alice")
	a.typ("seq 1 100\r")
	b.approve("seq")
	a.wait("PROMPT")
	time.Sleep(time.Second)

	// The connection breaks while a draft is being written, and comes back.
	a.typ("touch MA")
	a.wait("$ touch MA")
	open := blockUDP(t)
	a.wait("NO ANSWER")
	a.wait("CONNECTION LOST, reconnecting 0:0")
	b.wait("CONNECTION LOST")
	l.wait("actor is away")
	a.typ("XYZ\r") // must not be kept for later
	a.wait("not sent")
	open()
	a.wait("ACTOR alice  PROMPT")
	a.wait("$ touch MA")
	b.wait("WITNESS of alice")
	same(t, a, l, 20)
	time.Sleep(2 * time.Second)
	if a.has("XYZ") {
		t.Errorf("keys typed without a connection arrived:\n%s", a.screen())
	}
	a.typ("RK\r")
	b.wait("[a]pprove")
	l.wait("PENDING 0/1")

	// A request outlives a broken connection; approving without one does not work.
	open = blockUDP(t)
	b.wait("CONNECTION LOST")
	b.typ("a")
	b.wait("not sent")
	a.wait("CONNECTION LOST")
	clean(t)
	open()
	a.wait("PENDING 0/1")
	b.wait("PENDING 0/1")
	time.Sleep(2 * time.Second)
	clean(t)
	b.typ("a")
	a.wait("PROMPT")
	time.Sleep(time.Second)
	if !exists(marker) {
		t.Error("did not run")
	}

	// A full-screen program looks the same afterwards, and after it ends.
	sh(t, "seq 1 500 >/home/alice/long; chown alice: /home/alice/long")
	a.typ("vim -u NONE long\r")
	b.approve("vim")
	a.wait("RUNNING")
	time.Sleep(2 * time.Second)
	a.typ("100Gihello\x1b")
	a.wait("hello100")
	open = blockUDP(t)
	a.wait("CONNECTION LOST")
	open()
	a.wait("RUNNING")
	same(t, a, l, 20)
	a.wait("hello100")
	a.typ("xx:q!\r")
	a.wait("PROMPT")
	same(t, a, l, 20)

	// Once the user has quit, the login cannot be resumed.
	if n := strings.Count(log.String(), "resumed=true"); n < 4 {
		t.Errorf("%d resumptions", n)
	}
	a.typ("\x04")
	a.wait("logged out")
	b.wait("there is no session to witness")
	// The list survives a break as well.
	open = blockUDP(t)
	time.Sleep(20 * time.Second)
	open()
	b.typ("r\r")
	time.Sleep(time.Second)
	b.typ("q\r")
	if err := b.cmd.Wait(); err != nil {
		t.Errorf("%v\n%s", err, b.screen())
	}
}

func TestQUICNewAddress(t *testing.T) {
	// The client's IP address changes during a session.
	harden(t)
	fixtures(t)
	sshKey(t)
	startDaemon(t, "")
	sh(t, `ip netns add wt; ip link add wt0 type veth peer name wt1; ip link set wt1 netns wt
ip addr add 10.9.0.1/24 dev wt0; ip link set wt0 up
ip netns exec wt ip link set lo up; ip netns exec wt ip addr add 10.9.0.2/24 dev wt1; ip netns exec wt ip link set wt1 up`)
	defer sh(t, "ip link del wt0; ip netns del wt")
	args := append([]string{"netns", "exec", "wt", binary, "connect"}, sshOpts...)
	a := open(t, alice, exec.Command("ip", append(args, "alice@10.9.0.1")...))
	a.wait("ACTOR alice  PROMPT")
	b := attach(t, bob)
	b.wait("[1]")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.typ("echo be''fore\r")
	b.approve("before")
	a.wait("PROMPT")
	sh(t, "ip netns exec wt ip addr del 10.9.0.2/24 dev wt1; ip netns exec wt ip addr add 10.9.0.77/24 dev wt1")
	a.typ("touch MARK")
	a.wait("$ touch MARK")
	a.typ("\r")
	b.approve("MARK")
	a.wait("PROMPT")
	time.Sleep(time.Second)
	if !exists(marker) {
		t.Error("did not run")
	}
}

func TestQUICResumeSecret(t *testing.T) {
	harden(t)
	fixtures(t)
	sshKey(t)
	log := startDaemon(t, "detach_timeout = \"4s\"\n")
	resume := func(k []string, secret string) (*transport.Client, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return transport.Dial(ctx, "127.0.0.1:"+k[0], k[1], wire.Request{Type: wire.Resume, Text: secret})
	}
	k := ticketFor(t, "alice")
	c, err := dialQUIC(t, k)
	must(err)
	for _, s := range []string{"", "x", k[2], c.Secret + "x", strings.Repeat("A", 43)} {
		if _, err := resume(k, s); !errors.Is(err, transport.ErrRefused) {
			t.Errorf("%q: %v", s, err)
		}
	}
	// A second connection takes over from the first.
	c2, err := resume(k, c.Secret)
	must(err)
	for range 50 {
		if !c.Alive() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if c.Alive() {
		t.Error("the old connection stayed")
	}
	st, err := c2.Open()
	must(err)
	say(st, wire.Request{Type: wire.Actor, Rows: 24, Cols: 80})
	if s := until(t, st, phase(wire.Prompt)); s.Actor != "alice" {
		t.Errorf("%+v", s)
	}
	// Dropped: can come back in time, and not later.
	c2.Drop()
	time.Sleep(time.Second)
	c3, err := resume(k, c.Secret)
	must(err)
	c3.Drop()
	time.Sleep(6 * time.Second)
	if _, err := resume(k, c.Secret); !errors.Is(err, transport.ErrRefused) {
		t.Errorf("resumed too late: %v", err)
	}
	// Quit: cannot come back at all.
	c, err = dialQUIC(t, ticketFor(t, "bob"))
	must(err)
	c.Close()
	time.Sleep(time.Second)
	if _, err := resume(k, c.Secret); !errors.Is(err, transport.ErrRefused) {
		t.Errorf("resumed after quitting: %v", err)
	}
	if strings.Contains(log.String(), c.Secret) {
		t.Error("secret in the log")
	}
}

func TestQUICDaemonRestart(t *testing.T) {
	harden(t)
	fixtures(t)
	sshKey(t)
	sh(t, "rm -f /etc/witnesshell/config.toml; cp /usr/local/lib/deploy/witnesshell.service /etc/systemd/system/ && systemctl daemon-reload && systemctl start witnesshell && sleep 2")
	defer sh(t, "systemctl stop witnesshell; rm /etc/systemd/system/witnesshell.service; systemctl daemon-reload")
	a := connectWith(t, alice)
	a.wait("ACTOR alice  PROMPT")
	b := connectWith(t, bob)
	b.wait("[1]")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	sh(t, "systemctl kill -s KILL witnesshell; sleep 1; systemctl start witnesshell")
	// The new daemon is another host as far as clients can tell.
	a.wait("could not be resumed")
	a.wait("certificate is not the one")
	b.wait("could not be resumed")
	if out, _ := exec.Command("pgrep", "-f", "__session|__screen").Output(); len(out) != 0 {
		t.Errorf("left over: %s", out)
	}
}

func TestScreenProcess(t *testing.T) {
	// It has no privileges, and the session survives its end.
	harden(t)
	fixtures(t)
	startDaemon(t, "")
	a := attach(t, alice)
	a.wait("PROMPT")
	b := attach(t, bob)
	b.wait("[1]")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	pid := strings.TrimSpace(sh(t, "pgrep -f '[_]_screen'"))
	st := sh(t, "cat /proc/"+pid+"/status")
	for _, w := range []string{"Uid:\t65534\t65534\t65534\t65534", "Gid:\t65534\t65534\t65534\t65534", "CapPrm:\t0000000000000000", "CapBnd", "NoNewPrivs:\t1", "Groups:\t \n"} {
		if !strings.Contains(st, w) {
			t.Errorf("status lacks %q:\n%s", w, st)
		}
	}
	if fds := sh(t, "ls -l /proc/"+pid+"/fd"); strings.Contains(fds, "ptmx") || strings.Contains(fds, "pts") || strings.Contains(fds, "socket") {
		t.Errorf("%s", fds)
	}
	for _, how := range []string{"KILL", "STOP"} { // dead, and hanging
		sh(t, "pkill -"+how+" -f '[_]_screen'")
		time.Sleep(300 * time.Millisecond)
		a.typ("seq 1 2000\r")
		b.approve("seq")
		a.wait("PROMPT")
		a.typ("echo st''ill " + how + "\r")
		b.approve("still")
		a.wait("still " + how)
		b.wait("still " + how)
		a.wait("PROMPT")
	}
	if n := strings.Count(strings.TrimSpace(sh(t, "pgrep -f '[_]_screen'")), "\n") + 1; n != 1 {
		t.Errorf("%d screen processes", n)
	}
}

func TestQUICUnreachable(t *testing.T) {
	harden(t)
	sshKey(t)
	startDaemon(t, "")
	unblock := blockUDP(t)
	a := connectWith(t, alice)
	a.wait("no UDP connection")
	unblock()
	a = connectWith(t, alice, "--udp-host=localhost")
	a.wait("ACTOR alice  PROMPT")
	a.typ("\x04")
	a.wait("logged out")
}

func TestQUICDisabled(t *testing.T) {
	harden(t)
	sshKey(t)
	startDaemon(t, "udp_port = 0\n")
	a := connectWith(t, alice)
	a.wait("not available")
	a = connectWith(t, alice, "--ssh")
	a.wait("ACTOR alice  PROMPT")
	a.typ("\x04")
	must(os.Remove("/etc/witnesshell/config.toml"))
}
