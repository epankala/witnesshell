//go:build vmtest

package vm

import (
	"context"
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
	return transport.Dial(ctx, "127.0.0.1:"+k[0], k[1], k[2])
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
	out := ""
	_ = st.SetReadDeadline(time.Now().Add(15 * time.Second))
	for !strings.Contains(out, "inside a session") {
		var r wire.Reply
		if err := wire.Read(st, wire.MaxReply, &r); err != nil {
			t.Fatalf("%v %q", err, out)
		}
		out += string(r.Data)
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

func TestQUICVanished(t *testing.T) {
	// No farewell: the client is killed and its packets are dropped.
	harden(t)
	fixtures(t)
	sshKey(t)
	startDaemon(t, "")
	a := connectWith(t, alice)
	a.wait("ACTOR alice  PROMPT")
	b := attach(t, bob)
	b.wait("[1]")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	sh(t, "nft add table inet wt && nft add chain inet wt in '{ type filter hook input priority 0; }' && nft add rule inet wt in udp dport 60001 drop")
	defer func() { _ = exec.Command("nft", "delete", "table", "inet", "wt").Run() }()
	b.wait("actor is away")
	a.wait("timeout")
	sh(t, "nft delete table inet wt")
	a = connectWith(t, alice)
	a.wait("return to your session")
	a.typ("1\r")
	a.wait("ACTOR alice  PROMPT")
}

func TestQUICUnreachable(t *testing.T) {
	harden(t)
	sshKey(t)
	startDaemon(t, "")
	sh(t, "nft add table inet wt && nft add chain inet wt in '{ type filter hook input priority 0; }' && nft add rule inet wt in udp dport 60001 drop")
	a := connectWith(t, alice)
	a.wait("no UDP connection")
	sh(t, "nft delete table inet wt")
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
