//go:build vmtest

package vm

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"witnesshell/internal/audit"
	"witnesshell/internal/wire"
)

const logs = "/var/log/witnesshell"

func entries(t *testing.T, name string) (out []audit.Entry) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(logs, name))
	must(err)
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e audit.Entry
		must(json.Unmarshal([]byte(l), &e))
		out = append(out, e)
	}
	return out
}

func events(es []audit.Entry) string {
	var out []string
	for _, e := range es {
		out = append(out, e.Event)
	}
	return strings.Join(out, " ")
}

func find(es []audit.Entry, event string) audit.Data {
	for _, e := range es {
		if e.Event == event {
			return e.Data
		}
	}
	return audit.Data{}
}

func TestAudit(t *testing.T) {
	harden(t)
	fixtures(t)
	sh(t, "rm -rf "+logs)
	log := startDaemon(t, "")
	a := attach(t, alice)
	a.wait("PROMPT")
	b := attach(t, bob)
	b.wait("[1]")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.typ("./s.sh\r")
	a.wait("not signed")
	a.typ("\x03touch NOT\r")
	b.wait("[a]pprove")
	b.typ("r")
	b.wait("because:")
	b.typ("wrong host\r")
	a.wait("rejected by bob")
	a.typ("\x03echo re''corded\r")
	b.approve("recorded")
	a.wait("recorded")
	a.wait("PROMPT")
	a.typ("view /etc/hostname\r")
	a.wait("sha256")
	a.wait("PROMPT")
	b.typ("v")
	b.wait("view file:")
	b.typ("/etc/hostname\r")
	b.wait("[S]ign")
	b.typ("q")
	b.wait("WITNESS of alice")
	b.typ("v")
	b.wait("view file:")
	b.typ("/etc/shadow\r")
	b.wait("permission denied")
	// A password is typed and must be nowhere.
	a.typ("sudo -k id -u\r")
	b.approve("sudo")
	a.wait("assword")
	a.typ("test\r")
	a.wait("PROMPT")
	b.close()
	a.wait("no witness")
	c := attach(t, carolUser())
	c.wait("[1]")
	c.typ("1\r")
	c.wait("WITNESS of alice")
	a.typ("echo se''cond\r")
	c.approve("second")
	a.wait("PROMPT")
	b = attach(t, bob) // the same log goes on
	b.wait("[1]")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.typ("touch NEVER\r")
	b.wait("[a]pprove")
	a.close() // and logged out by the daemon's end below

	fs, err := os.ReadDir(logs)
	must(err)
	var names []string
	for _, f := range fs {
		names = append(names, f.Name())
	}
	m := regexp.MustCompile(`^witnesshell-(\d{8}T\d{6}\.\d{3}Z)-actor-alice\.cast$`).FindStringSubmatch(names[0])
	if len(names) != 4 || m == nil {
		t.Fatalf("%v", names)
	}
	id := m[1]
	al, bl, cl := names[1], names[2], names[3]
	if al != "witnesshell-"+id+"-actor-alice.log" || bl != "witnesshell-"+id+"-witness-bob.log" || cl != "witnesshell-"+id+"-witness-carol.log" {
		t.Fatalf("%v", names)
	}
	verify := func(args ...string) (string, error) {
		out, err := exec.Command(binary, append(append([]string{"audit", "verify"}, args...), id)...).CombinedOutput()
		return string(out), err
	}
	if out, err := verify(); err == nil || !strings.Contains(out, "still runs") {
		t.Errorf("running session: %s", out)
	}
	for _, n := range names {
		if st, _ := os.Stat(filepath.Join(logs, n)); st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v", n, st.Mode())
		}
	}
	// Alice cannot read, remove or add to them.
	if out, err := exec.Command("setpriv", "--reuid=alice", "--regid=alice", "--clear-groups", "sh", "-c", "ls "+logs+" || cat "+logs+"/"+al+" || touch "+logs+"/x || rm -rf "+logs).CombinedOutput(); err == nil {
		t.Errorf("alice: %s", out)
	}
	_ = exec.Command("pkill", "-TERM", "-f", "witsh daemon").Run()
	b.wait("the daemon is stopping")
	time.Sleep(3 * time.Second)
	out, err := verify()
	if err != nil || !strings.Contains(out, "ok ") {
		t.Fatalf("%v: %s", err, out)
	}
	seal := regexp.MustCompile(`seal +([0-9a-f]{64})`).FindStringSubmatch(out)
	if seal == nil || !strings.Contains(log.String(), seal[1]) {
		t.Errorf("seal not in the system's log: %s", out)
	}
	if out, err := verify("-seal", seal[1]); err != nil {
		t.Error(out)
	}
	if _, err := verify("-seal", strings.Repeat("0", 64)); err == nil {
		t.Error("wrong seal accepted")
	}

	ae, be, ce := entries(t, al), entries(t, bl), entries(t, cl)
	if got, want := events(ae), "session_start join join refused request vote request vote run_start run_end free_command run_end request vote run_start run_end leave join request vote run_start run_end join request leave purged session_end"; got != want {
		t.Errorf("actor log:\n got %s\nwant %s", got, want)
	}
	if got, want := events(be), "session_start join request vote request vote run_start inspect inspect request vote run_start leave join request purged session_end"; got != want {
		t.Errorf("bob's log:\n got %s\nwant %s", got, want)
	}
	if got, want := events(ce), "session_start join request vote run_start request purged session_end"; got != want {
		t.Errorf("carol's log:\n got %s\nwant %s", got, want)
	}
	v := find(ae, "vote")
	if v["by"] != "bob" || v["comment"] != "wrong host" || v["outcome"] != "rejected" || v["approve"] != false {
		t.Errorf("%v", v)
	}
	if d := find(ae, "refused"); d["text"] != "./s.sh" || !strings.Contains(fmt.Sprint(d["why"]), "not signed") {
		t.Errorf("%v", d)
	}
	if d := find(be, "inspect"); d["path"] != "/etc/hostname" || len(fmt.Sprint(d["sha256"])) != 64 {
		t.Errorf("%v", d)
	}
	if d := find(ae, "session_start"); d["host"] == "" || d["actor"] != "alice" {
		t.Errorf("%v", d)
	}
	cast, err := os.ReadFile(filepath.Join(logs, names[0]))
	must(err)
	for _, w := range []string{`"recorded\r\n"`, `"m","request: echo re''corded"`, `"m","approved by bob"`, `"m","rejected by bob: wrong host"`, `"m","ended, status 0"`} {
		if !strings.Contains(string(cast), w) {
			t.Errorf("recording lacks %s", w)
		}
	}
	for _, l := range strings.Split(strings.TrimSpace(string(cast)), "\n")[1:] {
		var e []any
		must(json.Unmarshal([]byte(l), &e))
		if e[1] == "i" || e[2] == "test\r\n" || e[2] == "test" {
			t.Errorf("input recorded: %s", l)
		}
	}
	// Tampering by someone who got root.
	b1, err := os.ReadFile(filepath.Join(logs, bl))
	must(err)
	must(os.WriteFile(filepath.Join(logs, bl), []byte(strings.Replace(string(b1), "wrong host", "right host", 1)), 0o600))
	if out, err := verify(); err == nil || !strings.Contains(out, "witness-bob") {
		t.Errorf("tampering not noticed: %s", out)
	}
	sh(t, "rm -f /home/alice/NOT /home/alice/NEVER")
}

func TestAuditDiskFull(t *testing.T) {
	// When nothing can be logged any more, nothing runs.
	harden(t)
	fixtures(t)
	sh(t, "mkdir -p /mnt/full && mount -t tmpfs -o size=256k,mode=700 none /mnt/full")
	defer sh(t, "umount /mnt/full")
	startDaemon(t, "record_dir = \"/mnt/full\"\n")
	a := dialAs(alice)
	defer a.Close()
	say(a, wire.Request{Type: wire.Actor, Rows: 24, Cols: 80})
	id := until(t, a, phase(wire.Prompt)).Session
	b := join2(t, bob, id)
	say(a, wire.Request{Type: wire.Key, Data: []byte("touch MARK\r")})
	p := until(t, b, phase(wire.Pending))
	_ = exec.Command("sh", "-c", "head -c 1M /dev/zero >/mnt/full/fill").Run()
	// Use up the rest of the log's last page: an entry for a join takes about
	// 200 bytes, one for a vote needs more than 380.
	name := "/mnt/full/witnesshell-" + id + "-actor-alice.log"
	for {
		st, err := os.Stat(name)
		must(err)
		if 4096-st.Size()%4096 < 380 {
			break
		}
		a = dialAs(alice)
		defer a.Close()
		say(a, wire.Request{Type: wire.Actor, Session: id, Rows: 24, Cols: 80})
		until(t, a, phase(wire.Pending))
	}
	say(b, wire.Request{Type: wire.Vote, ID: p.ID, Approve: true})
	for {
		r := hear(t, b, wire.End)
		if r.Type == wire.End {
			if !strings.Contains(r.Text, "no longer be logged") {
				t.Error(r.Text)
			}
			break
		}
		if r.Type == "closed" {
			break
		}
	}
	time.Sleep(2 * time.Second)
	if exists(marker) {
		t.Error("RAN WITHOUT A LOG ENTRY")
	}
	x, err := os.ReadFile(name)
	must(err)
	if strings.Contains(string(x), "run_start") {
		t.Error("the test did not fill the disk")
	}
	// And no session starts.
	c := dialAs(alice)
	defer c.Close()
	say(c, wire.Request{Type: wire.Actor, Rows: 24, Cols: 80})
	if r := hear(t, c, wire.StateType); r.Type != wire.Error || !strings.Contains(r.Text, "cannot be logged") {
		t.Errorf("started on a full disk: %+v", r)
	}
}

func TestAuditCrash(t *testing.T) {
	harden(t)
	fixtures(t)
	sh(t, "rm -rf "+logs)
	startDaemon(t, "")
	a := attach(t, alice)
	a.wait("PROMPT")
	b := attach(t, bob)
	b.wait("[1]")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.typ("echo be''fore\r")
	b.approve("before")
	a.wait("PROMPT")
	_ = exec.Command("pkill", "-KILL", "-f", "witsh daemon").Run()
	time.Sleep(2 * time.Second)
	fs, err := filepath.Glob(logs + "/*-actor-alice.log")
	must(err)
	id := regexp.MustCompile(`\d{8}T\d{6}\.\d{3}Z`).FindString(fs[0])
	out, err := exec.Command(binary, "audit", "verify", id).CombinedOutput()
	// What was written is whole, and the missing end is reported.
	if err == nil || strings.Contains(string(out), "chain") || strings.Contains(string(out), "not an entry") || strings.Count(string(out), "ended abnormally") != 2 {
		t.Errorf("%s", out)
	}
	if got := events(entries(t, filepath.Base(fs[0]))); !strings.HasSuffix(got, "request vote run_start run_end") {
		t.Errorf("%s", got)
	}
	sh(t, "pkill -f '[_]_session' || true")
}
