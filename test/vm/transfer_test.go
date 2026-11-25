//go:build vmtest

package vm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"witnesshell/internal/transfer"
	"witnesshell/internal/transport"
	"witnesshell/internal/wire"
)

// remote is a session over QUIC with bob as its witness.
type remote struct {
	t    *testing.T
	c    *transport.Client
	a, b net.Conn
	id   string
}

func remoteSession(t *testing.T) *remote {
	t.Helper()
	c, err := dialQUIC(t, ticketFor(t, "alice"))
	must(err)
	t.Cleanup(c.Close)
	a, err := c.Open()
	must(err)
	say(a, wire.Request{Type: wire.Actor, Rows: 24, Cols: 100})
	r := &remote{t: t, c: c, a: a}
	r.id = until(t, a, phase(wire.Prompt)).Session
	go func() { // nobody reads the screen
		for {
			var x wire.Reply
			if wire.Read(a, wire.MaxReply, &x) != nil {
				return
			}
		}
	}()
	r.b = join2(t, bob, r.id)
	return r
}

func local(t *testing.T, content string) string {
	t.Helper()
	p := t.TempDir() + "/f"
	must(os.WriteFile(p, []byte(content), 0o755))
	return p
}

// upload starts one and returns where its result will be.
func (r *remote) upload(file, to string) chan error {
	ch := make(chan error, 1)
	go func() {
		ch <- transfer.Upload(func() (net.Conn, error) { return r.c.Open() }, r.id, file, to, func(string) {})
	}()
	return ch
}

func (r *remote) download(from, to string) chan error {
	ch := make(chan error, 1)
	go func() {
		ch <- transfer.Download(func() (net.Conn, error) { return r.c.Open() }, r.id, from, to, 1<<30, func(string) {})
	}()
	return ch
}

func (r *remote) pending() *wire.State {
	r.t.Helper()
	return until(r.t, r.b, phase(wire.Pending))
}

func (r *remote) vote(p *wire.State, ok bool) {
	say(r.b, wire.Request{Type: wire.Vote, ID: p.ID, Approve: ok, Text: "no"})
}

func wait(t *testing.T, ch chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(120 * time.Second):
		t.Fatal("no result")
	}
	return nil
}

func want(t *testing.T, ch chan error, text string) {
	t.Helper()
	err := wait(t, ch)
	if text == "" && err != nil || text != "" && (err == nil || !strings.Contains(err.Error(), text)) {
		t.Errorf("got %v, want %q", err, text)
	}
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func transferSetup(t *testing.T, config string) {
	t.Helper()
	harden(t)
	fixtures(t)
	sshKey(t)
	sh(t, "cd /home/alice && chmod 755 . && rm -rf up up2 old sub link private big && mkdir sub && printf 'one\\ntwo\\nthree\\n' >old && printf secret >private && chmod 600 private && ln -s /etc/passwd link && chown -h alice: old sub link private; rm -rf /root/down*")
	startDaemon(t, config)
}

func TestUpload(t *testing.T) {
	transferSetup(t, "")
	r := remoteSession(t)
	script := "#!/bin/sh\ntouch /home/alice/MARK\n"
	f := local(t, script)

	// Approved: exactly that, alice's, and not executable.
	ch := r.upload(f, "up")
	p := r.pending()
	for _, w := range []string{`to "/home/alice/up"`, fmt.Sprintf("%d bytes, sha256 %s", len(script), sum(script)), "NEW file"} {
		if !strings.Contains(strings.Join(p.Details, "\n"), w) {
			t.Errorf("details lack %q: %v", w, p.Details)
		}
	}
	if !p.Transfer || exists(home+"/up") {
		t.Error("written before approval")
	}
	if out, _ := exec.Command("sh", "-c", "ls -A /var/lib/witnesshell/staging").Output(); len(out) != 0 {
		t.Errorf("staged file has a name: %s", out)
	}
	// The witness can read what is staged.
	say(r.b, wire.Request{Type: wire.Staged})
	if d := hear(t, r.b, wire.Doc); d.Doc == nil || d.Doc.SHA256 != sum(script) || d.Doc.Lines[1] != "touch /home/alice/MARK" {
		t.Errorf("%+v", d)
	}
	say(r.b, wire.Request{Type: wire.Changes})
	if d := hear(t, r.b, wire.Error); !strings.Contains(d.Text, "replaces no file") {
		t.Errorf("%+v", d)
	}
	r.vote(p, true)
	want(t, ch, "")
	if got := sh(t, "stat -c '%U %a' /home/alice/up; cat /home/alice/up"); got != "alice 644\n"+script {
		t.Errorf("%q", got)
	}
	// It cannot run, not even made executable.
	for _, argv := range [][]string{{"./up"}, {"sh", "up"}} {
		sh(t, "chmod 755 /home/alice/up")
		if x := try(t, "", argv...); x.planErr == nil || x.ran {
			t.Errorf("%v: uploaded file ran", argv)
		}
	}

	// Rejected, cancelled: nothing is written.
	ch = r.upload(f, "up2")
	r.vote(r.pending(), false)
	want(t, ch, "rejected by bob: no")
	ch = r.upload(f, "up2")
	r.pending()
	say(r.a, wire.Request{Type: wire.Key, Data: []byte("\x03")})
	want(t, ch, "cancelled")
	if exists(home + "/up2") {
		t.Error("written although refused")
	}

	// Replacing: the hash of the old file, and a diff.
	ch = r.upload(local(t, "one\nTWO\nthree\n"), "/home/alice/old")
	p = r.pending()
	if !strings.Contains(strings.Join(p.Details, "\n"), "REPLACES a file of 14 bytes, sha256 "+sum("one\ntwo\nthree\n")) {
		t.Errorf("%v", p.Details)
	}
	say(r.b, wire.Request{Type: wire.Changes})
	if d := hear(t, r.b, wire.Doc); d.Doc == nil || strings.Join(d.Doc.Lines, "|") != "@@ -1,3 +1,3 @@| one|-two|+TWO| three" || d.Doc.SHA256 != "" {
		t.Errorf("%+v", d.Doc)
	}
	// Changed after it was shown: not written.
	must(os.WriteFile(home+"/old", []byte("something else\n"), 0o644))
	r.vote(p, true)
	want(t, ch, "changed after it was approved")
	if got := sh(t, "cat /home/alice/old"); got != "something else\n" {
		t.Errorf("%q", got)
	}

	// A private file keeps its mode, and the witness does not see the old one.
	ch = r.upload(local(t, "new secret"), "private")
	p = r.pending()
	say(r.b, wire.Request{Type: wire.Changes})
	if d := hear(t, r.b, wire.Error); d.Type != wire.Error || !strings.Contains(d.Text, "permission denied") {
		t.Errorf("a witness saw the actor's private file: %+v", d)
	}
	r.vote(p, true)
	want(t, ch, "")
	if got := sh(t, "stat -c %a /home/alice/private; cat /home/alice/private"); got != "600\nnew secret" {
		t.Errorf("%q", got)
	}

	// While a program runs, it waits; the draft is left alone.
	say(r.a, wire.Request{Type: wire.Key, Data: []byte("sleep 3\r")})
	r.vote(r.pending(), true)
	until(t, r.b, phase(wire.Running))
	ch = r.upload(f, "up2")
	until(t, r.b, phase(wire.Prompt))
	r.vote(r.pending(), true)
	want(t, ch, "")
	say(r.a, wire.Request{Type: wire.Key, Data: []byte("half")})
	until(t, r.b, func(s *wire.State) bool { return s.Draft == "half" })
	ch = r.upload(f, "up3")
	r.vote(r.pending(), false)
	want(t, ch, "rejected")
	if s := until(t, r.b, phase(wire.Prompt)); s.Draft != "half" {
		t.Errorf("draft %q", s.Draft)
	}

	// The client goes away: withdrawn.
	c2, err := r.c.Open()
	must(err)
	say(c2, wire.Request{Type: wire.Upload, Session: r.id, Text: "up4", Size: 1, Hash: sum("x")})
	hear(t, c2, wire.OK)
	_, _ = c2.Write([]byte("x"))
	r.pending()
	_ = c2.Close()
	until(t, r.b, phase(wire.Prompt))
	if exists(home + "/up4") {
		t.Error("written although withdrawn")
	}
	// Logout deletes what waits.
	ch = r.upload(f, "up5")
	r.pending()
	r.c.Close()
	_ = wait(t, ch)
	sh(t, "rm -f /home/alice/up*")
}

func TestUploadRefused(t *testing.T) {
	transferSetup(t, "max_transfer = \"1MiB\"\n")
	r := remoteSession(t)
	f := local(t, "x")
	for to, text := range map[string]string{
		"": "no destination", "/root/x": "denied", "/etc/x": "ermission denied", "sub": "not a regular file", "sub/": "not a directory", "link": "not a regular file",
		"/proc/self/mem": "/proc", "/proc/1/x": "", "/dev/null": "not a regular file", "/dev/fd/4": "", "nope/x": "no such file", "a\x1b[2Jb": "control",
		"a‮b": "control", "/etc/passwd": "ermission denied", "/var/lib/witnesshell/staging/x": "denied", "/var/log/witnesshell/x": "denied",
		"/etc/witnesshell/public_keys/x": "ermission denied", strings.Repeat("x/", 3000): "bad request",
	} {
		ch := r.upload(f, to)
		var err error
		select {
		case err = <-ch:
		case <-time.After(700 * time.Millisecond): // some only show when it is written
			r.vote(r.pending(), true)
			err = wait(t, ch)
		}
		if err == nil || !strings.Contains(err.Error(), text) {
			t.Errorf("%.30q: %v", to, err)
		}
	}
	want(t, r.upload(local(t, strings.Repeat("x", 1<<20+1)), "big"), "larger than")
	want(t, r.upload("/dev/zero", "x"), "only regular")
	want(t, r.upload("/nope", "x"), "no such file")

	raw := func(q wire.Request, body string) string {
		t.Helper()
		c, err := r.c.Open()
		must(err)
		defer c.Close()
		q.Session = r.id
		say(c, q)
		_, _ = io.WriteString(c, body)
		for range 3 {
			if x := hear(t, c, wire.OK); x.Type != wire.OK {
				return x.Text
			}
		}
		return "accepted"
	}
	for _, q := range []wire.Request{{Type: wire.Upload, Text: "x", Size: -1, Hash: sum("")}, {Type: wire.Upload, Text: "x", Size: 1, Hash: "zz"},
		{Type: wire.Upload, Text: "x", Size: 1 << 60, Hash: sum("")}, {Type: wire.Upload, Text: "x", Size: 1}} {
		if s := raw(q, ""); s == "accepted" {
			t.Errorf("%+v accepted", q)
		}
	}
	if s := raw(wire.Request{Type: wire.Upload, Text: "x", Size: 3, Hash: sum("abc")}, "abX"); !strings.Contains(s, "damaged") {
		t.Error(s)
	}
	// Others, and other ways.
	for what, c := range map[string]func() net.Conn{
		"witness": func() net.Conn {
			k, err := dialQUIC(t, ticketFor(t, "bob"))
			must(err)
			t.Cleanup(k.Close)
			s, err := k.Open()
			must(err)
			return s
		},
		"local": func() net.Conn { return dialAs(alice) },
	} {
		for _, typ := range []string{wire.Upload, wire.Download} {
			s := c()
			say(s, wire.Request{Type: typ, Session: r.id, Text: "x", Size: 1, Hash: sum("x")})
			if x := hear(t, s, wire.OK); x.Type != wire.Error {
				t.Errorf("%s %s: %+v", what, typ, x)
			}
			_ = s.Close()
		}
	}
	say(r.b, wire.Request{Type: wire.Upload, Session: r.id, Text: "x", Size: 1, Hash: sum("x")})
	if x := hear(t, r.b, wire.Error); !strings.Contains(x.Text, "not allowed") {
		t.Errorf("%+v", x)
	}
	// Two at once.
	ch := r.upload(f, "up")
	p := r.pending()
	want(t, r.upload(f, "up2"), "another file")
	r.vote(p, false)
	want(t, ch, "rejected")
	sh(t, "cd /home/alice; [ -z \"$(ls -A sub)\" ] && [ ! -e up ] && [ ! -e x ] && [ -h link ]; ! ls -A | grep -q '^\\.witsh-'")
	// Refusals are in the log.
	if out := sh(t, "cat /var/log/witnesshell/*"+r.id+"-actor-alice.log"); strings.Count(out, `"transfer":"upload"`) < 10 || !strings.Contains(out, "damaged on the way") {
		t.Errorf("%s", out)
	}
}

func TestUploadOff(t *testing.T) {
	transferSetup(t, "allow_upload = false\n")
	r := remoteSession(t)
	want(t, r.upload(local(t, "x"), "up"), "not permitted")
}

func TestDownloadOffByDefault(t *testing.T) {
	transferSetup(t, "")
	r := remoteSession(t)
	want(t, r.download("old", "/root/down"), "not permitted")
	if exists("/root/down") {
		t.Error("something was saved")
	}
	if s := until2(t, r); s.Download {
		t.Error("shown as allowed")
	}
	if out := sh(t, "cat /var/log/witnesshell/*"+r.id+"-actor-alice.log"); !strings.Contains(out, `"transfer":"download"`) {
		t.Error("attempt not logged")
	}
}

func until2(t *testing.T, r *remote) *wire.State {
	t.Helper()
	c := dialAs(carolUser())
	defer c.Close()
	say(c, wire.Request{Type: wire.Witness, Session: r.id})
	return until(t, c, func(*wire.State) bool { return true })
}

func TestDownload(t *testing.T) {
	transferSetup(t, "allow_download = true\n")
	r := remoteSession(t)
	ch := r.download("old", "/root/down")
	p := r.pending()
	if d := strings.Join(p.Details, "\n"); !p.Download || !strings.Contains(d, "FROM THE HOST") || !strings.Contains(d, `"/home/alice/old"`) || !strings.Contains(d, sum("one\ntwo\nthree\n")) {
		t.Errorf("%+v", p)
	}
	// What was asked for is what is sent.
	must(os.WriteFile(home+"/old", []byte("changed"), 0o644))
	if exists("/root/down") {
		t.Error("sent before approval")
	}
	r.vote(p, true)
	want(t, ch, "")
	if got := sh(t, "cat /root/down; stat -c %a /root/down; ls -A /root | grep -c part- || true"); got != "one\ntwo\nthree\n600\n0\n" {
		t.Errorf("%q", got)
	}
	want(t, r.download("old", "/root/down"), "not overwritten")
	ch = r.download("old", "/root/down2")
	r.vote(r.pending(), false)
	want(t, ch, "rejected by bob")
	for _, f := range []string{"/etc/shadow", "/root/tk", "/proc/self/environ", "/dev/zero", "sub", "nope", "/dev/fd/3", "a\x1bb", ""} {
		if err := wait(t, r.download(f, "/root/down2")); err == nil {
			t.Errorf("%q sent", f)
		}
	}
	// A link does not hide what it is.
	ch = r.download("link", "/root/down3")
	p = r.pending()
	if !strings.Contains(strings.Join(p.Details, "\n"), `"/etc/passwd"`) {
		t.Errorf("%v", p.Details)
	}
	r.vote(p, true)
	want(t, ch, "")
	if exists("/root/down2") {
		t.Error("saved although refused")
	}
	// Something larger, with an approval for each.
	sh(t, "head -c 20M /dev/urandom >/home/alice/big; chmod 644 /home/alice/big")
	ch = r.download("big", "/root/down4")
	r.vote(r.pending(), true)
	want(t, ch, "")
	sh(t, "cmp /home/alice/big /root/down4")
	ch = r.upload("/root/down4", "big2")
	r.vote(r.pending(), true)
	want(t, ch, "")
	sh(t, "cmp /home/alice/big2 /root/down4; rm -f /root/down* /home/alice/big*")
}

func TestTransferScreens(t *testing.T) {
	transferSetup(t, "allow_download = true\n")
	must(os.WriteFile("/root/up", []byte("from the client\n"), 0o644))
	a := connectWith(t, alice)
	a.wait("ACTOR alice  PROMPT")
	a.wait("DOWNLOAD ALLOWED")
	b := connectWith(t, bob)
	b.wait("[1]")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.typ("\x1d")
	a.wait("LOCAL MENU")
	a.typ("u")
	a.wait("LOCAL file to send:")
	a.typ("/root/up\r")
	a.wait("on the HOST:")
	if b.has("/root/up") {
		t.Error("the local path reached others")
	}
	a.typ("up\r")
	b.wait("upload to /home/alice/up")
	b.typ("o")
	b.wait("from the client")
	b.typ("q")
	b.approve("NEW file")
	a.wait("uploaded")
	sh(t, "grep -q 'from the client' /home/alice/up")
	a.typ("\x1d")
	a.wait("LOCAL MENU")
	a.typ("g")
	a.wait("on the HOST to get:")
	a.typ("up\r")
	a.wait("save as LOCAL file:")
	a.typ("/root/down\r")
	b.approve("FROM THE HOST")
	a.wait("saved as /root/down")
	sh(t, "cmp /root/up /root/down; rm -f /root/down /root/up /home/alice/up")
	// Over plain ssh there is no menu.
	a.typ("\x1d")
	a.wait("LOCAL MENU")
	a.typ("d")
	a.wait("detached")
}

func TestSha256(t *testing.T) {
	transferSetup(t, "")
	sh(t, "cd /home/alice && truncate -s 300M big && echo x >small && chown alice: big small")
	s := shell(t)
	s.expect("sha256 big small", strings.Fields(sh(t, "sha256sum /home/alice/big"))[0]+"  big", 0)
	must(os.WriteFile("/tmp/sums", []byte(strings.ReplaceAll(s.text(), "\r", "\n")), 0o644))
	sh(t, "cd /home/alice && grep -a -e '^#' -e '^[0-9a-f]*  ' /tmp/sums >/tmp/sums2 && sha256sum -c /tmp/sums2")
	s.expect("sha256 /etc/shadow small", "denied", 1)
	s.expect("sha256 /dev/zero", "not a regular", 1)
	s.refused("sha256 small | sh")
	s.refused("sha256 small >x")
	sh(t, "truncate -s 20G /home/alice/big")
	s.begin("sha256 big")
	s.busy()
	s.key("\x03")
	if r := s.end(); r.Status != 130 {
		t.Errorf("%+v", r)
	}
	s.expect("echo alive", "alive", 0)
	// A witness's takes long and holds up nothing.
	startRemote := remoteSession(t)
	b := startRemote.b
	say(b, wire.Request{Type: wire.Sha256, Text: "big"})
	say(b, wire.Request{Type: wire.Sha256, Text: "big"})
	if x := hear(t, b, wire.Error); !strings.Contains(x.Text, "still busy") {
		t.Errorf("%+v", x)
	}
	say(startRemote.a, wire.Request{Type: wire.Key, Data: []byte("touch MARK\r")})
	startRemote.vote(startRemote.pending(), true)
	until(t, b, phase(wire.Prompt))
	time.Sleep(500 * time.Millisecond)
	if !exists(marker) {
		t.Error("held up")
	}
	c := join2(t, carolUser(), startRemote.id)
	say(c, wire.Request{Type: wire.Sha256, Text: "small"})
	if x := hear(t, c, wire.Report); !strings.Contains(x.Text, sum("x\n")) || !strings.Contains(x.Text, "2 bytes") {
		t.Errorf("%+v", x)
	}
	say(c, wire.Request{Type: wire.Sha256, Text: "private"})
	if x := hear(t, c, wire.Report); x.Type != wire.Error || !strings.Contains(x.Text, "denied") {
		t.Errorf("%+v", x)
	}
	sh(t, "rm -f /home/alice/big /home/alice/small")
}
