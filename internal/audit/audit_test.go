package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const id = "20261124T101500.123Z"

func name(role, user, ext string) string { return "witnesshell-" + id + "-" + role + "-" + user + ext }

// session writes a complete session and returns its directory and seal.
func session(t *testing.T) (string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "a", "b")
	s, err := Open(dir, id, "alice", 1001, Data{"actor": "alice"}, 24, 80, time.Now())
	must(t, err)
	h, err := s.Actor(Request, Data{"id": 1, "text": "ls <x> & \"y\""}, true)
	must(t, err)
	must(t, s.Witness(1002, "bob", Join, nil, false))
	must(t, s.Witness(1003, "carol", Join, nil, false))
	must(t, s.Witness(1002, "bob", Vote, Data{"request_hash": h, "approve": true}, true))
	_, err = s.Actor(Vote, Data{"request_hash": h, "by": "bob"}, true)
	must(t, err)
	must(t, s.Output([]byte("hi \xe6\x97")))
	must(t, s.Output([]byte("\xa5\xff\x1b[1m\r\n")))
	must(t, s.Resize(30, 100))
	must(t, s.Marker("✔ bob"))
	final, err := s.Close("done")
	must(t, err)
	if _, err := s.Actor(Join, nil, false); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := s.Close("again"); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	return dir, final
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestComplete(t *testing.T) {
	dir, final := session(t)
	r, err := Verify(dir, id)
	must(t, err)
	if len(r.Problems) != 0 || r.Final != final || len(r.Files) != 4 || r.Entries != 4+4+3 {
		t.Fatalf("%+v", r)
	}
	for _, f := range r.Files {
		st, err := os.Stat(filepath.Join(dir, f))
		must(t, err)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v", f, st.Mode())
		}
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("%v", st.Mode())
	}
}

func TestCast(t *testing.T) {
	dir, _ := session(t)
	b, err := os.ReadFile(filepath.Join(dir, name("actor", "alice", ".cast")))
	must(t, err)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var h map[string]any
	must(t, json.Unmarshal([]byte(lines[0]), &h))
	if h["version"] != 2.0 || h["width"] != 80.0 || h["height"] != 24.0 {
		t.Fatal(h)
	}
	got, last := "", -1.0
	for _, l := range lines[1:] {
		var e []any
		must(t, json.Unmarshal([]byte(l), &e))
		if len(e) != 3 || e[0].(float64) < last {
			t.Fatal(l)
		}
		last = e[0].(float64)
		got += e[1].(string) + ":" + e[2].(string) + "|"
	}
	if want := "o:hi |o:日�\x1b[1m\r\n|r:100x30|m:✔ bob|"; got != want {
		t.Fatalf("%q", got)
	}
}

func TestTampering(t *testing.T) {
	actor, bob, carol, cast := name("actor", "alice", ".log"), name("witness", "bob", ".log"), name("witness", "carol", ".log"), name("actor", "alice", ".cast")
	edit := func(f func([]byte) []byte) func(*testing.T, string) {
		return func(t *testing.T, p string) {
			b, err := os.ReadFile(p)
			must(t, err)
			n := f(bytes.Clone(b))
			if bytes.Equal(n, b) {
				t.Fatal("nothing changed")
			}
			must(t, os.WriteFile(p, n, 0o600))
		}
	}
	lines := func(f func([][]byte) [][]byte) func(*testing.T, string) {
		return edit(func(b []byte) []byte {
			return bytes.Join(f(bytes.SplitAfter(b, []byte("\n"))), nil)
		})
	}
	swap := edit(func(b []byte) []byte { return bytes.Replace(b, []byte("approve\":true"), []byte("approve\":false"), 1) })
	dropLast := lines(func(l [][]byte) [][]byte { return l[:len(l)-2] })
	dropSecond := lines(func(l [][]byte) [][]byte { return append(l[:1:1], l[2:]...) })
	dup := lines(func(l [][]byte) [][]byte { return append(l[:2:2], l[1:]...) })
	cut := edit(func(b []byte) []byte { return b[:len(b)-1] })
	more := edit(func(b []byte) []byte { return append(b, b...) })
	junk := edit(func(b []byte) []byte { return append(b, "x\n"...) })
	field := edit(func(b []byte) []byte { return bytes.Replace(b, []byte(`{"seq":1,`), []byte(`{"seq":1,"x":1,`), 1) })
	text := edit(func(b []byte) []byte { return bytes.Replace(b, []byte("hi "), []byte("ho "), 1) })
	reason := edit(func(b []byte) []byte { return bytes.Replace(b, []byte("done"), []byte("dnoe"), 1) })
	empty := func(t *testing.T, p string) { must(t, os.Truncate(p, 0)) }
	remove := func(t *testing.T, p string) { must(t, os.Remove(p)) }
	link := func(t *testing.T, p string) {
		must(t, os.Rename(p, p+"x"))
		must(t, os.Symlink(p+"x", p))
	}
	extra := func(t *testing.T, p string) { must(t, os.WriteFile(p, nil, 0o600)) }
	for _, c := range []struct {
		what, file string
		f          func(*testing.T, string)
	}{
		{"vote", bob, swap}, {"last", bob, dropLast}, {"last", actor, dropLast}, {"middle", actor, dropSecond}, {"middle", carol, dropSecond},
		{"dup", actor, dup}, {"cut", actor, cut}, {"cut", bob, cut}, {"more", bob, more}, {"junk", actor, junk}, {"field", bob, field},
		{"end", bob, reason}, {"empty", bob, empty}, {"empty", actor, empty}, {"empty", cast, empty}, {"removed", bob, remove},
		{"removed", carol, remove}, {"removed", actor, remove}, {"removed", cast, remove}, {"output", cast, text}, {"more", cast, more},
		{"link", bob, link}, {"extra witness", name("witness", "eve", ".log"), extra}, {"extra actor", name("actor", "eve", ".log"), extra},
		{"extra cast", name("actor", "eve", ".cast"), extra}, {"stray", name("other", "eve", ".log"), extra},
	} {
		dir, _ := session(t)
		c.f(t, filepath.Join(dir, c.file))
		r, err := Verify(dir, id)
		if err != nil || len(r.Problems) == 0 {
			t.Errorf("%s of %s not noticed: %+v %v", c.what, c.file, r, err)
		}
	}
	// A change to the last entry of the actor log shows in the seal only.
	dir, final := session(t)
	reason(t, filepath.Join(dir, actor))
	if r, err := Verify(dir, id); err != nil || r.Final == final {
		t.Errorf("seal unchanged: %+v %v", r, err)
	}
}

func TestUnfinished(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, id, "alice", 1, nil, 24, 80, time.Now())
	must(t, err)
	must(t, s.Witness(2, "bob", Join, nil, false))
	r, err := Verify(dir, id)
	if err != nil || len(r.Problems) != 2 || r.Final != "" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := Open(dir, id, "alice", 1, nil, 24, 80, time.Now()); err == nil {
		t.Fatal("existing logs overwritten")
	}
}

func TestFailureSticks(t *testing.T) {
	s, err := Open(t.TempDir(), id, "alice", 1, nil, 24, 80, time.Now())
	must(t, err)
	_ = s.cast.f.Close()
	if s.Output([]byte("x")) == nil {
		t.Fatal("no error")
	}
	if _, err := s.Actor(Vote, nil, true); err == nil {
		t.Fatal("logging went on")
	}
	if s.Witness(2, "bob", Join, nil, false) == nil || s.Marker("x") == nil {
		t.Fatal("logging went on")
	}
	if _, err := s.Close("x"); err == nil || errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestOpenRefuses(t *testing.T) {
	d := t.TempDir()
	must(t, os.Chmod(d, 0o777))
	if _, err := Open(d, id, "alice", 1, nil, 24, 80, time.Now()); err == nil {
		t.Fatal("unsafe directory accepted")
	}
	if st, _ := os.Stat(d); st.Mode().Perm() != 0o777 {
		t.Fatal("permissions of an existing directory changed")
	}
}

func TestNames(t *testing.T) {
	for in, want := range map[string]string{"bob": "bob", "a.b-c_d": "a.b-c_d", "../x": "uid7", "": "uid7", "a/b": "uid7", "-x": "uid7", "a b": "uid7",
		strings.Repeat("x", 65): "uid7"} {
		if got := fileName(id, "witness", in, 7, ".log"); got != name("witness", want, ".log") {
			t.Errorf("%q: %s", in, got)
		}
	}
	for _, bad := range []string{"", "*", "../x", id + "/", "2026"} {
		if _, err := Verify(t.TempDir(), bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := Verify(t.TempDir(), id); err == nil {
		t.Error("nothing to verify, yet no error")
	}
}

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{"seq":1,"time":"2026-11-24T10:15:00Z","event":"session_start","prev":""}` + "\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		d := t.TempDir()
		must(t, os.WriteFile(filepath.Join(d, name("actor", "a", ".log")), b, 0o600))
		r, err := Verify(d, id)
		if err != nil || len(r.Problems) == 0 {
			t.Fatalf("%+v %v", r, err)
		}
	})
}
