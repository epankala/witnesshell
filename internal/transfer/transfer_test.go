package transfer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"witnesshell/internal/launch"
)

func me() launch.User {
	return launch.User{Name: "me", UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func staged(t *testing.T, content string) (*os.File, int64, string) {
	t.Helper()
	f, err := Stage(t.TempDir())
	if err != nil {
		t.Skip(err) // no O_TMPFILE here
	}
	t.Cleanup(func() { f.Close() })
	h, err := Fill(f, strings.NewReader(content), int64(len(content)))
	must(t, err)
	if w := sha256.Sum256([]byte(content)); h != hex.EncodeToString(w[:]) {
		t.Fatal(h)
	}
	return f, int64(len(content)), h
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	must(t, err)
	return string(b)
}

// only checks that a directory holds just these.
func only(t *testing.T, dir string, names ...string) {
	t.Helper()
	es, err := os.ReadDir(dir)
	must(t, err)
	var got []string
	for _, e := range es {
		got = append(got, e.Name())
	}
	if fmt.Sprint(got) != fmt.Sprint(names) {
		t.Errorf("%v, want %v", got, names)
	}
}

func TestPlaceNew(t *testing.T) {
	d := t.TempDir()
	f, n, h := staged(t, "hello")
	x, err := Look(me(), d, "x")
	must(t, err)
	if x.Exists || x.Path() != filepath.Join(d, "x") {
		t.Fatalf("%+v", x)
	}
	must(t, Place(me(), x, f, n, h, 0o027))
	st, _ := os.Stat(filepath.Join(d, "x"))
	if read(t, x.Path()) != "hello" || st.Mode() != 0o640 {
		t.Fatal(st.Mode())
	}
	if err := Place(me(), x, f, n, h, 0); !errors.Is(err, ErrChanged) {
		t.Fatal("overwrote what was approved as new:", err)
	}
	only(t, d, "x")
}

func TestPlaceReplaces(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o777 | os.ModeSetuid} {
		d := t.TempDir()
		p := filepath.Join(d, "x")
		must(t, os.WriteFile(p, []byte("old"), 0o600))
		must(t, os.Chmod(p, mode))
		hard := filepath.Join(d, "y")
		must(t, os.Link(p, hard))
		f, n, h := staged(t, "new content")
		x, err := Look(me(), "/", p)
		must(t, err)
		if !x.Exists || x.Size != 3 || x.SHA256 == "" {
			t.Fatalf("%+v", x)
		}
		must(t, Place(me(), x, f, n, h, 0))
		st, _ := os.Stat(p)
		if read(t, p) != "new content" || st.Mode() != mode&0o666 {
			t.Error(st.Mode())
		}
		if read(t, hard) != "old" {
			t.Error("another link of the old file changed")
		}
		only(t, d, "x", "y")
	}
}

func TestPlaceChanged(t *testing.T) {
	for what, f := range map[string]func(p string) error{
		"content":  func(p string) error { return os.WriteFile(p, []byte("other!"), 0o600) },
		"mode":     func(p string) error { return os.Chmod(p, 0o644) },
		"swapped":  func(p string) error { _ = os.Remove(p); return os.WriteFile(p, []byte("old"), 0o600) },
		"gone":     os.Remove,
		"link":     func(p string) error { _ = os.Remove(p); return os.Symlink("/etc/passwd", p) },
		"fifo dir": func(p string) error { _ = os.Remove(p); return os.Mkdir(p, 0o700) },
	} {
		d := t.TempDir()
		p := filepath.Join(d, "x")
		must(t, os.WriteFile(p, []byte("old"), 0o600))
		s, n, h := staged(t, "new")
		x, err := Look(me(), d, "x")
		must(t, err)
		must(t, f(p))
		before, _ := os.Lstat(p)
		if err := Place(me(), x, s, n, h, 0); !errors.Is(err, ErrChanged) {
			t.Errorf("%s: %v", what, err)
		}
		after, _ := os.Lstat(p)
		if (before == nil) != (after == nil) || before != nil && (!os.SameFile(before, after) || before.Mode() != after.Mode()) {
			t.Errorf("%s: not left as it was", what)
		}
		if before == nil {
			only(t, d)
		} else {
			only(t, d, "x")
		}
	}
	// A directory on the way becomes a link to somewhere else.
	d := t.TempDir()
	must(t, os.Mkdir(filepath.Join(d, "sub"), 0o700))
	must(t, os.Mkdir(filepath.Join(d, "evil"), 0o700))
	s, n, h := staged(t, "new")
	x, err := Look(me(), d, "sub/x")
	must(t, err)
	must(t, os.Remove(filepath.Join(d, "sub")))
	must(t, os.Symlink("evil", filepath.Join(d, "sub")))
	if err := Place(me(), x, s, n, h, 0); !errors.Is(err, ErrChanged) {
		t.Error(err)
	}
	only(t, filepath.Join(d, "evil"))
}

func TestPlaceDamaged(t *testing.T) {
	d := t.TempDir()
	s, n, h := staged(t, "new")
	x, err := Look(me(), d, "x")
	must(t, err)
	_, _ = s.WriteAt([]byte("N"), 0)
	if Place(me(), x, s, n, h, 0) == nil {
		t.Error("placed something else")
	}
	only(t, d)
}

func TestLook(t *testing.T) {
	d := t.TempDir()
	must(t, os.Symlink("/etc/passwd", filepath.Join(d, "link")))
	must(t, os.Mkdir(filepath.Join(d, "dir"), 0o700))
	must(t, os.Symlink("dir", filepath.Join(d, "dl")))
	for _, p := range []string{"", "dir", "dir/", ".", "..", "link", "nope/x", "/proc/self/x", "/proc/sys/kernel/x", "/dev/null", "/dev/fd/3", "a\x00b", "a\x1bb", "a‮b", "x\ny", "/"} {
		if x, err := Look(me(), d, p); err == nil {
			t.Errorf("%q: %+v", p, x)
		}
	}
	for p, want := range map[string]string{"dl/x": "dir/x", "dir/../x": "x", "./x": "x"} {
		x, err := Look(me(), d, p)
		if err != nil || x.Path() != filepath.Join(d, want) {
			t.Errorf("%q: %+v %v", p, x, err)
		}
	}
}

func TestFillShort(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "")
	must(t, err)
	if _, err := Fill(f, strings.NewReader("abc"), 4); err == nil {
		t.Fatal("short file accepted")
	}
}

func TestDiff(t *testing.T) {
	a := strings.Split("1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20", " ")
	b := append(append(append([]string{}, a[:4]...), "NEW"), a[5:]...)
	b = append(b[:18], b[19:]...)
	got, err := Diff(a, b)
	must(t, err)
	want := "@@ -2,7 +2,7 @@| 2| 3| 4|-5|+NEW| 6| 7| 8|@@ -16,5 +16,4 @@| 16| 17| 18|-19| 20"
	if s := strings.Join(got, "|"); s != want {
		t.Errorf("\n%s\n%s", s, want)
	}
	if d, err := Diff(a, a); err != nil || len(d) != 0 {
		t.Error(d, err)
	}
	if _, err := Diff(make([]string, maxDiffLines+1), nil); err == nil {
		t.Error("no limit")
	}
}

// FuzzDiff checks a diff against the texts it compares: applied to the old
// lines it must give the new ones, empty texts included.
func FuzzDiff(f *testing.F) {
	f.Add("a\nb\nc\n", "a\nc\nd\n")
	f.Add("", "x\n")
	f.Add("x", "")
	f.Add("same\n", "same\n")
	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a) > 2048 || len(b) > 2048 {
			return
		}
		old, new := strings.Split(a, "\n"), strings.Split(b, "\n")
		d, err := Diff(old, new)
		if err != nil {
			return
		}
		if got := applyDiff(t, old, d); !slices.Equal(got, new) {
			t.Fatalf("diff of %q and %q:\n%s\ngives %q", a, b, strings.Join(d, "\n"), got)
		}
	})
}

// applyDiff applies what Diff returns, strictly.
func applyDiff(t *testing.T, old, d []string) []string {
	var out []string
	at := 0 // in old
	line := func(l string) string {
		if at >= len(old) || old[at] != l {
			t.Fatalf("%q does not match line %d of %q", l, at, old)
		}
		return old[at]
	}
	for _, l := range d {
		switch {
		case strings.HasPrefix(l, "@@ "):
			var a, na, b, nb int
			if _, err := fmt.Sscanf(l, "@@ -%d,%d +%d,%d @@", &a, &na, &b, &nb); err != nil {
				t.Fatalf("hunk %q: %v", l, err)
			}
			if a-1 < at || a-1 > len(old) {
				t.Fatalf("hunk %q at line %d", l, at)
			}
			out = append(out, old[at:a-1]...)
			at = a - 1
			if len(out) != b-1 {
				t.Fatalf("hunk %q, but %d lines came before", l, len(out))
			}
		case strings.HasPrefix(l, " "):
			out = append(out, line(l[1:]))
			at++
		case strings.HasPrefix(l, "-"):
			line(l[1:])
			at++
		case strings.HasPrefix(l, "+"):
			out = append(out, l[1:])
		default:
			t.Fatalf("line %q", l)
		}
	}
	return append(out, old[at:]...)
}

// TestDiffApplies checks random diffs with the real patch program.
func TestDiffApplies(t *testing.T) {
	if _, err := exec.LookPath("patch"); err != nil {
		t.Skip("no patch")
	}
	rnd := rand.New(rand.NewSource(1))
	text := func() []string {
		var l []string
		for range rnd.Intn(40) {
			l = append(l, string(rune('a'+rnd.Intn(4))))
		}
		return l
	}
	file := func(l []string) []byte {
		var b bytes.Buffer
		for _, s := range l {
			b.WriteString(s + "\n")
		}
		return b.Bytes()
	}
	for range 300 {
		a, b := text(), text()
		d, err := Diff(a, b)
		must(t, err)
		if len(d) == 0 || len(a) == 0 || len(b) == 0 {
			continue
		}
		p := filepath.Join(t.TempDir(), "f")
		must(t, os.WriteFile(p, file(a), 0o600))
		c := exec.Command("patch", "-s", "-F0", p)
		c.Stdin = strings.NewReader("--- f\n+++ f\n" + strings.Join(d, "\n") + "\n")
		if out, err := c.CombinedOutput(); err != nil || read(t, p) != string(file(b)) {
			t.Fatalf("%v %s\n%s\na=%q b=%q", err, out, strings.Join(d, "\n"), a, b)
		}
	}
}
