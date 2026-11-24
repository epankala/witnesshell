package view

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"witnesshell/internal/launch"
)

func me() launch.User {
	return launch.User{Name: "me", UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
}

func TestEscape(t *testing.T) {
	for in, want := range map[string]string{
		"a\tb": "a       b", "\x1b[2J": "^[[2J", "\x00\x7f": "^@^?", "\xff": `\xff`, "‮": `\u{202e}`, "\u009b1m": `\u{9b}1m`,
		"​": `\u{200b}`, "ä日": "ä日", "\r": "^M",
	} {
		if got := Escape(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestLoad(t *testing.T) {
	d := t.TempDir()
	write := func(n, c string) {
		if err := os.WriteFile(filepath.Join(d, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("f", "one\n\x1b]0;x\x07two\n")
	doc, err := Load(me(), d, "f")
	if err != nil || len(doc.Lines) != 2 || strings.ContainsAny(strings.Join(doc.Lines, ""), "\x1b\x07") || doc.Mode != 0o600 {
		t.Fatalf("%+v %v", doc, err)
	}
	write("big", strings.Repeat("x\n", maxShown))
	if doc, err := Load(me(), d, "big"); err != nil || !doc.Truncated || len(doc.Lines) > maxShown {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(d, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"fifo", "", ".", "nope", "/dev/zero", "/dev/stdin", "/proc/self/environ", "/proc/self/fd/0"} {
		if _, err := Load(me(), d, n); err == nil {
			t.Errorf("%q loaded", n)
		}
	}
}

func TestRun(t *testing.T) {
	var out bytes.Buffer
	Run(&Doc{Path: "x", Lines: []string{"a", "b"}}, strings.NewReader(""), &out, 24, 80)
	if !strings.Contains(out.String(), "a\r\nb") {
		t.Fatalf("%q", out.String())
	}
	out.Reset()
	lines := make([]string, 100)
	for i := range lines {
		lines[i] = strings.Repeat("L", i+1)
	}
	Run(&Doc{Path: "x", Lines: lines}, strings.NewReader("G gbkjq"), &out, 10, 200)
	if !strings.Contains(out.String(), lines[99]) || !strings.HasSuffix(out.String(), "\x1b[?1049l") {
		t.Fatalf("%q", out.String())
	}
}
