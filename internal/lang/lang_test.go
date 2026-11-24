package lang

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type env struct {
	dir  string
	vars map[string]string
}

func (e env) Var(n string) (string, bool) { v, ok := e.vars[n]; return v, ok }
func (e env) Home() string                { return "/home/me" }
func (e env) ReadDir(d string) ([]DirEntry, error) {
	if !filepath.IsAbs(d) {
		d = filepath.Join(e.dir, d)
	}
	es, err := os.ReadDir(d)
	var out []DirEntry
	for _, x := range es {
		out = append(out, DirEntry{x.Name(), x.IsDir()})
	}
	return out, err
}

func testEnv(t *testing.T, files ...string) env {
	t.Helper()
	d := t.TempDir()
	for _, f := range append([]string{"a.txt", "b.txt", ".hid", "sub/c.txt", "sub/d.go", "sub2/c.txt"}, files...) {
		p := filepath.Join(d, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return env{d, map[string]string{"A": "va", "S": "two words", "E": "", "G": "*", "B": `x\y`, "?": "7", "HOME": "/home/me"}}
}

// Cases that must give the same arguments as bash.
var same = []string{
	`a b  c`, `a 'b c' "d e"`, `a "x\"y\\z\q\$"`, `a b\ c \* \~ \"`, `a $A ${A}x "$S" "$E" "$G" "$B"`, `a '$A' "a'b" 'a"b'`,
	`a *.txt`, `a sub/*`, `a */c.txt`, `a ./*.txt`, `a ?.txt`, `a s*/*.go`, `a "*".txt '?' \*`, `a .h*`, `a *b*/c.txt`, `a *//c.txt`,
	`a ~ ~/x "~" x~ a~b`, `a {} "{a,b}" '{1..3}'`, `a # comment`, `a a#b`, `a ""  ''`, `a a=b --c=d`, "a \\\n b", "a 'x\ny'", `a !x`, `a [`,
	`a ünïcode 日本`, `a "$A$A" $A$A`, `a "tail\\"`, `a %s^x@y+z`, `a */`, `a -- -x`,
}

func TestMatchesBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	e := testEnv(t)
	for _, c := range same {
		l, err := Parse(c, e)
		if err != nil {
			t.Errorf("%q: %v", c, err)
			continue
		}
		cmd := exec.Command(bash, "--norc", "-c", "a() { printf '<%s>' \"$@\"; }\n"+c)
		cmd.Dir = e.dir
		cmd.Env = []string{"LC_ALL=C.UTF-8"}
		for k, v := range e.vars {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		want, err := cmd.Output()
		if err != nil {
			t.Fatalf("%q: bash: %v", c, err)
		}
		got := ""
		for _, a := range l[0].Cmds[0].Argv[1:] {
			got += "<" + a + ">"
		}
		if got == "" {
			got = "<>"
		}
		if got != string(want) {
			t.Errorf("%q: got %s, bash %s", c, got, want)
		}
	}
}

func TestRefused(t *testing.T) {
	e := testEnv(t)
	for _, c := range []string{
		"a $(b)", "a `b`", `a "$(b)"`, "a \"`b`\"", "a <(b)", "a >(b)", "$(a)", "a $((1+1))", "((1))", "let x=1",
		"(a)", "{ a; }", "if a; then b; fi", "while a; do b; done", "for x in a; do b; done", "case a in b) c;; esac", "f() { a; }",
		"[[ a ]]", "! a", "a |& b", "a & && b", "a && b &", "time a", "coproc a", "declare x=1", "local x", "readonly x=1", "typeset x", "nameref x=y",
		"a <<E\nx\nE", "a <<<x", "a <>x", "a >|x", "a 3>x", "a 9<x", "a >&3", "a >&x", "a <&0", "a {fd}>x", "a >&-", "a > *.txt", "> x", "a 0>x", "a 1<x", `a > ""`,
		"a ${A:-x}", "a; b $?", "a && b \"$?\"", "a || b $?", "a ${#A}", "a ${A%x}", "a ${!A}", "a ${A[0]}", "a ${A/x/y}", "a ${A^^}", "a ${A@Q}", "a $1", "a $@", "a $*", "a $$", "a $!", "a $#", "a $-", "a $0",
		"a $S", "a $E", "a $G", "a $B", "a $NOPE", `a "$NOPE"`, "$E", "*.txt x", "a $'x'", `a $"x"`,
		"a nope*", "a [ab].txt", "a {a,b}", "a {1..3}", "a x{", "a ~root", "a **/x[1]", "a @(x|y)", "a +(x)", "a */../x", "a */.",
		"x+=1", "x=(1 2)", "x[0]=1", "x=~", "x=a:~/b", "export x=(1)", "export -n x", "export x+=1", "a 'unclosed", "a \"x", "a |", "a &&", "| a", "a ;; b", "if", "a \\",
		"a | (b)", "(a) | b", "a | { b; } > x", "eval() { a; }",
	} {
		l, err := Parse(c, e)
		var le *Error
		if !errors.As(err, &le) {
			t.Errorf("%q: %+v %v", c, l, err)
		}
	}
}

func TestGlobTraps(t *testing.T) {
	for _, f := range []string{"-rf.txt", "x\x1b[2J.txt", "x\n.txt", "x\xe2\x80\xae.txt", "bad\xff.txt"} {
		e := testEnv(t, f)
		if l, err := Parse("rm *.txt", e); err == nil {
			t.Errorf("%q accepted: %+v", f, l)
		}
	}
	e := testEnv(t, "-rf.txt")
	l, err := Parse("rm ./*.txt", e)
	if err != nil || l[0].Cmds[0].Argv[1] != "./-rf.txt" {
		t.Fatal(l, err)
	}
}

func TestStructure(t *testing.T) {
	e := testEnv(t)
	for c, want := range map[string]string{
		"":                             "[]",
		"# only a comment":             "[]",
		"a; b":                         "[{0 [{[] [a] []}] false} {0 [{[] [b] []}] false}]",
		"a\nb":                         "[{0 [{[] [a] []}] false} {0 [{[] [b] []}] false}]",
		"a && b || c":                  "[{0 [{[] [a] []}] false} {1 [{[] [b] []}] false} {2 [{[] [c] []}] false}]",
		"a | b | c &":                  "[{0 [{[] [a] []} {[] [b] []} {[] [c] []}] true}]",
		"a & b":                        "[{0 [{[] [a] []}] true} {0 [{[] [b] []}] false}]",
		"X=1 Y=\"$S\" a":               "[{0 [{[{X 1} {Y two words}] [a] []}] false}]",
		"X=*.txt":                      "[{0 [{[{X *.txt}] [] []}] false}]",
		"export X=1 Y":                 "[{0 [{[] [export X=1 Y] []}] false}]",
		"a <i >o 2>&1":                 "[{0 [{[] [a] [{0 0 i 0} {1 1 o 0} {2 3  1}]}] false}]",
		"a &>o":                        "[{0 [{[] [a] [{1 1 o 0} {2 3  1}]}] false}]",
		"a >>o 2>e":                    "[{0 [{[] [a] [{1 2 o 0} {2 1 e 0}]}] false}]",
		"a 2>\"$A\"":                   "[{0 [{[] [a] [{2 1 va 0}]}] false}]",
		"a >&2":                        "[{0 [{[] [a] [{1 3  2}]}] false}]",
		"echo $?":                      "[{0 [{[] [echo 7] []}] false}]",
		"a $A; b \"$A\" | c && d &> x": "[{0 [{[] [a va] []}] false} {0 [{[] [b va] []} {[] [c] []}] false} {1 [{[] [d] [{1 1 x 0} {2 3  1}]}] false}]",
	} {
		l, err := Parse(c, e)
		if got := fmt.Sprint(l); err != nil || got != want {
			t.Errorf("%q:\n got %s %v\nwant %s", c, got, err, want)
		}
	}
}

func TestMatch(t *testing.T) {
	star := strings.Repeat("a*", 30) + "b"
	var p []char
	for _, r := range star {
		p = append(p, char{r, true})
	}
	if match(p, []rune(strings.Repeat("a", 5000))) { // must not blow up
		t.Fatal("matched")
	}
}

func FuzzParse(f *testing.F) {
	for _, c := range same {
		f.Add(c)
	}
	e := env{"/nonexistent", map[string]string{"A": "va"}}
	f.Fuzz(func(t *testing.T, s string) {
		l, err := Parse(s, e)
		if err != nil {
			return
		}
		for _, p := range l {
			if len(p.Cmds) == 0 {
				t.Fatal("empty pipeline")
			}
			for _, c := range p.Cmds {
				if len(c.Argv) == 0 && len(c.Assigns) == 0 {
					t.Fatalf("%q: empty command", s)
				}
			}
		}
	})
}
