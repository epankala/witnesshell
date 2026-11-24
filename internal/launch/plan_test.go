package launch

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"witnesshell/internal/sign"
)

// me is the actor; files made by the test are the actor's own.
func setup(t *testing.T) (*Policy, User, string) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("the actor must not be root")
	}
	st := &sign.Store{Dir: filepath.Join(t.TempDir(), "store"), LookupUID: func(string) (uint32, error) { return 0, errors.New("none") }}
	if err := st.Init(); err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	for n, c := range map[string]string{"x.sh": "#!/bin/sh\necho\n", "x.py": "print()\n", "data": "d\n", "noexec.sh": "#!/bin/sh\n"} {
		m := os.FileMode(0o755)
		if n == "data" || n == "noexec.sh" {
			m = 0o644
		}
		if err := os.WriteFile(filepath.Join(d, n), []byte(c), m); err != nil {
			t.Fatal(err)
		}
	}
	u := User{Name: "me", Home: d, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	return &Policy{Store: st}, u, d
}

func need(t *testing.T, names ...string) bool {
	for _, n := range names {
		if _, err := exec.LookPath(n); err != nil {
			return false
		}
	}
	return true
}

func TestRefusals(t *testing.T) {
	p, u, d := setup(t)
	ld, _ := filepath.Glob("/lib64/ld-linux*")
	cases := []string{
		"./x.sh", d + "/x.sh", "sh x.sh", "sh ./x.sh", "sh -e x.sh", "bash -eu x.sh", "bash --rcfile=x.sh -i",
		"bash --rcfile x.sh", "bash --init-file x.sh", "sh -o errexit x.sh", "sh -c true x.sh", "sh later.sh", "sh -- x.sh",
		"python3 x.py", "python3 -u x.py", "python3 -W ignore x.py", "python3 -W /usr/bin/env x.py", "python3 /dev/stdin",
		"python3 /proc/self/fd/0", "perl x.sh", "awk -f x.sh", "sed -f x.sh", "make -f x.sh",
		"env ./x.sh", "env A=b sh x.sh", "nice -n 5 ./x.sh", "timeout 5 sh x.sh", "sudo ./x.sh", "sudo sh x.sh",
		"sudo -u root python3 -u x.py", "xargs ./x.sh", "find . -exec ./x.sh ;", "nohup env nice sh x.sh",
		"/proc/self/exe", "data", "./data", "nosuchcommand", "", "/usr", "../../../../../../../../proc/self/exe",
	}
	if len(ld) > 0 {
		cases = append(cases, ld[0]+" ./x.sh", ld[0]+" --preload ./x.sh /usr/bin/env")
	}
	for _, c := range cases {
		argv := strings.Split(c, " ")
		if !strings.Contains(argv[0], "/") && argv[0] != "" && argv[0] != "nosuchcommand" && argv[0] != "data" && !need(t, argv[0]) {
			t.Logf("skip %q: not installed", c)
			continue
		}
		pl, err := p.Plan(Request{Argv: argv, Cwd: d, User: u})
		if !errors.Is(err, ErrRefused) {
			t.Errorf("%q: plan %+v, err %v", c, pl, err)
		}
	}
}

func TestAllowed(t *testing.T) {
	p, u, d := setup(t)
	for c, landlock := range map[string]bool{
		"ls -l": true, "cat data": true, "cat x.sh": true, "cp x.py y": true, "vi x.py": true, "grep x x.sh": true,
		"python3": true, "sh -c true": true, "awk {print} data2": true, "env A=b ls": true, "/usr/bin/env": true,
		"sudo ls": false, "sudo -u root cat data": false, "sudo mount -t tmpfs none /mnt": false,
	} {
		argv := strings.Split(c, " ")
		if !strings.Contains(argv[0], "/") && !need(t, argv[0]) {
			continue
		}
		pl, err := p.Plan(Request{Argv: argv, Cwd: d, User: u})
		if err != nil {
			t.Errorf("%q: %v", c, err)
			continue
		}
		if pl.Landlock != landlock || !filepath.IsAbs(pl.Path) || strings.Join(pl.Argv, " ") != c || len(pl.Files) == 0 || !pl.Files[0].Trusted {
			t.Errorf("%q: %+v", c, pl)
		}
	}
}

func TestSignedUsesStoredCopy(t *testing.T) {
	p, u, d := setup(t)
	for _, n := range []string{"x.sh", "x.py"} {
		f, _ := os.Open(filepath.Join(d, n))
		dg, err := sign.Hash(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Store.Record(u.UID+1, dg); err != nil {
			t.Fatal(err)
		}
	}
	pl, err := p.Plan(Request{Argv: []string{"./x.sh", "arg"}, Cwd: d, User: u})
	// In this unprivileged test the store belongs to the actor too.
	if err != nil || !strings.HasPrefix(pl.Path, p.Store.Dir) || pl.Argv[0] != "./x.sh" || pl.Argv[1] != "arg" ||
		pl.Files[0].Trusted || len(pl.Files[0].SignedBy) != 1 || len(pl.Files) < 2 || !pl.Files[1].Trusted {
		t.Fatalf("%+v %v", pl, err)
	}
	for _, c := range []string{"sh x.sh", "sudo sh x.sh", "python3 -u x.py", "env ./x.sh"} {
		argv := strings.Split(c, " ")
		if !need(t, argv[0]) {
			continue
		}
		pl, err := p.Plan(Request{Argv: argv, Cwd: d, User: u})
		if err != nil || !strings.HasPrefix(pl.Argv[len(pl.Argv)-1], p.Store.Dir) {
			t.Errorf("%q: %+v %v", c, pl, err)
		}
	}
	if err := os.WriteFile(filepath.Join(d, "x.sh"), []byte("#!/bin/sh\nevil\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Plan(Request{Argv: []string{"./x.sh"}, Cwd: d, User: u}); !errors.Is(err, ErrRefused) {
		t.Fatal("changed file still accepted")
	}
	if b, _ := os.ReadFile(pl.Path); strings.Contains(string(b), "evil") {
		t.Fatal("stored copy changed")
	}
}

func TestSignedScriptNeedsTrustedInterpreter(t *testing.T) {
	p, u, d := setup(t)
	for i, c := range []string{"#!" + d + "/x.sh\n", "#!x\n", "#!/usr/bin/env nosuchcommand\n", "no shebang\n"} {
		n := filepath.Join(d, "s"+string(rune('0'+i)))
		if err := os.WriteFile(n, []byte(c), 0o755); err != nil {
			t.Fatal(err)
		}
		dg, _ := sign.Hash(strings.NewReader(c))
		if err := p.Store.Record(u.UID+1, dg); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Plan(Request{Argv: []string{n}, Cwd: d, User: u}); !errors.Is(err, ErrRefused) {
			t.Errorf("%q: %v", c, err)
		}
	}
}

func TestEnvironment(t *testing.T) {
	p, u, d := setup(t)
	for _, n := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "PYTHONPATH", "PYTHONSTARTUP", "PERL5OPT", "BASH_ENV",
		"ENV", "PAGER", "EDITOR", "GIT_SSH_COMMAND", "LESSOPEN", "IFS", "a b", "", "BASH_FUNC_ls%%"} {
		if _, err := p.Plan(Request{Argv: []string{"ls"}, Cwd: d, User: u, Env: map[string]string{n: "x"}}); !errors.Is(err, ErrRefused) {
			t.Errorf("%s accepted", n)
		}
	}
	pl, err := p.Plan(Request{Argv: []string{"ls"}, Cwd: d, User: u, Env: map[string]string{"LANG": "C", "FOO": "1"}})
	if err != nil || !strings.Contains(strings.Join(pl.Env, " "), "FOO=1 LANG=C") {
		t.Fatal(pl, err)
	}
}

func TestRootRefused(t *testing.T) {
	p, u, d := setup(t)
	u.UID = 0
	if _, err := p.Plan(Request{Argv: []string{"ls"}, Cwd: d, User: u}); !errors.Is(err, ErrRefused) {
		t.Fatal(err)
	}
}
