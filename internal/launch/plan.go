// Package launch decides what exactly will run and starts it as the actor.
package launch

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"witnesshell/internal/sign"
	"witnesshell/internal/trust"
)

// SearchPath is where bare command names are looked up. It is fixed, so the
// actor cannot redirect a name to a file of their own.
const SearchPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// User is the account a command runs as.
type User struct {
	Name, Home string
	UID, GID   uint32
	Groups     []uint32
}

func (u User) actor() trust.Actor {
	return trust.Actor{UID: u.UID, GIDs: append(slices.Clone(u.Groups), u.GID)}
}

// Request is one simple command, fully expanded.
type Request struct {
	Argv []string
	Cwd  string
	Env  map[string]string // exported by the actor
	User User
}

// FileInfo describes a checked file, for witnesses.
type FileInfo struct {
	Arg      string // as written
	Path     string // resolved
	OwnerUID uint32
	Trusted  bool
	SignedBy []string
	SHA256   string // signed files only
}

// Plan is exactly what will be executed.
type Plan struct {
	Path     string
	Argv     []string
	Env      []string
	Cwd      string
	User     User
	Landlock bool
	Files    []FileInfo
}

// Policy turns requests into plans. It must run as root in production, to
// read files on the actor's behalf and write the signed store.
type Policy struct {
	Store *sign.Store
}

// ErrRefused marks a command the policy does not allow.
var ErrRefused = errors.New("refused")

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrRefused}, args...)...)
}

// Interpreters run the files they are given. Names may carry a version.
var interpreters = regexp.MustCompile(`^(sh|bash|rbash|dash|ash|ksh|mksh|zsh|fish|csh|tcsh|busybox|` +
	`python|pypy|perl|ruby|node|nodejs|php|lua|luajit|tclsh|wish|expect|guile|Rscript|java|gdb|` +
	`awk|gawk|mawk|nawk|sed|make|gmake|m4|bc|dc|ed|ex|osascript|deno|bun|ld|ld-linux.*)([-.]?[0-9][0-9.]*)?(\.so(\.[0-9]+)*)?$`)

// Wrappers run the command given in their arguments.
var wrappers = regexp.MustCompile(`^(sudo|su|runuser|doas|pkexec|env|nice|ionice|nohup|timeout|setsid|stdbuf|` +
	`time|xargs|parallel|chroot|unshare|nsenter|flock|watch|script|strace|ltrace|setpriv|capsh|chrt|taskset|` +
	`systemd-run|systemd-inhibit|find|busybox|run-parts|start-stop-daemon|logger|ssh-agent|dbus-run-session|prlimit|numactl|cgexec)$`)

// Elevators switch to another user; Landlock would break what they run.
var elevators = regexp.MustCompile(`^(sudo|su|doas|pkexec|runuser)$`)

// flagsOnly lists options that take no value, so the next non-option is the
// script. After any other option every argument is checked.
var flagsOnly = map[string]string{
	"sh": "euxvnilfam", "bash": "euxvnilfam", "dash": "euxvnilfam", "ksh": "euxvnilfam", "zsh": "euxvnilfam",
	"python": "uBEsSIOvqbdi", "perl": "wWTtX", "ruby": "wv",
}

var version = regexp.MustCompile(`[-.]?[0-9][0-9.]*$`)

// Plan checks a request. Any error means nothing may run.
func (p *Policy) Plan(r Request) (*Plan, error) {
	if len(r.Argv) == 0 || r.Argv[0] == "" {
		return nil, refuse("empty command")
	}
	if !path.IsAbs(r.Cwd) {
		return nil, refuse("no current directory")
	}
	if r.User.UID == 0 {
		return nil, refuse("the actor must not be root")
	}
	for _, a := range r.Argv {
		if strings.ContainsRune(a, 0) {
			return nil, refuse("argument contains NUL")
		}
	}
	env, err := environment(r.User, r.Cwd, r.Env)
	if err != nil {
		return nil, err
	}
	pl := &Plan{Argv: slices.Clone(r.Argv), Env: env, Cwd: r.Cwd, User: r.User}
	c := &checker{p: p, r: r, pl: pl}

	prog, err := lookup(r.Argv[0], r.Cwd)
	if err != nil {
		return nil, err
	}
	pl.Path, err = c.program(r.Argv[0], prog, 0)
	if err != nil {
		return nil, err
	}
	names := []string{path.Base(r.Argv[0]), path.Base(pl.Path)}
	if len(pl.Files) > 0 {
		names = append(names, path.Base(pl.Files[0].Path))
	}
	switch {
	case matchAny(interpreters, names):
		err = c.scriptArgs(names, 1)
	case matchAny(wrappers, names):
		err = c.wrapped()
	}
	if err != nil {
		return nil, err
	}
	pl.Landlock = !matchAny(elevators, names)
	return pl, nil
}

func matchAny(re *regexp.Regexp, names []string) bool {
	return slices.ContainsFunc(names, re.MatchString)
}

func abs(name, cwd string) string {
	if path.IsAbs(name) {
		return name
	}
	return cwd + "/" + name // not cleaned: ".." must be resolved physically
}

func lookup(name, cwd string) (string, error) {
	if strings.Contains(name, "/") {
		return abs(name, cwd), nil
	}
	for _, d := range strings.Split(SearchPath, ":") {
		var st unix.Stat_t
		if unix.Stat(d+"/"+name, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0o111 != 0 {
			return d + "/" + name, nil
		}
	}
	return "", refuse("%s: command not found", name)
}

type checker struct {
	p  *Policy
	r  Request
	pl *Plan
}

// check returns the path to use for file: itself if trusted, or the stored
// copy if signed.
func (c *checker) check(arg, file string) (string, *trust.File, error) {
	f, err := trust.Resolve(file, c.r.User.actor())
	if err != nil {
		return "", nil, refuse("%v", err)
	}
	info := FileInfo{Arg: arg, Path: f.Path, OwnerUID: f.Stat.Uid, Trusted: f.Trusted}
	use := f.Path
	if !f.Trusted {
		s, err := c.install(f, file)
		if err != nil {
			f.Close()
			return "", nil, refuse("%s: %s, and %v", arg, f.Reason, err)
		}
		info.SignedBy, info.SHA256, use = s.By, s.Digest.Hex(), s.Path
	}
	c.pl.Files = append(c.pl.Files, info)
	return use, f, nil
}

func (c *checker) install(f *trust.File, file string) (*sign.Signed, error) {
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var armored []byte
	if sf, err := trust.Resolve(file+".sig", c.r.User.actor()); err == nil {
		defer sf.Close()
		sr, err := sf.Open()
		if err != nil {
			return nil, err
		}
		defer sr.Close()
		if armored, err = sign.ReadSignature(sr); err != nil {
			return nil, err
		}
	}
	return c.p.Store.Install(r, armored, c.r.User.UID)
}

// program checks an executable and, for scripts, its interpreters.
func (c *checker) program(arg, file string, depth int) (string, error) {
	if depth > 4 {
		return "", refuse("%s: too many nested interpreters", arg)
	}
	use, f, err := c.check(arg, file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if !f.Regular() || f.Stat.Mode&0o111 == 0 {
		return "", refuse("%s: not an executable file", arg)
	}
	interp, opt, err := shebang(use)
	if err != nil {
		return "", refuse("%s: %v", arg, err)
	}
	if interp == "" {
		return use, nil
	}
	if !path.IsAbs(interp) {
		return "", refuse("%s: interpreter %q is not an absolute path", arg, interp)
	}
	if _, err := c.program(interp, interp, depth+1); err != nil {
		return "", err
	}
	if path.Base(interp) == "env" {
		// env finds its argument on SearchPath, which holds trusted names only
		// if the one found first is trusted.
		for _, w := range strings.Fields(opt) {
			if strings.HasPrefix(w, "-") || strings.Contains(w, "=") {
				continue
			}
			t, err := lookup(w, "/")
			if err != nil {
				return "", err
			}
			if _, err := c.program(w, t, depth+1); err != nil {
				return "", err
			}
			break
		}
	}
	return use, nil
}

// shebang reads a script's interpreter line. file must be unmodifiable by the
// actor. Execute-only files yield no interpreter.
func shebang(file string) (interp, opt string, err error) {
	f, err := os.Open(file)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	line, err := bufio.NewReader(io.LimitReader(f, 4096)).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", err
	}
	if !strings.HasPrefix(line, "#!") {
		if !strings.HasPrefix(line, "\x7fELF") {
			return "", "", errors.New("neither a script with #! nor an ELF program")
		}
		return "", "", nil
	}
	interp, opt, _ = strings.Cut(strings.TrimSpace(line[2:]), " ")
	if i := strings.IndexByte(interp, '\t'); i >= 0 {
		interp, opt = interp[:i], interp[i+1:]+" "+opt
	}
	return interp, strings.TrimSpace(opt), nil
}

// fileArg checks an argument if it names an existing regular file.
func (c *checker) fileArg(i int, execOnly bool) (found bool, err error) {
	a := c.pl.Argv[i]
	if a == "" || a == "-" {
		return false, nil
	}
	name := a
	if strings.HasPrefix(a, "-") { // --rcfile=x
		_, v, ok := strings.Cut(a, "=")
		if !ok || v == "" {
			return false, nil
		}
		name = v
	}
	f, err := trust.Resolve(abs(name, c.r.Cwd), c.r.User.actor())
	if err != nil {
		return false, nil
	}
	// Descriptors such as /dev/stdin are not regular, and not trusted either.
	kind, isExec, trusted, reason := f.Stat.Mode&unix.S_IFMT, f.Stat.Mode&0o111 != 0, f.Trusted, f.Reason
	f.Close()
	if kind == unix.S_IFDIR || execOnly && (!isExec || kind != unix.S_IFREG) {
		return false, nil
	}
	if kind != unix.S_IFREG {
		if trusted {
			return false, nil
		}
		return false, refuse("%s: %s, and it is not a regular file", a, reason)
	}
	use, tf, err := c.check(a, abs(name, c.r.Cwd))
	if err != nil {
		return false, err
	}
	tf.Close()
	if !trusted {
		// Run the stored copy. Trusted files keep their name.
		c.pl.Argv[i] = strings.TrimSuffix(a, name) + use
	}
	return true, nil
}

// scriptArgs checks the script an interpreter at argv[from-1] will run.
func (c *checker) scriptArgs(names []string, from int) error {
	flags := ""
	for _, n := range names {
		if f, ok := flagsOnly[version.ReplaceAllString(n, "")]; ok {
			flags = f
		}
	}
	sure := flags != "" // still certain where the script name is
	for i := from; i < len(c.pl.Argv); i++ {
		a := c.pl.Argv[i]
		if sure && len(a) > 1 && a[0] == '-' {
			sure = strings.Trim(a[1:], flags) == ""
			if sure {
				continue
			}
		}
		found, err := c.fileArg(i, false)
		if err != nil {
			return err
		}
		if sure {
			if !found && a != "-" {
				// It could be created between this check and the start.
				return refuse("%s: script not found", a)
			}
			return nil
		}
	}
	return nil
}

// wrapped checks programs and scripts named in a wrapper's arguments.
func (c *checker) wrapped() error {
	for i := 1; i < len(c.pl.Argv); i++ {
		a := c.pl.Argv[i]
		names := []string{path.Base(a)}
		if t, err := lookup(a, c.r.Cwd); err == nil {
			if f, err := trust.Resolve(t, c.r.User.actor()); err == nil {
				names = append(names, path.Base(f.Path))
				f.Close()
			}
		}
		if _, err := c.fileArg(i, true); err != nil {
			return err
		}
		if matchAny(interpreters, names) {
			if err := c.scriptArgs(names, i+1); err != nil {
				return err
			}
		}
	}
	return nil
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// badEnv lists variables that make programs load or run other files.
var badEnv = regexp.MustCompile(`^(LD_.*|GLIBC_.*|MALLOC_.*|GCONV_PATH|LOCPATH|NLSPATH|HOSTALIASES|RESOLV_.*|TMPDIR|` +
	`PATH|HOME|USER|LOGNAME|SHELL|PWD|OLDPWD|BASH_.*|BASHOPTS|SHELLOPTS|ENV|IFS|CDPATH|PS4|PROMPT_COMMAND|ZDOTDIR|FPATH|` +
	`PYTHON.*|PERL.*|RUBY.*|GEM_.*|BUNDLE_.*|NODE_.*|NPM_.*|LUA_.*|PHP.*|JAVA_.*|JDK_.*|_JAVA_.*|CLASSPATH|TCL.*|AWK.*|R_.*|` +
	`GIT_.*|SSH_ASKPASS|SUDO_.*|SYSTEMD_.*|PAGER|MANPAGER|LESS.*|MORE|EDITOR|VISUAL|VIM.*|EXINIT|VIMINIT|NVIM.*|BROWSER|XDG_.*|` +
	`TERMINFO.*|TERMCAP|MAKE.*|MFLAGS|CC|CXX|.*_PRELOAD)$`)

func environment(u User, cwd string, extra map[string]string) ([]string, error) {
	env := []string{"HOME=" + u.Home, "USER=" + u.Name, "LOGNAME=" + u.Name, "PATH=" + SearchPath, "PWD=" + cwd,
		"PYTHONSAFEPATH=1"} // do not import modules from the current directory
	names := make([]string, 0, len(extra))
	for n := range extra {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if !envName.MatchString(n) || strings.ContainsRune(extra[n], 0) {
			return nil, refuse("bad variable %q", n)
		}
		if badEnv.MatchString(n) {
			return nil, refuse("variable %s may not be exported", n)
		}
		env = append(env, n+"="+extra[n])
	}
	return env, nil
}
