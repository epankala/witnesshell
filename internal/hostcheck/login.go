package hostcheck

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const sshd = "/usr/sbin/sshd"

// Login returns what would let a user log in around witnesshell. self is the
// path of the witnesshell binary.
func Login(name, self string) ([]string, error) {
	var out []string
	sh, err := loginShell("/etc/passwd", name)
	if err != nil {
		return nil, err
	}
	if !same(sh, self) {
		out = append(out, fmt.Sprintf("the login shell of %s must be %s, not %s", name, self, sh))
	}
	// A shell in this list could be changed by the user with chsh.
	if in, _ := listed("/etc/shells", sh); in {
		out = append(out, fmt.Sprintf("%s must not be in /etc/shells", sh))
	}
	if _, err := os.Stat(sshd); err != nil {
		return out, nil // no ssh, no way around it
	}
	b, err := exec.Command(sshd, "-T", "-C", "user="+name+",host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22").Output()
	if err != nil {
		return append(out, "sshd's configuration cannot be read: "+err.Error()), nil
	}
	return append(out, sshProblems(string(b), name, self)...), nil
}

func same(a, b string) bool {
	x, err1 := filepath.EvalSymlinks(a)
	y, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && x == y
}

// sshProblems checks the effective configuration printed by sshd -T.
func sshProblems(conf, name, self string) (out []string) {
	set := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(conf))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), " ")
		set[strings.ToLower(k)] = strings.TrimSpace(v)
	}
	if f := strings.Fields(set["forcecommand"]); len(f) != 2 || f[1] != "bootstrap" || !same(f[0], self) {
		out = append(out, fmt.Sprintf("sshd must have ForceCommand \"%s bootstrap\" for %s", self, name))
	}
	for _, c := range [][2]string{{"disableforwarding", "yes"}, {"permittunnel", "no"}, {"permituserrc", "no"}, {"permituserenvironment", "no"}} {
		if set[c[0]] != c[1] {
			out = append(out, fmt.Sprintf("sshd must have %s %s for %s", c[0], c[1], name))
		}
	}
	for _, f := range strings.Fields(set["authorizedkeysfile"]) {
		if f != "none" && (!strings.HasPrefix(f, "/") || strings.Contains(f, "%h")) {
			out = append(out, fmt.Sprintf("sshd must not read %s, where %s can add keys", f, name))
		}
	}
	return out
}

func loginShell(passwd, name string) (string, error) {
	b, err := os.ReadFile(passwd)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Split(l, ":"); len(f) == 7 && f[0] == name {
			if f[6] == "" {
				return "/bin/sh", nil
			}
			return f[6], nil
		}
	}
	return "", fmt.Errorf("%s is not in %s", name, passwd)
}
