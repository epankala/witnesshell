package hostcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHProblems(t *testing.T) {
	self := filepath.Join(t.TempDir(), "witsh")
	if err := os.WriteFile(self, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	good := "forcecommand " + self + " bootstrap\ndisableforwarding yes\npermittunnel no\npermituserrc no\npermituserenvironment no\nauthorizedkeysfile /etc/ssh/authorized_keys/%u\n"
	if p := sshProblems(good, "alice", self); len(p) != 0 {
		t.Fatal(p)
	}
	for _, c := range [][2]string{
		{self + " bootstrap", "none"}, {self + " bootstrap", self + " bootstrap; sh"}, {self + " bootstrap", "/bin/sh bootstrap"},
		{"disableforwarding yes", "disableforwarding no"}, {"permittunnel no", "permittunnel yes"}, {"permituserrc no", "permituserrc yes"},
		{"permituserenvironment no", "permituserenvironment LANG"}, {"/etc/ssh/authorized_keys/%u", ".ssh/authorized_keys"},
		{"/etc/ssh/authorized_keys/%u", "%h/keys"}, {"/etc/ssh/authorized_keys/%u", "/etc/k /%h/keys"}, {"permituserrc no\n", ""},
	} {
		if p := sshProblems(strings.Replace(good, c[0], c[1], 1), "alice", self); len(p) != 1 {
			t.Errorf("%q: %v", c, p)
		}
	}
	if p := sshProblems("", "alice", self); len(p) != 5 {
		t.Errorf("%v", p)
	}
}

func TestLoginShell(t *testing.T) {
	f := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(f, []byte("a:x:1:1::/:/bin/x\nab:x:2:2::/:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]string{"a": "/bin/x", "ab": "/bin/sh", "b": ""} {
		if got, err := loginShell(f, n); got != want || (err == nil) != (want != "") {
			t.Errorf("%s: %q %v", n, got, err)
		}
	}
}
