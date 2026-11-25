//go:build vmtest

package vm

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"witnesshell/internal/hostcheck"
	"witnesshell/internal/launch"
	"witnesshell/internal/pty"
	"witnesshell/internal/wire"
)

// sshKey gives root a key for the test users.
func sshKey(t *testing.T) {
	t.Helper()
	sh(t, `[ -f /root/tk ] || ssh-keygen -q -t ed25519 -N '' -f /root/tk
for u in alice bob carol; do
  grep -qF "$(cat /root/tk.pub)" /etc/ssh/authorized_keys/$u || cat /root/tk.pub >>/etc/ssh/authorized_keys/$u
done`)
}

var sshOpts = []string{"-q", "-i", "/root/tk", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes"}

func connect(t *testing.T, u launch.User) *window {
	t.Helper()
	return connectWith(t, u, "--ssh")
}

// connectWith runs connect with options of its own.
func connectWith(t *testing.T, u launch.User, own ...string) *window {
	t.Helper()
	args := append(append([]string{"connect"}, own...), sshOpts...)
	return open(t, u, exec.Command(binary, append(args, u.Name+"@127.0.0.1")...))
}

func TestLoginSession(t *testing.T) {
	harden(t)
	fixtures(t)
	sshKey(t)
	startDaemon(t, "")
	a := connect(t, alice)
	a.wait("ACTOR alice  PROMPT")
	b := connect(t, bob)
	b.wait("[1] witness the session of alice")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.typ("touch MARK; id -un\r")
	b.approve("MARK")
	a.wait("PROMPT")
	time.Sleep(500 * time.Millisecond)
	if !exists(marker) {
		t.Error("did not run")
	}
	// The connection drops; a new login returns to the session.
	a.close()
	b.wait("actor is away")
	a = connect(t, alice)
	a.wait("return to your session")
	a.typ("1\r")
	a.wait("ACTOR alice  PROMPT")
	// Nothing in the session can start a login around the gate.
	a.typ("\x04")
	b.wait("there is no session to witness")
	b.typ("q\r")
	if err := b.cmd.Wait(); err != nil {
		t.Error(err)
	}
}

func TestLoginNothingElse(t *testing.T) {
	harden(t)
	fixtures(t)
	sshKey(t)
	startDaemon(t, "")
	must(os.WriteFile("/root/up", []byte("x"), 0o644))
	sh(t, `cd /home/alice; mkdir -p .ssh
for f in .bashrc .profile .bash_profile .bash_login .zshenv .kshrc .ssh/rc; do echo 'touch /home/alice/MARK' >$f; done
echo 'BASH_ENV=/home/alice/.bashrc' >.ssh/environment; echo 'BASH_ENV DEFAULT=/home/alice/.bashrc' >.pam_environment
ssh-keygen -q -t ed25519 -N '' -f /root/own$$ && cp /root/own$$.pub .ssh/authorized_keys && mv /root/own$$ /root/own
chown -R alice: .; chmod 700 .ssh`)
	opts := strings.Join(sshOpts, " ")
	for _, c := range []string{
		"ssh OPTS alice@127.0.0.1 touch MARK", "ssh OPTS alice@127.0.0.1 'bootstrap; touch MARK'", "ssh OPTS alice@127.0.0.1 -s sftp",
		"ssh OPTS -tt alice@127.0.0.1 bash -c 'touch MARK'", "scp OPTS /root/up alice@127.0.0.1:MARK", "scp -O OPTS /root/up alice@127.0.0.1:MARK",
		"echo 'touch MARK' | ssh OPTS alice@127.0.0.1", "echo 'put /root/up MARK' | sftp OPTS -b - alice@127.0.0.1",
		"ssh OPTS -o SetEnv=BASH_ENV=/home/alice/.bashrc alice@127.0.0.1 true", "ssh OPTS -W 127.0.0.1:22 alice@127.0.0.1 </dev/null",
		"ssh OPTS -N -o ExitOnForwardFailure=yes -R 7777:127.0.0.1:22 alice@127.0.0.1",
		strings.ReplaceAll("ssh OPTS alice@127.0.0.1", "/root/tk", "/root/own"),
	} {
		c = strings.ReplaceAll(c, "OPTS", opts)
		if strings.Contains(c, "-W") || strings.Contains(c, "-R") || c == strings.ReplaceAll("ssh OPTS alice@127.0.0.1", "OPTS", strings.ReplaceAll(opts, "/root/tk", "/root/own")) {
			c = strings.ReplaceAll(c, "-q ", "")
		}
		out, err := exec.Command("timeout", "15", "sh", "-c", c).CombinedOutput()
		if err == nil || strings.Contains(string(out), "SSH-2.0") {
			t.Errorf("%q succeeded: %s", c, out)
		}
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 124 {
			t.Errorf("%q stayed connected: %s", c, out)
		}
		clean(t)
	}
	out, _ := exec.Command("timeout", "15", "sh", "-c", "ssh "+strings.ReplaceAll(strings.ReplaceAll(opts, "-q ", ""), "/root/tk", "/root/own")+" alice@127.0.0.1").CombinedOutput()
	if !strings.Contains(string(out), "Permission denied (publickey") {
		t.Errorf("alice's own key file was used: %s", out)
	}
	// Other ways to start a login shell.
	for _, c := range []string{"su - alice -c 'touch MARK'", "su alice -c 'touch /home/alice/MARK'", "sudo -u alice -i touch MARK", "runuser -l alice -c 'touch MARK'"} {
		_ = exec.Command("timeout", "10", "sh", "-c", c).Run()
		clean(t)
	}
	a := connect(t, alice)
	a.wait("ACTOR alice  PROMPT")
	clean(t) // no startup file ran
	b := connect(t, bob)
	b.wait("[1]")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	a.typ("chsh -s /bin/bash\r")
	b.approve("chsh")
	time.Sleep(2 * time.Second)
	a.typ("test\r")
	time.Sleep(2 * time.Second)
	a.typ("\x03")
	if s := sh(t, "getent passwd alice"); !strings.Contains(s, "/usr/local/bin/witsh") {
		t.Errorf("shell changed: %s", s)
	}
}

func TestLoginTerminalsHidden(t *testing.T) {
	// A program in bob's session must not reach bob's witness terminal.
	harden(t)
	fixtures(t)
	startDaemon(t, "allow_weak_host = true\n")
	a := dialAs(alice)
	defer a.Close()
	say(a, wire.Request{Type: wire.Actor, Rows: 24, Cols: 80})
	id := until(t, a, phase(wire.Prompt)).Session
	if n := strings.Count(sh(t, "cat /proc/1/mountinfo"), " /dev/pts "); n != 1 {
		t.Errorf("%d mounts on the host's /dev/pts", n)
	}
	// Opened after the session started, like a later login would be.
	ptm, pts, err := pty.Open(24, 80)
	must(err)
	defer ptm.Close()
	defer pts.Close()
	name := strings.TrimSpace(sh(t, fmt.Sprintf("readlink /proc/%d/fd/%d", os.Getpid(), pts.Fd())))
	must(os.Chown(name, int(alice.UID), -1))
	must(os.Chmod(name, 0o666))
	got := make(chan string, 1)
	go func() {
		b := make([]byte, 100)
		n, _ := ptm.Read(b)
		got <- string(b[:n])
	}()
	b := join2(t, bob, id)
	prog := fmt.Sprintf(`import os,glob
print("tty", os.ttyname(0), sorted(os.listdir("/dev/pts")))
for p in [%q]+glob.glob("/dev/pts/*")+glob.glob("/proc/[0-9]*/fd/*")+glob.glob("/proc/[0-9]*/root%s"):
    try:
        if os.ttyname(0)==p or not (p.startswith("/dev") or "pts" in os.readlink(p) or "root" in p): continue
        if os.path.samefile(p, os.ttyname(0)): continue
        f=os.open(p,os.O_WRONLY|os.O_NOCTTY|os.O_NONBLOCK); os.write(f,b"SPOOF")
    except OSError: pass
import pty; m,s=pty.openpty(); print("new", os.ttyname(s))
`, name, name)
	must(os.WriteFile("/usr/local/lib/spoof.py", []byte(prog), 0o644))
	say(a, wire.Request{Type: wire.Key, Data: []byte("python3 /usr/local/lib/spoof.py\r")})
	p := until(t, b, phase(wire.Pending))
	say(b, wire.Request{Type: wire.Vote, ID: p.ID, Approve: true})
	out, sc := "", scr{}
	_ = a.SetReadDeadline(time.Now().Add(60 * time.Second))
	for !strings.Contains(out, "new /dev/pts/") {
		var r wire.Reply
		if err := wire.Read(a, wire.MaxReply, &r); err != nil {
			t.Fatalf("%v: %q", err, out)
		}
		sc.add(r)
		out = sc.text()
	}
	if !strings.Contains(out, "tty /dev/pts/0 ['0', 'ptmx']") || !strings.Contains(out, "new /dev/pts/") {
		t.Errorf("%q", out)
	}
	select {
	case s := <-got:
		t.Errorf("another terminal was written to: %q", s)
	case <-time.After(time.Second):
	}
}

func TestLoginSudoMountReachesHost(t *testing.T) {
	harden(t)
	fixtures(t)
	startDaemon(t, "")
	a := attach(t, alice)
	a.wait("PROMPT")
	b := attach(t, bob)
	b.wait("[1]")
	b.typ("1\r")
	b.wait("WITNESS of alice")
	sh(t, "mkdir -p /mnt/w")
	a.typ("sudo -k mount -t tmpfs none /mnt/w\r")
	b.approve("mount")
	a.wait("Password")
	a.typ("test\r")
	a.wait("PROMPT")
	time.Sleep(300 * time.Millisecond)
	if exec.Command("mountpoint", "-q", "/mnt/w").Run() != nil {
		t.Errorf("mount is not visible on the host:\n%s", a.screen())
	}
	sh(t, "umount /mnt/w")
}

func TestLoginHostCheck(t *testing.T) {
	harden(t)
	if p, err := hostcheck.Login("alice", binary); err != nil || len(p) != 0 {
		t.Fatal(p, err)
	}
	conf := "/etc/ssh/sshd_config.d/10-witnesshell.conf"
	defer forceLogin(t)
	for _, c := range [][2]string{
		{"usermod -s /bin/bash alice", "usermod -s /usr/local/bin/witsh alice"},
		{"echo /usr/local/bin/witsh >>/etc/shells", "sed -i /witsh/d /etc/shells"},
		{"gpasswd -d alice witnesshell", "gpasswd -a alice witnesshell"},
		{"sed -i s/DisableForwarding/#/ " + conf, "cp /usr/local/lib/deploy/10-witnesshell.conf " + conf},
		{"sed -i s/AuthorizedKeysFile/#/ " + conf, "cp /usr/local/lib/deploy/10-witnesshell.conf " + conf},
		{"mv " + conf + " /root/conf", "mv /root/conf " + conf},
		{"printf 'Match User alice\n ForceCommand /bin/sh\n' >/etc/ssh/sshd_config.d/00-x.conf", "rm /etc/ssh/sshd_config.d/00-x.conf"},
		{"echo nonsense >/etc/ssh/sshd_config.d/00-x.conf", "rm /etc/ssh/sshd_config.d/00-x.conf"},
	} {
		sh(t, c[0])
		p, err := hostcheck.Login("alice", binary)
		sh(t, c[1])
		if err != nil || len(p) == 0 {
			t.Errorf("%q not noticed (%v)", c[0], err)
		}
	}
}

func TestLoginService(t *testing.T) {
	harden(t)
	sh(t, "rm -f /etc/witnesshell/config.toml; cp /usr/local/lib/deploy/witnesshell.service /etc/systemd/system/ && systemctl daemon-reload && systemctl start witnesshell && sleep 2")
	defer sh(t, "systemctl stop witnesshell; rm /etc/systemd/system/witnesshell.service; systemctl daemon-reload")
	a := attach(t, alice)
	a.wait("ACTOR alice  PROMPT")
	sh(t, "systemctl stop witnesshell")
	a.wait("the daemon is stopping")
	if out, _ := exec.Command("pgrep", "-f", "__session").Output(); len(out) != 0 {
		t.Errorf("left: %s", out)
	}
}
