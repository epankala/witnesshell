//go:build vmtest

// Package vm attacks the launcher on a hardened host. It changes system
// settings, so run it only in the test VM: make vm-test.
package vm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"witnesshell/internal/hostcheck"
	"witnesshell/internal/launch"
	"witnesshell/internal/sign"
	"witnesshell/internal/trust"
)

const (
	home   = "/home/alice"
	evil   = home + "/evil"
	marker = home + "/MARK"
)

var (
	alice, bob launch.User
	policy     *launch.Policy
	execDirs   []string
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == launch.HelperArg {
		fmt.Fprintln(os.Stderr, "launch:", launch.Helper())
		os.Exit(126)
	}
	if h, _ := os.Hostname(); h != "witnesshell-vm" || os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "run as root in the test VM only")
		os.Exit(1)
	}
	alice, bob = mustUser("alice"), mustUser("bob")
	st := &sign.Store{Dir: "/var/lib/witnesshell", LookupUID: func(n string) (uint32, error) {
		u, err := user.Lookup(n)
		if err != nil {
			return 0, err
		}
		id, err := strconv.ParseUint(u.Uid, 10, 32)
		return uint32(id), err
	}}
	st.Keys = sign.KeyDir{Dir: sign.DefaultKeyDir}
	isLeader := len(os.Args) > 1 && os.Args[1] == leaderArg
	if !isLeader {
		must(os.RemoveAll(st.Dir))
		must(os.RemoveAll(st.Keys.Dir))
	}
	must(os.MkdirAll(st.Keys.Dir, 0o711))
	must(st.Init())
	policy = &launch.Policy{Store: st}
	execDirs = []string{"/usr", st.Dir + "/signed"}
	if isLeader {
		leader()
	}
	os.Exit(m.Run())
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func mustUser(n string) launch.User {
	u, err := user.Lookup(n)
	must(err)
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	out := launch.User{Name: n, Home: u.HomeDir, UID: uint32(uid), GID: uint32(gid)}
	gs, err := u.GroupIds()
	must(err)
	for _, g := range gs {
		id, _ := strconv.Atoi(g)
		out.Groups = append(out.Groups, uint32(id))
	}
	return out
}

func sh(t *testing.T, c string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", c).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", c, err, out)
	}
	return string(out)
}

// harden sets up what deploy documentation asks of a host.
func harden(t *testing.T) {
	t.Helper()
	sh(t, `sysctl -qw vm.memfd_noexec=2 kernel.yama.ptrace_scope=1
sysctl -qw kernel.apparmor_restrict_unprivileged_userns=0 2>/dev/null || true # do not rely on Ubuntu
for d in /home /tmp /var/tmp /dev/shm /run/lock /var/crash /dev/mqueue /run/screen /run/cloud-init/tmp; do
  [ -d $d ] || continue
  mountpoint -q $d || mount --bind $d $d
  mount -o remount,bind,noexec,nosuid,nodev $d
done
for t in cron at; do rm -f /etc/$t.allow; grep -qsx alice /etc/$t.deny || echo alice >>/etc/$t.deny; done
ln -sf /dev/null /etc/systemd/system/user@.service
systemctl daemon-reload
systemctl stop user@$(id -u alice).service 2>/dev/null || true
rm -f /var/lib/systemd/linger/alice`)
}

func fixtures(t *testing.T) {
	t.Helper()
	sh(t, "rm -rf /var/lib/witnesshell/records/*")
	sh(t, `cd /home/alice && rm -rf evil *.sh *.py *.sig MARK lib.so
cp "$(readlink -f /bin/bash)" evil
printf '#!/bin/sh\ntouch /home/alice/MARK\n' >s.sh
printf 'open("/home/alice/MARK","w")\n' >s.py
chmod 755 evil s.sh s.py; chown alice: evil s.sh s.py`)
}

type result struct {
	planErr error
	out     string
	ran     bool // the attack left its marker
}

func try(t *testing.T, stdin string, argv ...string) (r result) {
	t.Helper()
	_ = os.Remove(marker)
	pl, err := policy.Plan(launch.Request{Argv: argv, Cwd: home, User: alice, Umask: 0o022})
	if err != nil {
		return result{planErr: err}
	}
	return start(t, pl, stdin)
}

func start(t *testing.T, pl *launch.Plan, stdin string) (r result) {
	t.Helper()
	in, w, err := os.Pipe()
	must(err)
	_, _ = w.WriteString(stdin)
	_ = w.Close()
	outR, outW, err := os.Pipe()
	must(err)
	cmd, err := launch.Start(pl, launch.Options{Stdin: in, Stdout: outW, Stderr: outW, ExecDirs: execDirs})
	_, _ = in.Close(), outW.Close()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = buf.ReadFrom(outR); close(done) }()
	kill := time.AfterFunc(60*time.Second, func() { _ = cmd.Process.Kill() })
	_ = cmd.Wait()
	kill.Stop()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	_ = outR.SetReadDeadline(time.Now())
	<-done
	_ = outR.Close()
	time.Sleep(200 * time.Millisecond)
	_, err = os.Lstat(marker)
	r.ran, r.out = err == nil, buf.String()
	return r
}

func TestHostCheck(t *testing.T) {
	a := trust.Actor{UID: alice.UID, GIDs: alice.Groups}
	before, err := hostcheck.Check("alice", a)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("unhardened: %q", before)
	if len(before) == 0 {
		t.Log("(VM was already hardened)")
	}
	harden(t)
	t0 := time.Now()
	after, err := hostcheck.Check("alice", a)
	t.Logf("took %v", time.Since(t0))
	if err != nil || len(after) != 0 {
		t.Fatalf("hardened host still reported: %q %v", after, err)
	}
	// Each setting must be noticed on its own.
	for name, c := range map[string][2]string{
		"memfd":    {"sysctl -qw vm.memfd_noexec=1", "sysctl -qw vm.memfd_noexec=2"},
		"ptrace":   {"sysctl -qw kernel.yama.ptrace_scope=0", "sysctl -qw kernel.yama.ptrace_scope=1"},
		"noexec":   {"mount -o remount,bind,exec,nosuid,nodev /home", "mount -o remount,bind,noexec,nosuid,nodev /home"},
		"suid":     {"mount -o remount,bind,noexec,suid,nodev /tmp", "mount -o remount,bind,noexec,nosuid,nodev /tmp"},
		"cron":     {"sed -i /alice/d /etc/cron.deny", "echo alice >>/etc/cron.deny"},
		"user svc": {"rm /etc/systemd/system/user@.service", "ln -s /dev/null /etc/systemd/system/user@.service"},
		"dir":      {"mkdir -m 777 /opt/w", "rmdir /opt/w"},
		"file":     {"cp /bin/true /opt/f; chown alice /opt/f", "rm /opt/f"},
		"acl":      {"cp /bin/true /opt/f; python3 -c \"import os,struct;e=lambda t,p,i:struct.pack('<HHI',t,p,i);u=0xffffffff;os.setxattr('/opt/f','system.posix_acl_access',struct.pack('<I',2)+e(1,7,u)+e(2,7," + strconv.Itoa(int(alice.UID)) + ")+e(4,5,u)+e(16,7,u)+e(32,5,u))\"", "rm /opt/f"},
	} {
		sh(t, c[0])
		got, err := hostcheck.Check("alice", a)
		sh(t, c[1])
		if err != nil || len(got) == 0 {
			t.Errorf("%s: not noticed (%v)", name, err)
		}
	}
}

func TestIdentity(t *testing.T) {
	harden(t)
	fixtures(t)
	r := try(t, "", "python3", "-c", `
import os,resource
print(os.getresuid(), os.getresgid(), sorted(os.getgroups()))
s = open('/proc/self/status').read()
print([l for l in s.splitlines() if l.startswith(('CapInh','CapPrm','CapEff','CapAmb','NoNewPrivs'))])
print(sorted(os.listdir('/proc/self/fd'))[:3], len(os.listdir('/proc/self/fd')))
print(os.getcwd(), sorted(os.environ))
try: os.setuid(0); print('REGAINED')
except PermissionError: print('stuck')
`)
	t.Logf("%s%v", r.out, r.planErr)
	u, g := alice.UID, alice.GID
	for _, w := range []string{fmt.Sprintf("(%d, %d, %d) (%d, %d, %d)", u, u, u, g, g, g), "CapPrm:\\t0000000000000000",
		"CapEff:\\t0000000000000000", "CapInh:\\t0000000000000000", "CapAmb:\\t0000000000000000", "NoNewPrivs:\\t0", "'2'] 4", home, "stuck"} {
		if !strings.Contains(r.out, w) {
			t.Errorf("output lacks %q", w)
		}
	}
	if strings.Contains(r.out, "LD_") || strings.Contains(r.out, "SUDO_") {
		t.Error("environment leaked")
	}
}

const py = "import os,sys\n"

func TestAttacks(t *testing.T) {
	harden(t)
	fixtures(t)
	ld := "/lib64/ld-linux-x86-64.so.2"
	touch := "touch " + marker
	sudo := func(a ...string) []string { return append([]string{"sudo", "-S"}, a...) }
	for _, c := range []struct {
		name string
		want string // refused: by policy; blocked: by the kernel; RAN: known limit, or legitimate
		in   string
		argv []string
	}{
		{"control", "RAN", "", []string{"touch", marker}},
		{"./evil", "refused", "", []string{evil, "-c", touch}},
		{"./s.sh", "refused", "", []string{"./s.sh"}},
		{"sh s.sh", "refused", "", []string{"sh", "s.sh"}},
		{"python3 s.py", "refused", "", []string{"python3", "s.py"}},
		{"ld.so evil", "refused", "", []string{ld, evil, "-c", touch}},
		{"env evil", "refused", "", []string{"env", evil, "-c", touch}},
		{"sudo evil", "refused", "test\n", sudo(evil, "-c", touch)},
		{"sudo sh s.sh", "refused", "test\n", sudo("sh", "s.sh")},
		{"/proc/self/exe", "refused", "", []string{"/proc/self/exe"}},
		{"bash -c evil", "blocked", "", []string{"bash", "-c", evil + " -c '" + touch + "'"}},
		{"bash -c s.sh", "blocked", "", []string{"bash", "-c", "true; ./s.sh"}},
		{"bash -c ld.so evil", "blocked", "", []string{"bash", "-c", ld + " " + evil + " -c '" + touch + "'"}},
		{"bash exec after copy to /tmp", "blocked", "", []string{"bash", "-c", "cp evil /tmp/e$$ && /tmp/e$$ -c '" + touch + "'"}},
		{"bash exec after copy to /dev/shm", "blocked", "", []string{"bash", "-c", "cp evil /dev/shm/e$$ && /dev/shm/e$$ -c '" + touch + "'"}},
		{"vim :!evil", "blocked", "", []string{"vim", "-u", "NONE", "-es", "-c", "!" + evil + " -c '" + touch + "'", "-c", "qa!"}},
		{"memfd exec", "blocked", "", []string{"python3", "-c", py + "f=os.memfd_create('x',0);os.write(f,open('" + evil + "','rb').read());os.execve(f,['x','-c','" + touch + "'],dict(os.environ))"}},
		{"memfd MFD_EXEC", "blocked", "", []string{"python3", "-c", py + "f=os.memfd_create('x',0x10);os.write(f,open('" + evil + "','rb').read());os.execve(f,['x','-c','" + touch + "'],dict(os.environ))"}},
		{"mmap evil executable", "blocked", "", []string{"python3", "-c", py + "import mmap;f=os.open('" + evil + "',0);mmap.mmap(f,4096,flags=2,prot=5);open('" + marker + "','w')"}},
		{"LD_PRELOAD inside bash", "blocked", "", []string{"bash", "-c", "LD_PRELOAD=" + evil + " /usr/bin/true 2>&1 | grep -q 'cannot be preloaded' || " + touch}},
		{"user namespace remount exec", "blocked", "", []string{"unshare", "-Urm", "bash", "-c", "mount -t tmpfs none /mnt && cp " + evil + " /mnt/e && /mnt/e -c '" + touch + "'"}},
		{"crontab", "blocked", "", []string{"bash", "-c", "echo '0 0 1 1 * true' | crontab - && " + touch}},
		{"systemd-run --user", "blocked", "", []string{"bash", "-c", "XDG_RUNTIME_DIR=/run/user/$(id -u) systemd-run --user --wait -q " + touch}},
		{"ptrace launcher's session", "blocked", "", []string{"bash", "-c", "cat /proc/$PPID/environ >/dev/null && " + touch}},
		{"sudo bash -c evil", "blocked", "test\n", sudo("bash", "-c", evil+" -c '"+touch+"'")},
		{"sudo works", "RAN", "test\n", sudo("touch", marker)},
		{"sudo mount works", "RAN", "test\n", sudo("bash", "-c", "mount -t tmpfs none /mnt && umount /mnt && "+touch)},
		// Known limits (PLAN.md 4.5). A change here must be a conscious one.
		{"LIMIT bash reads unsigned script", "RAN", "", []string{"bash", "-c", ". ./s.sh"}},
		{"LIMIT script on interpreter's stdin", "RAN", touch + "\n", []string{"sh"}},
		{"LIMIT python reads unsigned script", "RAN", "", []string{"python3", "-c", "exec(open('s.py').read())"}},
		{"LIMIT machine code in memory", "RAN", "", []string{"python3", "-c", "import mmap;mmap.mmap(-1,4096,prot=7);open('" + marker + "','w')"}},
		{"LIMIT sudo launders a program", "RAN", "test\n", sudo("bash", "-c", "cp "+evil+" /usr/local/bin/e && /usr/local/bin/e -c '"+touch+"'; rm /usr/local/bin/e")},
		{"LIMIT sudo systemd-run", "RAN", "test\n", sudo("systemd-run", "--wait", "-q", "touch", marker)},
	} {
		r := try(t, c.in, c.argv...)
		got := "blocked"
		switch {
		case r.planErr != nil:
			got = "refused"
		case r.ran:
			got = "RAN"
		}
		why := strings.TrimSpace(r.out)
		if r.planErr != nil {
			why = r.planErr.Error()
		}
		if len(why) > 140 {
			why = "…" + why[len(why)-140:]
		}
		t.Logf("%-38s %-8s %q", c.name, got, why)
		if got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestLandlockAlone(t *testing.T) {
	// With /home executable again, Landlock must still hold by itself.
	harden(t)
	fixtures(t)
	sh(t, "mount -o remount,bind,exec,nosuid,nodev /home")
	defer harden(t)
	c := []string{"bash", "-c", evil + " -c 'touch " + marker + "'"}
	pl, err := policy.Plan(launch.Request{Argv: c, Cwd: home, User: alice, Umask: 0o022})
	if err != nil {
		t.Fatal(err)
	}
	if r := start(t, pl, ""); r.ran {
		t.Error("Landlock did not block")
	}
	pl.Landlock = false
	if r := start(t, pl, ""); !r.ran {
		t.Errorf("control without Landlock did not run: %s", r.out)
	}
}

func TestSigned(t *testing.T) {
	harden(t)
	fixtures(t)
	sh(t, `cd /root && rm -f k k.pub && ssh-keygen -q -t ed25519 -N '' -f k
for f in s.sh s.py evil; do ssh-keygen -q -Y sign -f k -n witnesshell /home/alice/$f 2>/dev/null; done; chown alice: /home/alice/*.sig`)
	pub, err := os.ReadFile("/root/k.pub")
	must(err)
	keyName, err := sign.PublicKeyName(pub)
	must(err)
	keyFile := filepath.Join(sign.DefaultKeyDir, keyName)
	set := func(who string) { must(os.WriteFile(keyFile, []byte(who+" "+string(pub)), 0o644)) }
	defer os.Remove(keyFile)
	run := func(want bool, argv ...string) {
		t.Helper()
		if r := try(t, "", argv...); r.ran != want {
			t.Errorf("%v: ran=%v err=%v out=%s", argv, r.ran, r.planErr, r.out)
		}
	}
	cases := [][]string{{"./s.sh"}, {"sh", "s.sh"}, {"python3", "s.py"}, {evil, "-c", "touch " + marker}}
	set("alice")
	for _, c := range cases {
		run(false, c...)
	}
	set("bob")
	for _, c := range cases {
		run(true, c...)
	}
	// A witness signing on the host needs no key.
	must(os.Remove(keyFile))
	run(false, "./s.sh")
	signHere(t, home+"/s.sh", bob.UID)
	run(true, "./s.sh")
	// Changing the file between approval and start has no effect.
	pl, err := policy.Plan(launch.Request{Argv: []string{"./s.sh"}, Cwd: home, User: alice, Umask: 0o022})
	must(err)
	must(os.WriteFile(home+"/s.sh", []byte("#!/bin/sh\ntouch /home/alice/SWAPPED\n"), 0o755))
	_ = os.Remove(marker)
	if r := start(t, pl, ""); !r.ran {
		t.Errorf("signed copy did not run: %s", r.out)
	}
	if _, err := os.Stat(home + "/SWAPPED"); err == nil {
		t.Error("SWAPPED SCRIPT RAN")
	}
	run(false, "./s.sh")
}

// signHere records an on-host signature.
func signHere(t *testing.T, file string, uid uint32) {
	t.Helper()
	f, err := os.Open(file)
	must(err)
	defer f.Close()
	d, err := sign.Hash(f)
	must(err)
	must(policy.Store.Record(uid, d))
}

func TestStoreProtected(t *testing.T) {
	var st unix.Stat_t
	for _, p := range []string{"/var/lib/witnesshell", "/var/lib/witnesshell/signed", "/var/lib/witnesshell/records", "/var/lib/witnesshell/tmp"} {
		must(unix.Stat(p, &st))
		if st.Uid != 0 || st.Mode&0o022 != 0 {
			t.Errorf("%s: uid %d mode %o", p, st.Uid, st.Mode)
		}
	}
	if m, _ := filepath.Glob("/var/lib/witnesshell/tmp/*"); len(m) != 0 {
		t.Errorf("temporary files left: %v", m)
	}
}

func TestKeyDirNotListable(t *testing.T) {
	harden(t)
	k := sign.DefaultKeyDir
	must(os.WriteFile(k+"/known", []byte("x"), 0o644))
	defer os.Remove(k + "/known")
	if r := try(t, "", "bash", "-c", "cat "+k+"/known && touch "+marker); !r.ran {
		t.Errorf("known key not readable: %s", r.out)
	}
	for _, c := range []string{"ls " + k, "touch " + k + "/new", "echo x >" + k + "/known", "rm -f " + k + "/known", "mv " + k + " /tmp/k"} {
		if r := try(t, "", "bash", "-c", c+" && touch "+marker); r.ran {
			t.Errorf("%q succeeded", c)
		}
	}
}
