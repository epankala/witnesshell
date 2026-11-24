package trust

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

var nobody = Actor{UID: 54321, GIDs: []uint32{54321}}

func resolve(t *testing.T, p string, a Actor) *File {
	t.Helper()
	f, err := Resolve(p, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	return f
}

func TestSystemFileTrusted(t *testing.T) {
	for _, p := range []string{"/usr/bin/env", "/bin/sh", "/usr/../usr/bin/./env"} {
		if f := resolve(t, p, nobody); !f.Trusted || !f.Regular() {
			t.Errorf("%s: %+v", p, f)
		}
	}
}

func TestRootActorTrustsNothing(t *testing.T) {
	if resolve(t, "/usr/bin/env", Actor{}).Trusted {
		t.Fatal("trusted")
	}
}

func TestProcNotTrusted(t *testing.T) {
	for _, p := range []string{"/proc/self/exe", "/proc/version", "/dev/stdin"} {
		f, err := Resolve(p, nobody)
		if err != nil {
			continue // unresolvable is refused too
		}
		if f.Trusted {
			t.Errorf("%s trusted", p)
		}
		f.Close()
	}
}

func TestOwnFileAndLinks(t *testing.T) {
	me := Actor{UID: uint32(os.Getuid()), GIDs: []uint32{uint32(os.Getgid())}}
	d := t.TempDir()
	own := filepath.Join(d, "own")
	if err := os.WriteFile(own, nil, 0o400); err != nil {
		t.Fatal(err)
	}
	if resolve(t, own, me).Trusted {
		t.Fatal("own read-only file trusted")
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink("/usr/bin/env", link); err != nil {
		t.Fatal(err)
	}
	f := resolve(t, link, me)
	if f.Trusted || f.Path != resolve(t, "/usr/bin/env", me).Path {
		t.Fatalf("link in the actor's directory: %+v", f)
	}
	loop := filepath.Join(d, "loop")
	if err := os.Symlink("loop", loop); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(loop, me); err == nil {
		t.Fatal("loop resolved")
	}
	if _, err := Resolve("relative", me); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestModeBits(t *testing.T) {
	p := "/usr/bin/env" // no ACL
	for _, c := range []struct {
		uid, gid, mode uint32
		want           bool
	}{
		{0, 0, 0o755, false}, {0, 0, 0o757, true}, {0, 54321, 0o775, true}, {0, 54321, 0o755, false},
		{0, 1, 0o775, false}, {54321, 0, 0o555, true}, {0, 0, 0o1777, true},
	} {
		w, err := Writable(p, &unix.Stat_t{Uid: c.uid, Gid: c.gid, Mode: c.mode}, nobody)
		if err != nil || w != c.want {
			t.Errorf("%+v: %v %v", c, w, err)
		}
	}
}

func TestACL(t *testing.T) {
	acl := func(e ...uint32) []byte {
		b := binary.LittleEndian.AppendUint32(nil, 2)
		for i := 0; i < len(e); i += 3 {
			b = binary.LittleEndian.AppendUint16(b, uint16(e[i]))
			b = binary.LittleEndian.AppendUint16(b, uint16(e[i+1]))
			b = binary.LittleEndian.AppendUint32(b, e[i+2])
		}
		return b
	}
	for i, c := range []struct {
		b    []byte
		want bool
	}{
		{acl(), false}, {acl(2, 7, 54321), true}, {acl(2, 5, 54321), false}, {acl(2, 7, 1), false},
		{acl(8, 6, 54321), true}, {acl(8, 6, 1), false}, {nil, true}, {[]byte{2, 0, 0, 0, 1}, true},
	} {
		if aclWritable(c.b, nobody) != c.want {
			t.Errorf("case %d", i)
		}
	}
}

func TestOpenRefusesNonRegular(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve(t, p, nobody).Open(); err == nil {
		t.Fatal("opened a FIFO")
	}
}
