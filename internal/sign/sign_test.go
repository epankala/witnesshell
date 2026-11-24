package sign

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const alice, bob = 1001, 1002

func lookup(u string) (uint32, error) {
	switch u {
	case "alice":
		return alice, nil
	case "bob":
		return bob, nil
	}
	return 0, errors.New("no such user")
}

// key makes an SSH key with the real ssh-keygen and returns its public line.
func key(t *testing.T, typ string) (path, pub string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen")
	}
	path = filepath.Join(t.TempDir(), "k")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", typ, "-N", "", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	b, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(b))
	return path, f[0] + " " + f[1]
}

func sig(t *testing.T, key, ns, content string, opts ...string) []byte {
	t.Helper()
	c := exec.Command("ssh-keygen", append([]string{"-q", "-Y", "sign", "-f", key, "-n", ns}, opts...)...)
	c.Stdin = strings.NewReader(content)
	out, err := c.Output()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func store(t *testing.T, signers string) *Store {
	t.Helper()
	s, err := ParseSigners(strings.NewReader(signers))
	if err != nil {
		t.Fatal(err)
	}
	st := &Store{Dir: filepath.Join(t.TempDir(), "s"), Signers: s, LookupUID: lookup}
	if err := st.Init(); err != nil {
		t.Fatal(err)
	}
	return st
}

const script = "#!/bin/sh\necho hi\n"

func TestSSHSignatures(t *testing.T) {
	for _, typ := range []string{"ed25519", "ecdsa", "rsa"} {
		k, pub := key(t, typ)
		s := store(t, "# c\n\nbob "+pub+" comment\n")
		for _, h := range []string{"sha256", "sha512"} {
			got, err := s.Install(strings.NewReader(script), sig(t, k, Namespace, script, "-O", "hashalg="+h), alice)
			if err != nil {
				t.Fatal(typ, h, err)
			}
			b, _ := os.ReadFile(got.Path)
			st, _ := os.Stat(got.Path)
			if string(b) != script || st.Mode() != 0o555 || len(got.By) != 1 || got.By[0] != "bob" {
				t.Fatalf("%+v %q %v", got, b, st.Mode())
			}
		}
	}
}

func TestRefused(t *testing.T) {
	k, pub := key(t, "ed25519")
	other, _ := key(t, "ed25519")
	good := sig(t, k, Namespace, script)
	corrupt := bytes.Replace(good, []byte("A"), []byte("B"), 1)
	for name, c := range map[string]struct {
		signers, content string
		sig              []byte
	}{
		"no signature":      {"bob " + pub, script, nil},
		"changed content":   {"bob " + pub, script + "x", good},
		"other namespace":   {"bob " + pub, script, sig(t, k, "file", script)},
		"unknown key":       {"bob " + pub, script, sig(t, other, Namespace, script)},
		"actor's key":       {"alice " + pub, script, good},
		"shared with actor": {"bob,alice " + pub, script, good},
		"shared, two lines": {"bob " + pub + "\nalice " + pub, script, good},
		"unknown user":      {"mallory " + pub, script, good},
		"corrupt":           {"bob " + pub, script, corrupt},
		"garbage":           {"bob " + pub, script, []byte("garbage")},
		"empty":             {"bob " + pub, script, []byte{}},
		"truncated":         {"bob " + pub, script, good[:len(good)/2]},
	} {
		s := store(t, c.signers)
		if _, err := s.Install(strings.NewReader(c.content), c.sig, alice); !errors.Is(err, ErrNotSigned) {
			t.Errorf("%s: err = %v", name, err)
		}
		for _, d := range []string{s.signedDir(), s.recordDir()} {
			if e, _ := os.ReadDir(d); len(e) != 0 {
				t.Errorf("%s: left files in %s", name, d)
			}
		}
	}
}

func TestOnHostRecords(t *testing.T) {
	s := store(t, "")
	d, _ := Hash(strings.NewReader(script))
	if err := s.Record(alice, d); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Install(strings.NewReader(script), nil, alice); !errors.Is(err, ErrNotSigned) {
		t.Fatal("actor's own record accepted")
	}
	if err := s.Record(bob, d); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Install(strings.NewReader(script), nil, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Install(strings.NewReader(script+" "), nil, alice); err == nil {
		t.Fatal("record accepted for other content")
	}
	if _, err := s.Install(strings.NewReader(script), nil, bob); err != nil {
		t.Fatal("alice signed this for bob:", err)
	}
}

func TestParseSignersStrict(t *testing.T) {
	_, pub := key(t, "ed25519")
	for _, l := range []string{
		"bob", "bob ssh-ed25519", "bob ssh-ed25519 AAAA", `bob namespaces="file" ` + pub,
		"bob cert-authority " + pub, "* " + pub, "bob,, " + pub, "!bob " + pub,
	} {
		if _, err := ParseSigners(strings.NewReader(l)); err == nil {
			t.Errorf("accepted %q", l)
		}
	}
}

func FuzzVerify(f *testing.F) {
	f.Add([]byte("-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ==\n-----END SSH SIGNATURE-----\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := (Signers{}).Verify(b, Digest{}); err == nil {
			t.Fatal("verified with no signers")
		}
	})
}
