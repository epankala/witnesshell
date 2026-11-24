// Package sign verifies witness signatures on files and keeps root-owned
// copies of signed files, which are what actually runs (D19, D22).
package sign

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Namespace separates our signatures from other uses of the same SSH key.
const Namespace = "witnesshell"

// MaxFile and maxSig bound what is read on the actor's behalf.
const (
	MaxFile = 256 << 20
	maxSig  = 64 << 10
)

var (
	ErrNotSigned = errors.New("not signed by a witness")
	ErrTooLarge  = errors.New("file is too large")
)

// Signers maps public keys (wire format) to the local users they belong to.
type Signers map[string][]string

// ParseSigners reads an allowed_signers file: "user[,user] keytype key". Key
// options are refused rather than ignored, since they restrict a key.
func ParseSigners(r io.Reader) (Signers, error) {
	s := Signers{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			return nil, fmt.Errorf("allowed_signers line %d: want \"user keytype key\"", n)
		}
		key, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(f[1] + " " + f[2]))
		if err != nil || len(opts) > 0 || len(rest) > 0 || key.Type() != f[1] {
			return nil, fmt.Errorf("allowed_signers line %d: bad key or unsupported options", n)
		}
		if strings.HasSuffix(f[1], "-cert-v01@openssh.com") {
			return nil, fmt.Errorf("allowed_signers line %d: certificates are not supported", n)
		}
		for _, u := range strings.Split(f[0], ",") {
			if u == "" || strings.ContainsAny(u, "*?!\"") {
				return nil, fmt.Errorf("allowed_signers line %d: bad user %q", n, u)
			}
			w := string(key.Marshal())
			s[w] = append(s[w], u)
		}
	}
	return s, sc.Err()
}

// Digest holds the hashes of a file's content.
type Digest struct {
	SHA256 [32]byte
	SHA512 [64]byte
}

// Hex returns the SHA-256 in hex.
func (d Digest) Hex() string { return hex.EncodeToString(d.SHA256[:]) }

func copyHash(w io.Writer, r io.Reader) (d Digest, err error) {
	h2, h5 := sha256.New(), sha512.New()
	n, err := io.Copy(io.MultiWriter(w, h2, h5), io.LimitReader(r, MaxFile+1))
	if err != nil {
		return d, err
	}
	if n > MaxFile {
		return d, ErrTooLarge
	}
	h2.Sum(d.SHA256[:0])
	h5.Sum(d.SHA512[:0])
	return d, nil
}

// Verify checks an armored SSH signature (ssh-keygen -Y sign) and returns the
// users the key belongs to.
func (s Signers) Verify(armored []byte, d Digest) ([]string, error) {
	p, _ := pem.Decode(armored)
	if p == nil || p.Type != "SSH SIGNATURE" {
		return nil, errors.New("not an SSH signature")
	}
	const magic = "SSHSIG"
	body, ok := bytes.CutPrefix(p.Bytes, []byte(magic))
	if !ok {
		return nil, errors.New("not an SSH signature")
	}
	var b struct {
		Version   uint32
		Key       []byte
		Namespace string
		Reserved  []byte
		Hash      string
		Sig       []byte
	}
	if err := ssh.Unmarshal(body, &b); err != nil {
		return nil, fmt.Errorf("bad SSH signature: %w", err)
	}
	if b.Version != 1 || b.Namespace != Namespace {
		return nil, fmt.Errorf("signature is for namespace %q, want %q", b.Namespace, Namespace)
	}
	users := s[string(b.Key)]
	if len(users) == 0 {
		return nil, errors.New("signed with an unknown key")
	}
	key, err := ssh.ParsePublicKey(b.Key)
	if err != nil {
		return nil, err
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(b.Sig, &sig); err != nil {
		return nil, fmt.Errorf("bad SSH signature: %w", err)
	}
	if sig.Format == ssh.KeyAlgoRSA {
		return nil, errors.New("SHA-1 signatures are not accepted")
	}
	var hash []byte
	switch b.Hash {
	case "sha256":
		hash = d.SHA256[:]
	case "sha512":
		hash = d.SHA512[:]
	default:
		return nil, fmt.Errorf("unsupported hash %q", b.Hash)
	}
	msg := ssh.Marshal(struct {
		Namespace string
		Reserved  []byte
		Hash      string
		H         []byte
	}{b.Namespace, b.Reserved, b.Hash, hash})
	if err := key.Verify(append([]byte(magic), msg...), &sig); err != nil {
		return nil, errors.New("signature does not match the file")
	}
	return users, nil
}

// Store holds signed copies and on-host signatures under Dir, which must be
// writable by root only.
type Store struct {
	Dir     string
	Signers Signers
	// LookupUID returns the uid of a local user.
	LookupUID func(string) (uint32, error)
}

// Init creates the directories.
func (s *Store) Init() error {
	for d, m := range map[string]os.FileMode{s.Dir: 0o711, s.signedDir(): 0o711, s.recordDir(): 0o700} {
		if err := os.MkdirAll(d, m); err != nil {
			return err
		}
		if err := os.Chmod(d, m); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) signedDir() string { return filepath.Join(s.Dir, "signed") }
func (s *Store) recordDir() string { return filepath.Join(s.Dir, "records") }

// Record notes that uid, authenticated by the caller, signed content d.
func (s *Store) Record(uid uint32, d Digest) error {
	f, err := os.OpenFile(s.recordName(uid, d), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

func (s *Store) recordName(uid uint32, d Digest) string {
	return filepath.Join(s.recordDir(), d.Hex()+"."+strconv.FormatUint(uint64(uid), 10))
}

// Hash returns the digest of r.
func Hash(r io.Reader) (Digest, error) { return copyHash(io.Discard, r) }

// Signed is the outcome of a successful check.
type Signed struct {
	Digest Digest
	By     []string // user names, or "uid N" for on-host signatures
	Path   string   // root-owned copy; empty from Check
}

// Check reports who signed content d, ignoring the actor's own signatures.
// armored may be nil if there is no signature file.
func (s *Store) Check(d Digest, armored []byte, actor uint32) (*Signed, error) {
	out := &Signed{Digest: d}
	var sigErr error
	if armored != nil {
		var users []string
		users, sigErr = s.Signers.Verify(armored, d)
		for _, u := range users {
			uid, err := s.LookupUID(u)
			if err != nil {
				sigErr = fmt.Errorf("signer %q: %w", u, err)
				continue
			}
			if uid == actor {
				// A key the actor holds proves nothing, whoever else is listed.
				out.By, sigErr = nil, errors.New("signed with the actor's own key")
				break
			}
			out.By = append(out.By, u)
		}
	}
	ents, err := filepath.Glob(filepath.Join(s.recordDir(), d.Hex()+".*"))
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		uid, err := strconv.ParseUint(strings.TrimPrefix(filepath.Ext(e), "."), 10, 32)
		if err == nil && uint32(uid) != actor {
			out.By = append(out.By, "uid "+strconv.FormatUint(uid, 10))
		}
	}
	if len(out.By) == 0 {
		if sigErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrNotSigned, sigErr)
		}
		return nil, ErrNotSigned
	}
	return out, nil
}

// Install copies r into the store if its content is signed. What is checked
// is the copy, so changing the original afterwards has no effect.
func (s *Store) Install(r io.Reader, armored []byte, actor uint32) (*Signed, error) {
	tmp, err := os.CreateTemp(s.recordDir(), "tmp-") // mode 0600, private directory
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	d, err := copyHash(tmp, r)
	if err != nil {
		return nil, err
	}
	out, err := s.Check(d, armored, actor)
	if err != nil {
		return nil, err
	}
	if err := tmp.Chmod(0o555); err != nil {
		return nil, err
	}
	if err := tmp.Close(); err != nil { // else exec fails with ETXTBSY
		return nil, err
	}
	out.Path = filepath.Join(s.signedDir(), d.Hex())
	return out, os.Rename(tmp.Name(), out.Path)
}

// ReadSignature reads a signature file's content.
func ReadSignature(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxSig+1))
	if err == nil && len(b) > maxSig {
		err = ErrTooLarge
	}
	return b, err
}
