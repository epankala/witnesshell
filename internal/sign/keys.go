package sign

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// DefaultKeyDir is where public keys live in production.
const DefaultKeyDir = "/etc/witnesshell/public_keys"

const keyDirMode = 0o711 // may be entered but not listed

// KeyDir is a directory with one public key per file. A file is named by
// KeyName, so it is found from a signature without listing the directory.
// Its content is one line: "user[,user] keytype key [comment]".
type KeyDir struct {
	Dir   string
	Owner uint32 // required owner; root in production
}

// KeyName returns the file name for a key in SSH wire format.
func KeyName(wire []byte) string {
	h := sha256.Sum256(wire)
	return hex.EncodeToString(h[:])
}

// PublicKeyName returns the file name for a key in OpenSSH .pub format.
func PublicKeyName(pub []byte) (string, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey(pub)
	if err != nil {
		return "", err
	}
	return KeyName(key.Marshal()), nil
}

// Lookup returns the users a key belongs to.
func (k KeyDir) Lookup(wire []byte) ([]string, error) {
	dir, err := unix.Open(k.Dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: k.Dir, Err: err}
	}
	defer unix.Close(dir)
	var st unix.Stat_t
	if err := unix.Fstat(dir, &st); err != nil {
		return nil, err
	}
	if st.Uid != k.Owner || st.Mode&0o777 != keyDirMode {
		return nil, fmt.Errorf("%s must be owned by uid %d with mode %o", k.Dir, k.Owner, keyDirMode)
	}
	name := KeyName(wire)
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, errors.New("signed with an unknown key")
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: filepath.Join(k.Dir, name), Err: err}
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != k.Owner || st.Mode&0o022 != 0 {
		return nil, fmt.Errorf("key file %s must be a regular file writable only by uid %d", name, k.Owner)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSig))
	if err != nil {
		return nil, err
	}
	users, key, err := parseKey(string(b))
	if err != nil {
		return nil, fmt.Errorf("key file %s: %w", name, err)
	}
	// The content counts, not the name.
	if string(key.Marshal()) != string(wire) {
		return nil, fmt.Errorf("key file %s holds a different key", name)
	}
	return users, nil
}

// parseKey reads a key file. Key options are refused rather than ignored,
// since they restrict a key.
func parseKey(s string) ([]string, ssh.PublicKey, error) {
	s = strings.TrimSpace(s)
	f := strings.Fields(s)
	if len(f) < 3 || strings.Contains(s, "\n") {
		return nil, nil, errors.New(`want one line "user keytype key"`)
	}
	key, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(f[1] + " " + f[2]))
	if err != nil || len(opts) > 0 || key.Type() != f[1] {
		return nil, nil, errors.New("bad key or unsupported options")
	}
	if strings.HasSuffix(f[1], "-cert-v01@openssh.com") {
		return nil, nil, errors.New("certificates are not supported")
	}
	users := strings.Split(f[0], ",")
	for _, u := range users {
		if u == "" || strings.ContainsAny(u, "*?!\"") {
			return nil, nil, fmt.Errorf("bad user %q", u)
		}
	}
	return users, key, nil
}
