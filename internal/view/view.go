// Package view shows files safely and without starting programs (D27).
package view

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"witnesshell/internal/launch"
	"witnesshell/internal/sign"
	"witnesshell/internal/trust"
)

// maxShown bounds how much of a file is shown; all of it is hashed.
const maxShown = 2 << 20

// Doc is a file's content, safe to print.
type Doc struct {
	Path      string
	SHA256    string
	Owner     uint32
	Mode      uint32
	Size      int64
	Truncated bool
	Lines     []string
}

// Load reads a file with u's permissions. name may be relative to dir.
func Load(u launch.User, dir, name string) (*Doc, error) {
	f, err := open(u, dir, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadFile(f, abs(dir, name))
}

// LoadFile reads an open file, which is called name.
func LoadFile(f *os.File, name string) (*Doc, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return nil, err
	}
	var buf limited
	dg, err := sign.Hash(io.TeeReader(f, &buf))
	if err != nil {
		return nil, err
	}
	d := &Doc{Path: name, SHA256: dg.Hex(), Owner: st.Uid, Mode: st.Mode & 0o7777, Size: st.Size, Truncated: buf.cut}
	text := strings.TrimSuffix(buf.b.String(), "\n")
	for _, l := range strings.Split(text, "\n") {
		d.Lines = append(d.Lines, Escape(l))
	}
	return d, nil
}

// Text reads up to max bytes of an open file as lines, unchanged.
func Text(f *os.File, max int64) ([]string, error) {
	b, err := io.ReadAll(io.NewSectionReader(f, 0, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("too large")
	}
	if bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) {
		return nil, errors.New("not text")
	}
	if len(b) == 0 {
		return nil, nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n"), nil
}

// Open opens a regular file with u's permissions.
func Open(u launch.User, dir, name string) (*os.File, error) { return open(u, dir, name) }

// ErrStopped means that stop told Sha256 to give up.
var ErrStopped = errors.New("stopped")

// Sha256 hashes a file of any size with u's permissions.
func Sha256(u launch.User, dir, name string, stop func() bool, progress func(done, size int64)) (hash string, size int64, err error) {
	f, err := open(u, dir, name)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	h, b := sha256.New(), make([]byte, 1<<20)
	for {
		if stop() {
			return "", 0, ErrStopped
		}
		n, err := f.Read(b)
		_, _ = h.Write(b[:n])
		size += int64(n)
		if err == io.EOF {
			return hex.EncodeToString(h.Sum(nil)), size, nil
		}
		if err != nil {
			return "", 0, err
		}
		progress(size, st.Size())
	}
}

// limited keeps the first maxShown bytes.
type limited struct {
	b   bytes.Buffer
	cut bool
}

func (l *limited) Write(p []byte) (int, error) {
	if room := maxShown - l.b.Len(); len(p) > room {
		l.b.Write(p[:room])
		l.cut = true
	} else {
		l.b.Write(p)
	}
	return len(p), nil
}

func abs(dir, name string) string {
	if path.IsAbs(name) {
		return name
	}
	return dir + "/" + name
}

func open(u launch.User, dir, name string) (*os.File, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return nil, errors.New("bad file name")
	}
	f, err := launch.OpenAs(u, dir, name, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s: not a regular file", name)
	}
	return f, nil
}

// Escape makes one line of text visible and harmless.
func Escape(s string) string {
	var b strings.Builder
	col := 0
	for len(s) > 0 {
		r, n := utf8.DecodeRuneInString(s)
		var out string
		switch {
		case r == utf8.RuneError && n == 1:
			out = fmt.Sprintf(`\x%02x`, s[0])
		case r == '\t':
			out = strings.Repeat(" ", 8-col%8)
		case r < 0x20:
			out = "^" + string(r+'@')
		case r == 0x7f:
			out = "^?"
		case !unicode.IsPrint(r) || r == 0x2800 ||
			unicode.In(r, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector):
			out = fmt.Sprintf(`\u{%x}`, r)
		default:
			out = s[:n]
		}
		b.WriteString(out)
		col += utf8.RuneCountInString(out)
		s = s[n:]
	}
	return b.String()
}

// Checksig reports on a file with u's permissions and returns its hash. actor is the user whose
// own signature would not count.
func Checksig(w io.Writer, u launch.User, dir, name string, store *sign.Store, actor launch.User) (sha256 string, err error) {
	f, err := open(u, dir, name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	dg, err := sign.Hash(f)
	if err != nil {
		return "", err
	}
	var armored []byte
	if sf, err := open(u, dir, name+".sig"); err == nil {
		defer sf.Close()
		if armored, err = sign.ReadSignature(sf); err != nil {
			return "", err
		}
	}
	a := trust.Actor{UID: actor.UID, GIDs: append([]uint32{actor.GID}, actor.Groups...)}
	var t *trust.File
	if err := launch.AsUser(u, func() (err error) {
		t, err = trust.Resolve(abs(dir, name), a)
		return err
	}); err != nil {
		return "", err
	}
	defer t.Close()
	fmt.Fprintf(w, "file     %s\nsha256   %s\nowner    uid %d, mode %04o\n", Escape(t.Path), dg.Hex(), t.Stat.Uid, t.Stat.Mode&0o7777)
	if t.Trusted {
		fmt.Fprintf(w, "trusted  yes, %s cannot modify it\n", actor.Name)
	} else {
		fmt.Fprintf(w, "trusted  no: %s\n", Escape(t.Reason))
	}
	signers, sigErr := store.Signers(dg, armored)
	for _, g := range signers {
		note := ""
		if g.UID == actor.UID {
			note = " (does not count for their own sessions)"
		}
		fmt.Fprintf(w, "signed   by %s%s\n", Escape(g.Name), note)
	}
	if len(signers) == 0 {
		fmt.Fprintln(w, "signed   no")
	}
	if sigErr != nil {
		fmt.Fprintf(w, "problem  %s\n", Escape(sigErr.Error()))
	}
	return dg.Hex(), nil
}

// Pager is the state of a simple pager.
type Pager struct {
	Doc *Doc
	Top int
}

// Header describes the file.
func (p *Pager) Header() string {
	d := p.Doc
	if d.SHA256 == "" { // a report rather than a file
		return Escape(d.Path)
	}
	s := fmt.Sprintf("%s  uid %d  %04o  sha256 %s", Escape(d.Path), d.Owner, d.Mode, d.SHA256)
	if d.Truncated {
		s += "  (only the beginning is shown)"
	}
	return s
}

// Wrap returns the document cut into lines of at most cols characters.
func (p *Pager) Wrap(cols int) []string {
	var out []string
	for _, l := range p.Doc.Lines {
		r := []rune(l)
		// Wide characters take two columns, so half as many always fit.
		w := cols
		for _, c := range r {
			if c > 0x10ff {
				w = max(1, cols/2)
				break
			}
		}
		for len(r) > w {
			out = append(out, string(r[:w]))
			r = r[w:]
		}
		out = append(out, string(r))
	}
	return out
}

// Key handles a key. It reports whether the pager should close.
func (p *Pager) Key(k byte, rows, total int) bool {
	switch k {
	case 'q', 0x03, 0x04:
		return true
	case ' ', 'f':
		p.Top += rows
	case 'b':
		p.Top -= rows
	case '\r', '\n', 'j':
		p.Top++
	case 'k':
		p.Top--
	case 'g':
		p.Top = 0
	case 'G':
		p.Top = total
	}
	p.Top = max(0, min(p.Top, total-rows))
	return false
}

// Run pages d on a terminal whose size is rows by cols, reading single keys
// from in. Files that fit on the screen are printed without waiting.
func Run(d *Doc, in io.Reader, out io.Writer, rows, cols int) {
	p := &Pager{Doc: d}
	lines := p.Wrap(cols)
	fmt.Fprintf(out, "\x1b[7m%s\x1b[0m\r\n", p.Header())
	if len(lines)+3 <= rows {
		fmt.Fprintf(out, "%s\r\n", strings.Join(lines, "\r\n"))
		return
	}
	rows = max(1, rows-2)
	fmt.Fprint(out, "\x1b[?1049h")
	defer fmt.Fprint(out, "\x1b[?1049l")
	b := make([]byte, 1)
	for {
		end := min(p.Top+rows, len(lines))
		fmt.Fprintf(out, "\x1b[H\x1b[2J%s\r\n\x1b[7m%s lines %d-%d of %d  space b j k g G q \x1b[0m",
			strings.Join(lines[p.Top:end], "\r\n"), Escape(path.Base(d.Path)), p.Top+1, end, len(lines))
		if n, err := in.Read(b); n == 0 || err != nil || p.Key(b[0], rows, len(lines)) {
			return
		}
	}
}
