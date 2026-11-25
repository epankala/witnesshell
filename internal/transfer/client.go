package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"witnesshell/internal/view"
	"witnesshell/internal/wire"
)

// The client's side. Local paths come from the person at the client only, and
// are not sent to the host.

// chunk is how much is sent between checks of the deadline.
const chunk = 64 << 10

// Local expands "~/" in what the user typed.
func Local(name string) (string, error) {
	if rest, ok := strings.CutPrefix(name, "~/"); ok {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(h, rest), nil
	}
	if name == "" {
		return "", errors.New("no local file")
	}
	return name, nil
}

func answer(c net.Conn) (wire.Reply, error) {
	var r wire.Reply
	if err := wire.Read(c, 64<<10, &r); err != nil {
		return r, fmt.Errorf("no answer from the host: %w", err)
	}
	if r.Type == wire.Error {
		return r, errors.New(view.Escape(r.Text))
	}
	return r, nil
}

// Copy copies size bytes, renewing the deadline, and reports progress.
func Copy(w io.Writer, r io.Reader, size int64, deadline func(time.Time) error, progress func(int64)) error {
	var done int64
	b := make([]byte, chunk)
	for done < size {
		_ = deadline(time.Now().Add(30 * time.Second))
		n, err := r.Read(b[:min(int64(len(b)), size-done)])
		if n > 0 {
			if _, err := w.Write(b[:n]); err != nil {
				return err
			}
			done += int64(n)
			progress(done)
		}
		if done == size {
			break
		}
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Upload sends a local file. It returns when it was placed or refused.
func Upload(open func() (net.Conn, error), session, local, remote string, say func(string)) error {
	local, err := Local(local)
	if err != nil {
		return err
	}
	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("only regular files can be sent")
	}
	size := st.Size()
	h := sha256.New()
	if n, err := io.Copy(h, io.LimitReader(f, size)); err != nil || n != size {
		return errors.Join(errors.New("the file changed"), err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	c, err := open()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := wire.Write(c, wire.Request{Type: wire.Upload, Version: wire.Version, Session: session, Text: remote, Size: size, Hash: hex.EncodeToString(h.Sum(nil))}); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Minute))
	if _, err := answer(c); err != nil {
		return err
	}
	if err := Copy(c, f, size, c.SetWriteDeadline, func(n int64) { say(fmt.Sprintf("sending %s", portion(n, size))) }); err != nil {
		if _, rerr := answer(c); rerr != nil && !errors.Is(rerr, io.EOF) {
			return rerr // the host's reason is more useful
		}
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Minute))
	if _, err := answer(c); err != nil {
		return err
	}
	say("sent; waiting for approval")
	_ = c.SetReadDeadline(time.Time{})
	_, err = answer(c)
	return err
}

func portion(n, size int64) string {
	if size == 0 {
		return "100%"
	}
	return fmt.Sprintf("%d%%", n*100/size)
}

// Download fetches a file from the host to a new local file.
func Download(open func() (net.Conn, error), session, remote, local string, max int64, say func(string)) (err error) {
	local, err = Local(local)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(local); err == nil {
		return fmt.Errorf("%s exists; it is not overwritten", local)
	}
	c, err := open()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := wire.Write(c, wire.Request{Type: wire.Download, Version: wire.Version, Session: session, Text: remote}); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Minute)) // it is staged first
	if _, err := answer(c); err != nil {
		return err
	}
	say("waiting for approval")
	_ = c.SetReadDeadline(time.Time{})
	r, err := answer(c)
	if err != nil {
		return err
	}
	if r.Size < 0 || r.Size > max {
		return errors.New("the file is too large")
	}
	dir, name := filepath.Split(local)
	if dir == "" {
		dir = "."
	}
	f, err := os.CreateTemp(dir, "."+name+".part-") // mode 0600
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()
	h := sha256.New()
	if err := Copy(io.MultiWriter(f, h), c, r.Size, c.SetReadDeadline, func(n int64) { say(fmt.Sprintf("receiving %s", portion(n, r.Size))) }); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != r.Text {
		return errors.New("what arrived is not what was approved")
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return os.Link(f.Name(), local) // fails if it exists by now
}
