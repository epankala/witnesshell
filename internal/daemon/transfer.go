package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"witnesshell/internal/audit"
	"witnesshell/internal/gate"
	"witnesshell/internal/launch"
	"witnesshell/internal/sign"
	"witnesshell/internal/transfer"
	"witnesshell/internal/transport"
	"witnesshell/internal/view"
	"witnesshell/internal/wire"
)

const (
	// keepFree is what staging leaves free on its filesystem.
	keepFree = 256 << 20
	// maxDiff is the largest file that is compared.
	maxDiff = 1 << 20
	maxPath = 4096
)

// pendingTransfer is a staged file that waits for approval.
type pendingTransfer struct {
	upload bool
	file   *os.File // has no name; see transfer.Stage
	size   int64
	hash   string
	dest   *transfer.Dest // upload
	path   string         // download
	result chan error     // nil: approved and, if an upload, placed
}

// about describes it for the logs.
func (t *pendingTransfer) about() audit.Data {
	d := audit.Data{"transfer": "download", "size": t.size, "sha256": t.hash, "path": t.path}
	if t.upload {
		d["transfer"], d["path"], d["replaces"] = "upload", t.dest.Path(), t.dest.Exists
		if t.dest.Exists {
			d["replaced_sha256"] = t.dest.SHA256
		}
	}
	return d
}

func (t *pendingTransfer) text() string {
	if t.upload {
		return "upload to " + t.dest.Path()
	}
	return "download " + t.path
}

func (t *pendingTransfer) details() []string {
	if !t.upload {
		return []string{"copy a file FROM THE HOST to the actor's machine", fmt.Sprintf("  file %q", t.path),
			fmt.Sprintf("  %d bytes, sha256 %s", t.size, t.hash), "  as it was when this was asked for; see it with [o]pen"}
	}
	out := []string{"copy a file from the actor's machine to the host", fmt.Sprintf("  to %q", t.dest.Path()),
		fmt.Sprintf("  %d bytes, sha256 %s", t.size, t.hash)}
	switch {
	case !t.dest.Exists:
		out = append(out, "  a NEW file; see it with [o]pen")
	case t.dest.SHA256 == "":
		out = append(out, fmt.Sprintf("  REPLACES a file of %d bytes that the actor cannot read; see the new one with [o]pen", t.dest.Size))
	default:
		out = append(out, fmt.Sprintf("  REPLACES a file of %d bytes, sha256 %s; see the new one with [o]pen, changes with [d]iff", t.dest.Size, t.dest.SHA256))
	}
	return out
}

// reserve makes sure that there is room for a staged file.
func (d *Daemon) reserve(size int64) (release func(), err error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(d.store.Dir, &fs); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.staged+size > 4*d.c.maxTransfer || int64(fs.Bavail)*fs.Bsize-size < keepFree {
		return nil, errors.New("there is no room on the host for this now")
	}
	d.staged += size
	return func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.staged -= size
	}, nil
}

// transfer serves a connection that is an upload or a download.
func (d *Daemon) transfer(conn net.Conn, u launch.User, q wire.Request) {
	fail := func(err error) {
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_ = wire.Write(conn, wire.Reply{Type: wire.Error, Text: view.Escape(err.Error())})
	}
	if _, ok := conn.(*transport.Stream); !ok {
		// Without a client at the other end there is nothing to copy to or from.
		fail(errors.New("files can be copied with witsh connect only"))
		return
	}
	var s *session
	d.mu.Lock()
	for _, o := range d.sessions {
		if o.id == q.Session && o.actor.UID == u.UID {
			s = o
		}
	}
	d.mu.Unlock()
	if s == nil {
		fail(errors.New("not your session"))
		return
	}
	s.mu.Lock()
	busy := s.staging || s.over
	if !busy {
		s.staging = true
	}
	s.mu.Unlock()
	if busy {
		fail(errors.New("another file is being copied"))
		return
	}
	defer func() {
		s.mu.Lock()
		s.staging = false
		s.mu.Unlock()
	}()
	var err error
	if q.Type == wire.Upload {
		err = s.receive(conn, q)
	} else {
		err = s.send(conn, q)
	}
	if err != nil {
		fail(err)
	}
}

// refused logs a transfer that did not get as far as a request.
func (s *session) refused(q wire.Request, err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.over {
		s.note(audit.Refused, audit.Data{"transfer": q.Type, "path": q.Text, "size": q.Size, "sha256": q.Hash, "why": err.Error()}, false)
	}
	return err
}

// receive stages an upload, gets it approved, and has it placed.
func (s *session) receive(conn net.Conn, q wire.Request) error {
	c := &s.d.c
	if !c.AllowUpload {
		return s.refused(q, errors.New("copying files to this host is not permitted"))
	}
	if b, err := hex.DecodeString(q.Hash); err != nil || len(b) != sha256.Size || q.Size < 0 || len(q.Text) > maxPath {
		return s.refused(wire.Request{Type: q.Type}, errors.New("bad request"))
	}
	if q.Size > c.maxTransfer {
		return s.refused(q, fmt.Errorf("the file is larger than the %d bytes allowed", c.maxTransfer))
	}
	// Known mistakes first, rather than after sending everything.
	if _, err := transfer.Look(s.actor, s.currentDir(), q.Text); err != nil {
		return s.refused(q, err)
	}
	release, err := s.d.reserve(q.Size)
	if err != nil {
		return s.refused(q, err)
	}
	defer release()
	f, err := transfer.Stage(s.d.stagingDir())
	if err != nil {
		return s.refused(q, err)
	}
	defer f.Close()
	if err := wire.Write(conn, wire.Reply{Type: wire.OK}); err != nil {
		return err
	}
	h := sha256.New()
	if err := transfer.Copy(io.MultiWriter(f, h), conn, q.Size, conn.SetReadDeadline, func(int64) {}); err != nil {
		return s.refused(q, fmt.Errorf("the file did not arrive: %w", err))
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != strings.ToLower(q.Hash) {
		return s.refused(q, errors.New("the file was damaged on the way"))
	}
	_ = conn.SetDeadline(time.Time{})
	if err := wire.Write(conn, wire.Reply{Type: wire.OK}); err != nil {
		return err
	}
	dest, err := transfer.Look(s.actor, s.currentDir(), q.Text)
	if err != nil {
		return s.refused(q, err)
	}
	t := &pendingTransfer{upload: true, file: f, size: q.Size, hash: strings.ToLower(q.Hash), dest: dest, result: make(chan error, 1)}
	if err := s.ask(conn, t, q); err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return wire.Write(conn, wire.Reply{Type: wire.OK})
}

// send stages a file of the host, gets it approved, and sends it.
func (s *session) send(conn net.Conn, q wire.Request) error {
	c := &s.d.c
	if !c.AllowDownload {
		return s.refused(q, errors.New("copying files from this host is not permitted"))
	}
	if len(q.Text) > maxPath || view.Escape(q.Text) != q.Text {
		return s.refused(wire.Request{Type: q.Type}, errors.New("bad request"))
	}
	src, err := view.Open(s.actor, s.currentDir(), q.Text)
	if err != nil {
		return s.refused(q, err)
	}
	defer src.Close()
	st, err := src.Stat()
	if err != nil {
		return s.refused(q, err)
	}
	q.Size = st.Size()
	if q.Size > c.maxTransfer {
		return s.refused(q, fmt.Errorf("the file is larger than the %d bytes allowed", c.maxTransfer))
	}
	release, err := s.d.reserve(q.Size)
	if err != nil {
		return s.refused(q, err)
	}
	defer release()
	f, err := transfer.Stage(s.d.stagingDir())
	if err != nil {
		return s.refused(q, err)
	}
	defer f.Close()
	hash, err := transfer.Fill(f, src, q.Size)
	if err != nil {
		return s.refused(q, err)
	}
	// The name as the kernel knows it, so that links do not hide what it is.
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", src.Fd()))
	if err != nil || view.Escape(path) != path {
		return s.refused(q, errors.New("the file's name has hidden or control characters"))
	}
	_ = conn.SetDeadline(time.Time{})
	if err := wire.Write(conn, wire.Reply{Type: wire.OK}); err != nil {
		return err
	}
	t := &pendingTransfer{file: f, size: q.Size, hash: hash, path: path, result: make(chan error, 1)}
	if err := s.ask(conn, t, q); err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	err = wire.Write(conn, wire.Reply{Type: wire.OK, Text: hash, Size: q.Size})
	if err == nil {
		err = transfer.Copy(conn, io.NewSectionReader(f, 0, q.Size), q.Size, conn.SetWriteDeadline, func(int64) {})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := t.about()
	if d["outcome"] = "sent"; err != nil {
		d["outcome"], d["error"] = "not sent completely", err.Error()
	}
	if !s.over {
		s.note(audit.RunEnd, d, true)
	}
	return err
}

// ask makes a request of a staged file, once the session is at its prompt, and
// waits for the outcome.
func (s *session) ask(conn net.Conn, t *pendingTransfer, q wire.Request) error {
	// The client says nothing more. If it goes away, it has changed its mind.
	gone := make(chan struct{})
	go func() {
		_, _ = conn.Read(make([]byte, 1))
		close(gone)
	}()
	for submitted := false; !submitted; {
		s.mu.Lock()
		switch {
		case s.over:
			s.mu.Unlock()
			return errOver
		case s.gate.State() == gate.Prompt && !s.checking:
			r, err := s.gate.SubmitOutside(t.text())
			if err != nil {
				s.mu.Unlock()
				return s.refused(q, err)
			}
			s.transfer, s.details, s.warnings = t, t.details(), nil
			d := t.about()
			d["id"], d["text"], d["details"] = r.ID, r.Text, s.details
			s.request, _ = s.note(audit.Request, d, true)
			s.logged(s.audit.Marker("request: " + r.Text))
			s.notice = ""
			s.broadcast()
			submitted = true
		}
		s.mu.Unlock()
		if !submitted {
			select {
			case <-gone:
				return s.refused(q, errors.New("the client went away"))
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	select {
	case err := <-t.result:
		return err
	case <-gone:
	}
	s.mu.Lock()
	if s.transfer == t && s.gate.State() == gate.Pending {
		if r, err := s.gate.Cancel(); err == nil {
			s.note(audit.Cancelled, audit.Data{"id": r.ID, "request_hash": s.request, "why": "the client went away"}, true)
			s.notice = "the transfer was withdrawn"
			s.transfer = nil
			s.broadcast()
			t.result <- errors.New("withdrawn")
		}
	}
	s.mu.Unlock()
	return <-t.result // it may just have been approved
}

// drop ends a pending transfer that was not approved. Lock held.
func (s *session) drop(why string) {
	if s.transfer != nil {
		s.transfer.result <- errors.New(why)
		s.transfer = nil
	}
}

// approved carries out an approved transfer, which was logged. Lock held.
func (s *session) approved(about audit.Data) {
	t := s.transfer
	s.transfer = nil
	if !t.upload {
		t.result <- nil // and is sent by its own connection
		return
	}
	s.checking = true // nothing else meanwhile
	umask := uint32(s.umask)
	s.do(func() {
		err := transfer.Place(s.actor, t.dest, t.file, t.size, t.hash, umask)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.checking = false
		d := t.about()
		for k, v := range about {
			d[k] = v
		}
		if d["outcome"], s.notice = "placed", "uploaded "+t.dest.Path(); err != nil {
			d["outcome"], d["error"], s.notice = "failed", err.Error(), view.Escape("upload failed: "+err.Error())
		}
		if !s.over {
			s.note(audit.RunEnd, d, true)
			s.logged(s.audit.Marker(fmt.Sprintf("upload %s", d["outcome"])))
			s.broadcast()
		}
		t.result <- err
	})
}

// showStaged shows a witness the file of the pending transfer, or what it
// changes. The file that would be replaced is read with the witness's own
// permissions (D31).
func (s *session) showStaged(c *client, q wire.Request) wire.Reply {
	s.mu.Lock()
	t := s.transfer
	var f *os.File
	var err error
	if t == nil {
		err = errors.New("no file is waiting for approval")
	} else if fd, e := unix.FcntlInt(t.file.Fd(), unix.F_DUPFD_CLOEXEC, 0); e != nil {
		err = e
	} else {
		f = os.NewFile(uintptr(fd), "staged") // it may be closed meanwhile
	}
	s.mu.Unlock()
	var doc *view.Doc
	if err == nil {
		defer f.Close()
		if q.Type == wire.Staged {
			doc, err = staged(f, t)
		} else {
			doc, err = s.changes(c, f, t)
		}
	}
	if err != nil {
		return wire.Reply{Type: wire.Error, Text: view.Escape(err.Error())}
	}
	d := audit.Data{"what": q.Type, "path": doc.Path, "sha256": t.hash}
	s.mu.Lock()
	ok := s.own(c, audit.Inspect, d)
	s.mu.Unlock()
	if !ok {
		return wire.Reply{Type: wire.Error, Text: "this cannot be logged"}
	}
	return wire.Reply{Type: wire.Doc, Doc: doc}
}

func staged(f *os.File, t *pendingTransfer) (*view.Doc, error) {
	if t.size > sign.MaxFile {
		return nil, errors.New("too large to show; compare its sha256")
	}
	// Not by the shared position, which others move.
	r, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	doc, err := view.LoadFile(r, "staged: "+t.text())
	if err == nil && doc.SHA256 != t.hash {
		err = errors.New("the staged file is damaged")
	}
	return doc, err
}

func (s *session) changes(c *client, f *os.File, t *pendingTransfer) (*view.Doc, error) {
	if !t.upload || !t.dest.Exists {
		return nil, errors.New("it replaces no file")
	}
	old, err := view.Open(c.user, "/", t.dest.Path())
	if err != nil {
		return nil, err
	}
	defer old.Close()
	a, err := view.Text(old, maxDiff)
	if err != nil {
		return nil, fmt.Errorf("the file on the host is %w", err)
	}
	b, err := view.Text(f, maxDiff)
	if err != nil {
		return nil, fmt.Errorf("the new file is %w", err)
	}
	lines, err := transfer.Diff(a, b)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		lines = []string{"(the same lines)"}
	}
	for i := range lines {
		lines[i] = view.Escape(lines[i])
	}
	// No hash: a diff is not a file that could be signed.
	return &view.Doc{Path: "changes to " + t.dest.Path(), Lines: lines}, nil
}

// hash answers a witness's sha256, which may take long, with their own
// permissions.
func (s *session) hash(c *client, q wire.Request) {
	dir := s.currentDir()
	h, size, err := view.Sha256(c.user, dir, q.Text, func() bool {
		select {
		case <-c.left:
			return true
		default:
			return false
		}
	}, func(int64, int64) {})
	d := audit.Data{"what": q.Type, "path": q.Text, "directory": dir, "sha256": h, "size": size}
	r := wire.Reply{Type: wire.Report, Text: fmt.Sprintf("%s\n%d bytes\nsha256 %s", view.Escape(q.Text), size, h)}
	if err != nil {
		d["error"] = err.Error()
		r = wire.Reply{Type: wire.Error, Text: view.Escape(err.Error())}
	}
	s.mu.Lock()
	ok := s.over || s.own(c, audit.Inspect, d)
	c.hashing = false
	s.mu.Unlock()
	if ok {
		s.reply(c, r)
	}
}
