package daemon

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"witnesshell/internal/audit"
	"witnesshell/internal/gate"
	"witnesshell/internal/launch"
	"witnesshell/internal/pty"
	"witnesshell/internal/sign"
	"witnesshell/internal/version"
	"witnesshell/internal/view"
	"witnesshell/internal/wire"
)

// client is one connection that has joined a session.
type client struct {
	conn   net.Conn
	screen bulkConn // carries frames and out; nil if conn does
	user   launch.User
	actor  bool
	out    chan wire.Reply // bulk: viewed files
	msgs   chan wire.Reply
	state  chan wire.Reply // the latest state
	dirty  chan struct{}   // the screen has changed
	frame  func() (*wire.Frame, bool)
	ver    uint64 // of the screen it has; session lock
	// left is closed when the client has gone.
	left    chan struct{}
	hashing bool // session lock
}

type bulkConn interface {
	io.Writer
	SetWriteDeadline(time.Time) error
}

func newClient(conn net.Conn, screen bulkConn, u launch.User, actor bool) *client {
	if c, ok := conn.(*net.UnixConn); ok {
		// A large socket buffer would hold output that state cannot overtake.
		_ = c.SetWriteBuffer(16 << 10)
	}
	return &client{conn: conn, screen: screen, user: u, actor: actor,
		out: make(chan wire.Reply, 64), msgs: make(chan wire.Reply, 256), state: make(chan wire.Reply, 1), dirty: make(chan struct{}, 1), left: make(chan struct{})}
}

// send queues a message. A client that cannot keep up is dropped; it can
// reconnect. Session lock held.
func (c *client) send(r wire.Reply) {
	q := c.msgs
	if r.Type == wire.Doc {
		q = c.out
	}
	select {
	case q <- r:
	default:
		_ = c.conn.Close()
	}
}

// sendState replaces a state that was not sent yet. Session lock held.
func (c *client) sendState(r wire.Reply) {
	select {
	case <-c.state:
	default:
	}
	c.state <- r
}

// changed notes that there is a new frame. A client that is slow gets fewer.
func (c *client) changed() {
	select {
	case c.dirty <- struct{}{}:
	default:
	}
}

func (c *client) writeFrame(w bulkConn) error {
	f, ok := c.frame()
	if !ok {
		return nil
	}
	return writeTo(w, wire.Reply{Type: wire.FrameType, Frame: f})
}

// finish ends the client once what is in msgs was sent. Session lock held.
func (c *client) finish() {
	close(c.left)
	close(c.msgs)
	close(c.out)
}

func writeTo(w bulkConn, r wire.Reply) error {
	_ = w.SetWriteDeadline(time.Now().Add(20 * time.Second))
	return wire.Write(w, r)
}

// writeLoop sends queued messages until finish is called. State and messages
// go before frames, or do not wait for them at all if they have their own
// stream.
func (c *client) writeLoop() {
	defer func() {
		_ = c.conn.Close()
		for range c.msgs { // discard
		}
		for range c.out {
		}
	}()
	out, dirty := c.out, c.dirty
	if c.screen != nil {
		out, dirty = nil, nil
		go c.screenLoop()
	}
	for {
		var r wire.Reply
		ok := true
		select {
		case r = <-c.state:
		default:
			select {
			case r = <-c.state:
			case r, ok = <-c.msgs:
			default:
				select {
				case r = <-c.state:
				case r, ok = <-c.msgs:
				case <-dirty:
					if c.writeFrame(c.conn) != nil {
						return
					}
					continue
				case r, ok = <-out:
					if !ok { // msgs is closed too, and may hold the farewell
						out, dirty, ok = nil, nil, true
						continue
					}
				}
			}
		}
		if !ok || writeTo(c.conn, r) != nil {
			return
		}
	}
}

func (c *client) screenLoop() {
	defer func() {
		if w, ok := c.screen.(io.Closer); ok {
			_ = w.Close()
		}
		for range c.out {
		}
	}()
	for {
		var err error
		select {
		case <-c.dirty:
			err = c.writeFrame(c.screen)
		case r, ok := <-c.out:
			if !ok {
				return
			}
			err = writeTo(c.screen, r)
		}
		if err != nil {
			_ = c.conn.Close()
			return
		}
	}
}

type session struct {
	d     *Daemon
	id    string
	actor launch.User
	since time.Time
	weak  []string
	log   *slog.Logger

	ptm    *os.File
	leader *leader
	cgroup string
	proc   *screenProc
	audit  *audit.Session
	pumped chan struct{} // closed when there is no more output

	mu         sync.Mutex
	gate       *gate.Gate
	keys       keys
	checking   bool
	serial     uint64           // of the prepared command
	request    string           // hash of the log entry of the pending request
	transfer   *pendingTransfer // that the pending request is about, if any
	staging    bool             // a transfer is going on
	umask      int
	entered    []time.Time // see mayEnter
	details    []string
	warnings   []string
	dir        string
	notice     string
	screen     screenState
	rows, cols uint16
	clients    []*client
	detach     *time.Timer
	over       bool
}

func clampSize(rows, cols uint16) (uint16, uint16) {
	return min(max(rows, 4), 300), min(max(cols, 20), 500)
}

func (d *Daemon) newSession(u launch.User, weak []string, rows, cols uint16) (*session, error) {
	g, err := gate.New(u.UID, d.c.ApprovalsRequired)
	if err != nil {
		return nil, err
	}
	s := &session{d: d, actor: u, weak: weak, gate: g, since: d.nextStart(), pumped: make(chan struct{}), umask: 0o022}
	s.id = s.since.Format("20060102T150405.000Z")
	s.log = d.log.With("session", s.id, "actor", u.Name)
	s.rows, s.cols = clampSize(rows, cols)
	host, _ := os.Hostname()
	s.audit, err = audit.Open(d.c.RecordDir, s.id, u.Name, u.UID, audit.Data{"session": s.id, "host": host, "actor": u.Name, "actor_uid": u.UID,
		"approvals_required": d.c.ApprovalsRequired, "host_problems": weak, "version": version.Version}, s.rows, s.cols, s.since)
	if err != nil {
		d.log.Error("cannot log sessions", "err", err)
		return nil, errors.New("the session cannot be logged, so it cannot start")
	}
	fail := func(err error) (*session, error) {
		s.removeCgroup()
		_, _ = s.audit.Close("could not be started")
		return nil, err
	}
	s.cgroup = cgroupBase + "/" + s.id
	if err := os.Mkdir(s.cgroup, 0o755); err != nil {
		return fail(err)
	}
	cg, err := os.Open(s.cgroup)
	if err != nil {
		return fail(err)
	}
	defer cg.Close()
	s.leader, s.ptm, s.dir, err = startLeader(leaderConfig{User: u, StoreDir: d.store.Dir, Keys: d.store.Keys, ExecDirs: d.c.ExecDirs}, cg, s.rows, s.cols)
	if err != nil {
		return fail(err)
	}
	s.proc = &screenProc{cgroup: s.cgroup, onFrame: s.newFrame, onLost: s.screenLost, size: func() (uint16, uint16) {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.rows, s.cols
	}}
	s.proc.mu.Lock()
	err = s.proc.start()
	s.proc.mu.Unlock()
	if err != nil {
		_ = s.ptm.Close()
		_ = s.leader.in.Close()
		return fail(err)
	}
	if len(weak) > 0 {
		s.notice = "this host does not meet the requirements; protection is weaker"
	}
	s.log.Info("session started", "weak", weak)
	s.audit.LimitRecording(d.c.maxRecording)
	s.do(s.pump)
	go func() {
		<-s.leader.done
		s.end("the shell ended")
	}()
	return s, nil
}

// removeCgroup kills whatever is left of the session.
func (s *session) removeCgroup() {
	if s.cgroup == "" {
		return
	}
	_ = os.WriteFile(s.cgroup+"/cgroup.kill", []byte("1"), 0)
	for range 50 {
		if err := os.Remove(s.cgroup); err == nil || errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.log.Error("cannot remove cgroup", "path", s.cgroup)
}

// pump feeds terminal output to the screen.
func (s *session) pump() {
	defer close(s.pumped)
	b := make([]byte, 32<<10)
	for {
		n, err := s.ptm.Read(b)
		if n > 0 {
			s.logged(s.audit.Output(b[:n]))
			s.proc.output(b[:n])
		}
		if err != nil {
			return
		}
	}
}

// logged ends the session if something could not be logged: nothing may go on
// without. It reports whether all is well.
func (s *session) logged(err error) bool {
	if err != nil && !errors.Is(err, audit.ErrClosed) {
		s.log.Error("cannot log", "err", err)
		why := "the session can no longer be logged"
		if errors.Is(err, audit.ErrFull) {
			why = "the recording reached its limit (max_recording)"
		}
		go s.end(why)
	}
	return err == nil
}

// do runs f in the background, guarded (see Daemon.guard).
func (s *session) do(f func()) { go s.d.guard(s, f) }

// note adds an event to the actor's log, and to those of witnesses who are
// there if asked to. It is on disk afterwards. Lock held.
func (s *session) note(event string, d audit.Data, witnesses bool) (string, bool) {
	h, err := s.audit.Actor(event, d, true)
	if !s.logged(err) || !witnesses {
		return h, err == nil
	}
	if event == audit.Request {
		d["request_hash"] = h
	}
	seen := map[uint32]bool{}
	for _, c := range s.clients {
		if c.actor || seen[c.user.UID] {
			continue
		}
		seen[c.user.UID] = true
		if !s.logged(s.audit.Witness(c.user.UID, c.user.Name, event, d, true)) {
			return "", false
		}
	}
	return h, true
}

// own adds an event to the log of the user it is about. Lock held.
func (s *session) own(c *client, event string, d audit.Data) bool {
	if c.actor {
		_, err := s.audit.Actor(event, d, false)
		return s.logged(err)
	}
	return s.logged(s.audit.Witness(c.user.UID, c.user.Name, event, d, true))
}

// newFrame takes a frame from the screen process.
func (s *session) newFrame(f *wire.Frame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.screen.apply(f)
	for _, c := range s.clients {
		c.changed()
	}
}

func (s *session) screenLost(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.over {
		return
	}
	s.log.Error("screen lost", "err", err)
	s.notice = "the screen could not be shown and was reset"
	s.broadcast()
}

// end closes the session. Waiting commands are purged (D6).
func (s *session) end(why string) {
	s.mu.Lock()
	if s.over {
		s.mu.Unlock()
		return
	}
	s.over = true
	s.mu.Unlock()
	// Before anyone is told, so that they do not see it in the list. Not while
	// holding the lock, since the daemon's lock comes first.
	s.d.forget(s)
	s.mu.Lock()
	if r, purged := s.gate.Logout(); purged {
		s.log.Info("request purged", "id", r.ID)
		s.note(audit.Purged, audit.Data{"id": r.ID, "request_hash": s.request, "why": why}, true)
	}
	s.drop("the session is over")
	if s.detach != nil {
		s.detach.Stop()
	}
	for _, c := range s.clients {
		c.send(wire.Reply{Type: wire.End, Text: why})
		c.finish()
	}
	s.clients = nil
	s.mu.Unlock()
	s.log.Info("session ended", "why", why)
	s.proc.close()
	_ = s.leader.in.Close() // lets an idle leader hang up its jobs
	_ = s.ptm.Close()       // hangs up the foreground job
	select {
	case <-s.leader.done:
	case <-time.After(time.Second):
	}
	// Nothing may outlive the session: it would be unwitnessed.
	s.removeCgroup()
	select {
	case <-s.pumped:
	case <-time.After(2 * time.Second):
	}
	// The seal also goes to the system's log, where changing it is harder.
	seal, err := s.audit.Close(why)
	if err != nil {
		s.log.Error("logs are incomplete", "err", err)
		return
	}
	s.log.Info("session sealed", "sha256", seal)
}

var errOver = errors.New("the session is over")

// join adds a client and sends it the current screen.
func (s *session) join(c *client, rows, cols uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.over {
		return errOver
	}
	d := audit.Data{"user": c.user.Name, "uid": c.user.UID, "as_actor": c.actor}
	if _, ok := s.note(audit.Join, d, false); !ok || !c.actor && !s.own(c, audit.Join, d) {
		return errors.New("the session can no longer be logged")
	}
	if c.actor {
		for _, o := range slices.Clone(s.clients) {
			if o.actor { // a lost connection, or another window
				o.send(wire.Reply{Type: wire.End, Text: "attached elsewhere"})
				s.remove(o)
			}
		}
		if s.detach != nil {
			s.detach.Stop()
			s.detach = nil
		}
		s.keys.reset()
		s.resize(rows, cols)
	}
	s.clients = append(s.clients, c)
	s.log.Info("joined", "user", c.user.Name, "as_actor", c.actor)
	c.frame = func() (*wire.Frame, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.screen.ver == c.ver {
			return nil, false
		}
		f, v := s.screen.since(c.ver)
		c.ver = v
		return f, true
	}
	c.changed()
	s.broadcast()
	return nil
}

// remove drops a client from the list. Lock held.
func (s *session) remove(c *client) bool {
	i := slices.Index(s.clients, c)
	if i < 0 {
		return false
	}
	s.clients = slices.Delete(s.clients, i, i+1)
	c.finish()
	return true
}

func (s *session) leave(c *client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.remove(c) {
		return
	}
	s.log.Info("left", "user", c.user.Name, "as_actor", c.actor)
	d := audit.Data{"user": c.user.Name, "uid": c.user.UID, "as_actor": c.actor}
	s.note(audit.Leave, d, false)
	if !c.actor {
		s.own(c, audit.Leave, d)
	}
	if c.actor {
		s.detach = time.AfterFunc(s.d.c.detach, func() { s.end("the actor was away too long") })
	}
	s.broadcast() // votes are kept (D13)
}

// resize sets the terminal size. Lock held.
func (s *session) resize(rows, cols uint16) {
	r, c := clampSize(rows, cols)
	if r == s.rows && c == s.cols {
		return
	}
	s.rows, s.cols = r, c
	s.logged(s.audit.Resize(r, c))
	_ = pty.Resize(s.ptm, s.rows, s.cols)
	go s.proc.resize()
}

// broadcast sends the state to everyone. Lock held.
func (s *session) broadcast() {
	st := &wire.State{Session: s.id, Actor: s.actor.Name, Dir: s.dir, Rows: s.rows, Cols: s.cols,
		Required: s.gate.Required(), Notice: s.notice, Weak: s.weak, Download: s.d.c.AllowDownload}
	st.Draft, st.Cursor = s.gate.Draft()
	switch {
	case s.checking:
		st.Phase = wire.Checking
	case s.gate.State() == gate.Running:
		st.Phase = wire.Running
	case s.gate.State() == gate.Pending:
		st.Phase = wire.Pending
		r, _ := s.gate.Pending()
		st.ID, st.Text, st.Details, st.Warnings, st.Transfer = r.ID, r.Text, s.details, s.warnings, s.transfer != nil
		for _, v := range r.Votes {
			st.Votes = append(st.Votes, wire.VoteInfo{Name: s.d.userName(v.UID), Approve: v.Approve})
		}
	default:
		st.Phase = wire.Prompt
	}
	for _, c := range s.clients {
		if c.actor {
			st.ActorOnline = true
		} else if !slices.Contains(st.Witnesses, c.user.Name) {
			st.Witnesses = append(st.Witnesses, c.user.Name)
		}
	}
	for _, c := range s.clients {
		c.sendState(wire.Reply{Type: wire.StateType, State: st})
	}
}

// Submissions in a while, at most: each is logged.
const (
	maxEntered = 20
	enterTime  = 10 * time.Second
)

// maxDocs is how many viewed files may wait to be sent to one client.
const maxDocs = 2

// mayEnter counts a submission. Lock held.
func (s *session) mayEnter() bool {
	now := time.Now()
	s.entered = slices.DeleteFunc(s.entered, func(t time.Time) bool { return now.Sub(t) > enterTime })
	if len(s.entered) >= maxEntered {
		return false
	}
	s.entered = append(s.entered, now)
	return true
}

// key handles bytes typed by the actor.
func (s *session) key(data []byte) {
	s.mu.Lock()
	logout := s.keyLocked(data)
	s.mu.Unlock()
	if logout {
		s.end("the actor logged out")
	}
}

func (s *session) keyLocked(data []byte) (logout bool) {
	if s.over || s.checking {
		return false
	}
	if s.gate.InputFree() {
		// The lock is held across the write, so the gate cannot close in
		// between. A program that does not read must not block the session.
		_ = s.ptm.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		_, _ = s.ptm.Write(data)
		return false
	}
	s.keys.buf = append(s.keys.buf, data...)
	for {
		e, ok := s.keys.next()
		if !ok {
			break
		}
		var err error
		s.notice = ""
		switch e.kind {
		case evText:
			err = s.gate.Insert(e.text)
		case evEdit:
			err = s.gate.Edit(e.op)
		case evInterrupt:
			if s.gate.State() == gate.Pending {
				var r gate.Request
				if r, err = s.gate.Cancel(); err == nil {
					s.log.Info("request cancelled", "id", r.ID)
					s.note(audit.Cancelled, audit.Data{"id": r.ID, "request_hash": s.request}, true)
					s.logged(s.audit.Marker("cancelled"))
					s.drop("cancelled")
					s.notice = "cancelled"
				}
			} else {
				err = s.gate.Edit(gate.Clear)
			}
		case evEOF:
			if d, _ := s.gate.Draft(); d == "" && s.gate.State() == gate.Prompt {
				return true
			}
		case evEnter:
			if !s.mayEnter() {
				s.notice = "too many lines at once; wait a moment"
				break
			}
			if d, _ := s.gate.Draft(); s.gate.State() == gate.Prompt && strings.TrimSpace(d) != "" {
				s.checking = true
				s.keys.reset() // what was typed ahead does not count
				s.do(func() { s.prepare(d) })
			}
		case evBad:
			s.notice = "that key does nothing here"
		}
		if err != nil {
			s.notice = err.Error()
		}
		if s.checking {
			break
		}
	}
	s.broadcast()
	return false
}

// prepare checks the draft, which cannot change meanwhile, and submits it.
func (s *session) prepare(text string) {
	r, err := s.leader.call(leaderReq{Text: text})
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checking = false
	if s.over {
		return
	}
	if err == nil && r.Err != "" {
		err = errors.New(r.Err)
	}
	if err != nil {
		s.notice = view.Escape(err.Error())
		s.note(audit.Refused, audit.Data{"text": text, "why": err.Error()}, false)
		s.broadcast()
		return
	}
	s.serial, s.details, s.warnings = r.Serial, r.Details, r.Warnings
	if r.Free {
		if _, err = s.gate.SubmitFree(); err == nil {
			s.log.Info("free command", "text", text)
			if _, ok := s.note(audit.Free, audit.Data{"text": text}, false); ok {
				s.do(func() { s.run(r.Serial, audit.Data{"text": text}) })
			}
		}
	} else {
		var req gate.Request
		if req, err = s.gate.Submit(); err == nil {
			s.log.Info("request", "id", req.ID, "text", text, "details", r.Details, "warnings", r.Warnings)
			s.request, _ = s.note(audit.Request, audit.Data{"id": req.ID, "text": text, "details": r.Details, "warnings": r.Warnings, "directory": s.dir}, true)
			s.logged(s.audit.Marker("request: " + text))
		}
	}
	if err != nil {
		s.notice = err.Error()
	}
	s.broadcast()
}

// run executes the prepared command, which was logged, and returns to the
// prompt. about goes into the entry for its end.
func (s *session) run(serial uint64, about audit.Data) {
	r, err := s.leader.call(leaderReq{Run: serial})
	s.mu.Lock()
	if s.over {
		s.mu.Unlock()
		return
	}
	_ = s.gate.Finished()
	s.keys.reset()
	s.dir, s.umask = r.Dir, r.Umask
	switch {
	case err != nil:
		s.notice = "the shell ended"
	case r.Err != "":
		s.notice = view.Escape(r.Err)
	case r.Status != 0:
		s.notice = fmt.Sprintf("exit status %d", r.Status)
	default:
		s.notice = ""
	}
	s.log.Info("command ended", "status", r.Status, "err", r.Err)
	about["status"], about["error"], about["directory"] = r.Status, r.Err, r.Dir
	if r.SHA256 != "" {
		about["sha256"] = r.SHA256
	}
	s.note(audit.RunEnd, about, false)
	s.logged(s.audit.Marker(fmt.Sprintf("ended, status %d", r.Status)))
	s.broadcast()
	s.mu.Unlock()
	if err != nil || r.Exited {
		s.end("the actor logged out")
	}
}

// vote records a witness's decision.
func (s *session) vote(c *client, q wire.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.over {
		return errOver
	}
	var r gate.Request
	var err error
	outside := s.transfer != nil
	if q.Approve {
		r, err = s.gate.Approve(c.user.UID, q.ID)
	} else {
		r, err = s.gate.Reject(c.user.UID, q.ID, q.Text)
	}
	if err != nil {
		return err
	}
	comment := ""
	if !q.Approve {
		comment = strings.TrimSpace(q.Text) // checked by Reject; an approval has none
	}
	s.log.Info("vote", "id", q.ID, "by", c.user.Name, "approve", q.Approve, "comment", comment, "outcome", r.Outcome.String())
	d := audit.Data{"id": q.ID, "request_hash": s.request, "by": c.user.Name, "uid": c.user.UID, "approve": q.Approve, "outcome": r.Outcome.String()}
	if !q.Approve {
		d["comment"] = strings.TrimSpace(q.Text)
	}
	_, ok := s.note(audit.Vote, d, false)
	if ok = ok && s.own(c, audit.Vote, d); !ok {
		if r.Outcome == gate.Approved {
			_ = s.gate.Finished() // it must not run
			s.drop("the session can no longer be logged")
		}
		return errors.New("the session can no longer be logged")
	}
	switch r.Outcome {
	case gate.Approved:
		s.notice = ""
		run := audit.Data{"id": q.ID, "request_hash": s.request}
		_, ok := s.note(audit.RunStart, run, true)
		var by []string
		for _, v := range r.Votes {
			by = append(by, s.d.userName(v.UID))
		}
		if !ok || !s.logged(s.audit.Marker("approved by "+strings.Join(by, ", "))) {
			_ = s.gate.Finished()
			s.drop("the session can no longer be logged")
			return errors.New("the session can no longer be logged")
		}
		if outside {
			s.approved(run)
		} else {
			serial := s.serial
			s.do(func() { s.run(serial, run) })
		}
	case gate.Rejected:
		s.drop(fmt.Sprintf("rejected by %s: %s", c.user.Name, strings.TrimSpace(q.Text)))
		s.logged(s.audit.Marker(fmt.Sprintf("rejected by %s: %s", c.user.Name, strings.TrimSpace(q.Text))))
		s.notice = fmt.Sprintf("rejected by %s: %s", c.user.Name, strings.ReplaceAll(strings.TrimSpace(q.Text), "\n", " "))
	}
	s.broadcast()
	return nil
}

func (s *session) currentDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dir
}

// inspect answers a witness's view or checksig, with their own permissions.
func (s *session) inspect(c *client, q wire.Request, store *sign.Store) wire.Reply {
	dir := s.currentDir()
	var r wire.Reply
	var err error
	d := audit.Data{"what": q.Type, "path": q.Text, "directory": dir}
	if q.Type == wire.View {
		r.Type = wire.Doc
		if r.Doc, err = view.Load(c.user, dir, q.Text); err == nil {
			d["sha256"] = r.Doc.SHA256
		}
	} else {
		var b strings.Builder
		r.Type = wire.Report
		var h string
		if h, err = view.Checksig(&b, c.user, dir, q.Text, store, s.actor); err == nil {
			d["sha256"] = h
		}
		r.Text = b.String()
	}
	s.log.Info(q.Type, "by", c.user.Name, "path", q.Text, "err", err)
	if err != nil {
		d["error"] = err.Error()
	}
	s.mu.Lock()
	ok := s.own(c, audit.Inspect, d)
	s.mu.Unlock()
	if !ok {
		return wire.Reply{Type: wire.Error, Text: "this cannot be logged"}
	}
	if err != nil {
		return wire.Reply{Type: wire.Error, Text: view.Escape(err.Error())}
	}
	return r
}

// reply queues an answer for one client, if it is still there.
func (s *session) reply(c *client, r wire.Reply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Contains(s.clients, c) {
		c.send(r)
	}
}

// serve handles a joined client's requests until it goes away.
func (s *session) serve(c *client) {
	for {
		var q wire.Request
		if err := wire.Read(c.conn, wire.MaxRequest, &q); err != nil {
			return
		}
		switch {
		case c.actor && q.Type == wire.Key:
			s.key(q.Data)
		case c.actor && q.Type == wire.Resize:
			s.mu.Lock()
			if !s.over {
				s.resize(q.Rows, q.Cols)
				s.broadcast()
			}
			s.mu.Unlock()
		case q.Type == wire.Ping:
			s.reply(c, wire.Reply{Type: wire.Pong})
		case !c.actor && q.Type == wire.Vote:
			if err := s.vote(c, q); err != nil {
				s.reply(c, wire.Reply{Type: wire.Error, Text: err.Error()})
			}
		case !c.actor && (q.Type == wire.View || q.Type == wire.Checksig):
			if len(c.out) >= maxDocs { // large answers must not pile up
				s.reply(c, wire.Reply{Type: wire.Error, Text: "too many requests"})
				continue
			}
			s.reply(c, s.inspect(c, q, s.d.store))
		case !c.actor && (q.Type == wire.Staged || q.Type == wire.Changes):
			if len(c.out) >= maxDocs {
				s.reply(c, wire.Reply{Type: wire.Error, Text: "too many requests"})
				continue
			}
			s.reply(c, s.showStaged(c, q))
		case !c.actor && q.Type == wire.Sha256:
			s.mu.Lock()
			busy := c.hashing
			c.hashing = true
			s.mu.Unlock()
			if busy {
				s.reply(c, wire.Reply{Type: wire.Error, Text: "still busy with the last one"})
				continue
			}
			s.do(func() { s.hash(c, q) })
		case !c.actor && q.Type == wire.Sign:
			r := wire.Reply{Type: wire.OK, Text: "signed"}
			if err := s.d.sign(c.user, q.Text); err != nil {
				r = wire.Reply{Type: wire.Error, Text: err.Error()}
			} else {
				s.mu.Lock()
				d := audit.Data{"by": c.user.Name, "uid": c.user.UID, "sha256": q.Text}
				s.note(audit.Signed, d, false)
				s.own(c, audit.Signed, d)
				s.mu.Unlock()
			}
			s.reply(c, r)
		default:
			s.reply(c, wire.Reply{Type: wire.Error, Text: "not allowed"})
		}
	}
}
