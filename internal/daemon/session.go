package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"witnesshell/internal/gate"
	"witnesshell/internal/launch"
	"witnesshell/internal/pty"
	"witnesshell/internal/sign"
	"witnesshell/internal/view"
	"witnesshell/internal/wire"
)

// replaySize is how much output a new client gets to rebuild the screen.
const replaySize = 64 << 10

// client is one connection that has joined a session.
type client struct {
	conn    net.Conn
	user    launch.User
	actor   bool
	out     chan wire.Reply
	state   chan wire.Reply // the latest state; overtakes output
	lagging bool            // output was skipped; see output
}

func newClient(conn *net.UnixConn, u launch.User, actor bool) *client {
	// A large socket buffer would hold output that state cannot overtake.
	_ = conn.SetWriteBuffer(16 << 10)
	return &client{conn: conn, user: u, actor: actor, out: make(chan wire.Reply, 1024), state: make(chan wire.Reply, 1)}
}

// send queues a message. A client that cannot keep up is dropped; it can
// reconnect. Session lock held.
func (c *client) send(r wire.Reply) {
	select {
	case c.out <- r:
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

// writeLoop sends queued messages until the queue is closed.
func (c *client) writeLoop() {
	defer func() {
		_ = c.conn.Close()
		for range c.out { // discard
		}
	}()
	for {
		var r wire.Reply
		ok := true
		select {
		case r = <-c.state:
		default:
			select {
			case r = <-c.state:
			case r, ok = <-c.out:
			}
		}
		if !ok {
			return
		}
		_ = c.conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
		if err := wire.Write(c.conn, r); err != nil {
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

	mu         sync.Mutex
	gate       *gate.Gate
	keys       keys
	checking   bool
	serial     uint64 // of the prepared command
	details    []string
	warnings   []string
	dir        string
	notice     string
	replay     []byte
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
	s := &session{d: d, actor: u, weak: weak, gate: g, since: d.nextStart()}
	s.id = s.since.Format("20060102T150405.000Z")
	s.log = d.log.With("session", s.id, "actor", u.Name)
	s.rows, s.cols = clampSize(rows, cols)
	ptm, pts, err := pty.Open(s.rows, s.cols)
	if err != nil {
		return nil, err
	}
	defer pts.Close()
	s.ptm = ptm
	fail := func(err error) (*session, error) {
		_ = ptm.Close()
		s.removeCgroup()
		return nil, err
	}
	// Programs such as tty and mesg expect the user to own the terminal.
	if err := unix.Fchown(int(pts.Fd()), int(u.UID), -1); err != nil {
		return fail(err)
	}
	if err := unix.Fchmod(int(pts.Fd()), 0o600); err != nil {
		return fail(err)
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
	s.leader, s.dir, err = startLeader(leaderConfig{User: u, StoreDir: d.store.Dir, Keys: d.store.Keys, ExecDirs: d.c.ExecDirs}, pts, cg)
	if err != nil {
		return fail(err)
	}
	if len(weak) > 0 {
		s.notice = "this host does not meet the requirements; protection is weaker"
	}
	s.log.Info("session started", "weak", weak)
	go s.pump()
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

// pump copies terminal output to the clients.
func (s *session) pump() {
	b := make([]byte, 32<<10)
	for {
		n, err := s.ptm.Read(b)
		if n > 0 {
			s.mu.Lock()
			data := bytes.Clone(b[:n])
			s.replay = append(s.replay, data...)
			if len(s.replay) > 2*replaySize {
				s.replay = bytes.Clone(s.replay[len(s.replay)-replaySize:])
			}
			for _, c := range s.clients {
				s.output(c, data)
			}
			s.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// Output queue lengths at which a client counts as behind, and as caught up.
const (
	behind   = 16
	caughtUp = 4
)

// output sends terminal output to a client. One that cannot keep up misses
// some and then gets a fresh screen, so it delays nobody. Lock held.
func (s *session) output(c *client, data []byte) {
	if c.lagging {
		return
	}
	if len(c.out) < behind {
		c.send(wire.Reply{Type: wire.Output, Data: data})
		return
	}
	c.lagging = true
	s.catchUp(c)
}

func (s *session) catchUp(c *client) {
	time.AfterFunc(50*time.Millisecond, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !slices.Contains(s.clients, c) {
			return
		}
		if len(c.out) > caughtUp {
			s.catchUp(c)
			return
		}
		c.lagging = false
		c.send(wire.Reply{Type: wire.Output, Data: bytes.Clone(s.replay), Reset: true})
	})
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
	}
	if s.detach != nil {
		s.detach.Stop()
	}
	for _, c := range s.clients {
		c.send(wire.Reply{Type: wire.End, Text: why})
		close(c.out)
	}
	s.clients = nil
	s.mu.Unlock()
	s.log.Info("session ended", "why", why)
	_ = s.leader.in.Close() // lets an idle leader hang up its jobs
	_ = s.ptm.Close()       // hangs up the foreground job
	select {
	case <-s.leader.done:
	case <-time.After(time.Second):
	}
	// Nothing may outlive the session: it would be unwitnessed.
	s.removeCgroup()
}

var errOver = errors.New("the session is over")

// join adds a client and sends it the current screen.
func (s *session) join(c *client, rows, cols uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.over {
		return errOver
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
	c.send(wire.Reply{Type: wire.Output, Data: bytes.Clone(s.replay), Reset: true})
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
	close(c.out)
	return true
}

func (s *session) leave(c *client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.remove(c) {
		return
	}
	s.log.Info("left", "user", c.user.Name, "as_actor", c.actor)
	if c.actor {
		s.detach = time.AfterFunc(s.d.c.detach, func() { s.end("the actor was away too long") })
	}
	s.broadcast() // votes are kept (D13)
}

// resize sets the terminal size. Lock held.
func (s *session) resize(rows, cols uint16) {
	s.rows, s.cols = clampSize(rows, cols)
	_ = pty.Resize(s.ptm, s.rows, s.cols)
}

// broadcast sends the state to everyone. Lock held.
func (s *session) broadcast() {
	st := &wire.State{Session: s.id, Actor: s.actor.Name, Dir: s.dir, Rows: s.rows, Cols: s.cols,
		Required: s.gate.Required(), Notice: s.notice, Weak: s.weak}
	st.Draft, st.Cursor = s.gate.Draft()
	switch {
	case s.checking:
		st.Phase = wire.Checking
	case s.gate.State() == gate.Running:
		st.Phase = wire.Running
	case s.gate.State() == gate.Pending:
		st.Phase = wire.Pending
		r, _ := s.gate.Pending()
		st.ID, st.Text, st.Details, st.Warnings = r.ID, r.Text, s.details, s.warnings
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
			if d, _ := s.gate.Draft(); s.gate.State() == gate.Prompt && strings.TrimSpace(d) != "" {
				s.checking = true
				s.keys.reset() // what was typed ahead does not count
				go s.prepare(d)
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
		s.broadcast()
		return
	}
	s.serial, s.details, s.warnings = r.Serial, r.Details, r.Warnings
	if r.Free {
		if _, err = s.gate.SubmitFree(); err == nil {
			s.log.Info("free command", "text", text)
			go s.run(r.Serial)
		}
	} else {
		var req gate.Request
		if req, err = s.gate.Submit(); err == nil {
			s.log.Info("request", "id", req.ID, "text", text, "details", r.Details, "warnings", r.Warnings)
		}
	}
	if err != nil {
		s.notice = err.Error()
	}
	s.broadcast()
}

// run executes the prepared command and returns to the prompt.
func (s *session) run(serial uint64) {
	r, err := s.leader.call(leaderReq{Run: serial})
	s.mu.Lock()
	if s.over {
		s.mu.Unlock()
		return
	}
	_ = s.gate.Finished()
	s.keys.reset()
	s.dir = r.Dir
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
	if q.Approve {
		r, err = s.gate.Approve(c.user.UID, q.ID)
	} else {
		r, err = s.gate.Reject(c.user.UID, q.ID, q.Text)
	}
	if err != nil {
		return err
	}
	s.log.Info("vote", "id", q.ID, "by", c.user.Name, "approve", q.Approve, "comment", q.Text, "outcome", r.Outcome.String())
	switch r.Outcome {
	case gate.Approved:
		s.notice = ""
		go s.run(s.serial)
	case gate.Rejected:
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
	if q.Type == wire.View {
		r.Type = wire.Doc
		r.Doc, err = view.Load(c.user, dir, q.Text)
	} else {
		var b strings.Builder
		r.Type = wire.Report
		err = view.Checksig(&b, c.user, dir, q.Text, store, s.actor)
		r.Text = b.String()
	}
	s.log.Info(q.Type, "by", c.user.Name, "path", q.Text, "err", err)
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
		case !c.actor && q.Type == wire.Vote:
			if err := s.vote(c, q); err != nil {
				s.reply(c, wire.Reply{Type: wire.Error, Text: err.Error()})
			}
		case !c.actor && (q.Type == wire.View || q.Type == wire.Checksig):
			if len(c.out) > 16 { // large answers must not pile up
				s.reply(c, wire.Reply{Type: wire.Error, Text: "too many requests"})
				continue
			}
			s.reply(c, s.inspect(c, q, s.d.store))
		case !c.actor && q.Type == wire.Sign:
			r := wire.Reply{Type: wire.OK, Text: "signed"}
			if err := s.d.sign(c.user, q.Text); err != nil {
				r = wire.Reply{Type: wire.Error, Text: err.Error()}
			}
			s.reply(c, r)
		default:
			s.reply(c, wire.Reply{Type: wire.Error, Text: "not allowed"})
		}
	}
}
