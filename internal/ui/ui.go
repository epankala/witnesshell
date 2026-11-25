// Package ui is the client's terminal interface. The session's screen comes as
// rows of text and is drawn above a panel that only this package writes to.
// Programs can therefore neither imitate the panel nor send commands to the
// user's terminal.
package ui

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"witnesshell/internal/transfer"
	"witnesshell/internal/transport"
	"witnesshell/internal/view"
	"witnesshell/internal/wire"
)

const (
	actorPanel = 3
	detachKey  = 0x1d // Ctrl-]
	// voteDelay is how long a request must be visible before it can be
	// approved, so that a key meant for something else does not count.
	voteDelay = 700 * time.Millisecond
)

type mode uint8

const (
	watching mode = iota
	comment
	askView
	askSig
	askHash
	menu // the actor's own, opened with Ctrl-]
	askSend
	askSendTo
	askGet
	askGetTo
	paging
	confirmSign
)

type ui struct {
	conn  net.Conn
	out   io.Writer
	actor bool
	rows  int
	cols  int

	frame wire.Frame   // without Lines
	lines [][]wire.Run // the screen
	st    wire.State

	retry   bool      // a lost connection is made again
	lost    time.Time // since when there is none; zero if there is one
	heard   time.Time // when something last arrived
	joining bool      // no state has come over this connection yet

	mode    mode
	input   []rune
	pager   *view.Pager
	message string // answer to the last request
	scroll  int
	seenEnd bool // the request was shown to its end
	shownID uint64
	shownAt time.Time
	bell    bool
	local   string // what the first question of a transfer was answered with
	copying bool
	done    chan struct{}
	notes   chan note
	open    func() (net.Conn, error)
	prev    []string
	real    map[int]bool // modes set on the user's terminal
}

// Result says how Run ended.
type Result struct {
	Why   string
	Ended bool // the daemon ended it, rather than the user leaving
}

// Joiner makes connections to a session.
type Joiner interface {
	// Join connects and sends q. If q asks for frames on a separate stream,
	// that arrives on the channel.
	Join(q wire.Request) (net.Conn, <-chan io.Reader, error)
	// Retry reports whether a lost connection should be made again.
	Retry() bool
	// Open makes a connection for copying a file; nil if that is impossible.
	Open() func() (net.Conn, error)
}

// note is news about a file that is being copied.
type note struct {
	text string
	done bool
}

const (
	pingEvery = 3 * time.Second
	quiet     = 7 * time.Second // without an answer before the user is told
	giveUp    = 35 * time.Minute
)

type event struct {
	gen int // which connection it is about
	r   wire.Reply
	err error
}

// Run joins a session. Nothing reads from in once it has returned.
func Run(j Joiner, q wire.Request, in, out *os.File) (Result, error) {
	u := &ui{out: out, actor: q.Type == wire.Actor, real: map[int]bool{}, retry: j.Retry(), open: j.Open(), notes: make(chan note)}
	if err := u.size(out); err != nil {
		return Result{}, err
	}
	q.Rows, q.Cols = u.termSize()
	done := make(chan struct{})
	defer close(done)
	u.done = done
	events := make(chan event)
	gen := 0
	// use starts reading from a new connection.
	use := func(conn net.Conn, screen <-chan io.Reader) {
		gen++
		g := gen
		receive := func(from io.Reader, failed func(error)) {
			for {
				var r wire.Reply
				if err := wire.Read(from, wire.MaxReply, &r); err != nil {
					failed(err)
					return
				}
				select {
				case events <- event{gen: g, r: r}:
				case <-done:
					return
				}
			}
		}
		u.conn, u.lost, u.heard, u.joining = conn, time.Time{}, time.Now(), true
		go receive(conn, func(err error) {
			select {
			case events <- event{gen: g, err: err}:
			case <-done:
			}
		})
		if screen != nil {
			go func() {
				select {
				case s := <-screen:
					receive(s, func(error) {}) // conn tells what happened
				case <-done:
				}
			}()
		}
	}
	conn, screen, err := j.Join(q)
	if err != nil {
		return Result{}, err
	}
	use(conn, screen)
	defer func() {
		if u.conn != nil {
			_ = u.conn.Close()
		}
	}()
	// The first answer says whether the request was accepted at all.
	first := <-events
	if first.err != nil {
		return Result{}, fmt.Errorf("connection closed: %w", first.err)
	}
	if first.r.Type == wire.Error {
		return Result{}, errors.New(escapeLines(first.r.Text))
	}
	old, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return Result{}, err
	}
	fmt.Fprint(out, "\x1b[?1049h\x1b[2J")
	defer func() {
		u.setModes(map[int]bool{})
		fmt.Fprint(out, "\x1b[0m\x1b[?25h\x1b[?1049l")
		_ = term.Restore(int(in.Fd()), old)
	}()
	keys, stopKeys, err := readKeys(in)
	if err != nil {
		return Result{}, err
	}
	defer stopKeys()
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, unix.SIGWINCH)
	defer signal.Stop(winch)
	if why, over := u.receive(first.r); over {
		return Result{why, true}, nil
	}
	type joined struct {
		conn   net.Conn
		screen <-chan io.Reader
		err    error
	}
	rejoined := make(chan joined)
	tick := time.NewTicker(30 * time.Millisecond)
	defer tick.Stop()
	ping := time.NewTicker(pingEvery)
	defer ping.Stop()
	dirty := true
	for {
		select {
		case e := <-events:
			if e.gen != gen {
				break // from a connection that was given up
			}
			if e.err != nil {
				_ = u.conn.Close()
				u.conn = nil
				if !u.retry || u.st.Session == "" {
					if errors.Is(e.err, io.EOF) {
						return Result{Why: "the connection was closed"}, nil
					}
					return Result{}, e.err
				}
				gen++ // nothing more from it
				u.lost, dirty = time.Now(), true
				again := wire.Request{Type: q.Type, Session: u.st.Session}
				again.Rows, again.Cols = u.termSize()
				go func(since time.Time) {
					for {
						c, s, err := j.Join(again)
						if err != nil && !errors.Is(err, transport.ErrRefused) && time.Since(since) < giveUp {
							select {
							case <-time.After(time.Second):
								continue
							case <-done:
								return
							}
						}
						select {
						case rejoined <- joined{c, s, err}:
						case <-done:
							if c != nil {
								_ = c.Close()
							}
						}
						return
					}
				}(u.lost)
				break
			}
			u.heard = time.Now()
			if u.joining && e.r.Type == wire.Error { // the session is gone
				return Result{escapeLines(e.r.Text), true}, nil
			}
			if why, over := u.receive(e.r); over {
				return Result{why, true}, nil
			}
			dirty = true
		case n := <-u.notes:
			u.message, dirty = n.text, true
			if n.done {
				u.copying = false
			}
		case n := <-rejoined:
			if n.err != nil {
				return Result{Why: "the session could not be resumed: " + n.err.Error()}, nil
			}
			use(n.conn, n.screen)
			if r, c := u.termSize(); u.actor { // it may have changed meanwhile
				u.request(wire.Request{Type: wire.Resize, Rows: r, Cols: c})
			}
			u.message, dirty = "", true
		case k, ok := <-keys:
			if !ok {
				return Result{}, nil
			}
			if u.key(k) {
				return Result{Why: "detached"}, nil
			}
			dirty = true
		case <-winch:
			if err := u.size(out); err != nil {
				return Result{}, err
			}
			u.prev = nil
			fmt.Fprint(out, "\x1b[2J")
			if u.actor {
				r, c := u.termSize()
				u.request(wire.Request{Type: wire.Resize, Rows: r, Cols: c})
			}
			dirty = true
		case <-ping.C:
			if u.retry && u.conn != nil {
				u.request(wire.Request{Type: wire.Ping})
			}
		case <-tick.C:
			if dirty || u.trouble() != "" {
				u.draw()
				dirty = false
			}
		}
	}
}

// maxDownload bounds what is taken from a host.
const maxDownload = 1 << 40

// trouble describes what is wrong with the connection, if anything.
func (u *ui) trouble() string {
	clock := func(t time.Time) string {
		s := int(time.Since(t).Seconds())
		return fmt.Sprintf("%d:%02d", s/60, s%60)
	}
	switch {
	case !u.lost.IsZero():
		return "CONNECTION LOST, reconnecting " + clock(u.lost) + "   (Ctrl-] quits)"
	case u.retry && time.Since(u.heard) > quiet:
		return "NO ANSWER for " + clock(u.heard)
	}
	return ""
}

// readKeys delivers what is typed until stop is called, which waits until
// nothing reads from in any more and drops what was typed but not read.
func readKeys(in *os.File) (keys <-chan []byte, stop func(), err error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	fd, rfd := int(in.Fd()), int(r.Fd())
	ch, done, gone := make(chan []byte), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(gone)
		b := make([]byte, 4096)
		for {
			p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}, {Fd: int32(rfd), Events: unix.POLLIN}}
			if _, err := unix.Poll(p, -1); err == unix.EINTR {
				continue
			} else if err != nil || p[1].Revents != 0 {
				return
			}
			n, err := unix.Read(fd, b)
			if err == unix.EINTR {
				continue
			}
			if err != nil || n <= 0 {
				close(ch)
				return
			}
			select {
			case ch <- append([]byte(nil), b[:n]...):
			case <-done:
				return
			}
		}
	}()
	return ch, func() {
		close(done)
		_ = w.Close() // wakes the poll
		<-gone
		_ = r.Close()
		_ = unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
	}, nil
}

func escapeLines(s string) string {
	l := strings.Split(s, "\n")
	for i := range l {
		l[i] = view.Escape(l[i])
	}
	return strings.Join(l, "\n")
}

func (u *ui) size(f *os.File) error {
	c, r, err := term.GetSize(int(f.Fd()))
	u.rows, u.cols = max(r, 8), max(c, 20)
	return err
}

// termSize is the space the actor's window leaves for the session.
func (u *ui) termSize() (rows, cols uint16) {
	return uint16(max(4, u.rows-actorPanel)), uint16(u.cols)
}

func (u *ui) request(q wire.Request) {
	q.Version = wire.Version
	if u.conn == nil {
		// Not kept for later: it was meant for what is on the screen now.
		u.message = "not sent: there is no connection"
		return
	}
	_ = u.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = wire.Write(u.conn, q) // a failure shows up when reading
}

// maxSide bounds the size of a screen.
const maxSide = 1000

// newFrame applies a frame to the screen.
func (u *ui) newFrame(f *wire.Frame) {
	if f.Rows < 1 || f.Cols < 1 || f.Rows > maxSide || f.Cols > maxSide {
		return
	}
	if f.Rows != u.frame.Rows || f.Cols != u.frame.Cols {
		u.lines = make([][]wire.Run, f.Rows)
	}
	for _, l := range f.Lines {
		if l.Y >= 0 && l.Y < f.Rows {
			u.lines[l.Y] = l.Runs
		}
	}
	u.bell = u.bell || u.frame.Rows > 0 && f.Bells > u.frame.Bells
	u.frame = *f
	u.frame.Lines = nil
}

func (u *ui) receive(r wire.Reply) (why string, over bool) {
	switch r.Type {
	case wire.FrameType:
		if r.Frame != nil {
			u.newFrame(r.Frame)
		}
	case wire.StateType:
		if r.State == nil {
			break
		}
		u.st = *r.State
		u.joining = false
		if u.st.ID != u.shownID {
			u.shownID, u.shownAt = u.st.ID, time.Now()
			u.scroll, u.seenEnd, u.message = 0, false, ""
			if u.mode == comment {
				u.mode = watching
			}
			u.bell = u.bell || !u.actor && u.st.ID != 0
		}
	case wire.Doc:
		if r.Doc == nil {
			break
		}
		for i := range r.Doc.Lines { // never trust what came over the wire
			r.Doc.Lines[i] = view.Escape(r.Doc.Lines[i])
		}
		u.mode, u.pager = paging, &view.Pager{Doc: r.Doc}
	case wire.Report:
		d := &view.Doc{Path: "signature"}
		for _, l := range strings.Split(strings.TrimSpace(r.Text), "\n") {
			d.Lines = append(d.Lines, view.Escape(l))
		}
		u.mode, u.pager = paging, &view.Pager{Doc: d}
	case wire.OK, wire.Error:
		u.message = r.Text
	case wire.End:
		return r.Text, true
	}
	return "", false
}

// key handles typed bytes. It reports whether to leave.
func (u *ui) key(b []byte) bool {
	if u.actor && u.mode == watching {
		for i, c := range b {
			if c != detachKey {
				continue
			}
			if i > 0 && u.conn != nil {
				u.request(wire.Request{Type: wire.Key, Data: b[:i]})
			}
			if u.open == nil || u.conn == nil {
				return true
			}
			// What follows in the same piece was not typed in answer to the menu.
			u.mode, u.message = menu, ""
			return false
		}
		u.request(wire.Request{Type: wire.Key, Data: b})
		return false
	}
	if u.mode == menu {
		return u.menuKey(b[0])
	}
	s := string(b)
	if b[0] == 0x1b && len(b) > 1 && (u.mode == watching || u.mode == paging) {
		k, ok := map[string]byte{"\x1b[A": 'k', "\x1b[B": 'j', "\x1b[5~": 'b', "\x1b[6~": ' '}[s]
		if !ok {
			return false
		}
		b = []byte{k}
	}
	switch u.mode {
	case watching:
		return u.watchKey(b[0])
	case paging:
		lines := u.pager.Wrap(u.cols)
		if b[0] == 'S' && u.pager.Doc.SHA256 != "" {
			u.mode = confirmSign
		} else if u.pager.Key(b[0], u.rows-2, len(lines)) {
			u.mode, u.prev = watching, nil
		}
	case confirmSign:
		if s == "y" {
			u.request(wire.Request{Type: wire.Sign, Text: u.pager.Doc.SHA256})
			u.mode, u.prev = watching, nil
		} else {
			u.mode = paging
		}
	default:
		if b[0] == 0x1b && len(b) > 1 {
			return false // arrows and the like
		}
		for _, r := range s {
			// After Enter the rest must not be taken as other keys.
			if m := u.mode; m == watching || m == paging {
				break
			} else if u.editKey(string(r)); u.mode != m {
				break
			}
		}
	}
	return false
}

func (u *ui) watchKey(k byte) bool {
	switch k {
	case 'a':
		switch {
		case u.st.Phase != wire.Pending:
			u.message = "nothing to approve"
		case !u.seenEnd:
			u.message = "read to the end first (space)"
		case time.Since(u.shownAt) < voteDelay:
			u.message = "that was very quick; press again if you mean it"
		default:
			u.request(wire.Request{Type: wire.Vote, ID: u.shownID, Approve: true})
		}
	case 'r':
		if u.st.Phase == wire.Pending {
			u.mode, u.input = comment, nil
		} else {
			u.message = "nothing to reject"
		}
	case 'v':
		u.mode, u.input = askView, nil
	case 's':
		u.mode, u.input = askSig, nil
	case 'h':
		u.mode, u.input = askHash, nil
	case 'o', 'd':
		if !u.st.Transfer {
			u.message = "no file is waiting for approval"
		} else if k == 'o' {
			u.request(wire.Request{Type: wire.Staged})
		} else {
			u.request(wire.Request{Type: wire.Changes})
		}
	case ' ', 'f':
		u.scroll += max(1, u.detailRows())
	case 'b':
		u.scroll -= max(1, u.detailRows())
	case 'j', '\r':
		u.scroll++
	case 'k':
		u.scroll--
	case 'q', detachKey:
		return true
	}
	return false
}

// menuKey handles the actor's menu, of which the host knows nothing.
func (u *ui) menuKey(k byte) bool {
	u.mode, u.input = watching, nil
	switch k {
	case 'd', detachKey:
		return true
	case 'u', 'g':
		switch {
		case u.copying:
			u.message = "a file is being copied already"
		case k == 'u':
			u.mode = askSend
		default:
			u.mode = askGet
		}
	}
	return false
}

// copyFile runs a transfer in the background.
func (u *ui) copyFile(f func(say func(string)) error, done string) {
	u.copying = true
	tell := func(n note) {
		select {
		case u.notes <- n:
		case <-u.done:
		}
	}
	go func() {
		last := time.Time{}
		err := f(func(s string) {
			if time.Since(last) > 200*time.Millisecond || !strings.HasSuffix(s, "%") {
				last = time.Now()
				tell(note{s, false})
			}
		})
		if err != nil {
			done = "NOT COPIED: " + err.Error()
		}
		tell(note{done, true})
	}()
}

func (u *ui) editKey(s string) {
	switch {
	case s == "\r" || s == "\n":
		text := strings.TrimSpace(string(u.input))
		switch {
		case text == "" && u.mode == comment:
			u.message = "a rejection needs a comment"
			return
		case text == "":
		case u.mode == comment:
			u.request(wire.Request{Type: wire.Vote, ID: u.shownID, Text: text})
		case u.mode == askView:
			u.request(wire.Request{Type: wire.View, Text: text})
		case u.mode == askSig:
			u.request(wire.Request{Type: wire.Checksig, Text: text})
		case u.mode == askHash:
			u.request(wire.Request{Type: wire.Sha256, Text: text})
		case u.mode == askSend:
			u.local, u.mode, u.input = text, askSendTo, nil
			return
		case u.mode == askGet:
			u.local, u.mode, u.input = text, askGetTo, nil
			return
		case u.mode == askSendTo:
			session, local := u.st.Session, u.local
			u.copyFile(func(say func(string)) error { return transfer.Upload(u.open, session, local, text, say) }, "uploaded")
		case u.mode == askGetTo:
			session, remote := u.st.Session, u.local
			u.copyFile(func(say func(string)) error {
				return transfer.Download(u.open, session, remote, text, maxDownload, say)
			}, "saved as "+text)
		}
		u.mode, u.message = watching, ""
	case s == "\x1b" || s == "\x03":
		u.mode = watching
	case s == "\x7f" || s == "\x08":
		if len(u.input) > 0 {
			u.input = u.input[:len(u.input)-1]
		}
	case s == "\x15":
		u.input = nil
	default:
		if strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0 && s != string(utf8.RuneError) && len(u.input) < 1000 {
			u.input = append(u.input, []rune(s)...)
		}
	}
}
