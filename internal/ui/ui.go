// Package ui is the client's terminal interface. The session's screen is
// drawn from an emulator, cell by cell, above a panel that only this package
// writes to. Programs can therefore neither imitate the panel nor send
// commands to the user's terminal.
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

	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
	"golang.org/x/sys/unix"
	"golang.org/x/term"

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
	paging
	confirmSign
)

type ui struct {
	conn  net.Conn
	out   io.Writer
	actor bool
	rows  int
	cols  int

	em    *vt.Emulator
	st    wire.State
	modes map[int]bool // terminal modes programs have switched on

	mode    mode
	input   []rune
	pager   *view.Pager
	message string // answer to the last request
	scroll  int
	seenEnd bool // the request was shown to its end
	shownID uint64
	shownAt time.Time
	bell    bool
	prev    []string
	real    map[int]bool // modes set on the user's terminal
}

// Run joins a session over conn and returns why it ended.
func Run(conn net.Conn, q wire.Request, in, out *os.File) (string, error) {
	u := &ui{conn: conn, out: out, actor: q.Type == wire.Actor, modes: map[int]bool{}, real: map[int]bool{}}
	if err := u.size(out); err != nil {
		return "", err
	}
	u.newEmulator(80, 24)
	q.Rows, q.Cols = u.termSize()
	if err := wire.Write(conn, q); err != nil {
		return "", err
	}
	msgs := make(chan wire.Reply)
	errs := make(chan error, 1)
	go func() {
		for {
			var r wire.Reply
			if err := wire.Read(conn, wire.MaxReply, &r); err != nil {
				errs <- err
				return
			}
			msgs <- r
		}
	}()
	// The first answer says whether the request was accepted at all.
	var first wire.Reply
	select {
	case first = <-msgs:
	case err := <-errs:
		return "", fmt.Errorf("connection closed: %w", err)
	}
	if first.Type == wire.Error {
		return "", errors.New(escapeLines(first.Text))
	}
	old, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Fprint(out, "\x1b[?1049h\x1b[2J")
	defer func() {
		u.setModes(map[int]bool{})
		fmt.Fprint(out, "\x1b[0m\x1b[?25h\x1b[?1049l")
		_ = term.Restore(int(in.Fd()), old)
	}()
	keys := make(chan []byte)
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := in.Read(b)
			if err != nil || n == 0 {
				close(keys)
				return
			}
			keys <- append([]byte(nil), b[:n]...)
		}
	}()
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, unix.SIGWINCH)
	defer signal.Stop(winch)
	if why, over := u.receive(first); over {
		return why, nil
	}
	tick := time.NewTicker(30 * time.Millisecond)
	defer tick.Stop()
	dirty := true
	for {
		select {
		case r := <-msgs:
			if why, over := u.receive(r); over {
				return why, nil
			}
			dirty = true
		case err := <-errs:
			if errors.Is(err, io.EOF) {
				return "the connection was closed", nil
			}
			return "", err
		case k, ok := <-keys:
			if !ok {
				return "", nil
			}
			if u.key(k) {
				return "detached", nil
			}
			dirty = true
		case <-winch:
			if err := u.size(out); err != nil {
				return "", err
			}
			u.prev = nil
			fmt.Fprint(out, "\x1b[2J")
			if u.actor {
				r, c := u.termSize()
				u.request(wire.Request{Type: wire.Resize, Rows: r, Cols: c})
			}
			dirty = true
		case <-tick.C:
			if dirty {
				u.draw()
				dirty = false
			}
		}
	}
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
	_ = u.conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
	_ = wire.Write(u.conn, q) // a failure shows up when reading
}

func (u *ui) newEmulator(cols, rows int) {
	if u.em != nil {
		_ = u.em.Close()
	}
	u.em = vt.NewEmulator(cols, rows)
	u.em.SetScrollbackSize(1)
	u.modes = map[int]bool{}
	u.em.SetCallbacks(vt.Callbacks{
		Bell:        func() { u.bell = true },
		EnableMode:  func(m ansi.Mode) { u.mode7(m, true) },
		DisableMode: func(m ansi.Mode) { u.mode7(m, false) },
	})
	// Answers to queries are not sent on: they would be typed input.
	go func(em *vt.Emulator) { _, _ = io.Copy(io.Discard, em) }(u.em)
}

// mode7 notes the harmless input modes that the actor's keyboard must follow.
func (u *ui) mode7(m ansi.Mode, on bool) {
	if d, ok := m.(ansi.DECMode); ok && (int(d) == 1 || int(d) == 2004) {
		u.modes[int(d)] = on
	}
}

// feed gives output to the emulator, which handles hostile input.
func (u *ui) feed(b []byte) {
	defer func() {
		if recover() != nil {
			u.newEmulator(int(u.st.Cols), int(u.st.Rows))
			u.message = "the screen could not be shown and was reset"
		}
	}()
	_, _ = u.em.Write(b)
}

func (u *ui) receive(r wire.Reply) (why string, over bool) {
	switch r.Type {
	case wire.Output:
		if r.Reset {
			u.newEmulator(max(1, u.em.Width()), max(1, u.em.Height()))
		}
		u.feed(r.Data)
	case wire.StateType:
		if r.State == nil {
			break
		}
		u.st = *r.State
		if int(u.st.Cols) != u.em.Width() || int(u.st.Rows) != u.em.Height() {
			u.em.Resize(int(u.st.Cols), int(u.st.Rows))
		}
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
	if u.actor {
		for i, c := range b {
			if c == detachKey {
				if i > 0 {
					u.request(wire.Request{Type: wire.Key, Data: b[:i]})
				}
				return true
			}
		}
		u.request(wire.Request{Type: wire.Key, Data: b})
		return false
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
			if u.mode != comment && u.mode != askView && u.mode != askSig {
				break
			}
			u.editKey(string(r))
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
