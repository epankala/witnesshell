// Package screen turns terminal output into rows of cells. It runs in a
// process of its own without privileges, since programs choose its input.
package screen

import (
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"

	"witnesshell/internal/view"
	"witnesshell/internal/wire"
)

// Emulator is a terminal.
type Emulator struct {
	em         *vt.Emulator
	drained    chan struct{} // closed when nothing reads em any more
	rows, cols int
	appKeys    bool
	paste      bool
	bells      uint64
	last       [][]wire.Run // as of the last Frame, of which
	lastRows   int          // these are the dimensions
	lastCols   int
}

// New returns an empty terminal.
func New(rows, cols int) *Emulator {
	e := &Emulator{}
	e.reset(rows, cols)
	return e
}

func (e *Emulator) reset(rows, cols int) {
	e.Close()
	e.rows, e.cols, e.appKeys, e.paste = rows, cols, false, false
	e.em = vt.NewEmulator(cols, rows)
	e.em.SetScrollbackSize(1)
	e.em.SetCallbacks(vt.Callbacks{
		Bell:        func() { e.bells++ },
		EnableMode:  func(m ansi.Mode) { e.mode(m, true) },
		DisableMode: func(m ansi.Mode) { e.mode(m, false) },
	})
	// Answers to queries are dropped: they would become typed input.
	e.drained = make(chan struct{})
	go func(em *vt.Emulator, done chan struct{}) {
		defer close(done)
		_, _ = io.Copy(io.Discard, em)
	}(e.em, e.drained)
}

// Close frees the terminal. The emulator's own Close may not be called while
// something reads it: its flag for that is not synchronised. So the reading is
// ended first, by closing the other end of its pipe.
func (e *Emulator) Close() {
	if e.em == nil {
		return
	}
	if w, ok := e.em.InputPipe().(*io.PipeWriter); ok {
		_ = w.Close()
		<-e.drained
	}
	_ = e.em.Close()
	e.em = nil
}

// mode notes the harmless input modes that the actor's keyboard must follow.
func (e *Emulator) mode(m ansi.Mode, on bool) {
	if d, ok := m.(ansi.DECMode); ok {
		switch int(d) {
		case 1:
			e.appKeys = on
		case 2004:
			e.paste = on
		}
	}
}

// Write feeds output to the terminal.
func (e *Emulator) Write(b []byte) {
	defer func() {
		if recover() != nil {
			e.reset(e.rows, e.cols)
		}
	}()
	_, _ = e.em.Write(b)
}

// Resize changes the size.
func (e *Emulator) Resize(rows, cols int) {
	defer func() {
		if recover() != nil {
			e.reset(rows, cols)
		}
	}()
	e.rows, e.cols = rows, cols
	e.em.Resize(cols, rows)
}

// Frame returns the rows that changed since the last call, and the rest.
func (e *Emulator) Frame() *wire.Frame {
	f := &wire.Frame{Rows: e.rows, Cols: e.cols, Hidden: e.em.CursorHidden(), AppKeys: e.appKeys, Paste: e.paste, Bells: e.bells}
	p := e.em.CursorPosition()
	f.CX, f.CY = max(0, min(p.X, e.cols-1)), max(0, min(p.Y, e.rows-1))
	all := e.lastRows != e.rows || e.lastCols != e.cols
	if all {
		e.last = make([][]wire.Run, e.rows)
		e.lastRows, e.lastCols = e.rows, e.cols
	}
	for y := range e.rows {
		r := e.row(y)
		if all || !slices.Equal(r, e.last[y]) {
			e.last[y] = r
			f.Lines = append(f.Lines, wire.Line{Y: y, Runs: r})
		}
	}
	return f
}

// row encodes a row as runs of equal style, without trailing blanks.
func (e *Emulator) row(y int) []wire.Run {
	var out []wire.Run
	add := func(text, style string, w int) {
		if n := len(out); n > 0 && out[n-1].S == style {
			out[n-1].T += text
			out[n-1].W += w
			return
		}
		out = append(out, wire.Run{T: text, S: style, W: w})
	}
	for x, width := 0, 0; x < e.cols; x++ {
		text, style, w := " ", "", 1
		if c := e.em.CellAt(x, y); c != nil {
			if c.Width == 0 && c.Content == "" && x > 0 {
				if prev := e.em.CellAt(x-1, y); prev != nil && prev.Width > 1 {
					continue // second half of a wide character
				}
			}
			if c.Content != "" {
				text, w = view.Escape(c.Content), max(1, c.Width)
				if ansi.StringWidth(text) != w { // Escape had to change it
					text, w = "?", 1
				}
			}
			if !c.Style.IsZero() {
				style = c.Style.String()
			}
		}
		if width+w > e.cols {
			break
		}
		width += w
		add(text, style, w)
	}
	if n := len(out); n > 0 && out[n-1].S == "" {
		t := strings.TrimRight(out[n-1].T, " ")
		out[n-1].W -= len(out[n-1].T) - len(t)
		if out[n-1].T = t; t == "" {
			out = out[:n-1]
		}
	}
	return out
}

// Messages to the process: a type, a length, and that many bytes.
const (
	MsgOutput = 'o'
	MsgResize = 'r' // rows and columns, 16 bits each
	maxMsg    = 64 << 10
)

// Message encodes a message.
func Message(typ byte, b []byte) []byte {
	return append(binary.BigEndian.AppendUint32([]byte{typ}, uint32(len(b))), b...)
}

// frameTime is the least time between frames.
const frameTime = 30 * time.Millisecond

// Serve reads messages and writes frames until in ends.
func Serve(in io.Reader, out io.Writer) error {
	type msg struct {
		typ byte
		b   []byte
	}
	msgs, done := make(chan msg), make(chan error, 1)
	go func() {
		for {
			var h [5]byte
			if _, err := io.ReadFull(in, h[:]); err != nil {
				done <- nil
				return
			}
			n := binary.BigEndian.Uint32(h[1:])
			if n > maxMsg {
				done <- errors.New("message too large")
				return
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(in, b); err != nil {
				done <- nil
				return
			}
			msgs <- msg{h[0], b}
		}
	}()
	e := New(24, 80)
	defer e.Close()
	dirty, last := true, time.Time{}
	tick := time.NewTicker(frameTime)
	defer tick.Stop()
	for {
		select {
		case m := <-msgs:
			switch {
			case m.typ == MsgOutput:
				e.Write(m.b)
			case m.typ == MsgResize && len(m.b) == 4:
				e.Resize(int(binary.BigEndian.Uint16(m.b)), int(binary.BigEndian.Uint16(m.b[2:])))
			}
			dirty = true
		case err := <-done:
			return err
		case <-tick.C:
		}
		if dirty && time.Since(last) >= frameTime {
			if err := wire.Write(out, e.Frame()); err != nil {
				return err
			}
			dirty, last = false, time.Now()
		}
	}
}
