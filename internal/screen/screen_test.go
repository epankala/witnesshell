package screen

import (
	"io"
	"strings"
	"testing"
	"time"

	"witnesshell/internal/wire"
)

func text(e *Emulator) string {
	var out []string
	for y := range e.rows {
		s := ""
		for _, r := range e.row(y) {
			s += r.T
		}
		out = append(out, s)
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

func TestRows(t *testing.T) {
	e := New(4, 10)
	e.Write([]byte("a\r\n\x1b[31mred\x1b[0m  x\r\n日本\x1b[?1h\x1b[?2004h\x07"))
	if got := text(e); got != "a\nred  x\n日本" {
		t.Fatalf("%q", got)
	}
	f := e.Frame()
	if len(f.Lines) != 4 || f.CY != 2 || f.CX != 4 || !f.AppKeys || !f.Paste || f.Bells != 1 {
		t.Fatalf("%+v", f)
	}
	if r := f.Lines[1].Runs; len(r) != 2 || r[0].T != "red" || r[0].S == "" || r[0].W != 3 || r[1].W != 3 {
		t.Fatalf("%+v", r)
	}
	if f := e.Frame(); len(f.Lines) != 0 {
		t.Fatalf("unchanged rows sent: %+v", f)
	}
	e.Write([]byte("\x1b[1;1Hb"))
	if f := e.Frame(); len(f.Lines) != 1 || f.Lines[0].Y != 0 || f.Lines[0].Runs[0].T != "b" {
		t.Fatalf("%+v", f)
	}
	e.Resize(3, 20)
	if f := e.Frame(); len(f.Lines) != 3 || f.Cols != 20 {
		t.Fatalf("%+v", f)
	}
}

func TestAlternateScreenComesBack(t *testing.T) {
	e := New(4, 20)
	e.Write([]byte("before\x1b[?1049h\x1b[2J\x1b[1;1Hediting"))
	if got := text(e); got != "editing" {
		t.Fatalf("%q", got)
	}
	e.Write([]byte("\x1b[?1049l"))
	if got := text(e); got != "before" {
		t.Fatalf("%q", got)
	}
}

func TestServe(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(inR, outW) }()
	frames := make(chan *wire.Frame, 100)
	go func() {
		for {
			var f wire.Frame
			if wire.Read(outR, 1<<20, &f) != nil {
				return
			}
			frames <- &f
		}
	}()
	_, _ = inW.Write(Message(MsgResize, []byte{0, 5, 0, 30}))
	for range 5000 {
		_, _ = inW.Write(Message(MsgOutput, []byte("line\r\n")))
	}
	_, _ = inW.Write(Message(MsgOutput, []byte("last")))
	for timeout := time.After(10 * time.Second); ; {
		select {
		case f := <-frames:
			if f.Rows == 5 && len(f.Lines) > 0 {
				l := f.Lines[len(f.Lines)-1]
				if l.Y == 4 && len(l.Runs) > 0 && l.Runs[0].T == "last" {
					_ = inW.Close()
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					return
				}
			}
		case <-timeout:
			t.Fatal("no final frame")
		}
	}
}

func TestTooLarge(t *testing.T) {
	if err := Serve(strings.NewReader("o\xff\xff\xff\xff"), io.Discard); err == nil {
		t.Fatal("accepted")
	}
}

func FuzzEmulator(f *testing.F) {
	f.Add([]byte("\x1b[2J\x1b[999;1HX\x1b[31mred\x1bc"), uint8(5))
	f.Fuzz(func(t *testing.T, b []byte, n uint8) {
		e := New(10, 40)
		defer e.Close()
		e.Write(b)
		e.Resize(int(n%50)+1, int(n/5)+1)
		e.Write(b)
		fr := e.Frame()
		for _, l := range fr.Lines {
			w := 0
			for _, r := range l.Runs {
				w += r.W
			}
			if w > fr.Cols || l.Y >= fr.Rows {
				t.Fatalf("row %d is %d wide of %d", l.Y, w, fr.Cols)
			}
		}
	})
}
