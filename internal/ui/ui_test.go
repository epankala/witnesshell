package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"witnesshell/internal/screen"
	"witnesshell/internal/wire"
)

func testUI(actor bool) (*ui, *bytes.Buffer) {
	var out bytes.Buffer
	u := &ui{out: &out, actor: actor, rows: 24, cols: 80, real: map[int]bool{}}
	u.st = wire.State{Actor: "alice", Rows: 21, Cols: 80, Phase: wire.Prompt}
	return u, &out
}

// FuzzScreen checks that no output of a program gets past the emulator: what
// reaches the user's terminal holds only text, colors and cursor movement.
func FuzzScreen(f *testing.F) {
	f.Add([]byte("\x1b]0;x\x07\x1b[2J\x1b[999;1HX\x1b[31mred\x1bc\x1bP+q\x1b\\"), true)
	f.Add([]byte("日本\x1b[1;1H\xff\xfe‮́é"), false)
	f.Fuzz(func(t *testing.T, data []byte, actor bool) {
		u, out := testUI(actor)
		e := screen.New(21, 80)
		defer e.Close()
		e.Write(data)
		u.newFrame(e.Frame())
		checkScreen(t, u, out)
		// Nor may a hostile host do what a program cannot.
		u, out = testUI(actor)
		u.newFrame(&wire.Frame{Rows: 2, Cols: 80, CX: int(int8(len(data))), CY: len(data) - 3, Lines: []wire.Line{
			{Y: 0, Runs: []wire.Run{{T: string(data), S: string(data), W: len(data)}}}, {Y: -1}, {Y: 9},
			{Y: 1, Runs: []wire.Run{{T: string(data), W: len([]rune(string(data)))}, {W: -5}, {W: 1 << 40}}}}})
		checkScreen(t, u, out)
	})
}

func checkScreen(t *testing.T, u *ui, out *bytes.Buffer) {
	t.Helper()
	{
		u.draw()
		s := strings.ReplaceAll(out.String(), "\a", "")
		for _, l := range u.prev {
			if strings.ContainsAny(l, "\r\n") {
				t.Fatalf("line break in row %q", l)
			}
		}
		for i := 0; i < len(s); i++ {
			switch {
			case s[i] == 0x1b:
				j := i + 2
				if i+1 >= len(s) || s[i+1] != '[' {
					t.Fatalf("escape sequence in %q", s[i:min(len(s), i+20)])
				}
				for j < len(s) && strings.IndexByte("0123456789;:?", s[j]) >= 0 {
					j++
				}
				if j >= len(s) || strings.IndexByte("mHhl", s[j]) < 0 {
					t.Fatalf("escape sequence in %q", s[i:min(len(s), j+1)])
				}
				i = j
			case s[i] < 0x20 || s[i] == 0x7f:
				t.Fatalf("control character %q", s[i])
			}
		}
		// The panel is at the bottom and is ours.
		n := u.rows - u.panelRows()
		if len(u.prev) != u.rows || !strings.Contains(u.prev[n], "alice") {
			t.Fatalf("panel missing: %q", u.prev)
		}
	}
}

func TestCommentInOneChunk(t *testing.T) {
	u, _ := testUI(false)
	u.st.Phase = wire.Pending
	u.mode = comment
	u.key([]byte("no"))
	u.key([]byte("\x7f\x7fab"))
	if string(u.input) != "ab" {
		t.Fatalf("%q", string(u.input))
	}
	u.key([]byte("\x1b[A"))
	u.key([]byte("\x1b"))
	if u.mode != watching {
		t.Fatal("escape did not leave")
	}
}

func TestNoConnection(t *testing.T) {
	u, out := testUI(false)
	u.st.Phase, u.st.ID, u.shownID, u.seenEnd, u.retry = wire.Pending, 1, 1, true, true
	u.lost = time.Now().Add(-65 * time.Second)
	u.key([]byte("a"))
	if u.message != "not sent: there is no connection" {
		t.Fatal(u.message)
	}
	u.draw()
	if !strings.Contains(out.String(), "CONNECTION LOST, reconnecting 1:05") {
		t.Fatalf("%q", out.String())
	}
	u.lost, u.heard = time.Time{}, time.Now().Add(-9*time.Second)
	if !strings.HasPrefix(u.trouble(), "NO ANSWER for 0:0") {
		t.Fatal(u.trouble())
	}
	if !u.key([]byte("q")) {
		t.Fatal("cannot leave")
	}
}
