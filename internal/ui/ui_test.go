package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/charmbracelet/x/vt"

	"witnesshell/internal/wire"
)

func BenchmarkScroll(b *testing.B) {
	for _, n := range []int{1, 100, 10000} {
		b.Run(strings.Repeat("s", len(strings.Repeat("x", n))%7+1), func(b *testing.B) {
			em := vt.NewEmulator(110, 27)
			em.SetScrollbackSize(n)
			data := bytes.Repeat([]byte("y\r\n"), 1000)
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				_, _ = em.Write(data)
			}
		})
	}
}

func testUI(actor bool) (*ui, *bytes.Buffer) {
	var out bytes.Buffer
	u := &ui{out: &out, actor: actor, rows: 24, cols: 80, modes: map[int]bool{}, real: map[int]bool{}}
	u.newEmulator(80, 21)
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
		defer u.em.Close()
		u.feed(data)
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
	})
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
