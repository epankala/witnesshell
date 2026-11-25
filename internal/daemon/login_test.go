package daemon

import (
	"testing"
	"time"

	"witnesshell/internal/wire"
)

func TestLogins(t *testing.T) {
	l := logins{life: time.Minute}
	now := time.Now()
	closed := make(chan int, 10)
	conn := func(n int) func() { return func() { closed <- n } }
	s, g, n1, err := l.start(7, now, conn(1))
	if err != nil || len(s) < 40 {
		t.Fatal(s, err)
	}
	// A live login can be resumed at any time, and the old connection goes.
	g2, n2, err := l.resume(s, now.Add(time.Hour), conn(2))
	if err != nil || g2 != g || g.uid != 7 {
		t.Fatal(err)
	}
	if n := <-closed; n != 1 {
		t.Fatal(n)
	}
	// The old connection's end must not end the login.
	l.ended(g, n1, true, now)
	l.ended(g, n2, false, now)
	if _, _, err := l.resume(s, now.Add(time.Minute), conn(3)); err == nil {
		t.Fatal("resumed after the timeout")
	}
	_, n3, err := l.resume(s, now.Add(time.Minute-1), conn(3))
	if err != nil {
		t.Fatal(err)
	}
	l.ended(g, n3, true, now) // quit
	if _, _, err := l.resume(s, now, conn(4)); err == nil {
		t.Fatal("resumed after quitting")
	}
	for _, bad := range []string{"", "x", s + "x"} {
		if _, _, err := l.resume(bad, now, conn(5)); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	for range loginsPerUID {
		_, g, n, err := l.start(8, now, conn(6))
		if err != nil {
			t.Fatal(err)
		}
		l.ended(g, n, false, now)
	}
	if _, _, _, err := l.start(8, now, conn(6)); err == nil {
		t.Fatal("no limit")
	}
	if _, _, _, err := l.start(8, now.Add(time.Minute), conn(6)); err != nil || len(l.m) != 1 {
		t.Fatal("expired logins kept", err, len(l.m))
	}
}

func TestScreenState(t *testing.T) {
	run := func(s string) []wire.Run { return []wire.Run{{T: s, W: len(s)}} }
	var s screenState
	s.apply(&wire.Frame{Rows: 3, Cols: 10, Lines: []wire.Line{{Y: 0, Runs: run("a")}, {Y: 1, Runs: run("b")}}})
	f, v := s.since(0)
	if len(f.Lines) != 3 || f.Lines[1].Runs[0].T != "b" {
		t.Fatalf("%+v", f)
	}
	s.apply(&wire.Frame{Rows: 3, Cols: 10, CX: 4, Lines: []wire.Line{{Y: 1, Runs: run("c")}}})
	s.apply(&wire.Frame{Rows: 3, Cols: 10, CX: 5})
	if f, _ := s.since(v); len(f.Lines) != 1 || f.Lines[0].Runs[0].T != "c" || f.CX != 5 {
		t.Fatalf("%+v", f)
	}
	if f, _ := s.since(0); len(f.Lines) != 3 || f.Lines[0].Runs[0].T != "a" {
		t.Fatalf("%+v", f)
	}
	_, v = s.since(0)
	s.apply(&wire.Frame{Rows: 2, Cols: 10})
	if f, _ := s.since(v); len(f.Lines) != 2 || len(f.Lines[0].Runs) != 0 {
		t.Fatalf("a new size must clear every row: %+v", f)
	}
}

func TestCheckFrame(t *testing.T) {
	ok := wire.Frame{Rows: 2, Cols: 5, Lines: []wire.Line{{Y: 1}}}
	if err := checkFrame(&ok); err != nil {
		t.Fatal(err)
	}
	for _, f := range []wire.Frame{{}, {Rows: 2}, {Rows: 301, Cols: 5}, {Rows: 2, Cols: 501}, {Rows: 2, Cols: 5, CY: 2}, {Rows: 2, Cols: 5, CX: -1},
		{Rows: 2, Cols: 5, Lines: []wire.Line{{Y: 2}}}, {Rows: 2, Cols: 5, Lines: []wire.Line{{Y: -1}}}, {Rows: 1, Cols: 5, Lines: make([]wire.Line, 2)},
		{Rows: 2, Cols: 1, Lines: []wire.Line{{Runs: make([]wire.Run, 2)}}}} {
		if checkFrame(&f) == nil {
			t.Errorf("accepted %+v", f)
		}
	}
}
