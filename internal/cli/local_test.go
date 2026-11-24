package cli

import (
	"errors"
	"io"
	"strings"
	"testing"

	"witnesshell/internal/wire"
)

func TestChoose(t *testing.T) {
	al := wire.Session{ID: "A", Actor: "alice"}
	own := wire.Session{ID: "O", Actor: "bob", Own: true}
	for i, c := range []struct {
		sessions []wire.Session
		can      bool
		start    bool
		id       string
		lobby    bool
		in       string
		typ, ses string // expected; empty typ means an error
	}{
		{can: true, typ: wire.Actor},
		{sessions: []wire.Session{al}, can: true, start: true, typ: wire.Actor},
		{sessions: []wire.Session{al, own}, can: true, in: "1\n", typ: wire.Witness, ses: "A"},
		{sessions: []wire.Session{al, own}, can: true, in: "2\n", typ: wire.Actor, ses: "O"},
		{sessions: []wire.Session{al}, can: true, in: "x\n9\nn\n", typ: wire.Actor},
		{sessions: []wire.Session{al}, in: "n\nn\nn\n"},
		{sessions: []wire.Session{al}, id: "A", typ: wire.Witness, ses: "A"},
		{sessions: []wire.Session{al}, id: "B"},
		{lobby: true, can: true, in: "q\n"}, // must not start a session by itself
		{lobby: true, can: true, in: ""},
		{lobby: true, can: true, in: "\n\n\n\n\nr\nn\n", typ: wire.Actor},
		{lobby: true, sessions: []wire.Session{al}, in: "r\n1\n", typ: wire.Witness, ses: "A"},
	} {
		list := func() (wire.Reply, error) { return wire.Reply{Sessions: c.sessions, CanStart: c.can}, nil }
		q, err := choose(list, c.start, c.id, c.lobby, strings.NewReader(c.in), io.Discard)
		if (err == nil) != (c.typ != "") || err == nil && (q.Type != c.typ || q.Session != c.ses) {
			t.Errorf("case %d: %+v %v", i, q, err)
		}
	}
	bad := errors.New("x")
	if _, err := choose(func() (wire.Reply, error) { return wire.Reply{}, bad }, false, "", true, strings.NewReader(""), io.Discard); !errors.Is(err, bad) {
		t.Error(err)
	}
}
