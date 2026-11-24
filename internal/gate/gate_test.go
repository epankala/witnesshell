package gate

import (
	"errors"
	"math/rand"
	"strings"
	"testing"
)

const actor = 1000

func newGate(t *testing.T, k int) *Gate {
	t.Helper()
	g, err := New(actor, k)
	ok(t, err)
	return g
}

func submit(t *testing.T, g *Gate, s string) Request {
	t.Helper()
	ok(t, g.Insert(s))
	r, err := g.Submit()
	ok(t, err)
	return r
}

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func is(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func state(t *testing.T, g *Gate, want State) {
	t.Helper()
	if g.State() != want || g.InputFree() != (want == Running) {
		t.Fatalf("state = %v, free = %v, want %v", g.State(), g.InputFree(), want)
	}
}

func wantDraft(t *testing.T, g *Gate, want string) {
	t.Helper()
	if s, _ := g.Draft(); s != want {
		t.Fatalf("draft = %q, want %q", s, want)
	}
}

func TestConfig(t *testing.T) {
	for _, k := range []int{0, -1} {
		_, err := New(actor, k)
		is(t, err, ErrConfig)
	}
}

func TestOneOfOne(t *testing.T) {
	g := newGate(t, 1)
	id := submit(t, g, "uptime").ID
	state(t, g, Pending)
	r, err := g.Approve(1, id)
	ok(t, err)
	if r.Outcome != Approved || r.Text != "uptime" {
		t.Fatalf("got %+v", r)
	}
	state(t, g, Running)
	wantDraft(t, g, "")
	ok(t, g.Finished())
	state(t, g, Prompt)
	is(t, g.Finished(), ErrNotRunning)
}

func TestQuorumCountsDistinctUsers(t *testing.T) {
	g := newGate(t, 3)
	id := submit(t, g, "x").ID
	for _, uid := range []uint32{1, 2} {
		r, err := g.Approve(uid, id)
		ok(t, err)
		if r.Outcome != Undecided {
			t.Fatal("approved early")
		}
		_, err = g.Approve(uid, id)
		is(t, err, ErrDuplicateVote)
		state(t, g, Pending)
	}
	r, err := g.Approve(3, id)
	ok(t, err)
	if r.Outcome != Approved || len(r.Votes) != 3 {
		t.Fatalf("got %+v", r)
	}
}

func TestVeto(t *testing.T) {
	for _, vetoer := range []uint32{1, 2} { // 1 changes their mind
		g := newGate(t, 2)
		id := submit(t, g, "rm x").ID
		_, err := g.Approve(1, id)
		ok(t, err)
		r, err := g.Reject(vetoer, id, " wrong host ")
		ok(t, err)
		if r.Outcome != Rejected || r.Votes[1] != (Vote{UID: vetoer, Comment: "wrong host"}) {
			t.Fatalf("got %+v", r)
		}
		state(t, g, Prompt)
		wantDraft(t, g, "rm x")
		n := submit(t, g, "y")
		if n.ID == id || len(n.Votes) != 0 || n.Text != "rm xy" {
			t.Fatalf("resubmission not fresh: %+v", n)
		}
		_, err = g.Approve(3, id)
		is(t, err, ErrStale)
		_, err = g.Reject(3, id, "no")
		is(t, err, ErrStale)
	}
}

func TestRejectComment(t *testing.T) {
	g := newGate(t, 1)
	id := submit(t, g, "x").ID
	for c, want := range map[string]error{
		"": ErrCommentNeeded, " \n ": ErrCommentNeeded, "\x1b[2J": ErrBadComment,
		strings.Repeat("a", MaxCommentBytes+1): ErrCommentTooLong,
	} {
		_, err := g.Reject(1, id, c)
		is(t, err, want)
		state(t, g, Pending)
	}
}

func TestActorCannotVote(t *testing.T) {
	g := newGate(t, 1)
	id := submit(t, g, "x").ID
	_, err := g.Approve(actor, id)
	is(t, err, ErrActorVote)
	_, err = g.Reject(actor, id, "no")
	is(t, err, ErrActorVote)
	state(t, g, Pending)
}

func TestSubmitFree(t *testing.T) {
	g := newGate(t, 2)
	ok(t, g.Insert("view x"))
	s, err := g.SubmitFree()
	ok(t, err)
	if s != "view x" {
		t.Fatal(s)
	}
	state(t, g, Running)
	_, err = g.SubmitFree()
	is(t, err, ErrRunning)
	ok(t, g.Finished())
	submit(t, g, "x")
	_, err = g.SubmitFree()
	is(t, err, ErrPending)
}

func TestCancel(t *testing.T) {
	g := newGate(t, 1)
	_, err := g.Cancel()
	is(t, err, ErrNoPending)
	id := submit(t, g, "x").ID
	r, err := g.Cancel()
	ok(t, err)
	if r.Outcome != Cancelled {
		t.Fatal(r.Outcome)
	}
	wantDraft(t, g, "x")
	_, err = g.Approve(1, id)
	is(t, err, ErrNoPending)
}

func TestLockedOutsidePrompt(t *testing.T) {
	g := newGate(t, 1)
	id := submit(t, g, "x").ID
	locked := func(want error) {
		t.Helper()
		is(t, g.Insert("evil"), want)
		is(t, g.Edit(Backspace), want)
		_, err := g.Submit()
		is(t, err, want)
	}
	locked(ErrPending)
	if r, _ := g.Pending(); r.Text != "x" {
		t.Fatal("pending text changed")
	}
	_, err := g.Approve(1, id)
	ok(t, err)
	locked(ErrRunning)
	g.Logout()
	locked(ErrClosed)
	_, err = g.Cancel()
	is(t, err, ErrClosed)
	is(t, g.Finished(), ErrClosed)
}

func TestLogout(t *testing.T) {
	g := newGate(t, 1)
	if _, purged := g.Logout(); purged {
		t.Fatal("nothing to purge")
	}
	g = newGate(t, 2)
	id := submit(t, g, "x").ID
	_, err := g.Approve(1, id)
	ok(t, err)
	r, purged := g.Logout()
	if !purged || r.Outcome != Purged || len(r.Votes) != 1 {
		t.Fatalf("got %+v %v", r, purged)
	}
	state(t, g, Closed)
	_, err = g.Approve(2, id)
	is(t, err, ErrClosed)
	if _, again := g.Logout(); again {
		t.Fatal("purged twice")
	}
}

func TestSnapshotsDoNotAlias(t *testing.T) {
	g := newGate(t, 2)
	id := submit(t, g, "x").ID
	r, err := g.Approve(1, id)
	ok(t, err)
	r.Votes[0].UID = 99
	p, _ := g.Pending()
	if p.Votes[0].UID != 1 {
		t.Fatal("caller changed gate state")
	}
}

func TestText(t *testing.T) {
	for _, s := range []string{
		"\x00", "\x03", "\x1b[A", "\t", "\x7f", "\u009b", "\xff", "\u202e",
		"\u200b", "\u2066", "\u00ad", "\u00a0", "\u2028", "\ufeff",
		"\u3164", "\u115f", "\ufe0f", "\U000e0100", "\u034f", "\u2800",
	} {
		g := newGate(t, 1)
		is(t, g.Insert("a"+s+"b"), ErrUnsafeText)
		wantDraft(t, g, "")
	}
	g := newGate(t, 1)
	ok(t, g.Insert("echo äö 日本\r\nls\rpwd"))
	wantDraft(t, g, "echo äö 日本\nls\npwd")
	g = newGate(t, 1)
	ok(t, g.Insert(strings.Repeat("a", MaxCommandBytes)))
	is(t, g.Insert("a"), ErrTooLong)
	g = newGate(t, 1)
	_, err := g.Submit()
	is(t, err, ErrEmpty)
	ok(t, g.Insert(" \n "))
	_, err = g.Submit()
	is(t, err, ErrEmpty)
}

func TestEditing(t *testing.T) {
	for _, c := range []struct {
		ops  []EditOp
		want string
	}{
		{[]EditOp{Backspace}, "ab ä|"},
		{[]EditOp{Home, Delete}, "|b äc"},
		{[]EditOp{Home, Left, Backspace}, "|ab äc"},
		{[]EditOp{End, Right, Delete}, "ab äc|"},
		{[]EditOp{Left, KillToStart}, "|c"},
		{[]EditOp{Left, KillToEnd}, "ab ä|"},
		{[]EditOp{KillWord}, "ab |"},
		{[]EditOp{KillWord, KillWord}, "|"},
		{[]EditOp{Clear}, "|"},
	} {
		g := newGate(t, 1)
		ok(t, g.Insert("ab äc"))
		for _, op := range c.ops {
			ok(t, g.Edit(op))
		}
		ok(t, g.Insert("|"))
		wantDraft(t, g, c.want)
	}
}

func TestHistoryOnlyApproved(t *testing.T) {
	g := newGate(t, 1)
	for _, s := range []string{"one", "two"} {
		_, err := g.Approve(1, submit(t, g, s).ID)
		ok(t, err)
		ok(t, g.Finished())
	}
	_, err := g.Reject(1, submit(t, g, "bad").ID, "no")
	ok(t, err)
	for _, s := range []struct {
		op   EditOp
		want string
	}{{HistoryNext, "bad"}, {HistoryPrev, "two"}, {HistoryPrev, "one"},
		{HistoryPrev, "one"}, {HistoryNext, "two"}, {HistoryNext, "bad"}} {
		ok(t, g.Edit(s.op))
		wantDraft(t, g, s.want)
	}
	ok(t, g.Edit(HistoryPrev))
	ok(t, g.Insert("!")) // editing a copy must not change history
	ok(t, g.Edit(Clear))
	ok(t, g.Edit(HistoryPrev))
	wantDraft(t, g, "two")
}

// TestRandom checks the core promise: Running is entered only by K distinct
// non-actor approvals of the current request with no veto.
func TestRandom(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	runs := 0
	for range 2000 {
		k := 1 + rnd.Intn(3)
		g := newGate(t, k)
		var id uint64
		var text string
		votes := map[uint32]bool{}
		for range 60 {
			uid := []uint32{actor, 1, 2, 3, 4}[rnd.Intn(5)]
			vid := id
			if rnd.Intn(5) == 0 {
				vid-- // stale
			}
			before := g.State()
			switch rnd.Intn(14) {
			case 0, 1, 2:
				_ = g.Insert("c")
				if r, err := g.Submit(); err == nil {
					id, text = r.ID, r.Text
					clear(votes)
				}
			case 3:
				_, _ = g.Reject(uid, vid, "no")
			case 4:
				_, _ = g.Cancel()
			case 5:
				_ = g.Finished()
			case 6:
				if rnd.Intn(20) == 0 {
					g.Logout()
				}
			default:
				if r, err := g.Approve(uid, vid); err == nil {
					if uid == actor || vid != id || before != Pending {
						t.Fatal("invalid vote accepted")
					}
					votes[uid] = true
					if (r.Outcome == Approved) != (len(votes) == k) || r.Text != text {
						t.Fatalf("k=%d votes=%v got %+v", k, votes, r)
					}
				}
			}
			if before != Running && g.State() == Running {
				runs++
				if len(votes) != k {
					t.Fatal("ran without quorum")
				}
			}
			if before == Closed && g.State() != Closed {
				t.Fatal("reopened")
			}
		}
	}
	if runs == 0 {
		t.Fatal("never exercised approval")
	}
}

func FuzzInsert(f *testing.F) {
	f.Add("ls -l\n\x1b")
	f.Fuzz(func(t *testing.T, s string) {
		g, _ := New(actor, 1)
		err := g.Insert(s)
		d, pos := g.Draft()
		if err != nil && d != "" {
			t.Fatal("failed insert changed draft")
		}
		if !safeText(d) || pos != len([]rune(d)) {
			t.Fatalf("bad draft %q", d)
		}
	})
}
