// Package gate decides which command lines may run. It is a pure state
// machine: no I/O, clocks or goroutines. Callers must serialize access.
package gate

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxCommandBytes and MaxCommentBytes bound untrusted input.
const (
	MaxCommandBytes = 64 << 10
	MaxCommentBytes = 4 << 10
)

var (
	ErrConfig         = errors.New("approvals required must be at least 1")
	ErrPending        = errors.New("a request is already pending")
	ErrNoPending      = errors.New("no request is pending")
	ErrStale          = errors.New("vote is for a different request")
	ErrActorVote      = errors.New("the actor cannot vote")
	ErrDuplicateVote  = errors.New("this user has already approved")
	ErrCommentNeeded  = errors.New("a rejection needs a comment")
	ErrCommentTooLong = errors.New("comment is too long")
	ErrBadComment     = errors.New("comment contains hidden or control characters")
	ErrEmpty          = errors.New("command is empty")
	ErrTooLong        = errors.New("command is too long")
	ErrUnsafeText     = errors.New("command contains hidden or control characters")
	ErrRunning        = errors.New("a command is running")
	ErrNotRunning     = errors.New("no command is running")
	ErrClosed         = errors.New("session is closed")
)

// State is the session's gate state.
type State uint8

const (
	Prompt  State = iota // the actor may draft
	Pending              // a request awaits votes
	Running              // an approved command runs; input is free (D17)
	Closed
)

func (s State) String() string {
	switch s {
	case Prompt:
		return "prompt"
	case Pending:
		return "pending"
	case Running:
		return "running"
	case Closed:
		return "closed"
	}
	return fmt.Sprintf("State(%d)", uint8(s))
}

// Outcome is the fate of a request. The zero value means undecided.
type Outcome uint8

const (
	Undecided Outcome = iota
	Approved
	Rejected
	Cancelled
	Purged
)

func (o Outcome) String() string {
	switch o {
	case Undecided:
		return "undecided"
	case Approved:
		return "approved"
	case Rejected:
		return "rejected"
	case Cancelled:
		return "cancelled"
	case Purged:
		return "purged"
	}
	return fmt.Sprintf("Outcome(%d)", uint8(o))
}

// Vote is one witness decision. Votes are never removed on disconnect (D13).
type Vote struct {
	UID     uint32
	Approve bool
	Comment string
}

// Request is a snapshot of a submitted command.
type Request struct {
	ID      uint64
	Text    string
	Votes   []Vote
	Outcome Outcome
}

// Gate is the approval state machine of one session.
type Gate struct {
	actor    uint32
	required int
	state    State
	lastID   uint64
	req      Request
	draft    draft
	history  []string
}

// New returns a gate at the prompt requiring K distinct approving uids.
func New(actorUID uint32, required int) (*Gate, error) {
	if required < 1 {
		return nil, ErrConfig
	}
	return &Gate{actor: actorUID, required: required}, nil
}

// State returns the current state.
func (g *Gate) State() State { return g.state }

// Required returns K, the number of approvals needed.
func (g *Gate) Required() int { return g.required }

// InputFree reports whether actor input may bypass the gate.
func (g *Gate) InputFree() bool { return g.state == Running }

// Draft returns the text and cursor (in runes) for display.
func (g *Gate) Draft() (string, int) { return g.draft.String(), g.draft.pos }

// Pending returns a copy of the pending request.
func (g *Gate) Pending() (Request, bool) {
	if g.state != Pending {
		return Request{}, false
	}
	return g.snapshot(), true
}

// Edit applies a change to the draft, only at the prompt.
func (g *Gate) Edit(op EditOp) error {
	if err := g.atPrompt(); err != nil {
		return err
	}
	g.draft.apply(op, g.history)
	return nil
}

// Insert adds typed or pasted text to the draft. It is all-or-nothing.
func (g *Gate) Insert(s string) error {
	if err := g.atPrompt(); err != nil {
		return err
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	if len(s) > MaxCommandBytes-len(g.draft.String()) {
		return ErrTooLong
	}
	if !safeText(s) {
		return ErrUnsafeText
	}
	g.draft.insert(s)
	return nil
}

// Submit turns the draft into the pending request.
func (g *Gate) Submit() (Request, error) {
	if err := g.atPrompt(); err != nil {
		return Request{}, err
	}
	text := g.draft.String()
	if strings.TrimSpace(text) == "" {
		return Request{}, ErrEmpty
	}
	g.lastID++
	g.req = Request{ID: g.lastID, Text: text}
	g.draft = draft{}
	g.state = Pending
	return g.snapshot(), nil
}

// SubmitFree takes the draft without approval (D27). The caller must have
// made sure that the text is such a command.
func (g *Gate) SubmitFree() (string, error) {
	if err := g.atPrompt(); err != nil {
		return "", err
	}
	text := g.draft.String()
	g.history = append(g.history, text)
	g.draft = draft{}
	g.state = Running
	return text, nil
}

// Approve records an approval of request id. When the result's Outcome is
// Approved the caller must execute exactly Request.Text.
func (g *Gate) Approve(uid uint32, id uint64) (Request, error) {
	if err := g.canVote(uid, id); err != nil {
		return Request{}, err
	}
	for _, v := range g.req.Votes {
		if v.UID == uid {
			return Request{}, ErrDuplicateVote
		}
	}
	g.req.Votes = append(g.req.Votes, Vote{UID: uid, Approve: true})
	// Every vote on a pending request is an approval by a distinct uid,
	// because a rejection resolves the request at once.
	if len(g.req.Votes) >= g.required {
		g.history = append(g.history, g.req.Text)
		return g.resolve(Approved, Running), nil
	}
	return g.snapshot(), nil
}

// Reject vetoes request id (D15). A witness who already approved may still
// veto while it is pending. The text returns to the draft for fixing.
func (g *Gate) Reject(uid uint32, id uint64, comment string) (Request, error) {
	if err := g.canVote(uid, id); err != nil {
		return Request{}, err
	}
	comment = strings.TrimSpace(comment)
	switch {
	case comment == "":
		return Request{}, ErrCommentNeeded
	case len(comment) > MaxCommentBytes:
		return Request{}, ErrCommentTooLong
	case !safeText(comment):
		return Request{}, ErrBadComment
	}
	g.req.Votes = append(g.req.Votes, Vote{UID: uid, Comment: comment})
	g.draft = newDraft(g.req.Text)
	return g.resolve(Rejected, Prompt), nil
}

// Cancel withdraws the pending request; its text returns to the draft.
func (g *Gate) Cancel() (Request, error) {
	if err := g.needPending(); err != nil {
		return Request{}, err
	}
	g.draft = newDraft(g.req.Text)
	return g.resolve(Cancelled, Prompt), nil
}

// Finished reports that the approved command ended; gating resumes.
func (g *Gate) Finished() error {
	switch g.state {
	case Running:
		g.state = Prompt
		return nil
	case Closed:
		return ErrClosed
	}
	return ErrNotRunning
}

// Logout closes the gate for good. It returns the purged request, if any.
// Callers also use it when the detach timeout expires (D13).
func (g *Gate) Logout() (Request, bool) {
	var r Request
	purged := g.state == Pending
	if purged {
		r = g.resolve(Purged, Closed)
	}
	g.state = Closed
	g.draft = draft{}
	return r, purged
}

func (g *Gate) atPrompt() error {
	switch g.state {
	case Prompt:
		return nil
	case Pending:
		return ErrPending
	case Running:
		return ErrRunning
	}
	return ErrClosed
}

func (g *Gate) needPending() error {
	switch g.state {
	case Pending:
		return nil
	case Closed:
		return ErrClosed
	}
	return ErrNoPending
}

func (g *Gate) canVote(uid uint32, id uint64) error {
	if uid == g.actor {
		return ErrActorVote
	}
	if err := g.needPending(); err != nil {
		return err
	}
	if id != g.req.ID {
		return ErrStale
	}
	return nil
}

func (g *Gate) resolve(o Outcome, next State) Request {
	g.req.Outcome = o
	r := g.snapshot()
	g.req = Request{}
	g.state = next
	return r
}

func (g *Gate) snapshot() Request {
	r := g.req
	r.Votes = append([]Vote(nil), g.req.Votes...)
	return r
}

// safeText rejects text that could look different to a witness than it does
// to the shell: invalid UTF-8, control characters, and invisible or
// bidirectional formatting. Newline is the sole exception.
func safeText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == '\n' {
			continue
		}
		// IsPrint excludes control, format and non-ASCII space characters,
		// but some letters and marks are drawn as nothing.
		if !unicode.IsPrint(r) || r == '\u2800' ||
			unicode.In(r, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector) {
			return false
		}
	}
	return true
}
