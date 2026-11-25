// Package wire defines the messages between clients and the daemon.
package wire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"witnesshell/internal/view"
)

// Version is the protocol version.
const Version = 1

// Limits on message sizes, in bytes.
const (
	MaxRequest = 256 << 10 // client to daemon
	MaxReply   = 32 << 20  // daemon to client; a viewed file is the largest
)

// Request is a message from a client.
type Request struct {
	Type    string // see below
	Version int    `json:",omitempty"`
	Session string `json:",omitempty"` // empty in "actor": a new session
	Rows    uint16 `json:",omitempty"`
	Cols    uint16 `json:",omitempty"`
	Data    []byte `json:",omitempty"`
	ID      uint64 `json:",omitempty"`
	Approve bool   `json:",omitempty"`
	Text    string `json:",omitempty"` // comment, path or hash
	Size    int64  `json:",omitempty"` // Upload
	Hash    string `json:",omitempty"` // Upload: SHA-256 in hex
	// Screen asks for frames on a separate stream with this name, if not 0.
	Screen uint64 `json:",omitempty"`
}

// Request types. A connection starts with List, Sign, Actor or Witness.
const (
	List     = "list"
	Sign     = "sign" // Text is a SHA-256 in hex
	Actor    = "actor"
	Witness  = "witness"
	Key      = "key"    // actor: typed bytes
	Resize   = "resize" // actor
	Vote     = "vote"   // witness
	View     = "view"   // witness: Text is a path
	Checksig = "checksig"
	Token    = "token"  // local only: a login for QUIC
	Auth     = "auth"   // QUIC only, first of all: Text is the token
	Resume   = "resume" // instead of Auth: Text is the secret of the login
	Ping     = "ping"
	Sha256   = "sha256" // witness: Text is a path
	Staged   = "staged" // witness: show the file of the pending transfer
	Changes  = "diff"   // witness: compare it with the file it replaces
	// These begin a connection of their own. Text is a path on the host.
	Upload   = "upload"   // the content follows
	Download = "download" // the content comes back
)

// Reply is a message from the daemon.
type Reply struct {
	Type     string
	Text     string    `json:",omitempty"`
	Sessions []Session `json:",omitempty"`
	State    *State    `json:",omitempty"`
	Doc      *view.Doc `json:",omitempty"`
	Frame    *Frame    `json:",omitempty"`
	Size     int64     `json:",omitempty"` // Download: what follows; Text is its hash
	CanStart bool      `json:",omitempty"` // Sessions
}

// Reply types.
const (
	Sessions  = "sessions"
	OK        = "ok"
	Error     = "error" // the request failed
	FrameType = "frame"
	Pong      = "pong"
	StateType = "state"
	Doc       = "doc"
	Report    = "report" // of checksig
	End       = "end"    // the session is over
	Screen    = "screen" // begins a stream of frames; Text is its name
)

// Session is an entry in the list of sessions.
type Session struct {
	ID    string
	Actor string
	Own   bool
	Since string
}

// Phase is what the session is doing.
type Phase string

const (
	Prompt   Phase = "prompt"
	Checking Phase = "checking"
	Pending  Phase = "pending"
	Running  Phase = "running"
)

// VoteInfo is a vote on the pending request.
type VoteInfo struct {
	Name    string
	Approve bool
	Comment string `json:",omitempty"`
}

// State is everything a client shows besides the terminal.
type State struct {
	Session, Actor, Dir string
	Phase               Phase
	Rows, Cols          uint16 // of the terminal
	Draft               string
	Cursor              int
	ID                  uint64 // pending request
	Text                string
	Details             []string
	Warnings            []string
	Votes               []VoteInfo
	Required            int
	Witnesses           []string
	ActorOnline         bool
	Notice              string
	Weak                []string // host problems that were overridden
	Download            bool     // is allowed
	Transfer            bool     // the pending request is one
}

// Frame is what changed on the screen. The first one a client gets is complete.
type Frame struct {
	Rows, Cols int
	Lines      []Line `json:",omitempty"`
	CX, CY     int
	Hidden     bool   `json:",omitempty"` // the cursor
	AppKeys    bool   `json:",omitempty"`
	Paste      bool   `json:",omitempty"`
	Bells      uint64 `json:",omitempty"` // so far
}

// Line is the new content of a row.
type Line struct {
	Y    int
	Runs []Run `json:",omitempty"`
}

// Run is text of one style, W columns wide. S is an SGR sequence.
type Run struct {
	T string
	S string `json:",omitempty"`
	W int
}

var errSize = errors.New("message too large")

// Write sends one message.
func Write(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxReply {
		return errSize
	}
	_, err = w.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...))
	return err
}

// Read receives one message of at most limit bytes.
func Read(r io.Reader, limit uint32, v any) error {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n > limit {
		return errSize
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
