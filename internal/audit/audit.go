// Package audit keeps a session's logs and recording (PLAN.md section 8). Each
// log is a chain: every entry holds the hash of the one before.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultDir is where logs go unless configured otherwise.
const DefaultDir = "/var/log/witnesshell"

// Events.
const (
	SessionStart = "session_start"
	SessionEnd   = "session_end"
	Join         = "join"
	Leave        = "leave"
	Request      = "request"
	Refused      = "refused" // before witnesses saw it
	Vote         = "vote"
	Cancelled    = "cancelled"
	Purged       = "purged"
	Free         = "free_command"
	RunStart     = "run_start"
	RunEnd       = "run_end"
	Inspect      = "inspect" // view or checksig
	Signed       = "signed"
)

// Data holds an event's details.
type Data map[string]any

// Entry is a line of a log.
type Entry struct {
	Seq   int       `json:"seq"`
	Time  time.Time `json:"time"`
	Event string    `json:"event"`
	Prev  string    `json:"prev"` // hash of the previous line; empty for the first
	Data  Data      `json:"data,omitempty"`
}

// Hash is the hash of a line without its newline.
func Hash(line []byte) string {
	h := sha256.Sum256(line)
	return hex.EncodeToString(h[:])
}

// logFile is one log.
type logFile struct {
	name string
	f    *os.File
	seq  int
	prev string
}

// add writes an entry and returns its hash. With durable it is on disk after.
func (l *logFile) add(event string, d Data, durable bool) (string, error) {
	l.seq++
	b, err := json.Marshal(Entry{l.seq, time.Now().UTC(), event, l.prev, d})
	if err != nil {
		return "", err
	}
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return "", err
	}
	if durable {
		if err := unix.Fdatasync(int(l.f.Fd())); err != nil {
			return "", err
		}
	}
	l.prev = Hash(b)
	return l.prev, nil
}

// ErrClosed means that the session's logs are complete.
var ErrClosed = errors.New("the logs are closed")

// ErrFull means that the recording reached its limit.
var ErrFull = errors.New("the recording reached its limit")

// Session is the logs and the recording of one session.
type Session struct {
	dir, id string

	mu        sync.Mutex
	err       error // the first failure; nothing is written after it
	actor     *logFile
	witnesses map[uint32]*logFile
	start     Data // repeated in each witness log
	cast      *cast
}

// Open creates the logs. Directories are created if needed, but an existing
// one must be safe from others.
func Open(dir, id, actor string, uid uint32, start Data, rows, cols uint16, began time.Time) (*Session, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0o022 != 0 {
		return nil, fmt.Errorf("%s must be owned by root and writable by nobody else", dir)
	}
	s := &Session{dir: dir, id: id, witnesses: map[uint32]*logFile{}, start: start}
	var err error
	if s.actor, err = s.create("actor", actor, uid, ".log"); err != nil {
		return nil, err
	}
	f, err := s.create("actor", actor, uid, ".cast")
	if err != nil {
		_ = s.actor.f.Close()
		return nil, err
	}
	if s.cast, err = newCast(f, fmt.Sprintf("%s %s", id, actor), rows, cols, began); err == nil {
		_, err = s.actor.add(SessionStart, start, true)
	}
	if err == nil { // the names must survive a crash, too
		err = syncDir(dir)
	}
	if err != nil {
		_, _ = s.actor.f.Close(), f.f.Close()
		return nil, err
	}
	return s, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

var plainName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

func fileName(id, role, user string, uid uint32, ext string) string {
	if !plainName.MatchString(user) {
		user = fmt.Sprintf("uid%d", uid)
	}
	return "witnesshell-" + id + "-" + role + "-" + user + ext
}

func (s *Session) create(role, user string, uid uint32, ext string) (*logFile, error) {
	name := fileName(s.id, role, user, uid, ext)
	f, err := os.OpenFile(filepath.Join(s.dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	return &logFile{name: name, f: f}, nil
}

// failed remembers the first failure. Lock held.
func (s *Session) failed(err error) error {
	if err != nil && s.err == nil {
		s.err = err
	}
	return err
}

// Actor adds an entry to the actor's log and returns its hash.
func (s *Session) Actor(event string, d Data, durable bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return "", s.err
	}
	h, err := s.actor.add(event, d, durable)
	return h, s.failed(err)
}

// Witness adds an entry to a witness's log, which begins with the first.
func (s *Session) Witness(uid uint32, name, event string, d Data, durable bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	l := s.witnesses[uid]
	if l == nil {
		var err error
		if l, err = s.create("witness", name, uid, ".log"); err != nil {
			return s.failed(err)
		}
		s.witnesses[uid] = l
		if _, err = l.add(SessionStart, s.start, true); err == nil {
			err = syncDir(s.dir)
		}
		if err != nil {
			return s.failed(err)
		}
	}
	_, err := l.add(event, d, durable)
	return s.failed(err)
}

// LimitRecording sets the largest size of the recording; 0 means no limit.
func (s *Session) LimitRecording(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cast.limit = n
}

// Output, Resize and Marker add to the recording.
func (s *Session) Output(b []byte) error {
	return s.record(func() error { return s.cast.output(b) })
}

func (s *Session) Resize(rows, cols uint16) error {
	return s.record(func() error { return s.cast.event("r", fmt.Sprintf("%dx%d", cols, rows)) })
}

func (s *Session) Marker(text string) error {
	return s.record(func() error { return s.cast.event("m", text) })
}

func (s *Session) record(f func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	return s.failed(f())
}

// Close completes the logs and returns the hash that seals them all.
func (s *Session) Close(why string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == ErrClosed {
		return "", ErrClosed
	}
	failure := s.err
	if errors.Is(failure, ErrFull) {
		failure = nil // what there is, is complete
	}
	s.err = ErrClosed
	defer func() {
		for _, l := range s.witnesses {
			_ = l.f.Close()
		}
		_, _ = s.actor.f.Close(), s.cast.f.Close()
	}()
	if failure != nil {
		return "", failure // incomplete, and audit verify says so
	}
	seals := map[string]string{}
	for _, l := range s.witnesses {
		h, err := l.add(SessionEnd, Data{"why": why}, true)
		if err != nil {
			return "", err
		}
		seals[l.name] = h
	}
	if err := s.cast.finish(); err != nil {
		return "", err
	}
	return s.actor.add(SessionEnd, Data{"why": why, "witness_logs": seals, "recording": s.cast.name, "recording_sha256": s.cast.hash()}, true)
}
