package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"math"
	"os"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// cast writes a recording in asciicast v2 format. It never holds input.
type cast struct {
	name  string
	f     *os.File
	began time.Time
	sum   hash.Hash
	rest  []byte // the beginning of a character whose end is still to come
	size  int64  // written so far
	limit int64  // of the size; 0 means none
}

func newCast(l *logFile, title string, rows, cols uint16, began time.Time) (*cast, error) {
	c := &cast{name: l.name, f: l.f, began: began, sum: sha256.New()}
	return c, c.line(map[string]any{"version": 2, "width": cols, "height": rows, "timestamp": began.Unix(),
		"title": title, "env": map[string]string{"TERM": "xterm-256color", "SHELL": "witsh"}})
}

func (c *cast) line(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if c.limit > 0 && c.size+int64(len(b)) > c.limit {
		return ErrFull
	}
	c.size += int64(len(b))
	if _, err := c.f.Write(b); err != nil {
		return err
	}
	_, _ = c.sum.Write(b)
	return nil
}

func (c *cast) event(kind, data string) error {
	t := max(0, math.Round(time.Since(c.began).Seconds()*1e6)/1e6)
	return c.line([]any{t, kind, data})
}

// output records output. A character that is cut in two is put together.
func (c *cast) output(b []byte) error {
	b = append(c.rest, b...)
	n := len(b)
	for i := 1; i < utf8.UTFMax && i <= len(b); i++ {
		if utf8.RuneStart(b[len(b)-i]) {
			if !utf8.FullRune(b[len(b)-i:]) {
				n = len(b) - i
			}
			break
		}
	}
	c.rest = append([]byte(nil), b[n:]...)
	if n == 0 {
		return nil
	}
	return c.event("o", string(b[:n]))
}

func (c *cast) finish() error {
	if len(c.rest) > 0 {
		if err := c.event("o", string(c.rest)); err != nil {
			return err
		}
	}
	return unix.Fdatasync(int(c.f.Fd()))
}

func (c *cast) hash() string { return hex.EncodeToString(c.sum.Sum(nil)) }
