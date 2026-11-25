package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// maxLine bounds a log line.
const maxLine = 16 << 20

var idFormat = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{3}Z$`)

// Result is what Verify found.
type Result struct {
	Files    []string
	Entries  int
	Final    string // the hash that seals the session
	Problems []string
}

type chain struct {
	entries []Entry
	hashes  []string
}

// readChain reads a log. Its error names the first thing wrong; what comes
// before is returned.
func readChain(name string) (c chain, err error) {
	f, err := os.Open(name)
	if err != nil {
		return c, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	prev := ""
	for n := 1; ; n++ {
		line, err := readLine(r)
		if err == io.EOF {
			return c, nil
		}
		if err != nil {
			return c, fmt.Errorf("line %d: %w", n, err)
		}
		d := json.NewDecoder(bytes.NewReader(line))
		d.DisallowUnknownFields()
		var e Entry
		if err := d.Decode(&e); err != nil {
			return c, fmt.Errorf("line %d is not an entry: %w", n, err)
		}
		if _, err := d.Token(); err != io.EOF {
			return c, fmt.Errorf("line %d has more than an entry", n)
		}
		if e.Seq != n || e.Prev != prev {
			return c, fmt.Errorf("the chain is broken at line %d", n)
		}
		prev = Hash(line)
		c.entries, c.hashes = append(c.entries, e), append(c.hashes, prev)
	}
}

// readLine returns a line without its newline, which must be there.
func readLine(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		b, err := r.ReadSlice('\n')
		out = append(out, b...)
		switch {
		case err == nil:
			return out[:len(out)-1], nil
		case errors.Is(err, bufio.ErrBufferFull) && len(out) < maxLine:
			continue
		case err == io.EOF && len(out) == 0:
			return nil, io.EOF
		case err == io.EOF:
			return nil, errors.New("cut off")
		case errors.Is(err, bufio.ErrBufferFull):
			return nil, errors.New("too long")
		}
		return nil, err
	}
}

// Verify checks the logs and the recording of a session.
func Verify(dir, id string) (*Result, error) {
	if !idFormat.MatchString(id) {
		return nil, fmt.Errorf("%q is not a session start such as 20261124T101500.123Z", id)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	r := &Result{}
	bad := func(format string, args ...any) { r.Problems = append(r.Problems, fmt.Sprintf(format, args...)) }
	var actors, casts, witnesses []string
	pre := "witnesshell-" + id + "-"
	for _, e := range ents {
		rest, ok := strings.CutPrefix(e.Name(), pre)
		if !ok {
			continue
		}
		r.Files = append(r.Files, e.Name())
		if !e.Type().IsRegular() {
			bad("%s is not a regular file", e.Name())
			continue
		}
		switch {
		case strings.HasPrefix(rest, "actor-") && strings.HasSuffix(rest, ".log"):
			actors = append(actors, e.Name())
		case strings.HasPrefix(rest, "actor-") && strings.HasSuffix(rest, ".cast"):
			casts = append(casts, e.Name())
		case strings.HasPrefix(rest, "witness-") && strings.HasSuffix(rest, ".log"):
			witnesses = append(witnesses, e.Name())
		default:
			bad("%s does not belong here", e.Name())
		}
	}
	if len(r.Files) == 0 {
		return nil, fmt.Errorf("no logs of session %s in %s", id, dir)
	}
	if len(actors) != 1 {
		bad("there are %d actor logs instead of one", len(actors))
		return r, nil
	}
	a, err := readChain(filepath.Join(dir, actors[0]))
	if err != nil {
		bad("%s: %v", actors[0], err)
	}
	r.Entries = len(a.entries)
	// What sealed the session.
	var end struct {
		Why       string            `json:"why"`
		Logs      map[string]string `json:"witness_logs"`
		Recording string            `json:"recording"`
		SHA256    string            `json:"recording_sha256"`
	}
	sealed := false
	checkEnds(actors[0], a, bad)
	if n := len(a.entries); n > 0 && a.entries[n-1].Event == SessionEnd {
		b, err := json.Marshal(a.entries[n-1].Data)
		if err == nil {
			err = json.Unmarshal(b, &end)
		}
		if err != nil {
			bad("%s: the last entry is damaged", actors[0])
		} else {
			sealed, r.Final = true, a.hashes[n-1]
		}
	}
	requests := map[string]bool{}
	for i, e := range a.entries {
		if e.Event == Request {
			requests[a.hashes[i]] = true
		}
	}
	for _, w := range witnesses {
		c, err := readChain(filepath.Join(dir, w))
		if err != nil {
			bad("%s: %v", w, err)
		}
		r.Entries += len(c.entries)
		checkEnds(w, c, bad)
		for _, e := range c.entries {
			if h, _ := e.Data["request_hash"].(string); (e.Event == Vote || e.Event == Request) && !requests[h] {
				bad("%s: entry %d is about a request that is not in the actor log", w, e.Seq)
			}
		}
		if !sealed {
			continue
		}
		want, ok := end.Logs[w]
		switch {
		case !ok:
			bad("%s is not among the logs that the actor log names", w)
		case len(c.hashes) == 0 || c.hashes[len(c.hashes)-1] != want:
			bad("%s is not as it was when the session ended", w)
		}
	}
	if !sealed {
		return r, nil
	}
	for w := range end.Logs {
		if !slices.Contains(witnesses, w) {
			bad("%s is missing", w)
		}
	}
	if !slices.Contains(casts, end.Recording) {
		bad("the recording %q is missing", end.Recording)
	}
	for _, c := range casts {
		if c != end.Recording {
			bad("%s is not the recording that the actor log names", c)
		} else if h, err := hashFile(filepath.Join(dir, c)); err != nil {
			bad("%s: %v", c, err)
		} else if h != end.SHA256 {
			bad("%s is not as it was when the session ended", c)
		}
	}
	return r, nil
}

func checkEnds(name string, c chain, bad func(string, ...any)) {
	n := len(c.entries)
	if n == 0 || c.entries[0].Event != SessionStart {
		bad("%s does not begin with the start of the session", name)
	}
	if n == 0 || c.entries[n-1].Event != SessionEnd {
		bad("%s does not end with the end of the session: it still runs, was cut off, or ended abnormally", name)
	}
	for i := 0; i+1 < n; i++ {
		if c.entries[i].Event == SessionEnd {
			bad("%s goes on after the end of the session", name)
			return
		}
	}
}

func hashFile(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
