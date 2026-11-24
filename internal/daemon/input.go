package daemon

import (
	"bytes"
	"unicode/utf8"

	"witnesshell/internal/gate"
)

type eventKind uint8

const (
	evText eventKind = iota
	evEdit
	evEnter
	evInterrupt // Ctrl-C
	evEOF       // Ctrl-D
	evBad       // a key with no meaning here
)

type event struct {
	kind eventKind
	text string
	op   gate.EditOp
}

// keys turns terminal input at the prompt into events.
type keys struct {
	buf     []byte
	pasting bool
}

const maxPending = gate.MaxCommandBytes + 64

var ctrl = map[byte]event{
	'\r': {kind: evEnter}, '\n': {kind: evEnter}, 0x03: {kind: evInterrupt}, 0x04: {kind: evEOF},
	0x7f: {kind: evEdit, op: gate.Backspace}, 0x08: {kind: evEdit, op: gate.Backspace},
	0x01: {kind: evEdit, op: gate.Home}, 0x05: {kind: evEdit, op: gate.End}, 0x02: {kind: evEdit, op: gate.Left}, 0x06: {kind: evEdit, op: gate.Right},
	0x15: {kind: evEdit, op: gate.KillToStart}, 0x0b: {kind: evEdit, op: gate.KillToEnd}, 0x17: {kind: evEdit, op: gate.KillWord},
	0x10: {kind: evEdit, op: gate.HistoryPrev}, 0x0e: {kind: evEdit, op: gate.HistoryNext},
}

var sequences = map[string]gate.EditOp{
	"[A": gate.HistoryPrev, "[B": gate.HistoryNext, "[C": gate.Right, "[D": gate.Left, "[H": gate.Home, "[F": gate.End,
	"OA": gate.HistoryPrev, "OB": gate.HistoryNext, "OC": gate.Right, "OD": gate.Left, "OH": gate.Home, "OF": gate.End,
	"[1~": gate.Home, "[7~": gate.Home, "[4~": gate.End, "[8~": gate.End, "[3~": gate.Delete,
}

var pasteEnd = []byte("\x1b[201~")

func (k *keys) reset() { k.buf, k.pasting = nil, false }

// next returns the next complete event in the buffer.
func (k *keys) next() (event, bool) {
	for len(k.buf) > 0 {
		if k.pasting {
			i := bytes.Index(k.buf, pasteEnd)
			if i < 0 {
				if len(k.buf) > maxPending {
					k.reset()
					return event{kind: evBad}, true
				}
				return event{}, false
			}
			text := string(k.buf[:i])
			k.buf, k.pasting = k.buf[i+len(pasteEnd):], false
			return event{kind: evText, text: text}, true
		}
		b := k.buf[0]
		if b == 0x1b {
			n, ok := sequenceLen(k.buf)
			if !ok {
				return event{}, false
			}
			seq := string(k.buf[1:n])
			k.buf = k.buf[n:]
			if seq == "[200~" {
				k.pasting = true
				continue
			}
			if op, ok := sequences[seq]; ok {
				return event{kind: evEdit, op: op}, true
			}
			return event{kind: evBad}, true
		}
		if b < 0x20 || b == 0x7f {
			k.buf = k.buf[1:]
			if e, ok := ctrl[b]; ok {
				return e, true
			}
			return event{kind: evBad}, true
		}
		// Text up to the next control character.
		n := 0
		for n < len(k.buf) && k.buf[n] >= 0x20 && k.buf[n] != 0x7f {
			if !utf8.FullRune(k.buf[n:]) {
				break
			}
			_, w := utf8.DecodeRune(k.buf[n:])
			n += w
		}
		if n == 0 {
			return event{}, false // the rest of a character is still to come
		}
		text := string(k.buf[:n])
		k.buf = k.buf[n:]
		return event{kind: evText, text: text}, true
	}
	return event{}, false
}

// sequenceLen returns the length of the escape sequence at the start of b.
func sequenceLen(b []byte) (int, bool) {
	if len(b) < 2 {
		return 0, false
	}
	switch b[1] {
	case 'O':
		return 3, len(b) >= 3
	case '[':
		for i := 2; i < len(b); i++ {
			if b[i] >= 0x40 && b[i] <= 0x7e {
				return i + 1, true
			}
			if b[i] < 0x20 || b[i] > 0x7e || i > 32 {
				return i, true // malformed
			}
		}
		return 0, false
	}
	return 2, true // Alt and a key
}
