package gate

import "slices"

// EditOp is a line-editing action.
type EditOp uint8

const (
	Left EditOp = iota
	Right
	Home
	End
	Backspace
	Delete
	KillToStart // Ctrl-U
	KillToEnd   // Ctrl-K
	KillWord    // Ctrl-W
	HistoryPrev
	HistoryNext
	Clear
)

// draft is the actor's unsubmitted line. The zero value is empty.
type draft struct {
	text []rune
	pos  int
	back int    // entries back in history; 0 = the actor's own text
	own  string // actor's text, saved while browsing history
}

func newDraft(s string) draft {
	r := []rune(s)
	return draft{text: r, pos: len(r)}
}

func (d *draft) String() string { return string(d.text) }

func (d *draft) insert(s string) {
	r := []rune(s)
	d.text = slices.Insert(d.text, d.pos, r...)
	d.pos += len(r)
}

func (d *draft) cut(from, to int) {
	d.text = slices.Delete(d.text, from, to)
	d.pos = from
}

func (d *draft) browse(back int, history []string) {
	if back < 0 || back > len(history) {
		return
	}
	own := d.own
	if d.back == 0 {
		own = d.String()
	}
	s := own
	if back > 0 {
		s = history[len(history)-back]
	}
	*d = newDraft(s)
	d.back, d.own = back, own
}

func (d *draft) apply(op EditOp, history []string) {
	switch op {
	case Left:
		d.pos = max(0, d.pos-1)
	case Right:
		d.pos = min(len(d.text), d.pos+1)
	case Home:
		d.pos = 0
	case End:
		d.pos = len(d.text)
	case Backspace:
		if d.pos > 0 {
			d.cut(d.pos-1, d.pos)
		}
	case Delete:
		if d.pos < len(d.text) {
			d.cut(d.pos, d.pos+1)
		}
	case KillToStart:
		d.cut(0, d.pos)
	case KillToEnd:
		d.cut(d.pos, len(d.text))
	case KillWord:
		space := func(r rune) bool { return r == ' ' || r == '\n' }
		i := d.pos
		for i > 0 && space(d.text[i-1]) {
			i--
		}
		for i > 0 && !space(d.text[i-1]) {
			i--
		}
		d.cut(i, d.pos)
	case HistoryPrev:
		d.browse(d.back+1, history)
	case HistoryNext:
		d.browse(d.back-1, history)
	case Clear:
		*d = draft{}
	}
}
