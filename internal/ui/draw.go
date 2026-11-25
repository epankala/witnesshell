package ui

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"witnesshell/internal/view"
	"witnesshell/internal/wire"
)

const (
	reset   = "\x1b[0m"
	reverse = "\x1b[7m"
	bold    = "\x1b[1m"
	red     = "\x1b[1;31m"
)

// fit cuts text to the width of the screen, or pads it.
func fit(s string, cols int) string {
	s = ansi.Truncate(s, cols, "…")
	return s + strings.Repeat(" ", max(0, cols-ansi.StringWidth(s)))
}

// wrap breaks safe text into lines.
func wrap(s string, cols int) []string {
	s = view.Escape(s)
	var out []string
	for ansi.StringWidth(s) > cols {
		n, w := 0, 0
		for i, r := range s {
			rw := ansi.StringWidth(string(r))
			if w+rw > cols {
				break
			}
			w += rw
			n = i + len(string(r))
		}
		if n == 0 {
			break
		}
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

// details is the pending request as lines.
func (u *ui) details() []string {
	if u.st.Phase != wire.Pending {
		return nil
	}
	var out []string
	add := func(style, s string) {
		for _, l := range strings.Split(s, "\n") {
			for _, w := range wrap(l, u.cols) {
				out = append(out, style+fit(w, u.cols)+reset)
			}
		}
	}
	for _, w := range u.st.Warnings {
		add(red, "WARNING: "+w)
	}
	add(bold, u.st.Text)
	for _, d := range u.st.Details {
		add("", d)
	}
	for _, v := range u.st.Votes {
		if v.Approve {
			add("", "approved by "+v.Name)
		}
	}
	return out
}

// panelRows is the height of the panel.
func (u *ui) panelRows() int {
	if u.actor {
		return actorPanel
	}
	return 3 + u.detailRows()
}

// detailRows is how many lines of the request are visible.
func (u *ui) detailRows() int {
	if u.actor {
		return 0
	}
	return min(len(u.details()), max(1, u.rows*2/3-3))
}

func (u *ui) draw() {
	var lines []string
	cx, cy, visible := 0, 0, false
	if u.mode == paging || u.mode == confirmSign {
		lines = u.drawPager()
	} else {
		n := u.rows - u.panelRows()
		lines, cx, cy, visible = u.drawScreen(n)
		p, px, pcursor := u.drawPanel()
		if pcursor >= 0 {
			cx, cy, visible = px, n+pcursor, true
		}
		lines = append(lines, p...)
	}
	var b strings.Builder
	b.WriteString("\x1b[?25l")
	for i, l := range lines {
		if i >= u.rows {
			break
		}
		if i >= len(u.prev) || u.prev[i] != l {
			fmt.Fprintf(&b, "\x1b[%d;1H%s%s", i+1, reset, l)
		}
	}
	b.WriteString(reset)
	if visible {
		fmt.Fprintf(&b, "\x1b[%d;%dH\x1b[?25h", cy+1, cx+1)
	}
	if u.bell {
		b.WriteByte('\a')
		u.bell = false
	}
	u.prev = lines
	_, _ = u.out.Write([]byte(b.String()))
	if u.actor {
		m := map[int]bool{2004: true} // the daemon understands pasting
		if u.st.Phase == wire.Running {
			m = map[int]bool{1: u.frame.AppKeys, 2004: u.frame.Paste}
		}
		u.setModes(m)
	}
}

// setModes brings the user's terminal to the wanted input modes.
func (u *ui) setModes(want map[int]bool) {
	for _, m := range []int{1, 2004} {
		if want[m] != u.real[m] {
			c := 'l'
			if want[m] {
				c = 'h'
			}
			fmt.Fprintf(u.out, "\x1b[?%d%c", m, c)
			u.real[m] = want[m]
		}
	}
}

// sgr is what a style may be: colors and attributes only.
var sgr = regexp.MustCompile(`^(\x1b\[[0-9;:]*m)*$`)

// drawScreen renders n rows of the session's screen, around the cursor if it
// is larger than the window.
func (u *ui) drawScreen(n int) (lines []string, cx, cy int, visible bool) {
	top := 0
	if u.frame.CY >= n {
		top = u.frame.CY - n + 1
	}
	for y := top; y < top+n; y++ {
		var runs []wire.Run
		if y < len(u.lines) {
			runs = u.lines[y]
		}
		var b strings.Builder
		width := 0
		for _, r := range runs {
			text := view.Escape(r.T)
			if ansi.StringWidth(text) != r.W {
				// What had to be changed does not belong here.
				text = strings.Repeat("?", max(0, min(r.W, u.cols)))
			}
			if room := u.cols - width; ansi.StringWidth(text) > room {
				text = ansi.Truncate(text, room, "")
			}
			width += ansi.StringWidth(text)
			b.WriteString(reset)
			if sgr.MatchString(r.S) {
				b.WriteString(r.S)
			}
			b.WriteString(text)
		}
		b.WriteString(reset + strings.Repeat(" ", max(0, u.cols-width)))
		lines = append(lines, b.String())
	}
	cy = u.frame.CY - top
	return lines, max(0, min(u.frame.CX, u.cols-1)), cy, !u.frame.Hidden && cy >= 0 && cy < n
}

func (u *ui) title() string {
	st := &u.st
	who := "WITNESS of " + st.Actor
	if u.actor {
		who = "ACTOR " + st.Actor
	}
	s := fmt.Sprintf(" %s  %s ", who, strings.ToUpper(string(st.Phase)))
	if st.Phase == wire.Pending {
		n := 0
		for _, v := range st.Votes {
			if v.Approve {
				n++
			}
		}
		s += fmt.Sprintf("%d/%d ", n, st.Required)
	}
	if len(st.Witnesses) == 0 {
		s += " no witness "
	} else {
		s += " witnesses: " + strings.Join(st.Witnesses, ", ") + " "
	}
	if !st.ActorOnline {
		s += " actor is away "
	}
	if len(st.Weak) > 0 {
		s += " WEAK HOST "
	}
	if st.Download {
		s += " DOWNLOAD ALLOWED "
	}
	return view.Escape(s + " " + st.Dir)
}

var prompts = map[mode]string{comment: "reject, because: ", askView: "view file: ", askSig: "check signature of: ", askHash: "sha256 of: ",
	askSend: "LOCAL file to send: ", askSendTo: "to which file on the HOST: ", askGet: "file on the HOST to get: ", askGetTo: "save as LOCAL file: "}

// drawPanel returns the panel and where its cursor is, if it has one.
func (u *ui) drawPanel() (lines []string, cx, cursorRow int) {
	cursorRow = -1
	add := func(style, s string) { lines = append(lines, style+fit(s, u.cols)+reset) }
	if t := u.trouble(); t != "" {
		add(red+reverse, " "+t)
	} else {
		add(reverse, u.title())
	}
	prompt := prompts[u.mode]
	asking := func() {
		s := prompt + view.Escape(string(u.input))
		if w := ansi.StringWidth(s); w >= u.cols {
			s = ansi.TruncateLeft(s, w-u.cols+1, "")
		}
		cx, cursorRow = ansi.StringWidth(s), len(lines)
		add(bold, s)
	}
	if u.actor {
		switch {
		case u.mode == menu:
			add(bold, "LOCAL MENU  [u]pload a file  [g]et a file  [d]etach  other keys: back")
		case prompt != "":
			asking()
		case u.st.Phase == wire.Running:
			add("", "running: what you type goes to the program")
		case u.st.Phase == wire.Pending:
			add(bold, "waiting: "+view.Escape(strings.ReplaceAll(u.st.Text, "\n", " ⏎ "))+"   (Ctrl-C cancels)")
		default:
			line, x := u.draftLine()
			cx, cursorRow = x, len(lines)
			add("", line)
		}
		notice := u.st.Notice
		if u.message != "" {
			notice = u.message
		}
		add("", view.Escape(notice))
		return lines, cx, cursorRow
	}
	d := u.details()
	n := u.detailRows()
	u.scroll = max(0, min(u.scroll, len(d)-n))
	if u.st.Phase == wire.Pending && u.scroll+n >= len(d) {
		u.seenEnd = true
	}
	lines = append(lines, d[u.scroll:u.scroll+n]...)
	switch {
	case prompt != "":
		asking()
	case u.message != "":
		add(bold, view.Escape(strings.TrimRight(strings.ReplaceAll(u.message, "\n", " | "), " |")))
	case u.st.Phase != wire.Pending && u.st.Draft != "":
		add("", "typing: "+view.Escape(strings.ReplaceAll(u.st.Draft, "\n", " ⏎ ")))
	default:
		add("", view.Escape(u.st.Notice))
	}
	help := "[v]iew [s]ignature [h]ash [q]uit"
	if u.st.Phase == wire.Pending {
		if u.st.Transfer {
			help = "[o]pen [d]iff " + help
		}
		help = "[a]pprove [r]eject " + help
		if u.scroll+n < len(d) {
			help = "MORE: space  " + help
		}
	}
	add(reverse, " "+help)
	return lines, cx, cursorRow
}

// draftLine shows the part of the draft around the cursor.
func (u *ui) draftLine() (string, int) {
	r := []rune(strings.ReplaceAll(u.st.Draft, "\n", "⏎"))
	cur := min(u.st.Cursor, len(r))
	pre := "$ "
	if u.st.Phase == wire.Checking {
		pre = "checking "
	}
	before := view.Escape(string(r[:cur]))
	room := u.cols - ansi.StringWidth(pre) - 1
	if w := ansi.StringWidth(before); w > room {
		before = ansi.TruncateLeft(before, w-room, "")
	}
	return pre + before + view.Escape(string(r[cur:])), ansi.StringWidth(pre + before)
}

func (u *ui) drawPager() []string {
	p := u.pager
	all := p.Wrap(u.cols)
	n := u.rows - 2
	lines := []string{reverse + fit(p.Header(), u.cols) + reset}
	for i := p.Top; i < p.Top+n; i++ {
		l := ""
		if i < len(all) {
			l = all[i]
		}
		lines = append(lines, fit(l, u.cols)+reset)
	}
	foot := fmt.Sprintf(" %s  %d-%d of %d   space b j k g G   [S]ign   [q]uit", view.Escape(path.Base(p.Doc.Path)), p.Top+1, min(p.Top+n, len(all)), len(all))
	if p.Doc.SHA256 == "" {
		foot = strings.Replace(foot, "[S]ign   ", "", 1)
	}
	if u.mode == confirmSign {
		foot = " sign exactly this content, sha256 " + view.Escape(p.Doc.SHA256[:min(16, len(p.Doc.SHA256))]) + "…?  y / n"
		if p.Doc.Truncated {
			foot = " ONLY THE BEGINNING WAS SHOWN. sign all of it anyway?  y / n"
		}
	}
	if u.st.Phase == wire.Pending {
		foot += "   REQUEST WAITING"
	}
	if t := u.trouble(); t != "" {
		foot = " " + t
	}
	return append(lines, reverse+fit(foot, u.cols)+reset)
}
