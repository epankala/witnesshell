// Package lang parses and expands the strict command language (PLAN.md 4.3).
// It is a small subset of bash. Whatever is not supported is an error: text
// must never run as something other than what it means in bash.
package lang

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

// Env supplies what expansion needs.
type Env interface {
	// Var returns a variable's value; "?" is the last exit status.
	Var(name string) (string, bool)
	Home() string
	// ReadDir lists a directory as the actor. Relative to the current one.
	ReadDir(dir string) ([]DirEntry, error)
}

// Chdirer is an Env that allows "cd DIR && ...": the rest of the line is
// expanded in the Env that Chdir returns.
type Chdirer interface {
	Chdir(args []string) (Env, error)
}

// DirEntry is one name found by ReadDir.
type DirEntry struct {
	Name string
	Dir  bool // a directory, or a link to one
}

// Op joins a pipeline to the one before it.
type Op uint8

const (
	Always Op = iota // ;
	And              // &&
	Or               // ||
)

// Line is an expanded command line.
type Line []Pipeline

// Pipeline is one or more commands joined by pipes.
type Pipeline struct {
	Op         Op
	Cmds       []Command
	Background bool
}

// Command is one simple command.
type Command struct {
	Assigns []Assign
	Argv    []string
	Redirs  []Redir
}

// Assign is a variable assignment.
type Assign struct{ Name, Value string }

// Redir is a redirection of descriptor FD, 0 to 2.
type Redir struct {
	FD     int
	Kind   RedirKind
	Path   string // for files
	Source int    // for Dup
}

// RedirKind says what a redirection does.
type RedirKind uint8

const (
	Read RedirKind = iota
	Write
	Append
	Dup
)

// Error is a syntax error or an unsupported construct.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errf(format string, args ...any) error { return &Error{fmt.Sprintf(format, args...)} }

// Parse parses and expands text. All words are expanded now, so the result is
// exactly what will run.
func Parse(text string, env Env) (Line, error) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil {
		return nil, errf("syntax error: %s", strings.TrimPrefix(err.Error(), ":"))
	}
	p := &parser{env: env}
	var out Line
	for _, s := range f.Stmts {
		l, err := p.list(s)
		if err != nil {
			return nil, err
		}
		out = append(out, l...)
	}
	return out, nil
}

type parser struct {
	env  Env
	done int // pipelines expanded so far
}

func (p *parser) plain(s *syntax.Stmt) error {
	switch {
	case s.Negated:
		return errf("'!' is not supported")
	case s.Coprocess, s.Disown:
		return errf("coprocesses are not supported")
	}
	return nil
}

// list flattens && and ||, which are left-associative with equal precedence.
func (p *parser) list(s *syntax.Stmt) (Line, error) {
	if err := p.plain(s); err != nil {
		return nil, err
	}
	if b, ok := s.Cmd.(*syntax.BinaryCmd); ok && (b.Op == syntax.AndStmt || b.Op == syntax.OrStmt) {
		if s.Background {
			return nil, errf("'&' after '&&' or '||' is not supported")
		}
		if len(s.Redirs) > 0 {
			return nil, errf("redirection of a list is not supported")
		}
		x, err := p.list(b.X)
		if err != nil {
			return nil, err
		}
		if c, ok := p.env.(Chdirer); ok && b.Op == syntax.AndStmt && p.done == 1 && IsCd(x[0]) {
			if p.env, err = c.Chdir(x[0].Cmds[0].Argv[1:]); err != nil {
				return nil, err
			}
		}
		y, err := p.list(b.Y)
		if err != nil {
			return nil, err
		}
		if len(y) != 1 {
			return nil, errf("unsupported list")
		}
		y[0].Op = And
		if b.Op == syntax.OrStmt {
			y[0].Op = Or
		}
		return append(x, y...), nil
	}
	cmds, err := p.pipeline(s)
	if err != nil {
		return nil, err
	}
	p.done++
	return Line{{Cmds: cmds, Background: s.Background}}, nil
}

// IsCd reports whether a pipeline is a plain cd.
func IsCd(p Pipeline) bool {
	return len(p.Cmds) == 1 && !p.Background && len(p.Cmds[0].Argv) > 0 && p.Cmds[0].Argv[0] == "cd" &&
		len(p.Cmds[0].Assigns) == 0 && len(p.Cmds[0].Redirs) == 0
}

func (p *parser) pipeline(s *syntax.Stmt) ([]Command, error) {
	if err := p.plain(s); err != nil {
		return nil, err
	}
	b, ok := s.Cmd.(*syntax.BinaryCmd)
	if !ok {
		c, err := p.command(s)
		if err != nil {
			return nil, err
		}
		return []Command{c}, nil
	}
	if b.Op != syntax.Pipe {
		return nil, errf("'%s' is not supported here", b.Op)
	}
	if len(s.Redirs) > 0 {
		return nil, errf("redirection of a pipeline is not supported")
	}
	if b.X.Background || b.Y.Background {
		return nil, errf("'&' inside a pipeline is not supported")
	}
	x, err := p.pipeline(b.X)
	if err != nil {
		return nil, err
	}
	y, err := p.pipeline(b.Y)
	if err != nil {
		return nil, err
	}
	return append(x, y...), nil
}

func (p *parser) command(s *syntax.Stmt) (c Command, err error) {
	switch n := s.Cmd.(type) {
	case nil:
		return c, errf("a redirection needs a command")
	case *syntax.CallExpr:
		for _, a := range n.Assigns {
			as, err := p.assign(a)
			if err != nil {
				return c, err
			}
			c.Assigns = append(c.Assigns, as)
		}
		for i, w := range n.Args {
			f, err := p.word(w)
			if err != nil {
				return c, err
			}
			if i == 0 && len(f) != 1 {
				return c, errf("the command name must be one word")
			}
			c.Argv = append(c.Argv, f...)
		}
	case *syntax.DeclClause:
		if n.Variant == nil || n.Variant.Value != "export" {
			return c, errf("'%s' is not supported", n.Variant.Value)
		}
		c.Argv = []string{"export"}
		for _, a := range n.Args {
			if a.Naked {
				if a.Name == nil || a.Value != nil || a.Index != nil || a.Array != nil {
					return c, errf("export takes NAME or NAME=value")
				}
				c.Argv = append(c.Argv, a.Name.Value)
				continue
			}
			as, err := p.assign(a)
			if err != nil {
				return c, err
			}
			c.Argv = append(c.Argv, as.Name+"="+as.Value)
		}
	default:
		return c, errf("%s is not supported", describe(n))
	}
	for _, r := range s.Redirs {
		rs, err := p.redirect(r)
		if err != nil {
			return c, err
		}
		c.Redirs = append(c.Redirs, rs...)
	}
	return c, nil
}

func describe(n syntax.Node) string {
	switch n.(type) {
	case *syntax.Subshell, *syntax.Block:
		return "a subshell or { } group"
	case *syntax.IfClause:
		return "'if'"
	case *syntax.WhileClause:
		return "'while'"
	case *syntax.ForClause:
		return "'for'"
	case *syntax.CaseClause:
		return "'case'"
	case *syntax.FuncDecl:
		return "a function"
	case *syntax.TestClause:
		return "'[['"
	case *syntax.CmdSubst:
		return "command substitution, $(...) or `...`,"
	case *syntax.ProcSubst:
		return "process substitution"
	case *syntax.ArithmExp, *syntax.ArithmCmd, *syntax.LetClause:
		return "arithmetic"
	case *syntax.ExtGlob:
		return "an extended pattern"
	}
	return strings.TrimPrefix(fmt.Sprintf("%T", n), "*syntax.")
}

func (p *parser) assign(a *syntax.Assign) (Assign, error) {
	if a.Append || a.Naked || a.Index != nil || a.Array != nil || a.Name == nil {
		return Assign{}, errf("only NAME=value assignments are supported")
	}
	out := Assign{Name: a.Name.Value}
	if a.Value == nil {
		return out, nil
	}
	t, err := p.expand(a.Value)
	if err != nil {
		return out, err
	}
	// Assignments are neither globbed nor split; ~ after ':' is expanded by
	// bash, so it must not pass unnoticed.
	for i, c := range t {
		if c.special && c.r == '~' && (i == 0 || t[i-1].r == ':') {
			return out, errf("quote '~' in an assignment or use $HOME")
		}
		out.Value += string(c.r)
	}
	return out, nil
}

func (p *parser) redirect(r *syntax.Redirect) ([]Redir, error) {
	if r.Hdoc != nil {
		return nil, errf("here-documents are not supported")
	}
	fd := -1
	if r.N != nil {
		if len(r.N.Value) != 1 || r.N.Value[0] < '0' || r.N.Value[0] > '2' {
			return nil, errf("only descriptors 0, 1 and 2 can be redirected")
		}
		fd = int(r.N.Value[0] - '0')
	}
	def := func(d int) int {
		if fd >= 0 {
			return fd
		}
		return d
	}
	if r.Op == syntax.DplOut {
		w := r.Word.Lit()
		if w != "1" && w != "2" {
			return nil, errf("only >&1 and >&2 are supported")
		}
		if def(1) == 0 {
			return nil, errf("descriptor 0 cannot be an output")
		}
		return []Redir{{FD: def(1), Kind: Dup, Source: int(w[0] - '0')}}, nil
	}
	f, err := p.word(r.Word)
	if err != nil {
		return nil, err
	}
	if len(f) != 1 || f[0] == "" {
		return nil, errf("a redirection needs exactly one file")
	}
	switch r.Op {
	case syntax.RdrIn:
		if def(0) != 0 {
			return nil, errf("only descriptor 0 can be an input")
		}
		return []Redir{{FD: 0, Kind: Read, Path: f[0]}}, nil
	case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll:
		k := Write
		if r.Op == syntax.AppOut || r.Op == syntax.AppAll {
			k = Append
		}
		if def(1) == 0 {
			return nil, errf("descriptor 0 cannot be an output")
		}
		out := []Redir{{FD: def(1), Kind: k, Path: f[0]}}
		if r.Op == syntax.RdrAll || r.Op == syntax.AppAll {
			out = append(out, Redir{FD: 2, Kind: Dup, Source: 1})
		}
		return out, nil
	}
	return nil, errf("redirection '%s' is not supported", r.Op)
}

// char is an expanded character. special means it was not quoted, so *, ? and
// ~ have their meaning.
type char struct {
	r       rune
	special bool
}

// expand resolves quotes and variables.
func (p *parser) expand(w *syntax.Word) ([]char, error) {
	var out []char
	quoted := func(s string) {
		for _, r := range s {
			out = append(out, char{r, false})
		}
	}
	for _, part := range w.Parts {
		switch n := part.(type) {
		case *syntax.Lit:
			rs := []rune(n.Value)
			for i := 0; i < len(rs); i++ {
				if rs[i] != '\\' {
					out = append(out, char{rs[i], true})
					continue
				}
				if i++; i == len(rs) {
					return nil, errf("backslash at the end")
				}
				if rs[i] != '\n' {
					quoted(string(rs[i]))
				}
			}
		case *syntax.SglQuoted:
			if n.Dollar {
				return nil, errf("$'...' is not supported")
			}
			quoted(n.Value)
		case *syntax.DblQuoted:
			if n.Dollar {
				return nil, errf("$\"...\" is not supported")
			}
			for _, q := range n.Parts {
				switch q := q.(type) {
				case *syntax.Lit:
					quoted(unescapeDouble(q.Value))
				case *syntax.ParamExp:
					v, err := p.param(q)
					if err != nil {
						return nil, err
					}
					quoted(v)
				default:
					return nil, errf("%s is not supported", describe(q))
				}
			}
		case *syntax.ParamExp:
			v, err := p.param(n)
			if err != nil {
				return nil, err
			}
			// bash would split or drop this, and treat *, ? and [ as patterns.
			if v == "" || strings.ContainsAny(v, " \t\n*?[\\") {
				return nil, errf("write \"$%s\" with quotes: its value is empty or has spaces or pattern characters", n.Param.Value)
			}
			quoted(v)
		default:
			return nil, errf("%s is not supported", describe(n))
		}
	}
	return out, nil
}

// unescapeDouble handles backslashes inside double quotes.
func unescapeDouble(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[i+1]) >= 0 {
			i++
			if s[i] == '\n' {
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (p *parser) param(n *syntax.ParamExp) (string, error) {
	// Only $name and ${name}: every other field must be unset.
	rest := *n
	rest.Dollar, rest.Rbrace, rest.Short, rest.Param = syntax.Pos{}, syntax.Pos{}, false, nil
	if n.Param == nil || !reflect.ValueOf(rest).IsZero() {
		return "", errf("only $NAME and ${NAME} are supported")
	}
	name := n.Param.Value
	if name != "?" && !syntax.ValidName(name) {
		return "", errf("$%s is not supported", name)
	}
	if name == "?" && p.done > 0 {
		return "", errf("$? is only known at the start of a line")
	}
	v, ok := p.env.Var(name)
	if !ok {
		return "", errf("variable %s is not set", name)
	}
	return v, nil
}

// word expands to one or more fields.
func (p *parser) word(w *syntax.Word) ([]string, error) {
	t, err := p.expand(w)
	if err != nil {
		return nil, err
	}
	pattern := false
	braces := ""
	for i, c := range t {
		if !c.special {
			continue
		}
		switch c.r {
		case '*', '?':
			pattern = true
		case '[':
			// "[" alone is the test command.
			if len(t) > 1 {
				return nil, errf("quote '[': such patterns are not supported")
			}
		case '{', '}':
			braces += string(c.r)
		case '~':
			if i == 0 {
				if len(t) > 1 && t[1].r != '/' {
					return nil, errf("~user is not supported")
				}
				if p.env.Home() == "" {
					return nil, errf("no home directory")
				}
			}
		}
	}
	if braces != "" && plainText(t) != "{}" {
		return nil, errf("quote '{' and '}': brace expansion is not supported")
	}
	if len(t) > 0 && t[0].special && t[0].r == '~' {
		var h []char
		for _, r := range p.env.Home() {
			h = append(h, char{r, false})
		}
		t = append(h, t[1:]...)
	}
	if !pattern {
		return []string{plainText(t)}, nil
	}
	return p.glob(t)
}

func plainText(t []char) string {
	var b strings.Builder
	for _, c := range t {
		b.WriteRune(c.r)
	}
	return b.String()
}

// maxGlob bounds how many names a pattern may produce.
const maxGlob = 4096

func (p *parser) glob(t []char) ([]string, error) {
	text := plainText(t)
	var comps [][]char
	start := 0
	for i := 0; i <= len(t); i++ {
		if i == len(t) || t[i].r == '/' {
			comps = append(comps, t[start:i])
			start = i + 1
		}
	}
	found := []string{""}
	if len(comps[0]) == 0 { // absolute
		found = []string{"/"}
		comps = comps[1:]
	}
	seen := false // a pattern was matched; later parts must exist
	for i, c := range comps {
		last := i == len(comps)-1
		var next []string
		if !isPattern(c) {
			for _, f := range found {
				name := plainText(c)
				if name == "" && !last {
					continue
				}
				next = append(next, f+name+slash(last))
			}
			if len(c) == 0 && !last { // a//b
				next = found
			}
			if seen && !last || seen && len(c) > 0 {
				var err error
				if next, err = p.existing(next, last); err != nil {
					return nil, err
				}
			}
			found = next
			continue
		}
		for _, f := range found {
			dir := f
			if dir == "" {
				dir = "."
			}
			ents, err := p.env.ReadDir(dir)
			if err != nil {
				if seen {
					continue // one of several; bash skips it too
				}
				return nil, errf("%s: %v", text, err)
			}
			for _, e := range ents { // sorted by name
				if strings.HasPrefix(e.Name, ".") && c[0].r != '.' || !match(c, []rune(e.Name)) || !last && !e.Dir {
					continue
				}
				if e.Name == "." || e.Name == ".." {
					continue
				}
				if !safe(e.Name) {
					return nil, errf("%s matches a name with hidden or control characters", text)
				}
				n := f + e.Name + slash(last)
				if strings.HasPrefix(n, "-") {
					return nil, errf("%s matches %q, which looks like an option; use ./%s", text, e.Name, text)
				}
				if next = append(next, n); len(next) > maxGlob {
					return nil, errf("%s matches more than %d names", text, maxGlob)
				}
			}
		}
		found, seen = next, true
	}
	if len(found) == 0 {
		return nil, errf("%s matches nothing", text)
	}
	return found, nil
}

// existing keeps the paths that exist.
func (p *parser) existing(paths []string, last bool) ([]string, error) {
	var out []string
	for _, f := range paths {
		trimmed := strings.TrimSuffix(f, "/")
		dir, name := "", trimmed
		if i := strings.LastIndexByte(trimmed, '/'); i >= 0 {
			dir, name = trimmed[:i+1], trimmed[i+1:]
		}
		if name == "." || name == ".." {
			return nil, errf("'.' or '..' after a pattern is not supported")
		}
		ents, err := p.env.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.Name == name && (last || e.Dir) {
				out = append(out, f)
			}
		}
	}
	return out, nil
}

func slash(last bool) string {
	if last {
		return ""
	}
	return "/"
}

func isPattern(t []char) bool {
	for _, c := range t {
		if c.special && (c.r == '*' || c.r == '?') {
			return true
		}
	}
	return false
}

// match is a linear-backtracking matcher for * and ?.
func match(p []char, s []rune) bool {
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && p[pi].special && p[pi].r == '*':
			star, mark = pi, si
			pi++
		case pi < len(p) && (p[pi].special && p[pi].r == '?' || p[pi].r == s[si] && !(p[pi].special && p[pi].r == '*')):
			pi++
			si++
		case star >= 0:
			mark++
			pi, si = star+1, mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi].special && p[pi].r == '*' {
		pi++
	}
	return pi == len(p)
}

func safe(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) || r == 0x2800 ||
			unicode.In(r, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector) {
			return false
		}
	}
	return true
}
