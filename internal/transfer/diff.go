package transfer

import "fmt"

const (
	maxDiffLines = 20000
	maxEdits     = 2000
	context      = 3
)

// Diff returns the differences between two texts in unified format, or why it
// cannot.
func Diff(a, b []string) ([]string, error) {
	if len(a) > maxDiffLines || len(b) > maxDiffLines {
		return nil, fmt.Errorf("too large to compare")
	}
	ops, ok := myers(a, b)
	if !ok {
		return nil, fmt.Errorf("too different to compare")
	}
	var out []string
	for i := 0; i < len(ops); {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		// A hunk: until more than 2*context equal lines follow.
		start := max(0, i-context)
		end, equal := i, 0
		for end < len(ops) && equal <= 2*context {
			if ops[end].kind == ' ' {
				equal++
			} else {
				equal = 0
			}
			end++
		}
		end = min(len(ops), end-max(0, equal-context))
		na, nb := 0, 0
		for _, o := range ops[start:end] {
			if o.kind != '+' {
				na++
			}
			if o.kind != '-' {
				nb++
			}
		}
		out = append(out, fmt.Sprintf("@@ -%d,%d +%d,%d @@", ops[start].a+1, na, ops[start].b+1, nb))
		for _, o := range ops[start:end] {
			out = append(out, string(o.kind)+o.text)
		}
		i = end
	}
	return out, nil
}

type op struct {
	kind byte
	text string
	a, b int // positions in both texts
}

// myers finds a shortest edit script.
func myers(a, b []string) ([]op, bool) {
	n, m := len(a), len(b)
	v := map[int]int{1: 0}
	var trace []map[int]int
	found := false
	for d := 0; d <= min(n+m, maxEdits) && !found; d++ {
		c := make(map[int]int, 2*d+1)
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || k != d && v[k-1] < v[k+1] {
				x = v[k+1]
			} else {
				x = v[k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x, y = x+1, y+1
			}
			c[k] = x
			if x >= n && y >= m {
				found = true
				break
			}
		}
		trace = append(trace, v)
		v = make(map[int]int, len(v)+len(c))
		for k, x := range c {
			v[k] = x
		}
	}
	if !found {
		return nil, false
	}
	var rev []op
	x, y := n, m
	for d := len(trace) - 1; d >= 0; d-- {
		p, k := trace[d], x-y
		pk := k - 1
		if k == -d || k != d && p[k-1] < p[k+1] {
			pk = k + 1
		}
		px := p[pk]
		py := px - pk
		for x > px && y > py && x > 0 && y > 0 {
			x, y = x-1, y-1
			rev = append(rev, op{' ', a[x], x, y})
		}
		if d > 0 {
			if x == px {
				y--
				rev = append(rev, op{'+', b[y], x, y})
			} else {
				x--
				rev = append(rev, op{'-', a[x], x, y})
			}
		}
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev, true
}
