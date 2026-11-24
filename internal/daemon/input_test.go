package daemon

import (
	"fmt"
	"testing"
)

func parse(chunks ...string) (out []string) {
	var k keys
	for _, c := range chunks {
		k.buf = append(k.buf, c...)
		for {
			e, ok := k.next()
			if !ok {
				break
			}
			switch e.kind {
			case evText:
				out = append(out, "T"+e.text)
			case evEdit:
				out = append(out, fmt.Sprintf("E%d", e.op))
			default:
				out = append(out, fmt.Sprintf("K%d", e.kind))
			}
		}
	}
	return out
}

func TestKeys(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{[]string{"ls -l\r"}, "[Tls -l K2]"},
		{[]string{"\x1b[A\x1bOB\x1b[3~"}, "[E9 E10 E5]"},
		{[]string{"\x1b", "[", "A"}, "[E9]"},
		{[]string{"\xc3", "\xa4"}, "[Tä]"},
		{[]string{"\x1b[200~a\nb\r", "c\x1b[2", "01~d"}, "[Ta\nb\rc Td]"},
		{[]string{"\x1b[200~\x03\x1b[201~"}, "[T\x03]"}, // refused by the gate, not obeyed
		{[]string{"\x03\x04\t"}, "[K3 K4 K5]"},
		{[]string{"\x1b[99;99X"}, "[K5]"},
		{[]string{"\x1bx"}, "[K5]"},
	} {
		if got := fmt.Sprint(parse(c.in...)); got != c.want {
			t.Errorf("%q: %q, want %q", c.in, got, c.want)
		}
	}
}

func FuzzKeys(f *testing.F) {
	f.Add("ls\r\x1b[200~x\x1b[201~", 3)
	f.Fuzz(func(t *testing.T, s string, cut int) {
		if cut < 0 || cut > len(s) {
			return
		}
		parse(s[:cut], s[cut:])
	})
}
