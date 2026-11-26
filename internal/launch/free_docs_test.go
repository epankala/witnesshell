package launch

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestSuggestedFreeDocumented keeps the lists in the README and the demo VM
// the same as SuggestedFree.
func TestSuggestedFreeDocumented(t *testing.T) {
	quoted := regexp.MustCompile(`"([^"]*)"`)
	for _, f := range []string{"../../README.md", "../../scripts/vm-demo.sh"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		i := strings.Index(s, "free_commands = [\n")
		if i < 0 {
			t.Fatalf("%s: no free_commands list", f)
		}
		end := strings.Index(s[i:], "\n]")
		var names []string
		for _, l := range strings.Split(s[i+len("free_commands = [\n"):i+end], "\n") {
			l, _, _ = strings.Cut(l, "#")
			for _, m := range quoted.FindAllStringSubmatch(l, -1) {
				names = append(names, m[1])
			}
		}
		if !slices.Equal(names, SuggestedFree) {
			t.Errorf("%s lists %q, want %q", f, names, SuggestedFree)
		}
	}
}
