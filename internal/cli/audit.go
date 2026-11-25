package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"witnesshell/internal/audit"
	"witnesshell/internal/view"
)

func runAudit(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, "usage: witsh audit verify [-dir DIR] [-seal SHA256] SESSION-START")
		return ExitUsage
	}
	if len(args) == 0 || args[0] != "verify" {
		return usage()
	}
	f := flags("audit verify", stderr)
	dir := f.String("dir", audit.DefaultDir, "where the logs are")
	seal := f.String("seal", "", "the expected seal, from the system's log")
	if f.Parse(args[1:]) != nil || f.NArg() != 1 {
		return usage()
	}
	r, err := audit.Verify(*dir, f.Arg(0))
	if err != nil {
		return fail(stderr, "audit", errors.New(view.Escape(err.Error())))
	}
	for _, n := range r.Files {
		fmt.Fprintln(stdout, "file   ", view.Escape(n))
	}
	if r.Final != "" {
		fmt.Fprintln(stdout, "seal   ", r.Final)
	}
	if *seal != "" && !strings.EqualFold(*seal, r.Final) {
		r.Problems = append(r.Problems, "the seal is not the expected one")
	}
	for _, p := range r.Problems {
		fmt.Fprintln(stdout, "PROBLEM", view.Escape(p))
	}
	if len(r.Problems) > 0 {
		return ExitError
	}
	fmt.Fprintf(stdout, "ok      %d entries\n", r.Entries)
	if *seal == "" {
		fmt.Fprintln(stdout, "note    compare the seal with the one in the system's log (journalctl -u witnesshell)")
	}
	return ExitOK
}
