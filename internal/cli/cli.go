// Package cli implements witnesshell's subcommand dispatch.
package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"

	"witnesshell/internal/sign"
	"witnesshell/internal/version"
)

// Exit codes.
const (
	ExitOK             = 0
	ExitError          = 1
	ExitUsage          = 2
	ExitNotImplemented = 3
)

type command struct {
	summary   string
	milestone string // non-empty while the command is still a stub
	run       func(args []string, stdout, stderr io.Writer) int
}

var commands = map[string]command{
	"connect":   {summary: "log in to a host: connect [--ssh] [--udp-host=HOST] [ssh options] [user@]host", run: runConnect},
	"bootstrap": {summary: "remote side of connect; started by sshd ForceCommand", run: runBootstrap},
	"daemon":    {summary: "run the session daemon (root)", run: runDaemon},
	"attach":    {summary: "on this host: start, reattach to or witness a session", run: runAttach},
	"sessions":  {summary: "list active sessions on this host", run: runSessions},
	"audit":     {summary: "audit tools: 'audit verify <file.log>'", milestone: "M6"},
	"version":   {summary: "print version information", run: runVersion},
	"checksig":  {summary: "show whether a file is trusted or signed: checksig FILE", run: runChecksig},
	"sign":      {summary: "sign a file on this host as a witness: sign [-sha256 HASH] FILE", run: runSign},
	"keyname":   {summary: "print the file name for a public key: keyname KEY.pub", run: runKeyname},
	"help":      {summary: "show this help"}, // handled in Run (avoids init cycle)
}

// Run dispatches args (without the program name) and returns an exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	name := args[0]
	switch name {
	case "-h", "--help":
		name = "help"
	case "-v", "--version":
		name = "version"
	}
	if name == "help" {
		usage(stdout)
		return ExitOK
	}
	cmd, ok := commands[name]
	if !ok {
		fmt.Fprintf(stderr, "witnesshell: unknown command %q\n\n", args[0])
		usage(stderr)
		return ExitUsage
	}
	if cmd.run == nil {
		fmt.Fprintf(stderr, "witnesshell %s: not implemented yet (milestone %s)\n", name, cmd.milestone)
		return ExitNotImplemented
	}
	return cmd.run(args[1:], stdout, stderr)
}

func runKeyname(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: witnesshell keyname KEY.pub")
		return ExitUsage
	}
	b, err := os.ReadFile(args[0])
	var name string
	if err == nil {
		name, err = sign.PublicKeyName(b)
	}
	if err != nil {
		fmt.Fprintln(stderr, "witnesshell keyname:", err)
		return ExitError
	}
	fmt.Fprintln(stdout, name)
	return ExitOK
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: witnesshell version")
		return ExitUsage
	}
	fmt.Fprintln(stdout, version.String())
	fmt.Fprintln(stdout, "protocol "+strconv.Itoa(version.ProtocolVersion))
	return ExitOK
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: witnesshell <command> [args]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "commands:")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c := commands[n]
		s := c.summary
		if c.run == nil && c.milestone != "" {
			s += " [not yet implemented]"
		}
		fmt.Fprintf(w, "  %-10s %s\n", n, s)
	}
}
