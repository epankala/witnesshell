package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// LoginShell reports whether the binary was started as a login shell, which
// is how sshd, login and su start it. Then nothing but Bootstrap may happen.
func LoginShell(argv []string) bool {
	return len(argv) == 0 || strings.HasPrefix(argv[0], "-") || len(argv) > 1 && argv[1] == "-c"
}

// Bootstrap is all that a user of witnesshell can reach by logging in.
func Bootstrap(stdout, stderr io.Writer) int {
	// Other programs of this user must not reach into this process.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fail(stderr, "bootstrap", err)
	}
	// Set by sshd when the client asked for a command or a subsystem.
	if c := os.Getenv("SSH_ORIGINAL_COMMAND"); c == quicCommand {
		return giveTicket(stdout, stderr)
	} else if c != "" {
		return fail(stderr, "bootstrap", errors.New("only interactive logins are possible here (no commands, scp or sftp)"))
	}
	return runAttach(nil, stdout, stderr)
}

func runBootstrap(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintln(stderr, "usage: witsh bootstrap")
		return ExitUsage
	}
	return Bootstrap(stdout, stderr)
}
