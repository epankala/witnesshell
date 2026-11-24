package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// LoginShell reports whether the binary was started as a login shell, which
// is how sshd, login and su start it. Then nothing but Bootstrap may happen.
func LoginShell(argv []string) bool {
	return len(argv) == 0 || strings.HasPrefix(argv[0], "-") || len(argv) > 1 && argv[1] == "-c"
}

// Bootstrap is all that a user of witnesshell can reach by logging in.
func Bootstrap(stdout, stderr io.Writer) int {
	// Set by sshd when the client asked for a command or a subsystem.
	if os.Getenv("SSH_ORIGINAL_COMMAND") != "" {
		return fail(stderr, "bootstrap", errors.New("only interactive logins are possible here (no commands, scp or sftp)"))
	}
	// Other programs of this user must not reach into this process.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fail(stderr, "bootstrap", err)
	}
	return runAttach(nil, stdout, stderr)
}

func runBootstrap(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintln(stderr, "usage: witnesshell bootstrap")
		return ExitUsage
	}
	return Bootstrap(stdout, stderr)
}

// sshArgs is the command line for ssh. The last argument must be the host, so
// that nothing can follow it as a command.
func sshArgs(args []string) ([]string, error) {
	if len(args) == 0 {
		return nil, errors.New("usage: witnesshell connect [ssh options] [user@]host")
	}
	host := args[len(args)-1]
	if host == "" || strings.HasPrefix(host, "-") {
		return nil, errors.New("the last argument must be [user@]host")
	}
	out := []string{"ssh", "-t", "-a", "-x"} // a terminal, no agent, no X11
	out = append(out, args[:len(args)-1]...)
	return append(out, "--", host), nil
}

func runConnect(args []string, _, stderr io.Writer) int {
	argv, err := sshArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	ssh, err := exec.LookPath("ssh")
	if err == nil {
		err = syscall.Exec(ssh, argv, os.Environ())
	}
	return fail(stderr, "connect", err)
}
