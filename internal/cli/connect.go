package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"witnesshell/internal/transport"
	"witnesshell/internal/ui"
	"witnesshell/internal/wire"
)

// quicCommand is the only command that Bootstrap accepts over ssh.
const quicCommand = "quic 1"

// dialer opens connections to a daemon.
type dialer interface {
	open() (net.Conn, error)
	// screen asks for a separate stream of output; id 0 means there is none.
	screen() (id uint64, arrives <-chan io.Reader)
}

type localDialer struct{}

func (localDialer) open() (net.Conn, error)            { return dial() }
func (localDialer) screen() (uint64, <-chan io.Reader) { return 0, nil }

type quicDialer struct{ *transport.Client }

func (q quicDialer) open() (net.Conn, error)            { return q.Open() }
func (q quicDialer) screen() (uint64, <-chan io.Reader) { return q.NewScreen() }

// ticket is what the bootstrap hands to the client over ssh.
type ticket struct {
	port        int
	fingerprint string
	token       string
}

var ticketLine = regexp.MustCompile(`^WITNESSHELL 1 ([0-9]{1,5}) ([0-9a-f]{64}) ([A-Za-z0-9_-]{43})$`)

func parseTicket(r io.Reader) (ticket, error) {
	sc := bufio.NewScanner(io.LimitReader(r, 64<<10)) // banners may come first
	for sc.Scan() {
		if m := ticketLine.FindStringSubmatch(strings.TrimRight(sc.Text(), "\r")); m != nil {
			p, err := strconv.ParseUint(m[1], 10, 16)
			if err != nil || p == 0 {
				break
			}
			return ticket{int(p), m[2], m[3]}, nil
		}
	}
	return ticket{}, errors.New("the host did not offer a session; is witnesshell its login shell?")
}

// giveTicket is the remote side of connect.
func giveTicket(stdout, stderr io.Writer) int {
	c, err := dial()
	if err != nil {
		return fail(stderr, "bootstrap", err)
	}
	defer c.Close()
	r, err := ask(c, wire.Request{Type: wire.Token})
	if err != nil {
		return fail(stderr, "bootstrap", err)
	}
	fmt.Fprintf(stdout, "WITNESSHELL 1 %s\n", r.Text)
	return ExitOK
}

type connectOptions struct {
	ssh     bool   // stay on ssh
	udpHost string // where to send UDP, if not to the ssh host
	opts    []string
	host    string
}

func parseConnect(args []string) (o connectOptions, err error) {
	for len(args) > 0 {
		if args[0] == "--ssh" {
			o.ssh = true
		} else if v, ok := strings.CutPrefix(args[0], "--udp-host="); ok && v != "" {
			o.udpHost = v
		} else {
			break
		}
		args = args[1:]
	}
	// The last argument is the host, so that nothing follows it as a command.
	if len(args) == 0 || args[len(args)-1] == "" || strings.HasPrefix(args[len(args)-1], "-") {
		return o, errors.New("usage: witnesshell connect [--ssh] [--udp-host=HOST] [ssh options] [user@]host")
	}
	o.opts, o.host = args[:len(args)-1], args[len(args)-1]
	return o, nil
}

// argv is a command line for ssh: no agent and no X11.
func (o connectOptions) argv(first []string, command ...string) []string {
	out := append([]string{"ssh", "-a", "-x"}, first...)
	out = append(out, o.opts...)
	return append(append(out, "--", o.host), command...)
}

func runConnect(args []string, stdout, stderr io.Writer) int {
	o, err := parseConnect(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		return fail(stderr, "connect", err)
	}
	if o.ssh {
		return fail(stderr, "connect", syscall.Exec(ssh, o.argv([]string{"-t"}), os.Environ()))
	}
	if !term.IsTerminal(0) || !term.IsTerminal(1) {
		return fail(stderr, "connect", errors.New("needs a terminal"))
	}
	c, err := quicConnect(ssh, o, stderr)
	if err != nil {
		return fail(stderr, "connect", err)
	}
	defer c.Close()
	if err := attachLoop(quicDialer{c}, false, "", stdout); err != nil {
		return fail(stderr, "connect", err)
	}
	return ExitOK
}

func quicConnect(ssh string, o connectOptions, stderr io.Writer) (*transport.Client, error) {
	addrs, err := udpAddresses(ssh, o)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(ssh)
	cmd.Args = o.argv([]string{"-T"}, quicCommand)
	cmd.Stderr = stderr // ssh asks for passwords on the terminal itself
	out, err := cmd.Output()
	t, perr := parseTicket(bytes.NewReader(out))
	if perr != nil {
		if err != nil {
			return nil, fmt.Errorf("ssh: %w", err)
		}
		return nil, perr
	}
	for _, a := range addrs {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var c *transport.Client
		c, err = transport.Dial(ctx, net.JoinHostPort(a, strconv.Itoa(t.port)), t.fingerprint, t.token)
		cancel()
		if err == nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no UDP connection to %s port %d: %w\n(--udp-host=HOST sends UDP elsewhere; --ssh does without)", strings.Join(addrs, ", "), t.port, err)
}

// udpAddresses finds where to send UDP: where ssh would connect to.
func udpAddresses(ssh string, o connectOptions) ([]string, error) {
	host := o.udpHost
	if host == "" {
		cmd := exec.Command(ssh)
		cmd.Args = o.argv([]string{"-G"})
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("ssh -G: %w", err)
		}
		for _, l := range strings.Split(string(out), "\n") {
			if h, ok := strings.CutPrefix(l, "hostname "); ok {
				host = strings.TrimSpace(h)
			}
		}
	}
	a, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// attachLoop joins sessions until the user is done.
func attachLoop(d dialer, start bool, id string, stdout io.Writer) error {
	for lobby := false; ; lobby = true {
		next, err := attachOnce(d, start, id, lobby, stdout)
		if err != nil || !next {
			return err
		}
		start, id = false, ""
	}
}

// joinSession joins a session over c.
func joinSession(d dialer, c net.Conn, q wire.Request) (ui.Result, error) {
	q.Version = wire.Version
	var arrives <-chan io.Reader
	q.Screen, arrives = d.screen()
	return ui.Run(c, q, arrives, os.Stdin, os.Stdout)
}
