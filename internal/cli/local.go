package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"witnesshell/internal/daemon"
	"witnesshell/internal/sign"
	"witnesshell/internal/view"
	"witnesshell/internal/wire"
)

func fail(stderr io.Writer, cmd string, err error) int {
	fmt.Fprintf(stderr, "witnesshell %s: %s\n", cmd, err)
	return ExitError
}

func flags(name string, stderr io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(stderr)
	return f
}

func runDaemon(args []string, _, stderr io.Writer) int {
	f := flags("daemon", stderr)
	config := f.String("config", daemon.DefaultConfig, "configuration `file`")
	if f.Parse(args) != nil || f.NArg() > 0 {
		return ExitUsage
	}
	c, err := daemon.LoadConfig(*config)
	if err != nil {
		return fail(stderr, "daemon", err)
	}
	d, err := daemon.New(c, slog.New(slog.NewTextHandler(stderr, nil)))
	if err != nil {
		return fail(stderr, "daemon", err)
	}
	l, err := daemon.Listen(daemon.DefaultSocket)
	if err != nil {
		return fail(stderr, "daemon", err)
	}
	if err := d.ServeQUIC(); err != nil {
		return fail(stderr, "daemon", err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, unix.SIGINT, unix.SIGTERM)
	go func() {
		<-sig
		_ = l.Close()
	}()
	err = d.Serve(l)
	d.Close()
	if err != nil {
		return fail(stderr, "daemon", err)
	}
	return ExitOK
}

// ask sends one request to the daemon and returns the answer.
func ask(c net.Conn, q wire.Request) (wire.Reply, error) {
	q.Version = wire.Version
	var r wire.Reply
	if err := wire.Write(c, q); err != nil {
		return r, err
	}
	if err := wire.Read(c, wire.MaxReply, &r); err != nil {
		return r, fmt.Errorf("no answer from the daemon: %w", err)
	}
	if r.Type == wire.Error {
		return r, errors.New(view.Escape(r.Text))
	}
	return r, nil
}

func dial() (net.Conn, error) {
	c, err := net.Dial("unix", daemon.DefaultSocket)
	if err != nil {
		return nil, fmt.Errorf("is the daemon running? %w", err)
	}
	return c, nil
}

func runSessions(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintln(stderr, "usage: witnesshell sessions")
		return ExitUsage
	}
	c, err := dial()
	if err != nil {
		return fail(stderr, "sessions", err)
	}
	defer c.Close()
	r, err := ask(c, wire.Request{Type: wire.List})
	if err != nil {
		return fail(stderr, "sessions", err)
	}
	for _, s := range r.Sessions {
		fmt.Fprintf(stdout, "%s  %s\n", view.Escape(s.ID), view.Escape(s.Actor))
	}
	return ExitOK
}

func runSign(args []string, stdout, stderr io.Writer) int {
	f := flags("sign", stderr)
	want := f.String("sha256", "", "refuse unless the file has this `hash`")
	if f.Parse(args) != nil || f.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: witnesshell sign [-sha256 HASH] FILE")
		return ExitUsage
	}
	file, err := os.Open(f.Arg(0))
	if err != nil {
		return fail(stderr, "sign", err)
	}
	defer file.Close()
	d, err := sign.Hash(file)
	if err != nil {
		return fail(stderr, "sign", err)
	}
	if *want != "" && !strings.EqualFold(*want, d.Hex()) {
		return fail(stderr, "sign", fmt.Errorf("the file's SHA-256 is %s", d.Hex()))
	}
	c, err := dial()
	if err != nil {
		return fail(stderr, "sign", err)
	}
	defer c.Close()
	if _, err := ask(c, wire.Request{Type: wire.Sign, Text: d.Hex()}); err != nil {
		return fail(stderr, "sign", err)
	}
	fmt.Fprintf(stdout, "signed sha256 %s\n", d.Hex())
	return ExitOK
}

func runAttach(args []string, stdout, stderr io.Writer) int {
	f := flags("attach", stderr)
	start := f.Bool("new", false, "start a session")
	id := f.String("session", "", "join this session `id`")
	if f.Parse(args) != nil || f.NArg() > 0 || *start && *id != "" {
		fmt.Fprintln(stderr, "usage: witnesshell attach [-new | -session ID]")
		return ExitUsage
	}
	if !term.IsTerminal(0) || !term.IsTerminal(1) {
		return fail(stderr, "attach", errors.New("needs a terminal"))
	}
	if err := attachLoop(localDialer{}, *start, *id, stdout); err != nil {
		return fail(stderr, "attach", err)
	}
	return ExitOK
}

// attachOnce joins one session. It reports whether to offer another: a
// witness whose session ends may go on to a different one (D32).
func attachOnce(d dialer, start bool, id string, lobby bool, stdout io.Writer) (bool, error) {
	if lobby {
		// Keys meant for the session that just ended must not choose.
		time.Sleep(time.Second)
		_ = unix.IoctlSetInt(0, unix.TCFLSH, unix.TCIFLUSH)
	}
	c, err := d.open()
	if err != nil {
		return false, err
	}
	defer c.Close()
	q, err := choose(func() (wire.Reply, error) { return ask(c, wire.Request{Type: wire.List}) }, start, id, lobby, os.Stdin, stdout)
	if errors.Is(err, errQuit) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	res, err := joinSession(d, c, q)
	if err != nil {
		if lobby { // for example, the session has ended meanwhile
			fmt.Fprintf(stdout, "witnesshell: %s\n", err)
			return true, nil
		}
		return false, err
	}
	if res.Why != "" {
		fmt.Fprintf(stdout, "witnesshell: %s\n", view.Escape(res.Why))
	}
	return res.Ended && q.Type == wire.Witness, nil
}

var errQuit = errors.New("quit")

// choose asks what to do, unless there is only one possibility (D14). In the
// lobby it always asks, until there is an answer.
func choose(list func() (wire.Reply, error), start bool, id string, lobby bool, in io.Reader, out io.Writer) (wire.Request, error) {
	newSession := wire.Request{Type: wire.Actor}
	join := func(s wire.Session) wire.Request {
		if s.Own {
			return wire.Request{Type: wire.Actor, Session: s.ID}
		}
		return wire.Request{Type: wire.Witness, Session: s.ID}
	}
	b := bufio.NewReaderSize(in, 16)
	for try := 0; lobby || try < 3; try++ {
		r, err := list()
		if err != nil {
			return newSession, err
		}
		if !lobby && (start || id == "" && len(r.Sessions) == 0) {
			return newSession, nil
		}
		if id != "" {
			for _, s := range r.Sessions {
				if s.ID == id {
					return join(s), nil
				}
			}
			return newSession, errors.New("no such session")
		}
		others := false
		for i, s := range r.Sessions {
			what := "return to your session"
			if !s.Own {
				what, others = "witness the session of "+s.Actor, true
			}
			fmt.Fprintf(out, "  [%d] %s, started %s\n", i+1, view.Escape(what), view.Escape(s.Since))
		}
		if !others {
			fmt.Fprintln(out, "  there is no session to witness")
		}
		if r.CanStart {
			fmt.Fprintln(out, "  [n] start your own session")
		}
		fmt.Fprint(out, "  [r] refresh  [q] quit\nchoose: ")
		l, err := b.ReadString('\n')
		if err != nil {
			return newSession, errQuit
		}
		switch l = strings.TrimSpace(l); {
		case l == "q":
			return newSession, errQuit
		case l == "r":
			try = -1
		case l == "n" && r.CanStart:
			return newSession, nil
		}
		// The numbers are those of the list that was shown.
		if n, err := strconv.Atoi(l); err == nil && n >= 1 && n <= len(r.Sessions) {
			return join(r.Sessions[n-1]), nil
		}
	}
	return newSession, errors.New("nothing chosen")
}
