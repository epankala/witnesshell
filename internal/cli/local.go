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

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"witnesshell/internal/daemon"
	"witnesshell/internal/sign"
	"witnesshell/internal/ui"
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
	c, err := dial()
	if err != nil {
		return fail(stderr, "attach", err)
	}
	defer c.Close()
	r, err := ask(c, wire.Request{Type: wire.List})
	if err != nil {
		return fail(stderr, "attach", err)
	}
	q, err := choose(r, *start, *id, os.Stdin, stdout)
	if err != nil {
		return fail(stderr, "attach", err)
	}
	q.Version = wire.Version
	why, err := ui.Run(c, q, os.Stdin, os.Stdout)
	if err != nil {
		return fail(stderr, "attach", err)
	}
	if why != "" {
		fmt.Fprintf(stdout, "witnesshell: %s\n", view.Escape(why))
	}
	return ExitOK
}

// choose asks what to do, unless there is only one possibility (D14).
func choose(r wire.Reply, start bool, id string, in io.Reader, out io.Writer) (wire.Request, error) {
	newSession := wire.Request{Type: wire.Actor}
	join := func(s wire.Session) wire.Request {
		if s.Own {
			return wire.Request{Type: wire.Actor, Session: s.ID}
		}
		return wire.Request{Type: wire.Witness, Session: s.ID}
	}
	if start || id == "" && len(r.Sessions) == 0 {
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
	for i, s := range r.Sessions {
		what := "witness the session of " + s.Actor
		if s.Own {
			what = "return to your session"
		}
		fmt.Fprintf(out, "  [%d] %s, started %s\n", i+1, view.Escape(what), view.Escape(s.Since))
	}
	if r.CanStart {
		fmt.Fprintln(out, "  [n] start your own session")
	}
	b := bufio.NewReaderSize(in, 16)
	for range 3 {
		fmt.Fprint(out, "choose: ")
		l, err := b.ReadString('\n')
		if err != nil {
			return newSession, err
		}
		l = strings.TrimSpace(l)
		if l == "n" && r.CanStart {
			return newSession, nil
		}
		if n, err := strconv.Atoi(l); err == nil && n >= 1 && n <= len(r.Sessions) {
			return join(r.Sessions[n-1]), nil
		}
	}
	return newSession, errors.New("nothing chosen")
}
