package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"witnesshell/internal/wire"
)

var ends = make(chan bool, 100)

func serve(t *testing.T) (*Server, string) {
	t.Helper()
	s, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	go func() {
		_ = s.Serve(func(q wire.Request, _ func()) (Accepted, error) {
			if q.Text != "good" {
				return Accepted{}, errors.New("bad token")
			}
			return Accepted{42, "secret", func(quit bool) { ends <- quit }}, nil
		}, func(st *Stream, uid uint32) {
			defer st.Close()
			var q wire.Request
			if wire.Read(st, 1<<16, &q) != nil {
				return
			}
			_ = wire.Write(st, wire.Reply{Type: wire.OK, Text: fmt.Sprint(uid, " ", q.Text)})
			if q.Screen != 0 {
				if out, err := st.Screen(q.Screen); err == nil {
					_, _ = io.WriteString(out, "screen")
					_ = out.Close()
				}
			}
			_, _ = io.Copy(io.Discard, st)
		})
	}()
	return s, fmt.Sprintf("127.0.0.1:%d", s.Port)
}

func dial(t *testing.T, addr, fp, tok string) (*Client, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, addr, fp, wire.Request{Type: wire.Auth, Text: tok})
	if err == nil {
		t.Cleanup(c.Close)
	}
	return c, err
}

func TestStreams(t *testing.T) {
	s, addr := serve(t)
	c, err := dial(t, addr, s.Fingerprint, "good")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 20 { // more than may be open at once
		st, err := c.Open()
		if err != nil {
			t.Fatal(i, err)
		}
		id, ch := c.NewScreen()
		if err := wire.Write(st, wire.Request{Text: "x", Screen: id}); err != nil {
			t.Fatal(err)
		}
		var r wire.Reply
		if err := wire.Read(st, 1<<16, &r); err != nil || r.Text != "42 x" {
			t.Fatal(i, r, err)
		}
		select {
		case rd := <-ch:
			if b, err := io.ReadAll(rd); string(b) != "screen" {
				t.Fatal(string(b), err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no screen")
		}
		_ = st.Close()
	}
	if n := s.strangers.Load(); n != 0 {
		t.Errorf("%d strangers left", n)
	}
}

func TestEnded(t *testing.T) {
	s, addr := serve(t)
	for _, quit := range []bool{true, false} {
		c, err := dial(t, addr, s.Fingerprint, "good")
		if err != nil || c.Secret != "secret" || !c.Alive() {
			t.Fatal(err)
		}
		for len(ends) > 0 {
			<-ends
		}
		if quit {
			c.Close()
		} else {
			c.Drop()
		}
		select {
		case got := <-ends:
			if got != quit {
				t.Errorf("quit = %v, want %v", got, quit)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("end not noticed")
		}
		if c.Alive() {
			t.Error("still alive")
		}
	}
}

func TestRefused(t *testing.T) {
	s, addr := serve(t)
	for _, tok := range []string{"bad", ""} {
		if _, err := dial(t, addr, s.Fingerprint, tok); !errors.Is(err, ErrRefused) {
			t.Error(err)
		}
	}
	if _, err := dial(t, addr, strings.Repeat("0", 64), "good"); !errors.Is(err, ErrRefused) {
		t.Error(err)
	}
	if _, err := dial(t, addr, s.Fingerprint, "bad"); err == nil || !strings.Contains(err.Error(), "bad token") {
		t.Error(err)
	}
	if _, err := dial(t, addr, strings.Repeat("0", 64), "good"); err == nil || !strings.Contains(err.Error(), "ssh vouched") {
		t.Error(err)
	}
	if _, err := dial(t, addr, "", "good"); err == nil {
		t.Error("no fingerprint accepted")
	}
	// An impostor on the same port never sees the token.
	other, oaddr := serve(t)
	if _, err := dial(t, oaddr, s.Fingerprint, "good"); err == nil || other.Fingerprint == s.Fingerprint {
		t.Error("impostor accepted")
	}
}

// TestStrangers checks that a client without a token gets nowhere and does
// not stay.
func TestStrangers(t *testing.T) {
	s, addr := serve(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tc := clientTLS()
	var conns []*quic.Conn
	for range 40 {
		c, err := quic.DialAddr(ctx, addr, tc, &quic.Config{KeepAlivePeriod: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	// Streams that skip the token are not handled.
	st, err := conns[0].OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = wire.Write(st, wire.Request{Type: wire.List, Version: wire.Version})
	if b, _ := io.ReadAll(st); len(b) != 0 {
		t.Errorf("answered %q", b)
	}
	if st, err := conns[1].OpenStreamSync(ctx); err == nil {
		_, _ = st.Write([]byte{0xff, 0xff, 0xff, 0xff})
	}
	for _, c := range conns {
		select {
		case <-c.Context().Done():
		case <-ctx.Done():
			t.Fatal("stranger stayed")
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := s.strangers.Load(); n != 0 {
		t.Errorf("%d strangers left", n)
	}
	if _, err := dial(t, addr, s.Fingerprint, "good"); err != nil {
		t.Error("no longer reachable:", err)
	}
}

func TestGarbage(t *testing.T) {
	s, addr := serve(t)
	u, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for i := range 2000 {
		_, _ = u.Write([]byte(strings.Repeat(string(rune(i%256)), i%1400)))
	}
	if _, err := dial(t, addr, s.Fingerprint, "good"); err != nil {
		t.Fatal(err)
	}
}
