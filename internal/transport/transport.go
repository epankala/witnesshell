// Package transport carries the protocol over QUIC. The client learns the
// server's certificate and a one-time token over ssh, so each side knows who
// the other is.
package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"witnesshell/internal/wire"
)

const (
	alpn        = "witnesshell/1"
	authTimeout = 5 * time.Second
	// Strangers who have not presented a token yet.
	maxStrangers   = 256
	manyStrangers  = 16 // from here on their addresses are verified
	streamsPerConn = 8
)

// Codes with which connections are closed.
const (
	codeQuit quic.ApplicationErrorCode = iota // the user has finished
	codeDone
)

// ErrRefused means that trying again is pointless.
var ErrRefused = errors.New("not accepted")

func config() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: authTimeout,
		MaxIdleTimeout:       15 * time.Second,
		// Small windows: what is in flight cannot be overtaken or dropped.
		InitialStreamReceiveWindow:     64 << 10,
		MaxStreamReceiveWindow:         256 << 10,
		InitialConnectionReceiveWindow: 256 << 10,
		MaxConnectionReceiveWindow:     1 << 20,
	}
}

// Stream is a QUIC stream as a net.Conn.
type Stream struct {
	*quic.Stream
	conn *quic.Conn
}

func (s *Stream) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// Close ends both directions.
func (s *Stream) Close() error {
	s.CancelRead(0)
	return s.Stream.Close()
}

// Screen opens a stream to the client for output, named by the client's id.
func (s *Stream) Screen(id uint64) (*quic.SendStream, error) {
	ctx, cancel := context.WithTimeout(s.conn.Context(), authTimeout)
	defer cancel()
	out, err := s.conn.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	_ = out.SetWriteDeadline(time.Now().Add(authTimeout))
	return out, wire.Write(out, wire.Reply{Type: wire.Screen, Text: strconv.FormatUint(id, 10)})
}

// Server accepts QUIC connections.
type Server struct {
	// Fingerprint is the SHA-256 of the certificate, in hex.
	Fingerprint string
	Port        int

	tr        *quic.Transport
	ln        *quic.Listener
	strangers atomic.Int64
}

type strangerKey struct{}

// Listen binds a UDP port, with a certificate made for this run.
func Listen(port int) (*Server, error) {
	cert, err := newCertificate()
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(cert.Certificate[0])
	s := &Server{Fingerprint: hex.EncodeToString(h[:]), Port: pc.LocalAddr().(*net.UDPAddr).Port}
	var reset quic.StatelessResetKey
	if _, err := rand.Read(reset[:]); err != nil {
		return nil, err
	}
	s.tr = &quic.Transport{
		Conn:                pc,
		StatelessResetKey:   &reset,
		VerifySourceAddress: func(net.Addr) bool { return s.strangers.Load() >= manyStrangers },
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			if s.strangers.Add(1) > maxStrangers {
				s.strangers.Add(-1)
				return nil, errors.New("too many connections")
			}
			known := sync.OnceFunc(func() { s.strangers.Add(-1) })
			context.AfterFunc(ctx, known)
			return context.WithValue(ctx, strangerKey{}, known), nil
		},
	}
	c := config()
	c.MaxIncomingStreams, c.MaxIncomingUniStreams = streamsPerConn, -1
	s.ln, err = s.tr.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn},
		MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true}, c)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return s, nil
}

// Close stops accepting and ends all connections.
func (s *Server) Close() {
	_ = s.ln.Close()
	_ = s.tr.Close()
	_ = s.tr.Conn.Close()
}

// Accepted says whose a connection is.
type Accepted struct {
	UID    uint32
	Secret string          // lets the client resume; empty if it knows
	Ended  func(quit bool) // called when the connection is over
}

// Auth decides about a connection by its first message. close ends it later.
type Auth func(q wire.Request, close func()) (Accepted, error)

// Serve accepts connections; handle serves each stream of their users.
func (s *Server) Serve(auth Auth, handle func(*Stream, uint32)) error {
	for {
		c, err := s.ln.Accept(context.Background())
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, quic.ErrTransportClosed) {
				return nil
			}
			return err
		}
		go s.serve(c, auth, handle)
	}
}

func (s *Server) serve(c *quic.Conn, auth Auth, handle func(*Stream, uint32)) {
	defer c.CloseWithError(codeDone, "")
	ctx, cancel := context.WithTimeout(c.Context(), authTimeout)
	defer cancel()
	first, err := c.AcceptStream(ctx)
	if err != nil {
		return
	}
	_ = first.SetDeadline(time.Now().Add(authTimeout))
	var q wire.Request
	if err := wire.Read(first, 4096, &q); err != nil || q.Type != wire.Auth && q.Type != wire.Resume {
		return
	}
	a, err := auth(q, func() { _ = c.CloseWithError(codeDone, "") })
	if err != nil {
		_ = wire.Write(first, wire.Reply{Type: wire.Error, Text: err.Error()})
		_ = first.Close()
		// Give the answer time to arrive before the connection goes.
		select {
		case <-c.Context().Done():
		case <-time.After(time.Second):
		}
		return
	}
	defer func() {
		// Only a client that says so has quit; others may come back.
		var ae *quic.ApplicationError
		a.Ended(errors.As(context.Cause(c.Context()), &ae) && ae.Remote && ae.ErrorCode == codeQuit)
	}()
	if known, ok := c.Context().Value(strangerKey{}).(func()); ok {
		known()
	}
	if err := wire.Write(first, wire.Reply{Type: wire.OK, Text: a.Secret}); err != nil {
		return
	}
	_ = first.Close()
	for {
		st, err := c.AcceptStream(c.Context())
		if err != nil {
			return
		}
		go handle(&Stream{st, c}, a.UID)
	}
}

func newCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, err
	}
	// Clients check the fingerprint, not the dates.
	t := &x509.Certificate{SerialNumber: n, NotBefore: time.Now().AddDate(0, 0, -1), NotAfter: time.Now().AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, t, t, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, err
}

var errImpostor = errors.New("the server's certificate is not the one that ssh vouched for")

// Client is a connection to a server.
type Client struct {
	// Secret lets a later Dial resume the login.
	Secret string

	conn *quic.Conn

	mu      sync.Mutex
	lastID  uint64
	screens map[uint64]chan io.Reader
}

// Dial connects to addr, which must have the given certificate, and sends auth,
// an Auth or Resume request.
func Dial(ctx context.Context, addr, fingerprint string, auth wire.Request) (*Client, error) {
	want, err := hex.DecodeString(fingerprint)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("bad fingerprint")
	}
	impostor := false
	tc := &tls.Config{
		NextProtos:             []string{alpn},
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		// There is no authority to ask: exactly this certificate is expected.
		InsecureSkipVerify: true,
		VerifyConnection: func(st tls.ConnectionState) error {
			if len(st.PeerCertificates) != 1 {
				return errors.New("the server sent no certificate")
			}
			got := sha256.Sum256(st.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				impostor = true
				return errImpostor
			}
			return nil
		},
	}
	qc := config()
	qc.KeepAlivePeriod = 3 * time.Second
	qc.MaxIncomingStreams, qc.MaxIncomingUniStreams = -1, streamsPerConn
	conn, err := quic.DialAddr(ctx, addr, tc, qc)
	if impostor {
		return nil, fmt.Errorf("%w: %w", ErrRefused, errImpostor)
	}
	if err != nil {
		return nil, err
	}
	c := &Client{conn: conn, screens: map[uint64]chan io.Reader{}}
	if err := c.auth(auth); err != nil {
		c.Drop()
		return nil, err
	}
	go c.acceptScreens()
	return c, nil
}

func (c *Client) auth(q wire.Request) error {
	q.Version = wire.Version
	st, err := c.Open()
	if err != nil {
		return err
	}
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(authTimeout))
	if err := wire.Write(st, q); err != nil {
		return err
	}
	var r wire.Reply
	if err := wire.Read(st, 4096, &r); err != nil {
		return err
	}
	if r.Type != wire.OK {
		return fmt.Errorf("%w: %q", ErrRefused, r.Text)
	}
	if c.Secret = r.Text; q.Type == wire.Resume {
		c.Secret = q.Text
	}
	return nil
}

// Open starts a new stream.
func (c *Client) Open() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(c.conn.Context(), authTimeout)
	defer cancel()
	st, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &Stream{st, c.conn}, nil
}

// NewScreen returns an id to ask the server for a separate stream of output,
// and where that stream will arrive.
func (c *Client) NewScreen() (uint64, <-chan io.Reader) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastID++
	ch := make(chan io.Reader, 1)
	c.screens[c.lastID] = ch
	return c.lastID, ch
}

func (c *Client) acceptScreens() {
	for {
		st, err := c.conn.AcceptUniStream(c.conn.Context())
		if err != nil {
			return
		}
		go func() {
			_ = st.SetReadDeadline(time.Now().Add(authTimeout))
			var r wire.Reply
			err := wire.Read(st, 4096, &r)
			id, _ := strconv.ParseUint(r.Text, 10, 64)
			c.mu.Lock()
			ch := c.screens[id]
			delete(c.screens, id)
			c.mu.Unlock()
			if err != nil || r.Type != wire.Screen || ch == nil {
				st.CancelRead(0)
				return
			}
			_ = st.SetReadDeadline(time.Time{})
			ch <- st
		}()
	}
}

// Alive reports whether the connection is still thought to work.
func (c *Client) Alive() bool { return c.conn.Context().Err() == nil }

// Close ends the connection and the login.
func (c *Client) Close() { _ = c.conn.CloseWithError(codeQuit, "") }

// Drop ends the connection but not the login.
func (c *Client) Drop() { _ = c.conn.CloseWithError(codeDone, "") }
