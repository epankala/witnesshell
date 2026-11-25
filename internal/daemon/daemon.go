// Package daemon is the root service that owns sessions.
package daemon

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/sys/unix"

	"witnesshell/internal/audit"
	"witnesshell/internal/hostcheck"
	"witnesshell/internal/launch"
	"witnesshell/internal/sign"
	"witnesshell/internal/transport"
	"witnesshell/internal/trust"
	"witnesshell/internal/wire"
)

// Defaults for production.
const (
	DefaultConfig = "/etc/witnesshell/config.toml"
	DefaultSocket = "/run/witnesshell.sock"
	cgroupRoot    = "/sys/fs/cgroup"
	cgroupName    = "/witnesshell-sessions"
	cgroupBase    = cgroupRoot + cgroupName
	maxPerUser    = 32 // connections
)

// Config is the configuration file.
type Config struct {
	ApprovalsRequired int      `toml:"approvals_required"`
	MaxSessions       int      `toml:"max_sessions"` // 0 means no limit
	DetachTimeout     string   `toml:"detach_timeout"`
	AllowWeakHost     bool     `toml:"allow_weak_host"`
	UDPPort           int      `toml:"udp_port"` // 0 disables QUIC
	ExecDirs          []string `toml:"exec_dirs"`
	RecordDir         string   `toml:"record_dir"`
	AllowUpload       bool     `toml:"allow_upload"`
	AllowDownload     bool     `toml:"allow_download"`
	MaxTransfer       string   `toml:"max_transfer"` // of one file
	maxTransfer       int64
	detach            time.Duration
}

// LoadConfig reads a configuration file. A missing file means defaults.
func LoadConfig(name string) (Config, error) {
	c := Config{ApprovalsRequired: 1, UDPPort: 60001, DetachTimeout: "30m", ExecDirs: []string{"/usr"}, RecordDir: audit.DefaultDir,
		AllowUpload: true, MaxTransfer: "1GiB"}
	md, err := toml.DecodeFile(name, &c)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return c, err
	}
	if u := md.Undecoded(); len(u) > 0 {
		return c, fmt.Errorf("%s: unknown setting %s", name, u[0])
	}
	if c.detach, err = time.ParseDuration(c.DetachTimeout); err != nil || c.detach <= 0 {
		return c, fmt.Errorf("%s: bad detach_timeout %q", name, c.DetachTimeout)
	}
	if c.ApprovalsRequired < 1 || c.MaxSessions < 0 {
		return c, fmt.Errorf("%s: approvals_required must be at least 1 and max_sessions at least 0", name)
	}
	if c.UDPPort < 0 || c.UDPPort > 65535 {
		return c, fmt.Errorf("%s: bad udp_port", name)
	}
	if c.maxTransfer, err = parseSize(c.MaxTransfer); err != nil {
		return c, fmt.Errorf("%s: bad max_transfer: %w", name, err)
	}
	if !filepath.IsAbs(c.RecordDir) {
		return c, fmt.Errorf("%s: record_dir must be an absolute path", name)
	}
	for _, d := range c.ExecDirs {
		if !filepath.IsAbs(d) {
			return c, fmt.Errorf("%s: exec_dirs must be absolute paths", name)
		}
	}
	return c, nil
}

// parseSize reads a number of bytes such as "100MiB".
func parseSize(s string) (int64, error) {
	shift := 0
	for i, u := range []string{"KiB", "MiB", "GiB", "TiB"} {
		if n, ok := strings.CutSuffix(s, u); ok {
			s, shift = n, 10*(i+1)
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 1 || n > 1<<50>>shift {
		return 0, fmt.Errorf("%q is not a size such as 100MiB", s)
	}
	return n << shift, nil
}

// Daemon serves sessions.
type Daemon struct {
	c     Config
	store *sign.Store
	log   *slog.Logger

	mu       sync.Mutex
	sessions []*session
	starting int
	conns    map[uint32]int
	staged   int64 // bytes of files being copied
	tokens   tokens
	logins   logins
	quic     *transport.Server // nil if disabled
	last     time.Time
}

// New prepares the daemon. It must run as root.
func New(c Config, log *slog.Logger) (*Daemon, error) {
	if os.Getuid() != 0 {
		return nil, errors.New("the daemon must run as root")
	}
	d := &Daemon{c: c, log: log, conns: map[uint32]int{}, store: &sign.Store{
		Dir: sign.DefaultStoreDir, Keys: sign.KeyDir{Dir: sign.DefaultKeyDir}, LookupUID: launch.LookupUID}}
	if err := d.store.Init(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(d.stagingDir(), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(d.stagingDir(), 0o700); err != nil {
		return nil, err
	}
	d.logins.life = c.detach
	d.c.ExecDirs = append(slices.Clone(c.ExecDirs), d.store.Dir+"/signed")
	var fs unix.Statfs_t
	if err := unix.Statfs(cgroupRoot, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, errors.New("cgroup v2 is required at " + cgroupRoot)
	}
	// Left over from a daemon that crashed.
	old, _ := filepath.Glob(cgroupBase + "/*/cgroup.kill")
	for _, f := range old {
		_ = os.WriteFile(f, []byte("1"), 0)
		time.Sleep(50 * time.Millisecond)
		_ = os.Remove(filepath.Dir(f))
	}
	if err := os.MkdirAll(cgroupBase, 0o755); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Daemon) stagingDir() string { return d.store.Dir + "/staging" }

// Listen opens the socket. Any user may connect; the kernel tells who they are.
func Listen(name string) (*net.UnixListener, error) {
	if st, err := os.Lstat(name); err == nil && st.Mode()&os.ModeSocket != 0 {
		if c, err := net.Dial("unix", name); err == nil {
			_ = c.Close()
			return nil, errors.New("another daemon is running")
		}
		_ = os.Remove(name)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
	if err != nil {
		return nil, err
	}
	return l, os.Chmod(name, 0o666)
}

// Serve accepts connections until the listener is closed.
func (d *Daemon) Serve(l *net.UnixListener) error {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			d.log.Error("accept", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go d.handle(c)
	}
}

// ServeQUIC accepts QUIC connections until Close, if they are enabled.
func (d *Daemon) ServeQUIC() error {
	if d.c.UDPPort == 0 {
		return nil
	}
	q, err := transport.Listen(d.c.UDPPort)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.quic = q
	d.mu.Unlock()
	go func() {
		err := q.Serve(d.authQUIC, d.handleQUIC)
		if err != nil {
			d.log.Error("QUIC", "err", err)
		}
	}()
	return nil
}

// authQUIC accepts a new login or the return to one.
func (d *Daemon) authQUIC(q wire.Request, closeConn func()) (a transport.Accepted, err error) {
	defer func() {
		if err != nil {
			d.log.Warn("QUIC login refused", "err", err)
		}
	}()
	var g *login
	var serial uint64
	now := time.Now()
	if q.Type == wire.Resume {
		g, serial, err = d.logins.resume(q.Text, now, closeConn)
	} else {
		if a.UID, err = d.tokens.redeem(q.Text, now); err == nil {
			a.Secret, g, serial, err = d.logins.start(a.UID, now, closeConn)
		}
	}
	if err != nil {
		return a, err
	}
	a.UID = g.uid
	a.Ended = func(quit bool) { d.logins.ended(g, serial, quit, time.Now()) }
	d.log.Info("QUIC login", "uid", a.UID, "resumed", q.Type == wire.Resume)
	return a, nil
}

// Close ends all sessions.
func (d *Daemon) Close() {
	d.mu.Lock()
	all := slices.Clone(d.sessions)
	d.mu.Unlock()
	for _, s := range all {
		s.end("the daemon is stopping")
	}
	if d.quic != nil {
		time.Sleep(300 * time.Millisecond) // for the farewells
		d.quic.Close()
	}
}

// peer identifies the process that connected. Processes inside a session are
// refused: an approved program must not vote, sign or type as its user.
func peer(c *net.UnixConn) (uint32, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var pidfd int
	var e1, e2 error
	if err := rc.Control(func(fd uintptr) {
		cred, e1 = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		pidfd, e2 = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	}); err != nil {
		return 0, err
	}
	if err := errors.Join(e1, e2); err != nil {
		return 0, err
	}
	defer unix.Close(pidfd)
	unix.CloseOnExec(pidfd)
	b, err := os.ReadFile("/proc/" + strconv.Itoa(int(cred.Pid)) + "/cgroup")
	if err != nil {
		return 0, err
	}
	// Still the same process? Otherwise the pid may have been reused.
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return 0, errors.New("the connecting process is gone")
	}
	for _, l := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			if p == cgroupName || strings.HasPrefix(p, cgroupName+"/") {
				return 0, errors.New("not from inside a session")
			}
			return cred.Uid, nil
		}
	}
	return 0, errors.New("cannot tell where the connection comes from")
}

// handle serves a connection to the socket.
func (d *Daemon) handle(conn *net.UnixConn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	uid, err := peer(conn)
	if err != nil {
		d.log.Warn("connection refused", "err", err)
		// Read first: closing with something unread would lose the answer.
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		var q wire.Request
		_ = wire.Read(conn, 4096, &q)
		_ = wire.Write(conn, wire.Reply{Type: wire.Error, Text: err.Error()})
		return
	}
	d.serve(conn, uid)
}

// handleQUIC serves a stream of a user who presented a token.
func (d *Daemon) handleQUIC(st *transport.Stream, uid uint32) {
	defer st.Close()
	d.serve(st, uid)
}

// serve answers the requests of a known user.
func (d *Daemon) serve(conn net.Conn, uid uint32) {
	fail := func(err error) { _ = wire.Write(conn, wire.Reply{Type: wire.Error, Text: err.Error()}) }
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	d.mu.Lock()
	ok := d.conns[uid] < maxPerUser
	if ok {
		d.conns[uid]++
	}
	d.mu.Unlock()
	if !ok {
		fail(errors.New("too many connections"))
		return
	}
	defer func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.conns[uid]--; d.conns[uid] == 0 {
			delete(d.conns, uid)
		}
	}()
	u, err := launch.LookupUser(uid)
	if err != nil {
		fail(err)
		return
	}
	for {
		var q wire.Request
		if err := wire.Read(conn, wire.MaxRequest, &q); err != nil {
			return
		}
		if q.Version != wire.Version {
			fail(fmt.Errorf("protocol version %d needed", wire.Version))
			return
		}
		switch q.Type {
		case wire.List:
			_ = wire.Write(conn, d.list(u))
			_ = conn.SetDeadline(time.Now().Add(5 * time.Minute)) // time to choose
		case wire.Token:
			// Only from the socket: a token must not breed others.
			if _, ok := conn.(*net.UnixConn); !ok || d.quic == nil {
				fail(errors.New("not available"))
				return
			}
			t, err := d.tokens.issue(uid, time.Now())
			if err != nil {
				fail(err)
				return
			}
			_ = wire.Write(conn, wire.Reply{Type: wire.OK, Text: fmt.Sprintf("%d %s %s", d.quic.Port, d.quic.Fingerprint, t)})
			return
		case wire.Sign:
			if err := d.sign(u, q.Text); err != nil {
				fail(err)
			} else {
				_ = wire.Write(conn, wire.Reply{Type: wire.OK})
			}
			return
		case wire.Upload, wire.Download:
			d.transfer(conn, u, q)
			return
		case wire.Actor, wire.Witness:
			_ = conn.SetDeadline(time.Now().Add(5 * time.Minute)) // the host check takes a while
			s, err := d.find(u, q)
			if err != nil {
				fail(err)
				return
			}
			_ = conn.SetDeadline(time.Time{})
			var screen bulkConn
			if st, ok := conn.(*transport.Stream); ok && q.Screen != 0 {
				if screen, err = st.Screen(q.Screen); err != nil {
					return
				}
			}
			c := newClient(conn, screen, u, q.Type == wire.Actor)
			if err := s.join(c, q.Rows, q.Cols); err != nil {
				fail(err)
				return
			}
			go c.writeLoop()
			s.serve(c)
			s.leave(c)
			return
		default:
			fail(errors.New("unknown request"))
			return
		}
	}
}

func (d *Daemon) list(u launch.User) wire.Reply {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := wire.Reply{Type: wire.Sessions, CanStart: u.UID != 0 && d.roomLocked()}
	for _, s := range d.sessions {
		r.Sessions = append(r.Sessions, wire.Session{ID: s.id, Actor: s.actor.Name, Own: s.actor.UID == u.UID, Since: s.since.Format(time.RFC3339)})
	}
	return r
}

func (d *Daemon) roomLocked() bool {
	return d.c.MaxSessions == 0 || len(d.sessions)+d.starting < d.c.MaxSessions
}

// find returns the session a client wants, starting one if asked to.
func (d *Daemon) find(u launch.User, q wire.Request) (*session, error) {
	d.mu.Lock()
	for _, s := range d.sessions {
		if s.id != q.Session {
			continue
		}
		d.mu.Unlock()
		own := s.actor.UID == u.UID
		if own && q.Type == wire.Witness {
			return nil, errors.New("you cannot witness your own session")
		}
		if !own && q.Type == wire.Actor {
			return nil, errors.New("not your session")
		}
		return s, nil
	}
	switch {
	case q.Session != "" || q.Type != wire.Actor:
		d.mu.Unlock()
		return nil, errors.New("no such session")
	case u.UID == 0 || u.GID == 0:
		d.mu.Unlock()
		return nil, errors.New("root cannot be an actor")
	case !d.roomLocked():
		d.mu.Unlock()
		return nil, errors.New("the maximum number of sessions is reached")
	}
	d.starting++
	d.mu.Unlock()
	s, err := d.start(u, q)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.starting--
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	over := s.over
	s.mu.Unlock()
	if over { // already forgotten
		return nil, errOver
	}
	d.sessions = append(d.sessions, s)
	return s, nil
}

func (d *Daemon) start(u launch.User, q wire.Request) (*session, error) {
	weak, err := hostcheck.Check(u.Name, trust.Actor{UID: u.UID, GIDs: append(slices.Clone(u.Groups), u.GID)})
	if err != nil {
		return nil, fmt.Errorf("host check: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	login, err := hostcheck.Login(u.Name, self)
	if err != nil {
		return nil, fmt.Errorf("host check: %w", err)
	}
	weak = append(weak, login...)
	if len(weak) > 0 && !d.c.AllowWeakHost {
		d.log.Error("host does not meet the requirements", "user", u.Name, "problems", weak)
		return nil, errors.New("this host does not meet the requirements:\n  " + strings.Join(weak, "\n  "))
	}
	return d.newSession(u, weak, q.Rows, q.Cols)
}

func (d *Daemon) forget(s *session) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sessions = slices.DeleteFunc(d.sessions, func(o *session) bool { return o == s })
}

// nextStart returns a start time no other session has.
func (d *Daemon) nextStart() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	t := time.Now().UTC().Truncate(time.Millisecond)
	if !t.After(d.last) {
		t = d.last.Add(time.Millisecond)
	}
	d.last = t
	return t
}

// sign records that u signed content with a given SHA-256 (D22).
func (d *Daemon) sign(u launch.User, hash string) error {
	var dg sign.Digest
	b, err := hex.DecodeString(hash)
	if err != nil || len(b) != len(dg.SHA256) {
		return errors.New("bad SHA-256")
	}
	copy(dg.SHA256[:], b)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.log.Info("signed", "by", u.Name, "sha256", dg.Hex())
	return d.store.Record(u.UID, dg)
}

func (d *Daemon) userName(uid uint32) string {
	if u, err := launch.LookupUser(uid); err == nil {
		return u.Name
	}
	return "uid " + strconv.FormatUint(uint64(uid), 10)
}
