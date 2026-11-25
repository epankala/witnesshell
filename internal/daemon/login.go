package daemon

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const loginsPerUID = 32

// logins let a client whose connection broke return without ssh. The secret
// of a login is known to the client only, and travels only inside TLS.
type logins struct {
	mu   sync.Mutex
	life time.Duration // without a connection
	m    map[[32]byte]*login
}

type login struct {
	uid     uint32
	key     [32]byte
	close   func() // ends its current connection; nil if there is none
	serial  uint64 // of that connection
	expires time.Time
}

// start begins a login and returns its secret.
func (l *logins) start(uid uint32, now time.Time, closeConn func()) (string, *login, uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for k, v := range l.m {
		if v.close == nil && !now.Before(v.expires) {
			delete(l.m, k)
		} else if v.uid == uid {
			n++
		}
	}
	if n >= loginsPerUID {
		return "", nil, 0, errors.New("too many logins")
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", nil, 0, err
	}
	s := base64.RawURLEncoding.EncodeToString(b[:])
	if l.m == nil {
		l.m = map[[32]byte]*login{}
	}
	g := &login{uid: uid, key: sha256.Sum256([]byte(s)), close: closeConn, serial: 1}
	l.m[g.key] = g
	return s, g, 1, nil
}

// resume returns to a login. A connection it still has is closed.
func (l *logins) resume(secret string, now time.Time, closeConn func()) (*login, uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	g := l.m[sha256.Sum256([]byte(secret))]
	if g == nil || g.close == nil && !now.Before(g.expires) {
		return nil, 0, errors.New("the login has expired")
	}
	if g.close != nil {
		go g.close()
	}
	g.serial++
	g.close = closeConn
	return g, g.serial, nil
}

// ended notes that a connection of the login is over. If the user quit, the
// login is over too.
func (l *logins) ended(g *login, serial uint64, quit bool, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if g.serial != serial {
		return // it has another one
	}
	g.close, g.expires = nil, now.Add(l.life)
	if quit {
		delete(l.m, g.key)
	}
}
