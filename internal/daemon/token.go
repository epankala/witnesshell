package daemon

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const (
	tokenLife    = 30 * time.Second
	tokensPerUID = 8
)

// tokens are one-time passwords that carry a login from ssh to QUIC.
type tokens struct {
	mu sync.Mutex
	m  map[[32]byte]token // by hash, so that lookups reveal nothing by timing
}

type token struct {
	uid     uint32
	expires time.Time
}

func (t *tokens) issue(uid uint32, now time.Time) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for k, v := range t.m {
		if !now.Before(v.expires) {
			delete(t.m, k)
		} else if v.uid == uid {
			n++
		}
	}
	if n >= tokensPerUID {
		return "", errors.New("too many logins at once; try again in a moment")
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(b[:])
	if t.m == nil {
		t.m = map[[32]byte]token{}
	}
	t.m[sha256.Sum256([]byte(s))] = token{uid, now.Add(tokenLife)}
	return s, nil
}

func (t *tokens) redeem(s string, now time.Time) (uint32, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := sha256.Sum256([]byte(s))
	v, ok := t.m[k]
	delete(t.m, k)
	if !ok || !now.Before(v.expires) {
		return 0, errors.New("the login has expired")
	}
	return v.uid, nil
}
