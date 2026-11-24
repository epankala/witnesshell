package daemon

import (
	"testing"
	"time"
)

func TestTokens(t *testing.T) {
	var k tokens
	now := time.Now()
	a, err := k.issue(1, now)
	b, err2 := k.issue(2, now)
	if err != nil || err2 != nil || a == b || len(a) < 40 {
		t.Fatal(a, b, err, err2)
	}
	if uid, err := k.redeem(b, now.Add(tokenLife-1)); uid != 2 || err != nil {
		t.Fatal(uid, err)
	}
	if _, err := k.redeem(b, now); err == nil {
		t.Fatal("redeemed twice")
	}
	if _, err := k.redeem(a, now.Add(tokenLife)); err == nil {
		t.Fatal("expired token redeemed")
	}
	if _, err := k.redeem(a, now); err == nil {
		t.Fatal("token survived a failed attempt")
	}
	if _, err := k.redeem("", now); err == nil {
		t.Fatal("empty token")
	}
	for range tokensPerUID {
		if _, err := k.issue(3, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := k.issue(3, now); err == nil {
		t.Fatal("no limit")
	}
	if _, err := k.issue(4, now); err != nil {
		t.Fatal("limit is not per user:", err)
	}
	if _, err := k.issue(3, now.Add(tokenLife)); err != nil || len(k.m) != 1 {
		t.Fatal("expired tokens kept:", err, len(k.m))
	}
}
