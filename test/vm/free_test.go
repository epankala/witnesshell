//go:build vmtest

package vm

import (
	"strings"
	"testing"
)

func TestFreeCommands(t *testing.T) {
	// Listed commands run without a witness; anything else still waits.
	harden(t)
	fixtures(t)
	startDaemon(t, `free_commands = ["cd", "ls", "grep", "cat", "wc"]`+"\n")
	a := attach(t, alice)
	a.wait("ACTOR alice  PROMPT")
	a.wait("no witness")

	a.typ("ls /home/alice | grep s.sh && echo ok\r") // echo is not listed
	a.wait("PENDING")
	a.typ("\x03")
	a.wait("cancelled")
	a.typ("\x15\x0b") // the draft is kept; empty it

	// What it prints differs from what was typed.
	a.typ("cd /home/alice && ls | grep 's[.]py'\r")
	a.wait("s.py")
	a.wait("ACTOR alice  PROMPT")

	for _, line := range []string{"ls >listing", "ls >>listing", "ls &", "LC_ALL=C ls", "/usr/bin/ls", "touch MARK", "wc -l <s.sh | cat >n"} {
		a.typ(line + "\r")
		a.wait("PENDING")
		a.typ("\x03")
		a.wait("ACTOR alice  PROMPT")
		a.typ("\x15\x0b")
	}
	if exists("/home/alice/listing") || exists(marker) || exists("/home/alice/n") {
		t.Error("ran without approval")
	}
	log := sh(t, "cat $(ls -t /var/log/witnesshell/*-actor-alice.log | head -1)")
	if !strings.Contains(log, `"free_command"`) || !strings.Contains(log, `s[.]py`) {
		t.Errorf("free command not logged:\n%s", log)
	}
}
