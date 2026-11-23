package cli

import (
	"bytes"
	"strings"
	"testing"
)

func run(args ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = Run(args, &o, &e)
	return code, o.String(), e.String()
}

func TestNoArgsShowsUsage(t *testing.T) {
	code, _, stderr := run()
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "usage: witnesshell") {
		t.Fatalf("stderr missing usage: %q", stderr)
	}
}

func TestVersion(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-v"} {
		code, stdout, _ := run(arg)
		if code != ExitOK {
			t.Fatalf("%s: code = %d", arg, code)
		}
		if !strings.HasPrefix(stdout, "witnesshell ") || !strings.Contains(stdout, "protocol 1") {
			t.Fatalf("%s: unexpected output %q", arg, stdout)
		}
	}
}

func TestVersionRejectsArgs(t *testing.T) {
	if code, _, _ := run("version", "extra"); code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

func TestHelp(t *testing.T) {
	code, stdout, _ := run("help")
	if code != ExitOK {
		t.Fatalf("code = %d", code)
	}
	for name := range commands {
		if !strings.Contains(stdout, "  "+name+" ") {
			t.Errorf("help does not list %q", name)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, stderr := run("frobnicate")
	if code != ExitUsage || !strings.Contains(stderr, `unknown command "frobnicate"`) {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
}

func TestStubsReportNotImplemented(t *testing.T) {
	for name, c := range commands {
		if c.run != nil || c.milestone == "" {
			continue
		}
		code, _, stderr := run(name)
		if code != ExitNotImplemented || !strings.Contains(stderr, "not implemented yet") {
			t.Errorf("%s: code = %d, stderr = %q", name, code, stderr)
		}
	}
}
