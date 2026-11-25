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
	if !strings.Contains(stderr, "usage: witsh") {
		t.Fatalf("stderr missing usage: %q", stderr)
	}
}

func TestVersion(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-v"} {
		code, stdout, _ := run(arg)
		if code != ExitOK {
			t.Fatalf("%s: code = %d", arg, code)
		}
		if !strings.HasPrefix(stdout, "witsh ") || !strings.Contains(stdout, "protocol 1") {
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

func TestConnectArgs(t *testing.T) {
	for in, want := range map[string]string{
		"alice@h": "ssh -a -x -T -- alice@h quic 1", "-p 22 h": "ssh -a -x -T -p 22 -- h quic 1",
		"--ssh h": "ssh -a -x -T -- h quic 1", "--udp-host=1.2.3.4 -p 22 h": "ssh -a -x -T -p 22 -- h quic 1",
		"": "", "-oProxyCommand=x": "", "h -v": "", "--udp-host= h": "ssh -a -x -T --udp-host= -- h quic 1", "--ssh": "",
	} {
		o, err := parseConnect(strings.Fields(in))
		got := ""
		if err == nil {
			got = strings.Join(o.argv([]string{"-T"}, quicCommand), " ")
		}
		if got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
}

func TestParseTicket(t *testing.T) {
	fp, tok := strings.Repeat("a", 64), strings.Repeat("B", 43)
	good := "WITNESSHELL 1 60001 " + fp + " " + tok
	for in, ok := range map[string]bool{
		good: true, "banner\n" + good + "\r\n": true, "": false, "x" + good: false, good + "x": false,
		"WITNESSHELL 2 60001 " + fp + " " + tok: false, "WITNESSHELL 1 0 " + fp + " " + tok: false,
		"WITNESSHELL 1 99999 " + fp + " " + tok: false, "WITNESSHELL 1 1 " + fp: false,
		strings.Repeat("x", 70000) + "\n" + good: false,
	} {
		tk, err := parseTicket(strings.NewReader(in))
		if (err == nil) != ok || ok && (tk.port != 60001 || tk.token != tok || tk.fingerprint != fp) {
			t.Errorf("%.40q: %+v %v", in, tk, err)
		}
	}
}

func TestLoginShell(t *testing.T) {
	for in, want := range map[string]bool{
		"-witsh": true, "witsh -c x": true, "": true, "-witsh daemon": true,
		"witsh": false, "witsh daemon": false, "/usr/local/bin/witsh version": false,
	} {
		if got := LoginShell(strings.Fields(in)); got != want {
			t.Errorf("%q: %v", in, got)
		}
	}
}
