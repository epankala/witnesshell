package runner

import (
	"testing"

	"witnesshell/internal/lang"
	"witnesshell/internal/launch"
)

func TestFree(t *testing.T) {
	free := map[string]bool{"ls": true, "grep": true, "cd": true, "jobs": true, "bash": true}
	cmd := func(argv ...string) Cmd {
		return Cmd{Plan: &launch.Plan{Argv: argv, Path: "/usr/bin/" + argv[0], Landlock: true,
			Files: []launch.FileInfo{{Path: "/usr/bin/" + argv[0], Trusted: true}}}}
	}
	line := func(steps ...Step) *Prepared { return &Prepared{Steps: steps, free: free} }
	step := func(cmds ...Cmd) Step { return Step{Cmds: cmds} }
	with := func(c Cmd, f func(*Cmd)) Cmd { f(&c); return c }

	yes := map[string]*Prepared{
		"ls -l":           line(step(cmd("ls", "-l"))),
		"ls | grep x":     line(step(cmd("ls"), cmd("grep", "x"))),
		"ls && grep x f":  line(step(cmd("ls")), Step{Op: lang.And, Cmds: []Cmd{cmd("grep", "x", "f")}}),
		"grep x <f":       line(step(with(cmd("grep", "x"), func(c *Cmd) { c.Redirs = []lang.Redir{{Kind: lang.Read, Path: "f"}} }))),
		"ls 2>&1 | grep":  line(step(with(cmd("ls"), func(c *Cmd) { c.Redirs = []lang.Redir{{FD: 2, Kind: lang.Dup, Source: 1}} }), cmd("grep"))),
		"cd /tmp && ls":   {Steps: []Step{step(cmd("ls"))}, cdTo: "/tmp", free: free},
		"cd /tmp":         {builtin: []string{"cd", "/tmp"}, free: free},
		"jobs":            {builtin: []string{"jobs"}, free: free},
		"view f (always)": {builtin: []string{"view", "f"}},
	}
	no := map[string]*Prepared{
		"not listed":          line(step(cmd("rm", "x"))),
		"one of two":          line(step(cmd("ls"), cmd("rm"))),
		"path":                line(step(cmd("/usr/bin/ls"))),
		"relative path":       line(step(cmd("./ls"))),
		"output to a file":    line(step(with(cmd("ls"), func(c *Cmd) { c.Redirs = []lang.Redir{{FD: 1, Kind: lang.Write, Path: "f"}} }))),
		"appended to a file":  line(step(with(cmd("ls"), func(c *Cmd) { c.Redirs = []lang.Redir{{FD: 1, Kind: lang.Append, Path: "f"}} }))),
		"background":          line(Step{Background: true, Cmds: []Cmd{cmd("ls")}}),
		"own variable":        line(step(with(cmd("ls"), func(c *Cmd) { c.Env = []string{"X=1"} }))),
		"warning":             line(step(with(cmd("ls"), func(c *Cmd) { c.Plan.Warnings = []string{launch.WarnUnsigned} }))),
		"signed, not trusted": line(step(with(cmd("ls"), func(c *Cmd) { c.Plan.Files = []launch.FileInfo{{Trusted: false}} }))),
		"no Landlock":         line(step(with(cmd("ls"), func(c *Cmd) { c.Plan.Landlock = false }))),
		"listed but refused":  line(step(cmd("bash"))),
		"assignment":          {assigns: []lang.Assign{{Name: "X", Value: "1"}}, free: free},
		"cd not listed":       {Steps: []Step{step(cmd("ls"))}, cdTo: "/tmp", free: map[string]bool{"ls": true}},
		"export":              {builtin: []string{"export", "X=1"}, free: map[string]bool{"export": true}},
		"nothing listed":      {Steps: []Step{step(cmd("ls"))}},
	}
	for what, p := range yes {
		if !p.Free() {
			t.Errorf("%s: not free", what)
		}
	}
	for what, p := range no {
		if p.Free() {
			t.Errorf("%s: free", what)
		}
	}
}
