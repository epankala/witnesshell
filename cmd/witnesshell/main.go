// Command witnesshell is a four-eyes remote shell: an actor's commands run
// only after K-of-N witnesses approve them. See PLAN.md for the design.
package main

import (
	"fmt"
	"os"

	"witnesshell/internal/cli"
	"witnesshell/internal/daemon"
	"witnesshell/internal/launch"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == launch.HelperArg {
		fmt.Fprintln(os.Stderr, "witnesshell:", launch.Helper())
		os.Exit(126)
	}
	if len(os.Args) > 1 && os.Args[1] == daemon.LeaderArg {
		if err := daemon.Leader(); err != nil {
			fmt.Fprintln(os.Stderr, "witnesshell:", err)
			os.Exit(1)
		}
		return
	}
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
