// Command witnesshell is a four-eyes remote shell: an actor's commands run
// only after K-of-N witnesses approve them. See PLAN.md for the design.
package main

import (
	"os"

	"witnesshell/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
