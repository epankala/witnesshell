package cli

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"

	"witnesshell/internal/launch"
	"witnesshell/internal/sign"
	"witnesshell/internal/view"
)

// systemStore is the production store.
func systemStore() *sign.Store {
	return &sign.Store{Dir: sign.DefaultStoreDir, Keys: sign.KeyDir{Dir: sign.DefaultKeyDir}, LookupUID: launch.LookupUID}
}

// self is the calling user, with the groups the process really has.
func self() (launch.User, error) {
	u := launch.User{Name: "uid " + strconv.Itoa(os.Getuid()), UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	if c, err := user.Current(); err == nil {
		u.Name, u.Home = c.Username, c.HomeDir
	}
	gs, err := os.Getgroups()
	for _, g := range gs {
		u.Groups = append(u.Groups, uint32(g))
	}
	return u, err
}

// runChecksig reports on a file with the caller's own permissions (D27). It
// is information only: the launcher checks again.
func runChecksig(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: witnesshell checksig FILE")
		return ExitUsage
	}
	u, err := self()
	var wd string
	if err == nil {
		wd, err = os.Getwd()
	}
	if err == nil {
		err = view.Checksig(stdout, u, wd, args[0], systemStore(), u)
	}
	if err != nil {
		fmt.Fprintf(stderr, "witnesshell checksig: %v\n", err)
		return ExitError
	}
	return ExitOK
}
