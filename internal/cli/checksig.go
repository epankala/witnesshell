package cli

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"witnesshell/internal/sign"
	"witnesshell/internal/trust"
)

// systemStore is the production store.
func systemStore() *sign.Store {
	return &sign.Store{Dir: sign.DefaultStoreDir, Keys: sign.KeyDir{Dir: sign.DefaultKeyDir}, LookupUID: lookupUID}
}

func lookupUID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(id), err
}

// runChecksig reports on a file with the caller's own permissions (D27). It
// is information only: the launcher checks again.
func runChecksig(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: witnesshell checksig FILE")
		return ExitUsage
	}
	if err := checksig(args[0], stdout, systemStore()); err != nil {
		fmt.Fprintf(stderr, "witnesshell checksig: %v\n", err)
		return ExitError
	}
	return ExitOK
}

func checksig(name string, w io.Writer, store *sign.Store) error {
	if !filepath.IsAbs(name) {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		name = wd + "/" + name
	}
	a := trust.Actor{UID: uint32(os.Getuid()), GIDs: []uint32{uint32(os.Getgid())}}
	gs, err := os.Getgroups()
	if err != nil {
		return err
	}
	for _, g := range gs {
		a.GIDs = append(a.GIDs, uint32(g))
	}
	f, err := trust.Resolve(name, a)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := f.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	d, err := sign.Hash(r)
	if err != nil {
		return err
	}
	var armored []byte
	if sf, err := trust.Resolve(name+".sig", a); err == nil {
		defer sf.Close()
		sr, err := sf.Open()
		if err != nil {
			return err
		}
		defer sr.Close()
		if armored, err = sign.ReadSignature(sr); err != nil {
			return err
		}
	}
	signers, sigErr := store.Signers(d, armored)
	fmt.Fprintf(w, "file     %q\nsha256   %s\nowner    uid %d, mode %04o\n", f.Path, d.Hex(), f.Stat.Uid, f.Stat.Mode&0o7777)
	if f.Trusted {
		fmt.Fprintln(w, "you      cannot modify it")
	} else {
		fmt.Fprintf(w, "you      can modify it, or it is not trusted: %q\n", f.Reason)
	}
	for _, g := range signers {
		note := ""
		if g.UID == a.UID {
			note = " (does not count for your own sessions)"
		}
		fmt.Fprintf(w, "signed   by %q%s\n", g.Name, note)
	}
	if len(signers) == 0 {
		fmt.Fprintln(w, "signed   no")
	}
	if sigErr != nil {
		fmt.Fprintf(w, "problem  %q\n", sigErr.Error())
	}
	return nil
}
