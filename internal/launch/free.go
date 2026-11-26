package launch

import (
	"fmt"
	"regexp"
)

// SuggestedFree are commands that only read and show, suggested for
// free_commands (D39). None runs another program or changes a file, whatever
// its arguments. cd and jobs are shell builtins.
var SuggestedFree = []string{
	"cd", "jobs",
	"ls", "pwd", "cat", "head", "tail", "wc", "stat", "du", "df",
	"realpath", "readlink", "basename", "dirname",
	"grep", "cut", "tr", "nl", "cmp", "diff",
	"sha256sum", "sha1sum", "md5sum", "b2sum",
	"id", "whoami", "groups", "uname", "date", "uptime", "free", "ps", "w", "who", "nproc",
	"lsblk", "findmnt", "printenv", "echo", "printf", "tty", "locale",
}

var bareName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._+-]*$`)

// neverFree can run other programs, change files or start interactive
// programs that can. Free, they would be a shell nobody witnesses. The list
// cannot be complete; it catches the obvious mistakes, together with
// interpreters and wrappers.
var neverFree = regexp.MustCompile(`^(` +
	// pagers, editors, interactive tools with shell escapes
	`less|more|most|pg|man|info|vi|vim|nvim|view|vimdiff|rvim|nano|pico|emacs|joe|jed|mcedit|mc|` +
	`top|htop|atop|btop|journalctl|systemctl|loginctl|busctl|screen|tmux|` +
	// version control, network, archives
	`git|hg|svn|ssh|scp|sftp|rsync|curl|wget|nc|ncat|netcat|socat|telnet|ftp|` +
	`tar|cpio|zip|unzip|gzip|gunzip|zcat|bzip2|xz|zstd|7z|ar|` +
	// changing files, or writing them through options and operands
	`cp|mv|rm|ln|dd|tee|install|mkdir|rmdir|touch|chmod|chown|chgrp|chattr|setfacl|truncate|shred|` +
	`mknod|mkfifo|sort|uniq|tree|split|csplit|patch|file|crontab|at|batch|mail|sendmail|` +
	`kill|pkill|killall|coreutils` +
	`)$`)

// Builtins that may be free; the others change what later commands do.
var freeBuiltins = map[string]bool{"cd": true, "jobs": true}
var otherBuiltins = map[string]bool{"export": true, "unset": true, "umask": true, "fg": true, "bg": true}

// CheckFree tells why a name may not be in free_commands, if it may not.
func CheckFree(name string) error {
	switch {
	case !bareName.MatchString(name):
		return fmt.Errorf("%q: give a command name, not a path or pattern", name)
	case freeBuiltins[name]:
		return nil
	case otherBuiltins[name]:
		return fmt.Errorf("%s: this builtin changes what later commands do; it always needs approval", name)
	case interpreters.MatchString(name), wrappers.MatchString(name), elevators.MatchString(name):
		return fmt.Errorf("%s runs other programs; free, it would run anything without approval", name)
	case neverFree.MatchString(name):
		return fmt.Errorf("%s can run other programs or change files; it always needs approval", name)
	}
	return nil
}
