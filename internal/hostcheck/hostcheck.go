// Package hostcheck verifies the host settings that enforcement relies on
// (D26). An empty result means the host is fit for the given actor.
package hostcheck

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"witnesshell/internal/trust"
)

// maxReport bounds how many writable places are listed.
const maxReport = 5

// Check returns the problems found. It scans filesystems on which programs
// may be executed, so it can take a few seconds. It must run as root.
func Check(name string, a trust.Actor) ([]string, error) {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	for _, c := range []struct {
		file string
		min  int
		why  string
	}{
		{"/proc/sys/vm/memfd_noexec", 2, "programs can run from memory"},
		{"/proc/sys/kernel/yama/ptrace_scope", 1, "programs can control each other"},
	} {
		b, err := os.ReadFile(c.file)
		n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || n < c.min {
			add("%s must be at least %d: %s", c.file, c.min, c.why)
		}
	}
	if b, err := os.ReadFile("/sys/kernel/security/lsm"); err != nil || !slices.Contains(strings.Split(strings.TrimSpace(string(b)), ","), "landlock") {
		add("Landlock is not active")
	}
	for _, tool := range []string{"cron", "at"} {
		bin := map[string]string{"cron": "/usr/bin/crontab", "at": "/usr/bin/at"}[tool]
		if _, err := os.Stat(bin); err == nil && !denied(tool, name) {
			add("%s may use %s: list the user in /etc/%s.deny, or leave them out of /etc/%s.allow", name, bin, tool, tool)
		}
	}
	if !masked("user@.service") && !masked("user@"+strconv.FormatUint(uint64(a.UID), 10)+".service") {
		add("%s may start user services: mask user@%d.service", name, a.UID)
	}
	mounts, err := execMounts()
	if err != nil {
		return nil, err
	}
	var found []string
	for _, m := range mounts {
		if err := scan(m, a, &found); err != nil {
			return nil, err
		}
		if len(found) > maxReport {
			break
		}
	}
	for i, f := range found {
		if i == maxReport {
			add("and more")
			break
		}
		add("%s can be modified by %s and is not on a noexec,nosuid mount", f, name)
	}
	return out, nil
}

func listed(file, name string) (listed, exists bool) {
	b, err := os.ReadFile(file)
	if err != nil {
		return false, !errors.Is(err, fs.ErrNotExist)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) == name {
			return true, true
		}
	}
	return false, true
}

func denied(tool, name string) bool {
	if in, ok := listed("/etc/"+tool+".allow", name); ok {
		return !in
	}
	in, _ := listed("/etc/"+tool+".deny", name)
	return in
}

func masked(unit string) bool {
	t, err := os.Readlink("/etc/systemd/system/" + unit)
	return err == nil && t == "/dev/null"
}

// execMounts lists mount points that allow execution or setuid.
func execMounts() ([]string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.Fields(sc.Text())
		if len(l) < 6 {
			return nil, fmt.Errorf("bad mountinfo line %q", sc.Text())
		}
		o := strings.Split(l[5], ",")
		if slices.Contains(o, "noexec") && slices.Contains(o, "nosuid") || slices.Contains(o, "ro") {
			continue
		}
		mp := unescape(l[4])
		if mp == "/proc" || mp == "/sys" || strings.HasPrefix(mp, "/proc/") || strings.HasPrefix(mp, "/sys/") {
			continue
		}
		out = append(out, mp)
	}
	return out, sc.Err()
}

// unescape undoes mountinfo's octal escapes.
func unescape(s string) string {
	for _, e := range [][2]string{{`\040`, " "}, {`\011`, "\t"}, {`\012`, "\n"}, {`\134`, `\`}} {
		s = strings.ReplaceAll(s, e[0], e[1])
	}
	return s
}

// scan finds directories and regular files the actor can modify, staying on
// one mount.
func scan(mount string, a trust.Actor, found *[]string) error {
	var top unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, mount, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &top); err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EACCES) {
			return nil
		}
		return fmt.Errorf("%s: %w", mount, err)
	}
	return filepath.WalkDir(mount, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		if d.IsDir() {
			var sx unix.Statx_t
			if unix.Statx(unix.AT_FDCWD, p, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &sx) != nil || sx.Mnt_id != top.Mnt_id {
				return fs.SkipDir
			}
		}
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil {
			return nil // vanished
		}
		w, err := trust.Writable(p, &st, a)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("%s: %w", p, err)
		}
		if !w {
			return nil
		}
		*found = append(*found, p)
		if len(*found) > maxReport {
			return fs.SkipAll
		}
		if d.IsDir() {
			return fs.SkipDir
		}
		return nil
	})
}
