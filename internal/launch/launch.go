package launch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// HelperArg is the hidden first argument that makes the binary run Helper.
const HelperArg = "__launch"

// Options controls how a plan is started.
type Options struct {
	Stdin, Stdout, Stderr *os.File
	ExecDirs              []string // where Landlock allows execution
	SysProcAttr           *syscall.SysProcAttr
}

type spec struct {
	Plan     Plan
	ExecDirs []string
}

// Start runs a plan. The caller is root. The process is this binary as root
// for a moment, until Helper has dropped privileges and executed the program.
func Start(p *Plan, o Options) (*exec.Cmd, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer w.Close()
	cmd := exec.Command("/proc/self/exe", HelperArg)
	cmd.Args[0] = "witnesshell"
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = o.Stdin, o.Stdout, o.Stderr
	cmd.ExtraFiles = []*os.File{r}
	cmd.SysProcAttr = o.SysProcAttr
	err = cmd.Start()
	_ = r.Close()
	if err != nil {
		return nil, err
	}
	if err := json.NewEncoder(w).Encode(spec{*p, o.ExecDirs}); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	return cmd, nil
}

// Helper is the child side of Start. It returns only on failure.
func Helper() error {
	if os.Getuid() != 0 {
		return errors.New("must be root")
	}
	in := os.NewFile(3, "spec")
	unix.CloseOnExec(3)
	var s spec
	if err := json.NewDecoder(in).Decode(&s); err != nil {
		return err
	}
	_ = in.Close()
	u := s.Plan.User
	if u.UID == 0 || u.GID == 0 {
		return errors.New("refusing to run as root")
	}
	// Landlock and credentials below are per thread; exec keeps this one.
	runtime.LockOSThread()
	if s.Plan.Landlock {
		// Installed as root so that no_new_privs, which breaks setuid
		// programs, is not needed.
		if err := restrictExec(s.ExecDirs); err != nil {
			return fmt.Errorf("landlock: %w", err)
		}
	}
	if err := dropTo(u); err != nil {
		return err
	}
	unix.Umask(s.Plan.Umask)
	// As the actor, so that the actor's own directory permissions apply.
	if err := unix.Chdir(s.Plan.Cwd); err != nil {
		return fmt.Errorf("%s: %w", s.Plan.Cwd, err)
	}
	// Nothing but the standard streams may leak into the program.
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return err
	}
	return fmt.Errorf("%s: %w", s.Plan.Path, syscall.Exec(s.Plan.Path, s.Plan.Argv, s.Plan.Env))
}

func dropTo(u User) error {
	groups := append([]uint32{u.GID}, u.Groups...)
	for _, c := range []struct {
		nr   uintptr
		a, b uintptr
		c    uintptr
	}{
		{unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0},
		{unix.SYS_SETGROUPS, uintptr(len(groups)), uintptr(unsafe.Pointer(&groups[0])), 0},
		{unix.SYS_SETRESGID, uintptr(u.GID), uintptr(u.GID), uintptr(u.GID)},
		{unix.SYS_SETRESUID, uintptr(u.UID), uintptr(u.UID), uintptr(u.UID)},
	} {
		if _, _, e := unix.RawSyscall6(c.nr, c.a, c.b, c.c, 0, 0, 0); e != 0 {
			return fmt.Errorf("drop privileges: %w", e)
		}
	}
	// Inheritable capabilities survive a uid change.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("drop capabilities: %w", err)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, 0, 0, 0); e == 0 {
		return errors.New("privileges could be regained")
	}
	return nil
}

const landlockExecute = 1

// restrictExec lets this thread, and all it starts, execute files only
// beneath dirs.
func restrictExec(dirs []string) error {
	attr := uint64(landlockExecute) // handled_access_fs, the first field
	fd, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), 8, 0)
	if e != 0 {
		return e
	}
	defer unix.Close(int(fd))
	for _, d := range dirs {
		dir, err := unix.Open(d, unix.O_PATH|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return err
		}
		rule := unix.LandlockPathBeneathAttr{Allowed_access: landlockExecute, Parent_fd: int32(dir)}
		_, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH,
			uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
		_ = unix.Close(dir)
		if e != 0 {
			return e
		}
	}
	if _, _, e := unix.RawSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); e != 0 {
		return e
	}
	return nil
}
