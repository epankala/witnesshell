package runner

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// lockThreadBlocking blocks sig on the calling goroutine's thread, which ends
// with the goroutine.
func lockThreadBlocking(sig unix.Signal) {
	runtime.LockOSThread()
	var set unix.Sigset_t
	n := uint(sig) - 1
	set.Val[n/64] |= 1 << (n % 64)
	_ = unix.PthreadSigmask(unix.SIG_BLOCK, &set, nil)
}
