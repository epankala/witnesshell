package launch

import "testing"

func TestCheckFree(t *testing.T) {
	for _, n := range SuggestedFree {
		if err := CheckFree(n); err != nil {
			t.Errorf("suggested %s refused: %v", n, err)
		}
	}
	for _, n := range []string{"bash", "sh", "python3", "perl", "awk", "sed", "env", "sudo", "xargs", "find", "busybox",
		"less", "vim", "git", "ssh", "tar", "rm", "tee", "sort", "export", "fg", "umask",
		"/bin/ls", "./ls", "l*", "", "ls -l", "coreutils"} {
		if CheckFree(n) == nil {
			t.Errorf("%q allowed", n)
		}
	}
}
