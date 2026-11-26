package launch

import "os"

// ChildEnv is the environment of witsh's own child processes: empty, except
// for the race detector's settings in a test build.
func ChildEnv() []string {
	if v, ok := os.LookupEnv("GORACE"); ok {
		return []string{"GORACE=" + v}
	}
	return []string{}
}
