// Package version holds build metadata, set at link time via -ldflags -X.
package version

import "runtime"

var (
	// Version is the release version, e.g. "v0.1.0". Set by the Makefile.
	Version = "dev"
	// Commit is the short git commit hash. Set by the Makefile.
	Commit = "unknown"
)

// ProtocolVersion is the wire protocol version spoken between client,
// bootstrap and daemon. It appears in the bootstrap handshake line.
const ProtocolVersion = 1

// String returns a one-line human readable version description.
func String() string {
	return "witsh " + Version + " (" + Commit + ", " + runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
