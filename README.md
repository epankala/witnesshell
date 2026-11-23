# witnesshell

A four-eyes remote shell. An **actor** runs commands on a remote Linux host
only after **K-of-N witnesses** approve each command line. Any witness can
veto a command with a comment. Sessions are bootstrapped over SSH, then run
over QUIC, and are logged and recorded as asciicast.

Status: **M2 in progress** – approval logic and shell exist but are not connected to a daemon or each
other, so nothing is usable yet; see [PLAN.md](PLAN.md)
for the design and milestones.

## Build

Requires Go ≥ 1.27. Produces static binaries with no libc dependency.

```sh
make            # gofmt check, go vet, tests, build amd64+arm64, verify static
make build      # just the binaries → dist/witnesshell-linux-{amd64,arm64}
make check      # just fmt/vet/test
```
