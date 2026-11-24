# witnesshell

A four-eyes remote shell. An **actor** runs commands on a remote Linux host
only after **K-of-N witnesses** approve each command line. Any witness can
veto a command with a comment. Sessions are bootstrapped over SSH, then run
over QUIC, and are logged and recorded as asciicast.

Status: **M2b done** – approval logic, trust rules, signing, launcher, shell
language and job control exist. There is no daemon or approval screen yet, so
it is not usable; see [PLAN.md](PLAN.md) for the design and milestones.

## Build

Requires Go ≥ 1.27. Produces static binaries with no libc dependency.

```sh
make            # gofmt check, go vet, tests, build amd64+arm64, verify static
make build      # just the binaries → dist/witnesshell-linux-{amd64,arm64}
make check      # just fmt/vet/test
```

## Test VM

For tests that need root. Needs QEMU, curl and ssh; uses KVM if `/dev/kvm`
is writable, else slow emulation. Reachable on localhost only.

```sh
make vm-start   # first run downloads an Ubuntu 26.04 image (860 MB)
make vm-ssh     # log in as vmadmin (root via sudo); VM_USER=alice for an actor
make vm-test    # attack tests as root in the VM (hardens the VM first)
make vm-status
make vm-stop    # keeps the disk
make vm-reset   # stops and discards the disk
```

Accounts: `vmadmin`, `alice` (sudo with password `test`), `bob`, `carol`.
Settings such as `VM_DIR` and `VM_SSH_PORT` can go in an untracked `local.mk`.
