# witnesshell

**A remote shell where nothing runs until someone else has approved it.**

One person, the *actor*, types commands on a remote Linux host. Other people,
the *witnesses*, see each command before it runs and approve or reject it.
witnesshell is the shell itself, not a wrapper around bash, so it knows exactly
what it is about to execute and can restrict what that program may start.

It guards against both mistakes and deliberate misuse: production maintenance,
contractor access, four-eyes rules, and privileged work that must be reviewable
afterwards.

> [!WARNING]
> **Under development.** Sessions work over SSH. There is no QUIC transport and
> no audit log yet. This page describes the intended whole; parts not built yet
> are marked *planned*. Do not rely on it for security.

## Contents

[How it works](#how-it-works) ·
[Witnessing](#witnessing) ·
[Validation](#validation-what-may-run) ·
[Signing](#signing) ·
[Security](#security) ·
[Restrictions](#restrictions-of-the-shell) ·
[Limits](#what-it-does-not-protect-against) ·
[Logging](#logging-and-recording) ·
[Status](#status) ·
[Installing](#installing) ·
[Using it](#using-it) ·
[Building](#building) ·
[Testing](#testing)

## How it works

```
   actor                         remote host                        witness
     │   ssh login                    │                     ssh login   │
     ├───────────────────────────────▶│◀────────────────────────────────┤
     │   QUIC session                 │                  QUIC session   │
     │                                │                                 │
     │  systemctl restart nginx  ───▶ │  parse, expand, check           │
     │                                │  ── what exactly will run ────▶ │
     │                                │ ◀── approve, or reject+comment  │
     │                                │  run as the actor, restricted   │
     │ ◀── output ────────────────────┤──── the same output ──────────▶ │
```

1. The actor logs in over SSH and starts a session. It will continue over QUIC,
   to cope with packet loss and reconnect by itself. *(QUIC planned)*
2. Witnesses log in with their own accounts and join that session.
3. The actor types a line. It is parsed, expanded and checked; **nothing has
   run yet**.
4. Witnesses see the line, the full program path, the final arguments, the
   file's owner, whether it is trusted or signed, and any warnings.
5. Once enough witnesses approve, exactly that is executed, once.

## Witnessing

- **K-of-N approval.** The number of approvals needed is configurable. Each
  user counts once.
- **Any rejection is a veto** while a command is waiting. A rejection must have
  a comment, and the actor can then fix the command and submit it again. The
  last approval needed starts the command at once.
- **No self-approval.** The actor's own account cannot vote.
- **Votes are for one specific request**, so a late keypress cannot approve a
  newer command.
- **No witness, no execution.** A command waits, one at a time. When the actor
  logs out, or has been disconnected for 30 minutes, it is dropped.
- **Any user of the host may witness.** Witnesses watch the terminal live,
  including full-screen programs, but can never type into it.
- **No spoofing.** Screens are drawn from a terminal emulator, so a program can
  neither paint a fake approval panel nor send commands to a terminal.
- **No voting by programs.** Connections from inside a session are refused.
- **Read before approving.** Long requests must be paged to the end.
- **No hidden text.** Control, invisible and text-direction characters are
  refused, so a command does not look different from what it does.
- **While an approved program runs, the actor may type into it freely.**
  Witnesses watch. Approval is required again when it exits or is suspended.

When the actor logs out, everything the session started ends, and its witnesses
return to the list of sessions to witness another actor, if there is one.

Witnesses never act with the actor's permissions. To let one read a private
file, the actor shows it in the session or makes it readable.

Actor and witnesses can look at files (`view`) and check signatures
(`checksig`) **without approval**, with their own file permissions. Neither
starts another program.

## Validation: what may run

| File | May run? |
|---|---|
| The actor **cannot modify** it, or any directory on its path | Yes, with approval |
| The actor **can modify** it, and a witness has **signed** it | Yes, with approval, every time |
| The actor can modify it and it is not signed | **No** |

"Can modify" covers ownership, mode bits, groups and ACLs. The same rules apply
to:

- scripts given to an interpreter: `python3 job.py`, `sh < job.sh`
- programs started through another one: `sudo ./tool`, `env ./tool`
- the interpreter on a script's `#!` line

Starting an interpreter without a checked script (`python3`, `bash -c ...`)
needs approval and is marked **"this allows unsigned code"**.

Commands get a clean environment and a fixed `PATH`. Variables known to make
programs load or run other code (`LD_PRELOAD`, `PYTHONPATH`, `PAGER`, ...) are
refused.

## Signing

A file the actor can modify needs a signature from **another user**. One is
enough; the actor's own never counts.

**Off the host**, with an ordinary SSH key:

```sh
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n witnesshell deploy.sh
# copy deploy.sh and deploy.sh.sig to the host, side by side
```

**On the host**: `witnesshell sign deploy.sh`, or `S` while viewing a file as a
witness. No private key is
involved; the daemon records which logged-in user signed which content.

Check a file:

```sh
witnesshell checksig deploy.sh
```

It shows the SHA-256, the owner, whether you could modify the file, and who
signed it.

**Swapping a signed file does not work.** witnesshell checks a root-owned copy
and runs that copy, so later changes to the original have no effect.

### Public keys

Keys are root-owned files in `/etc/witnesshell/public_keys/`. The directory
cannot be listed. A key's file is named by the SHA-256 of the key, which is
found from the signature itself. To add bob's key, as root:

```sh
mkdir -p /etc/witnesshell
install -d -m 711 /etc/witnesshell/public_keys
name=$(witnesshell keyname bob.pub)
printf 'bob %s\n' "$(cut -d' ' -f1,2 bob.pub)" > "/etc/witnesshell/public_keys/$name"
chmod 644 "/etc/witnesshell/public_keys/$name"
```

Delete the file to revoke the key. A signature is refused if the key file or
the directory has an unsafe owner or unsafe permissions.

## Security

Approval alone is not enough: an approved editor could start anything. So what
the shell starts is restricted in layers:

| Layer | Stops |
|---|---|
| **Landlock**: execute only in approved directories | Running the actor's own programs, directly or from bash, Python or vim |
| **`noexec,nosuid`** on everything the actor can write | `ld.so ./program`, loading own libraries |
| **`vm.memfd_noexec=2`** | Programs run from memory files |
| **No cron, at or user services** for actors | Running outside the session |
| **Separate privileges** | The shell is root; programs run as the actor with no capabilities and cannot kill, trace or read the shell |
| **witnesshell as login shell and SSH forced command**, no scp, sftp or forwarding | Logging in around witnesshell; startup files such as `~/.bashrc` |
| **Private terminals** | Reading or faking the same user's other logins |

Landlock is not applied to commands run through `sudo`, because it breaks tools
such as `mount`.

The shell never reads commands from the terminal. Text typed ahead while a
program runs is discarded before the next command.

### Host requirements

Checked when a session starts. Without them the daemon refuses, unless
`allow_weak_host` is set; then everyone sees `WEAK HOST`.

- Linux with Landlock active
- `kernel.yama.ptrace_scope` ≥ 1 and `vm.memfd_noexec` = 2
- every place the actor can write to mounted `noexec,nosuid`: `/home`, `/tmp`,
  `/var/tmp`, `/dev/shm`, and others the check finds
- actors denied cron and at; `user@.service` and `user-runtime-dir@.service`
  masked
- actors have witnesshell as login shell and forced command, see
  [Installing](#installing)

## Restrictions of the shell

The language is a small, strict subset of bash. **What is not supported is
refused rather than guessed.**

| Supported | Refused |
|---|---|
| commands, pipes, `&&` `\|\|` `;` `&` | `$(...)`, backticks, `<(...)` |
| `>` `>>` `<` `2>` `2>&1` `&>` | here-documents, descriptors above 2 |
| `$NAME`, `$?`, quotes, `~`, `*`, `?` | `${x:-y}`, arithmetic, `{a,b}`, `[a-z]` |
| `cd export unset umask exit view checksig` | functions, aliases, `if`, `for`, `while` |
| `jobs fg bg kill`, Ctrl-C, Ctrl-Z | `exec`, `eval`, `source` |

- Everything is expanded **before** approval, so witnesses see the final
  arguments. In `touch x.txt; rm *.txt` the pattern does not include a newly
  created `x.txt`.
- `cd`, `export` and assignments need a line of their own, except
  `cd DIR && command`.
- Programs end with the session, even with `nohup`.
- Unset variables, and patterns that match nothing or match a name that looks
  like an option, are errors.
- No tab completion.

Scripts run by an approved interpreter can use that language in full.

## What it does not protect against

These are known and accepted. Several are part of the test suite, so that a
change does not go unnoticed.

- **Approving an interpreter or scriptable program** (bash, Python, vim, awk)
  trusts the actor inside it. It can read and run unsigned scripts, be fed code
  through a pipe, and may build machine code in its own memory.
- **Approved `sudo` can undo everything**: copy a program somewhere trusted,
  start services, change settings.
- **Interpreters and wrappers are recognized by name.** One under an unusual
  name is not.
- **Witnesses approve what is started, not what it goes on to do.**
- A file or directory named in a command can change between approval and use.
- One person with two accounts can witness themselves.
- Other ways into the host, such as a console or an unrestricted admin account.

## Logging and recording

*Planned.* Actor and witnesses get separate logs with the same session start:

```
witnesshell-<session start>-actor-<name>.log
witnesshell-<session start>-actor-<name>.cast
witnesshell-<session start>-witness-<name>.log
```

Each log is a chain of hashes, so changes are noticed. The `.cast` file is a
terminal recording in asciicast v2 format for `asciinema play`, with a marker
for each request. Typed keys are not recorded, but anything shown on screen is,
secrets included.

## Status

| Part | State |
|---|---|
| Approval logic: K-of-N, veto, comments | ✅ done |
| Trust rules, SSH signatures, `checksig`, `keyname` | ✅ done |
| Restricted launcher, host checks | ✅ done |
| Shell language and job control | ✅ done |
| Daemon, approval screens, `view`, on-host `sign` | ✅ done |
| Forced SSH login | ✅ done |
| QUIC transport and reconnecting | 🚧 next |
| Audit logs and recording | planned |
| Hardening, packaging, releases | planned |

The design, decisions and reasons are in [PLAN.md](PLAN.md). Nothing has been
audited by a third party.

## Installing

Not on a machine you care about yet. As root, with an account outside the group
`witnesshell` as a way back in:

```sh
install -m 755 witnesshell /usr/local/bin/
groupadd -r witnesshell
install -d -m 755 /etc/ssh/authorized_keys
# for every user, after putting their key in /etc/ssh/authorized_keys/USER:
usermod -s /usr/local/bin/witnesshell -aG witnesshell USER
cp deploy/10-witnesshell.conf /etc/ssh/sshd_config.d/
sshd -t && systemctl reload ssh          # a mistake locks everyone out
cp deploy/witnesshell.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now witnesshell
```

Do not add witnesshell to `/etc/shells`. Meet the [host
requirements](#host-requirements) too; a refused session says what is missing.

## Using it

Each user, from their own machine:

```sh
witnesshell connect alice@host      # or just: ssh alice@host
```

On the host itself, `witnesshell attach` does the same.

| Actor | Witness |
|---|---|
| Enter: submit | `a` approve, `r` reject |
| Ctrl-C: cancel | Space, `b`: scroll |
| Ctrl-D: log out | `v` view file, `s` check signature |
| Ctrl-]: detach | `q` leave |

Configuration, all optional, in `/etc/witnesshell/config.toml`:

```toml
approvals_required = 1
max_sessions       = 0          # no limit
detach_timeout     = "30m"
exec_dirs          = ["/usr"]
allow_weak_host    = false
```

## Building

Requires Go 1.27 or newer. Produces static Linux binaries without library
dependencies.

```sh
make            # format check, vet, tests, build amd64 and arm64, verify static
make build      # just dist/witnesshell-linux-{amd64,arm64}
make check      # just format check, vet and tests
```

## Testing

Unit tests run anywhere with `make check`. Attack tests need root, so they run
in a disposable VM. It needs QEMU, curl and ssh, uses KVM when available, and is
reachable on localhost only.

```sh
make vm-test    # start the VM if needed, harden it, run all attack tests
make vm-start   # first run downloads an Ubuntu 26.04 image (860 MB)
make vm-ssh     # log in as vmadmin; VM_USER=alice for an actor
make vm-status
make vm-stop    # keeps the disk
make vm-reset   # stops and discards the disk
```

VM accounts: `vmadmin` (root through sudo), `alice` (sudo with password `test`),
`bob` and `carol`. Settings such as `VM_DIR` and `VM_SSH_PORT` can go in an
untracked `local.mk`. Only amd64 has been tested; arm64 is built but untested.
