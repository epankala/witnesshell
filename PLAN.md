# witnesshell — design & implementation plan (v0.4)

> Status: M0, M1, M2a and M2b done. v0.4 (2026-11-23) makes witnesshell itself the
> shell; the earlier bash code is gone. Next: M2c.

## 0. Decisions

| # | Decision |
|---|---|
| D1 | Guard against **accidental and malicious** shell commands → enforcement mode |
| D2 | **witnesshell is the shell**, replacing bash; started programs are restricted by the kernel (§4.5) |
| D3 | Witnesses see a live mirror of the terminal, full-screen programs included |
| D4 | Approval policy **K-of-N** (configurable K, e.g. 1-of-1) |
| D5 | Any user with a login on the host can witness, except the actor's own uid |
| D6 | Requests wait in a queue; actor logout → queue purged |
| D7 | Shell runs as the target (login) user; `sudo` is used inside the session for root |
| D8 | Remote IP is fixed; client IP may change; a broken connection on an IP change is OK; client installed locally |
| D9 | Recording: **asciicast v2** with markers per request (§8.1) |
| D10 | Linux only, both ends |
| D11 | Language: **Go**, static binary (`CGO_ENABLED=0`) |
| D12 | Witness powers: **approve** or **reject with a comment**. The actor then submits a new command. Nothing else (no typing, no Ctrl-C, no kill), except the read-only commands of D27 |
| D13 | Actor disconnected **30 min** → treated as logout. A witness disconnecting does **not** remove votes already given |
| D14 | On login with sessions active: **ask** "witness one of them / start own session". Several sessions allowed; `max_sessions = 1` can enforce a single session |
| D15 | **Any rejection vetoes**, even if K approvals exist |
| D16 | **No file-edit feature.** Users keep config in git and show `git diff`; witnesses refuse to approve use of unreviewed edits. This is a process rule, documented in README |
| D17 | **Approving a command approves the whole program run.** While an approved command is in the foreground, all input passes freely (watched live and recorded). When it exits and the shell is back in the foreground, gating resumes |
| D18 | A program or script may run, with witness approval, if the actor **cannot modify it** (§4.4) |
| D19 | A file the actor owns or can modify may run only if **signed by a witness**; approval is still needed |
| D20 | Interpreters the actor cannot modify may be started **if witnesses approve** |
| D21 | `sudo` stays (D7) for now |
| D22 | Signing happens off the host (signature copied in) or on the host. One witness signature is enough; the actor's own does not count |
| D23 | Root and sandbox tests run in a **VM** (`make vm-start`), used over ssh |
| D24 | Command substitution (`$(...)` and backticks) at the prompt is **refused** for now; two-step approval (inner command, then the completed line) is a later option. Scripts run by an approved interpreter may use it |
| D25 | A signed file still needs witness approval **every time** it runs |
| D26 | Host requirements (§4.5: `noexec,nosuid` on user-writable filesystems, `vm.memfd_noexec=2`, no cron or user services for actors) are **required by default**; the config setting `allow_weak_host` skips the checks |
| D27 | Actor **and** witnesses can view files and check a file's signature with built-in commands, **without approval** (§4.6) |
| D28 | **Separate logs** for the actor and each witness: `witnesshell-<session start>-actor-<name>` and `witnesshell-<same session start>-witness-<name>` (§8) |
| D29 | A request that starts an interpreter without a checked script file (`python3`, `sh`, `bash -c ...`), also behind `sudo` and similar, shows witnesses the warning **"this allows unsigned code"** |
| D30 | Initially, users' public keys are root-owned files in `/etc/witnesshell/public_keys/`. The directory **cannot be listed** (0711); the file name follows from the signature |

## 1. Goal

A "four-eyes" remote shell. One person (the **actor**) runs commands on a
remote Linux host. One or more other people (**witnesses**) watch live, and
K of them must approve each command line before it reaches the shell. Any
witness can veto a command by rejecting it with a comment. Everything is
logged and recorded so it can be replayed.

SSH is used only for login and bootstrap. The session itself runs over
**QUIC/UDP**, mosh-style.

## 2. Roles & user flow

```
 actor laptop                      remote host                     witness laptop
 ────────────                      ───────────                     ──────────────
 witnesshell connect alice@host
   └─ ssh alice@host  (ForceCommand → witnesshell bootstrap)
                                   witnesshelld (daemon, root)
                                     ├─ peer uid = alice (SO_PEERCRED)
                                     ├─ no sessions → create S1, PTY shell as alice
                                     └─ → port, cert-hash, token, S1
   ssh exits; QUIC ──────────────▶ UDP :60001  ◀────────────── QUIC
                                                     witnesshell connect bob@host
                                                       └─ ssh bob@host → bootstrap
                                     ├─ peer uid = bob, sessions exist → ask:
                                     │    [1] witness alice's session S1
                                     │    [n] start own session  (hidden if max_sessions reached)
                                     └─ → port, cert-hash, token, S1, role
```

1. Everyone uses the same command, `witnesshell connect user@host`. It runs
   the system `ssh`, so `~/.ssh/config`, agents and jump hosts all work.
2. sshd forces `witnesshell bootstrap` (`ForceCommand`) for every
   member of group `witnesshell`. Bootstrap talks to the daemon over
   `/run/witnesshell.sock`; the daemon identifies the caller by kernel
   peer credentials.
3. Role choice (D14): if there are sessions owned by other users, the user
   is asked, over the ssh TTY, whether to witness one or start their own.
   A user's own sessions are listed for **reattach** (as actor). Witnessing
   your own session is never offered.
4. Bootstrap prints `WITNESSHELL 1 <port> <cert-sha256> <token> <session> <role>`
   and exits. The ssh connection closes.
5. The client connects with QUIC, pins the certificate hash (trust carried
   over from the SSH host key) and presents the one-time token.

## 3. Threat model (D1)

| Requirement | Why |
|---|---|
| The shell process of each session is **root** and leads the terminal's session; programs run as the actor, and the shell touches files on a thread with the actor's file access and no capabilities | Only the parent of the jobs can do job control. Tested: the actor can neither kill, trace nor read it, and redirections cannot reach its own `/proc` files |
| `Match Group witnesshell` → `ForceCommand witnesshell bootstrap`, `AllowTcpForwarding no`, `AllowAgentForwarding no`, `X11Forwarding no`, `PermitTunnel no`, no sftp subsystem | Otherwise the actor opens a plain shell or tunnels around the gate |
| The shell never reads commands from the PTY (§4.3) | Type-ahead would run unapproved |
| Actor uid ≠ witness uid | No self-witnessing |
| Admin break-glass access (console / separate un-forced admin account) is outside witnesshell and documented | Need a way in if the daemon is broken |

### 3.1 Why shell hooks are not enough
A bash `DEBUG` trap, `PROMPT_COMMAND` or `bind -x` can be bypassed in
several ways:
- Disable it: `trap - DEBUG`, `bind -r`.
- Start a shell without it: `exec sh`, `bash --norc`, `busybox sh`.
- Run commands from inside a program: `python3` → `os.system()`,
  `vim` → `:!cmd`, `less` → `!cmd`, `awk 'BEGIN{system(...)}'`.

witnesshell is therefore the shell (D2).

### 3.2 Accepted consequences of D17
Approving an interactive program (`bash`, `python3`, `vim`, `mysql`,
`sudo -i`) means trusting everything done inside it until it exits. That
activity is shown live and recorded, but not gated. Witnesses should treat
"approve `sudo -i`" as "approve an unwitnessed root shell, watched only".
The README will spell this out.

## 4. Gating model

witnesshell starts every command, so it knows when one ends. Two states:

### 4.1 PROMPT state: no foreground job
- The actor's keystrokes go into a **draft buffer** in the daemon, never
  to the PTY.
- The draft is shown in the actor's bottom bar (`draft> …`), and witnesses
  see it update live.
- Editing keys: ←/→, Home/End, Backspace/Delete, Ctrl-A/E/U/W/K, and ↑/↓
  for history of *approved* lines. A multi-line paste becomes one request.
- **Enter** submits the draft as a request. After that the draft is locked,
  and the actor can only cancel it (Esc / Ctrl-C).
- No tab completion: the shell never sees a partial line.
- Ctrl-D on an empty draft logs out (it is sent as `exit`; logout does not
  need approval). Logout purges the queue (D6).

### 4.2 Request lifecycle
```
draft ──Enter──▶ PENDING ──K approvals, 0 rejects──▶ APPROVED ──▶ executed by witnesshell (§4.3)
                   │                                               (state becomes RUNNING
                   ├──any reject + comment──▶ REJECTED              until the job ends or stops)
                   ├──actor cancels──▶ CANCELLED
                   └──actor logout / 30 min detach──▶ PURGED
```
- Only one request is pending at a time. While a request is pending, the
  actor cannot write a new draft; the actor can only cancel. **Rejected**:
  the actor sees the witness name and comment. The rejected text is put
  back into the draft so it can be fixed and resubmitted (D12).
- A comment is **required** when rejecting.
- A veto counts only while the request is pending: the K-th approval starts
  the command at once. Until then a witness may veto even after approving.
- Votes name the request ID, so a late keypress cannot approve a newer one.
- Control, invisible and bidirectional characters (and tabs) are refused, so
  witnesses are not shown something different from what runs.
- Votes are tied to witness **uid**, and are kept if the witness
  disconnects (D13). Two logins by the same uid count as one vote.
- K is checked against distinct approving uids. If fewer than K witnesses
  are connected, the request simply waits.

### 4.3 RUNNING state: an approved command is running (D17)
- All actor input (keys, Ctrl-C, Ctrl-Z, mouse, paste) goes **straight to
  the PTY**. This covers `y/N` prompts, `sudo` password prompts, vim, top,
  less, REPLs and nested shells.
- Witnesses watch the live output, which is also recorded.
- **Transition back to PROMPT** happens when the foreground job exits or is
  suspended with Ctrl-Z; witnesshell then takes back the terminal. `fg` / `bg` are normal
  commands that need approval.
- The session must serialize "is input free? → write to PTY" against
  "finished" and the next command, or a late key could slip through.

- The PTY input queue is flushed before each command, so leftover typing
  cannot feed it (tested; it does not race, as no keys pass while idle).

**Language** (`internal/lang`). A small strict subset of bash: simple
commands, pipelines, `&&` `||` `;` `&`, redirections of descriptors 0-2,
quotes, `$NAME`, `*` and `?`, `~`. Anything else is refused with an error,
never approximated. Supported text is tested to give the same arguments as
bash. Stricter than bash where bash surprises:
- an unset variable, and an unquoted one that bash would split or drop;
- a pattern that matches nothing, a name that looks like an option, or a name
  with hidden characters;
- bash builtins that are not supported, even if a program has that name.

Builtins: `cd export unset umask jobs fg bg kill exit`. They and plain
assignments need a line of their own, because **all words of a line are
expanded before approval**: in `touch x.txt; rm *.txt` the pattern does not
include `x.txt`. `kill` takes jobs only. Parser: `mvdan.cc/sh/v3/syntax`.

**What witnesses approve.** Besides the text: resolved program path, expanded
arguments, owner, trusted/signed status and warnings. Exactly that is
executed (`internal/runner`), once; if the shell's state changed since, it is
refused. Words that cannot be known beforehand are refused: command
substitution (D24) and process substitution (`<(...)`).

A line is abandoned when a command in it is suspended or ended by Ctrl-C. Not
pinned down: the current directory and file arguments are paths, so what they
point to can change between approval and use, as in any shell.

### 4.4 What may run (D18–D20, D22)
A file is **trusted** if it, and every directory on its resolved path, is not
owned by the actor and not writable by the actor (mode, group, ACL). Otherwise
it must be **signed**. Loose ends that count as files to check:
- `#!` interpreters must be trusted.
- For known interpreters, script arguments (`python3 x.py`, `sh x.sh`), also
  behind `sudo`, `env`, `nice` and similar.
- Commands get a fresh environment with a fixed `PATH`. Exporting variables
  that load code (`LD_*`, `PYTHON*`, `PAGER`, `GIT_*`, ...) is refused.
- Options not known to take no value make every argument count as a possible
  script. This can refuse a harmless line, such as `bash -c ./data`.
- Interpreters and wrappers are recognized by name (`internal/launch`); one
  under an unknown name is not.
- `sh < mine.sh` is checked like `sh mine.sh`. What a pipe feeds an
  interpreter cannot be (warning, D29).

**Signed files.** The daemon hashes the file, checks the signature, and copies
it to a root-owned store `/var/lib/witnesshell/signed/<sha256>`; the copy is
what runs, so a later edit has no effect. Two ways to sign:
- *Off the host:* an SSH signature (`ssh-keygen -Y sign -n witnesshell`),
  checked against `/etc/witnesshell/public_keys/` (D30), never against
  `~/.ssh`, which users can edit. An SSH signature holds the signer's public
  key but no name, so a key's file is named by the SHA-256 of that key:
  `witnesshell keyname KEY.pub`. It holds `user keytype key`. The directory
  must be root-owned with mode 0711 and the file writable by root only, or the
  signature is refused; the key inside must equal the one in the signature.
- *On the host:* `witnesshell sign FILE`. The daemon identifies the witness by
  peer credentials and records the hash, so no private key is on the host.

### 4.5 Kernel restrictions
Tested in the VM (Ubuntu 26.04, kernel 7.0), as alice started by root.
"Ran" means the attempt succeeded:

| Attempt | None | Landlock exec only from /usr | noexec mounts | Both |
|---|---|---|---|---|
| `./evil`, `./s.sh` | ran | blocked | blocked | blocked |
| `ld.so ./evil` | ran | **ran** | blocked | blocked |
| program from memory (memfd) | ran | **ran** | **ran** | **ran** |
| `python3 s.py` | ran | **ran** | **ran** | **ran** |
| `sudo ./evil` | ran | blocked | blocked | blocked |
| `sudo mount` (legitimate) | works | **broken** | works | **broken** |
| `sudo systemd-run ./evil` | ran | **ran** | **ran** | **ran** |
| `systemd-run --user ./evil` | ran | **ran** | (*) | (*) |
| install a crontab | works | works | works | works |

(*) Blocked, but probably only because the test hid the user's bus socket.
Treat as an escape. memfd was blocked with `vm.memfd_noexec=2` (with both).

Implemented and tested in M2a (`make vm-test`): uid switch, Landlock, trust
policy, signed store, host checks. Every attack above is a test, as are the
known limits (an unsigned script read by an approved interpreter or piped to
it, machine code in memory, programs copied or started through `sudo`).
Landlock also stops remounting inside a user namespace.

Consequences:
- **Host requirements:** every filesystem the actor can write to is mounted
  `noexec,nosuid` host-wide (so cron and user services are covered too);
  `vm.memfd_noexec=2`; cron/at and user services denied to actors. Besides
  `/home` and `/tmp`, places such as `/run/screen`, `/run/lock`, `/var/crash` and
  `/dev/shm` count; the check scans for them (3 s in the VM). The daemon
  checks these and refuses to start otherwise (`allow_weak_host` overrides).
- **Landlock** exec rules apply to commands not run through `sudo`, because
  they break `sudo mount`. `sudo` needs root's power; witnesses decide.
- seccomp: still to be designed. `no_new_privs` cannot be set (breaks sudo).

**Not enforceable:** an approved interpreter or scriptable program (python,
vim, awk) can run any logic typed or read inside it, including an unsigned
script and machine code it builds in its own memory (Python could allocate
writable+executable memory under every variant). Approving one trusts the
actor with it (D17). Approved root (`sudo`) can undo everything.

### 4.6 Commands without approval (D27)
| Command | Does |
|---|---|
| `view FILE` | built-in pager, like `less`; content, owner, mode and SHA-256 |
| `checksig FILE` | trusted / signed by whom / neither, and the SHA-256 |

Both start no program. Rules:
- They run with the **caller's own** file permissions, never the daemon's:
  the actor's view as the actor, a witness's view as that witness. Files only
  root may read still need an approved `sudo` command.
- Only a line that is exactly one such command skips approval. Combined with
  a pipe, redirection, `;`, `&&` or `&` it is refused.
- The pager has no shell escape, no editor and no saving to a file. Content is
  shown with control and invisible characters escaped, so a file cannot send
  commands to the terminal.
- Regular files only, checked after opening without blocking, so FIFOs and
  devices cannot hang the session or have side effects. Reading is by chunks.
- Pressing a key in the pager never reaches a program or the PTY.
- The actor's view is part of the mirrored screen and is recorded. A witness's
  view is private to that witness, works while a request is pending, and
  resolves relative paths from the actor's current directory.
- A viewed file can change before a command uses it. The SHA-256 lets a
  witness compare; for signed files the stored copy runs (§4.4).

## 5. Authorisation & config (D5, D13, D14)

Any member of group `witnesshell` who logs in may witness any session they
do not own. `/etc/witnesshell/config.toml`:

```toml
approvals_required = 1        # K
max_sessions       = 0        # 0 = unlimited, 1 = single session on host
detach_timeout     = "30m"    # actor gone this long → logout, queue purged, SIGHUP
udp_port           = 60001
record_dir         = "/var/log/witnesshell"
allow_weak_host    = false    # skip the host checks of §4.5
```

Known limit: one person with two accounts can witness themselves. Account
management on the host has to prevent that.

## 6. Transport: QUIC

- **quic-go** with TLS 1.3 and a self-signed ECDSA certificate created when
  the daemon starts. The client pins its SHA-256 hash, obtained over ssh.
- One UDP port for all sessions; connections are routed by token.
- Streams:
  - control (CBOR messages, both directions: hello, draft updates,
    request/vote/result, state changes, resize, witness list)
  - terminal output (server → clients)
  - actor input (actor → server)
- Keepalive every 3 s; idle timeout 15 s.
- **Reconnect** (D8: no seamless roaming needed): when the connection
  drops, the client retries with its **resume token**, from the new IP if
  that changed, without ssh. The server keeps a **VT emulator** per
  session and sends the current screen on resume (as mosh does), then the
  live stream continues. Control messages have sequence numbers.
- The actor UI shows `connection lost — reconnecting (0:12)`. After 30 min
  without the actor the server treats it as logout (D13). Witnesses can
  reconnect at any time while the session exists.
- Optional later: if the resume token has expired, the client automatically
  runs the ssh bootstrap again.

## 7. User interfaces

**Actor:** the full shell screen, with a status bar on the bottom line (a
DECSTBM scroll region). The bar shows the connection state, the witnesses
connected, and either the draft or the request state:
- `⏳ 0/1 — waiting for witness`
- `✔ approved by bob`
- `✘ rejected by bob: "wrong host, use db2"`
- `▶ running (input free)`

**Witness:** a read-only mirror of the actor's screen plus a 2-line panel
showing the live draft or pending request:
- keys: `[a] approve`, `[r] reject`, `[v] view file`, `[s] check signature`. Reject prompts for a comment, and
  the comment is required.
- the panel shows who has approved so far.
- a bell rings on each new request.

Witness keystrokes never reach the PTY.

## 8. Audit

Each participant has an append-only JSON-lines log in `record_dir`, named by
session start (UTC, milliseconds) and user (D28):

```
witnesshell-20261124T101500.123Z-actor-alice.log
witnesshell-20261124T101500.123Z-actor-alice.cast
witnesshell-20261124T101500.123Z-witness-bob.log
witnesshell-20261124T101500.123Z-witness-carol.log
```

Every file of a session uses the same session start, whenever the witness
joined. A witness who reconnects continues the same file. The daemon never
gives two sessions the same start time. Files are owned by root, mode 0600.

| Event | Actor log | Witness log |
|---|---|---|
| Session start/end, host, `allow_weak_host` warning | yes | yes |
| Joins and leaves | all witnesses | own |
| Request text, resolved program, SHA-256, outcome | yes | yes, while joined |
| Votes and comments (uid, time) | all | own |
| `view`, `checksig`: path, SHA-256, result (not content) | own | own |
| Command start, end, exit status; queue purge | yes | no |

Each entry carries the SHA-256 of the previous one, forming a chain per file.
Votes carry the request ID and hash in both logs, and the final hash of every
witness log goes into the actor log, so a removed or altered file is noticed.
`witnesshell audit verify <session start>` checks a session's files together.

### 8.1 Recording: asciicast v2 (D9)

The recording is one `.cast` file next to the actor log. asciicast v2
was chosen over v3, `script`/`scriptreplay`, ttyrec and tlog because it has
the widest replay support (`asciinema play`, the web player, `agg` for
GIF) and is written one line at a time, so a crash loses at most the
last line.

Contents:
- header: session id, actor, host, terminal size, start time
- `o` events: all terminal output, whatever the state
- `r` events: resizes
- `m` markers: `⏳ alice: systemctl restart nginx`,
  `✔ bob,carol`, `✘ bob: "…"`, `▶ running`, `■ exited`. The web player
  shows markers as chapters you can jump between.
- **no `i` (input) events**, so passwords typed in RUNNING state never end
  up in the file.

When the session ends, the cast file's SHA-256 is written into the actor
log. Witnesses have no recording of their own; they see the same screen.

## 9. Dependencies (Go, D11)

| Need | Library |
|---|---|
| QUIC + TLS | `github.com/quic-go/quic-go` |
| VT emulation (resume screen state) | `github.com/charmbracelet/x/vt` (fallback `hinshun/vt10x`) |
| Raw mode / size | `golang.org/x/term` |
| PTY, peer creds, tcflush | `golang.org/x/sys/unix` |
| Wire format | `github.com/fxamacker/cbor/v2` |
| Config | `github.com/BurntSushi/toml` |

Build: `CGO_ENABLED=0 GOOS=linux GOARCH={amd64,arm64} go build -trimpath -ldflags='-s -w'`.

## 10. Code layout

```
cmd/witnesshell/        one binary: connect | bootstrap | daemon | sessions | audit verify | version
internal/proto/         CBOR message types, protocol version
internal/transport/     QUIC server/client, cert pinning, resume tokens
internal/bootstrap/     ssh exec, role menu, handshake line
internal/daemon/        unix socket API, SO_PEERCRED, session registry, max_sessions
internal/pty/           pseudo-terminals
internal/lang/          parse, refuse, expand into an exact execution plan
internal/trust/         file trust rules, signatures, signed store
internal/launch/        policy, root launcher, Landlock, uid switch
internal/runner/        the shell: prepare, run, job control, builtins
internal/session/       joins gate + shell, VT emulator
internal/gate/          draft editor, request state machine, votes, K-of-N, veto
internal/view/          read-only pager and signature check (D27)
internal/audit/         hash-chained actor and witness logs, asciicast writer
internal/ui/            actor status bar, witness panel
deploy/                 systemd unit, sshd_config snippet, example config.toml
test/e2e/               docker compose: host + 3 users; tc netem loss; IP change
```

## 11. Milestones

| # | Milestone | Done when |
|---|---|---|
| M0 | Skeleton | Go module, Makefile, static build verified, `go vet` / tests in a `make check` |
| M1 | Gate core | `gate` state machine (draft, pending, K-of-N, veto, comment, cancel, purge) fully unit-tested, no I/O |
| M2a | Trust & launcher | trust rules, signed store, uid switch, Landlock, host checks; every attack in §4.5 is a VM regression test (`make vm-test`) |
| M2b | Shell language | strict parser, expansion to exact plan, job control, Ctrl-C/Z; attack tests ported from `internal/shell`, which is then removed |
| M2c | Local session | gate + shell + daemon; `witnesshell sign`; `view`, `checksig` in a session; actor and witness over the **unix socket** on one host (no network yet) |
| M3 | Bootstrap & roles | ssh bootstrap, role menu, `max_sessions`, ForceCommand docs |
| M4 | QUIC | QUIC transport, cert pinning, tokens; works between two machines |
| M5 | Resilience | resume tokens, VT screen resync, 30 min detach → logout; e2e with 30 % loss and a client IP change |
| M6 | Audit & recording | separate hash-chained actor and witness logs, asciicast with markers, `audit verify`; replay checked with `asciinema play` |
| M7 | Hardening & release | fuzz proto decoder, privilege-drop review, systemd unit, README (incl. D16 git-diff rule, §3.2 warning), release binaries |

## 12. Known limitations

- No tab completion at the prompt.
- Approving an interactive program grants free input inside it (D17, §3.2).
- Approval covers what is started, not what an approved interpreter or
  scriptable program then does (§4.5).
- One person with two accounts can witness themselves (§5).
- UDP must be reachable on the host (D8). There is no TCP fallback in v1.
- The root daemon is security-critical: keep it small, fuzz input, and
  drop privileges in the child before exec.
