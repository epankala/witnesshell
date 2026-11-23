# witnesshell — design & implementation plan (v0.3)

> Status: design settled (all questions answered 2026-11-23). Next: M0.

## 0. Decisions

| # | Decision |
|---|---|
| D1 | Guard against **accidental and malicious** shell commands → enforcement mode |
| D2 | Enforce on the **PTY input stream**, not via shell hooks (they can be bypassed, §3.1) |
| D3 | Witnesses see a live mirror of the terminal, full-screen programs included |
| D4 | Approval policy **K-of-N** (configurable K, e.g. 1-of-1) |
| D5 | Any user with a login on the host can witness, except the actor's own uid |
| D6 | Requests wait in a queue; actor logout → queue purged |
| D7 | Shell runs as the target (login) user; `sudo` is used inside the session for root |
| D8 | Remote IP is fixed; client IP may change; a broken connection on an IP change is OK; client installed locally |
| D9 | Recording: **asciicast v2** with markers per request (§8.1) |
| D10 | Linux only, both ends |
| D11 | Language: **Go**, static binary (`CGO_ENABLED=0`) |
| D12 | Witness powers: **approve** or **reject with a comment**. The actor then submits a new command. Nothing else (no typing, no Ctrl-C, no kill) |
| D13 | Actor disconnected **30 min** → treated as logout. A witness disconnecting does **not** remove votes already given |
| D14 | On login with sessions active: **ask** "witness one of them / start own session". Several sessions allowed; `max_sessions = 1` can enforce a single session |
| D15 | **Any rejection vetoes**, even if K approvals exist |
| D16 | **No file-edit feature.** Users keep config in git and show `git diff`; witnesses refuse to approve use of unreviewed edits. This is a process rule, documented in README |
| D17 | **Approving a command approves the whole program run.** While an approved command is in the foreground, all input passes freely (watched live and recorded). When it exits and the shell is back in the foreground, gating resumes |

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
| Session server is a **root daemon**; the shell is forked and drops to the target uid | Same-uid processes could be ptraced or killed by the actor |
| `Match Group witnesshell` → `ForceCommand witnesshell bootstrap`, `AllowTcpForwarding no`, `AllowAgentForwarding no`, `X11Forwarding no`, `PermitTunnel no`, no sftp subsystem | Otherwise the actor opens a plain shell or tunnels around the gate |
| Gate on PTY input, bash takes commands only from a **private socket** (§4.3) | Shell hooks can be undone |
| Actor uid ≠ witness uid | No self-witnessing |
| Admin break-glass access (console / separate un-forced admin account) is outside witnesshell and documented | Need a way in if the daemon is broken |

### 3.1 Why shell hooks are not enough
A bash `DEBUG` trap, `PROMPT_COMMAND` or `bind -x` can be bypassed in
several ways:
- Disable it: `trap - DEBUG`, `bind -r`.
- Start a shell without it: `exec sh`, `bash --norc`, `busybox sh`.
- Run commands from inside a program: `python3` → `os.system()`,
  `vim` → `:!cmd`, `less` → `!cmd`, `awk 'BEGIN{system(...)}'`.

witnesshell therefore controls what reaches the PTY itself.

### 3.2 Accepted consequences of D17
Approving an interactive program (`bash`, `python3`, `vim`, `mysql`,
`sudo -i`) means trusting everything done inside it until it exits. That
activity is shown live and recorded, but not gated. Witnesses should treat
"approve `sudo -i`" as "approve an unwitnessed root shell, watched only".
The README will spell this out.

## 4. Gating model

The daemon asks the kernel whether bash is waiting for its next command
(§4.3), which the actor cannot fake by printing. It gives two states:

### 4.1 PROMPT state: bash is waiting for a command
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
draft ──Enter──▶ PENDING ──K approvals, 0 rejects──▶ APPROVED ──▶ line written to command socket (§4.3)
                   │                                               (state becomes RUNNING
                   ├──any reject + comment──▶ REJECTED              until bash is idle)
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
- **Transition back to PROMPT** happens when bash waits for its next command:
  the program exited, or was suspended with Ctrl-Z. `fg` / `bg` are normal
  commands that need approval.
- The session must serialize "is input free? → write to PTY" against
  "finished" and the next command, or a late key could slip through.

**Command channel** (`internal/shell`, chosen by prototype 2026-11-23):
- bash runs as `bash --noediting -i`. Its stdin is a **private socket**;
  stdout, stderr and the controlling terminal are the PTY.
- Each approved text is sent as `\builtin eval '<text>' </dev/tty`: one unit,
  with the terminal as its stdin. Children therefore do not get the socket,
  and incomplete syntax is an error instead of swallowing the next command.
- Idle = socket empty and `/proc/PID/syscall` shows bash blocked in `read`
  on that socket. Programs cannot fake this by printing.
- The PTY input queue is flushed just before each command. This is required:
  without it leftover typing feeds the next command. It does not race,
  because no keys are passed while idle.

Rejected alternatives, each shown to fail:

| Design | Failure |
|---|---|
| Interactive bash on the PTY + flush on exit | Type-ahead runs unapproved (5/5) |
| Script from a pipe, `bash -m` (also `-i`, or with `trap : INT`) | Programs inject commands by reopening the pipe in `/proc`; Ctrl-C in loops kills bash |
| Interactive bash with readline on the socket | Waits in `pselect`, so idle detection sees nothing |

Requirements and open points:
- bash only in v1. The daemon needs `CAP_SYS_PTRACE` to read `/proc/PID/syscall`.
- A program that may ptrace bash can control it. Hosts need
  `kernel.yama.ptrace_scope` ≥ 1; the daemon should refuse to start otherwise.
- Not yet tested: `sudo` with a password, running as root with a uid switch,
  login profile files, arm64 hardware.

### 4.4 Edge cases
- `cmd &`: bash is idle again, so the next input is gated. The background
  job's output is still mirrored and recorded.
- **`exec bash` / `exec python3`** replaces the gated bash and, under D17,
  leaves input free for the rest of the session. Open: end the session
  instead (recommended).
- Shell exits (e.g. the shell itself was killed): the session ends, the
  queue is purged, and the end is logged.

## 5. Authorisation & config (D5, D13, D14)

Any member of group `witnesshell` who logs in may witness any session they
do not own. `/etc/witnesshell/config.toml`:

```toml
approvals_required = 1        # K
max_sessions       = 0        # 0 = unlimited, 1 = single session on host
detach_timeout     = "30m"    # actor gone this long → logout, queue purged, SIGHUP
udp_port           = 60001
record_dir         = "/var/log/witnesshell"
shell              = "/bin/bash"  # bash only in v1
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
- keys: `[a] approve` and `[r] reject`. Reject prompts for a comment, and
  the comment is required.
- the panel shows who has approved so far.
- a bell rings on each new request.

Witness keystrokes never reach the PTY.

## 8. Audit

Each session has an append-only JSON-lines log, `/var/log/witnesshell/<session>.log`.
It records:
- session start/end
- actor
- each witness join/leave
- each request: its text, every vote (uid, time, comment) and the outcome
- RUNNING start/end
- queue purge.

Each entry carries the SHA-256 of the previous one, forming a chain.
`witnesshell audit verify <file>` checks the chain.

### 8.1 Recording: asciicast v2 (D9)

The recording is one `<session>.cast` file next to the log. asciicast v2
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

When the session ends, the cast file's SHA-256 is written into the audit
chain.

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
internal/shell/         bash on a PTY, command socket, idle detection
internal/session/       joins gate + shell, VT emulator
internal/gate/          draft editor, request state machine, votes, K-of-N, veto
internal/audit/         hash-chained log, asciicast writer
internal/ui/            actor status bar, witness panel
deploy/                 systemd unit, sshd_config snippet, example config.toml
test/e2e/               docker compose: host + 3 users; tc netem loss; IP change
```

## 11. Milestones

| # | Milestone | Done when |
|---|---|---|
| M0 | Skeleton | Go module, Makefile, static build verified, `go vet` / tests in a `make check` |
| M1 | Gate core | `gate` state machine (draft, pending, K-of-N, veto, comment, cancel, purge) fully unit-tested, no I/O |
| M2 | Local session | daemon + PTY as uid + command socket (§4.3) + PROMPT/RUNNING switching; type-ahead bypass regression test; actor and witness over the **unix socket** on one host (no network yet) |
| M3 | Bootstrap & roles | ssh bootstrap, role menu, `max_sessions`, ForceCommand docs |
| M4 | QUIC | QUIC transport, cert pinning, tokens; works between two machines |
| M5 | Resilience | resume tokens, VT screen resync, 30 min detach → logout; e2e with 30 % loss and a client IP change |
| M6 | Audit & recording | hash-chained log, asciicast with markers, `audit verify`; replay checked with `asciinema play` |
| M7 | Hardening & release | fuzz proto decoder, privilege-drop review, systemd unit, README (incl. D16 git-diff rule, §3.2 warning), release binaries |

## 12. Known limitations

- No tab completion at the prompt.
- Approving an interactive program grants free input inside it (D17, §3.2).
- Approval covers the text of a command, not what scripts it runs do.
  Partly covered by the D16 git-diff convention.
- One person with two accounts can witness themselves (§5).
- UDP must be reachable on the host (D8). There is no TCP fallback in v1.
- The root daemon is security-critical: keep it small, fuzz input, and
  drop privileges in the child before exec.
