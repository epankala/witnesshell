# witnesshell — design & implementation plan (DRAFT v0.1)

> Status: draft. Items marked **[Q#]** depend on open questions (see end).
> Each has a recommended default so the plan is complete as written.

## 1. Goal

A "four-eyes" remote shell. One person (the **actor**) runs commands on a
remote machine. One or more other people (**witnesses**) watch the session
live and must **approve** each piece of input before it reaches the shell.
Everything is logged.

Transport: bootstrap over SSH (for authentication), then switch to **QUIC
over UDP** with mosh-style resilience (survives packet loss, roaming, and
sleep/resume).

## 2. Roles & user flow

```
 actor laptop                      remote host                     witness laptop
 ────────────                      ───────────                     ──────────────
 witnesshell connect alice@host
   └─ ssh alice@host witnesshell bootstrap --actor
                                   witnesshelld (daemon, root)
                                     ├─ verifies peer uid = alice (SO_PEERCRED)
                                     ├─ creates session S1, PTY shell as alice
                                     └─ returns  port, cert-hash, token, S1
   ssh exits; QUIC ──────────────▶ UDP :60001  ◀────────────── QUIC
                                                     ssh bob@host witnesshell bootstrap --witness S1
                                     ├─ verifies peer uid = bob, bob may witness alice
                                     └─ returns port, cert-hash, token
                                                   witnesshell witness bob@host [S1]
```

1. The actor runs `witnesshell connect user@host` locally. This calls the system
   `ssh` binary, so `~/.ssh/config`, agents, jump hosts and keys all work as usual.
2. On the remote side, `witnesshell bootstrap` asks the local daemon for a session
   over a unix socket. The daemon identifies the caller by kernel peer
   credentials. The shell runs **as the actor's login user**, which covers
   "start with the credentials the login was done with".
3. The bootstrap prints one line,
   `WITNESSHELL 1 <udp-port> <cert-sha256> <one-time-token> <session-id>`,
   then exits, and the SSH connection closes, just like mosh.
4. The client connects with QUIC. It pins the server's certificate by hash, so
   no PKI is needed, and presents the token. Trust in the server is carried
   over from SSH host-key verification.
5. Witnesses do the same with `witnesshell witness user@host [session-id]`. If
   only one session is eligible, the client picks it automatically. Otherwise
   it shows a list.

## 3. Threat model **[Q1]**

Recommended default: **enforcement mode**. The actor is not trusted to bypass
the gate on purpose. That forces the following:

| Requirement | Why |
|---|---|
| Session server is a separate **daemon running as root** (or a dedicated user with CAP_SETUID), not a process owned by the actor | Same-uid processes can be ptraced or killed by the actor |
| Actor accounts get `ForceCommand witnesshell bootstrap --actor` in `sshd_config` (Match Group witnessed) | Otherwise the actor just opens a normal ssh shell |
| Gate sits on the **PTY input stream**, not inside the shell (no bash hooks) | Shell hooks (DEBUG trap, `bind -x`) can be undone by the actor |
| Actor uid ≠ witness uid, and the witness must be authorised for that actor | Prevents self-witnessing |
| No port forwarding, agent forwarding or sftp for actor accounts | Those are side channels around the gate |

Cooperative mode is the lighter alternative: a safety net against mistakes,
with nobody assumed malicious. It could run without a root daemon and use
shell integration, which keeps tab completion. The architecture below
supports adding it later as a flag.

## 4. Gating model **[Q2][Q3]**

The core idea: **no byte reaches the PTY unless it was approved**, except a
small allow-list.

### 4.1 Line mode (default state)
- The actor's keystrokes go into a **draft buffer held by witnesshell**,
  not into the shell.
- The draft is shown in a bottom bar on the actor's screen
  (`draft> rm -rf /var/tmp/x`). Witnesses see it update live as it is typed.
- Basic line editing works: ←/→, backspace, Ctrl-A/E/U/W, history of
  *approved* lines (↑/↓), and paste.
- **Enter** submits the draft as a *request*. A multi-line paste becomes one
  request.
- Once the request is approved, the bytes plus `\r` are written to the PTY.
- Tab completion is not available, because the shell never sees a partial
  line. Possible later addition: a server-side filename completer that only
  reads the filesystem (no execution).
- The input state of the PTY is checked through termios. If ECHO is off (a
  password prompt), the witness sees `«hidden input, 14 chars»`. Approval is
  still required.

### 4.2 Allow-list (passes immediately, configurable)
`Ctrl-C` (SIGINT), `Ctrl-\`, and window resize. `Ctrl-Z` and `Ctrl-D` are
gated by default: Ctrl-D can confirm prompts, and Ctrl-Z leads to job control.

### 4.3 Interactive grants (vim, top, less, REPLs…) **[Q3]**
- Line mode works for programs that read lines, such as `y/N` prompts, but
  not for full-screen apps.
- The actor can ask for an **interactive grant**: "raw keystrokes for up to
  N minutes".
- Once a witness approves, keystrokes stream live. Witnesses watch, and any
  of them can **revoke** instantly with a hotkey.
- The grant also ends when its time runs out, when the foreground process
  group changes back to the shell, or when a witness disconnects.
- Side effect: a full-screen app (the alternate screen is active) gets no
  input until a grant is approved. The UI shows a hint about this.

### 4.4 Approval policy **[Q4]**
- Configurable per actor: `any` (1 of N), `all`, or `quorum:K`.
  Default: `any`, and **any rejection vetoes**.
- A rejection can carry a short reason, which the actor sees.
- Requests are handled one at a time (FIFO). The actor can cancel a pending
  request.
- If no witness is connected, the actor can still type and submit, but
  requests wait **[Q6]**. Optional timeout to auto-reject.

## 5. Authorisation of witnesses **[Q5]**

Default: a config file `/etc/witnesshell/policy.toml`.

```toml
[actor.alice]
witnesses = ["bob", "@ops"]      # users or unix groups
policy    = "any"
grant_max = "15m"

[defaults]
witnesses = ["@witness"]
```

Optional extra: the actor's session shows a short join code, which a witness
must also enter. This proves the witness is talking to the actor in real time.

## 6. Transport: QUIC, mosh-style

- **Library**: quic-go (Go) or quinn (Rust). TLS 1.3 with a self-signed
  certificate created per daemon start. The client pins it by SHA-256.
- **Port**: one UDP port per daemon, configurable range (e.g.
  60001–60100 like mosh) **[Q8]**. All sessions share it and are routed by
  token or connection ID.
- **Streams**:
  - stream 0: control (CBOR messages: hello/auth, draft updates, requests,
    votes, grants, resize, chat)
  - stream 1: terminal output (server → client)
  - stream 2: actor input (client → server)
- **Resilience**:
  - QUIC handles loss and reordering, and its connection IDs allow NAT
    rebinding and client IP changes (roaming).
  - If the connection dies anyway (laptop sleep, idle timeout), the client
    **reconnects with a resume token**.
  - The server keeps a **virtual terminal (VT emulator) per session**. On
    resume, it sends the screen state as it is now, not a replay of
    everything missed, the way mosh works. Control messages carry sequence
    numbers so none are lost or duplicated.
  - Keepalive every 3 s. The UI shows "connection lost — reconnecting
    (12s)" without dropping the session.
  - Not in v1: mosh's predictive local echo. It matters less here, since
    the actor's draft is local anyway.
- The session lives on the server for a configurable time after the actor
  disconnects (default 24 h, like tmux detach).

## 7. User interfaces

**Actor:** the full shell screen, plus a 1-line status/draft bar at the
bottom, made with a DECSTBM scroll region. The bar shows the connection
state, the witnesses present, and the pending request with its state
(`⏳ waiting for bob`, `✔ approved by bob`, `✘ rejected: "wrong host"`).

**Witness:** a read-only mirror of the actor's screen. A bottom panel shows
the live draft and the pending request:
`[a] approve  [r] reject  [v] view full  [g] grant/revoke  [m] message`.
A bell or highlight fires on each new request. Witnesses can never write to
the PTY.

**Both:** a simple chat/message line, to ask "why?" before approving
**[Q12]**.

## 8. Audit

- An append-only JSON-lines log in `/var/log/witnesshell/`. Each line holds:
  session, actor, witnesses present, request text (or hidden marker), each
  vote with uid and timestamp, and the outcome.
- Each entry carries the hash of the previous entry, making a tamper-evident
  chain.
- Optional asciicast v2 recording of the terminal output for each session
  **[Q9]**.
- Optional syslog/journald copy.

## 9. Language & dependencies **[Q11]**

**Recommendation: Go.** `CGO_ENABLED=0 go build` gives a single static
binary for linux/amd64, linux/arm64, darwin and windows (client side) with
no libc dependency. All the needed libraries are pure Go:

| Need | Library |
|---|---|
| QUIC + TLS | `github.com/quic-go/quic-go` |
| PTY | `github.com/creack/pty` |
| VT emulation (server screen state) | `github.com/charmbracelet/x/vt` or `hinshun/vt10x` |
| Terminal raw mode / size | `golang.org/x/term` |
| Peer creds, setuid, termios | `golang.org/x/sys/unix` |
| Messages | `github.com/fxamacker/cbor/v2` |
| Config | `github.com/BurntSushi/toml` |

Rust (quinn + rustls + musl target) is a solid second choice. It is stronger
on memory safety, but cross-compiling static builds is slower and fussier.
Zig's QUIC ecosystem is too young.

## 10. Code layout (Go)

```
cmd/witnesshell/        single binary; subcommands:
                        connect | witness | bootstrap | daemon | sessions | version
internal/proto/         CBOR message types, versioning
internal/transport/     QUIC server/client, cert pinning, resume
internal/bootstrap/     ssh exec + handshake line parsing
internal/daemon/        unix socket API, SO_PEERCRED, session registry
internal/session/       PTY spawn as uid, VT emulator, state machine
internal/gate/          draft buffer, request queue, votes, grants, allow-list
internal/policy/        policy.toml loading & evaluation
internal/audit/         hash-chained log, asciicast writer
internal/ui/            actor bar & witness panel rendering
deploy/                 systemd unit, sshd_config snippet, example policy
test/e2e/               docker-compose: host + actor + 2 witnesses, netem loss
```

## 11. Milestones

| # | Milestone | Done when |
|---|---|---|
| M0 | Skeleton | Go module, Makefile, static build check (`file` reports statically linked), CI script |
| M1 | Gate core, local only | `gate` state machine fully unit-tested; PTY session with a witness over a unix socket on one machine |
| M2 | Daemon & auth | root daemon, SO_PEERCRED, policy.toml, shell spawned as actor uid, self-witness blocked |
| M3 | QUIC + SSH bootstrap | `connect` / `witness` work across machines; cert pinning; one-time tokens |
| M4 | Resilience | VT screen-state resume, roaming, reconnect UI; e2e test with `tc netem` 30 % loss + IP change |
| M5 | Interactive grants & hidden input | vim/top usable via grant; revoke; ECHO-off masking |
| M6 | Audit | hash-chained log, asciicast, `witnesshell audit verify` |
| M7 | Hardening & packaging | systemd unit, sshd ForceCommand docs, fuzzing of proto decoder, release binaries |

M1 is the heart of the project. It is worth getting the state machine right
before any networking.

## 12. Known limitations / risks

- No tab completion in line mode under enforcement.
- Approval covers **text**, not meaning. A witness who approves
  `./deploy.sh` is trusting whatever that script contains. Mitigation: keep
  a read-only "show file" helper, `[v]` on a path in the witness UI, for
  later.
- The actor can still run long-lived or background processes once a line
  is approved (`nohup …&`). This is by design: you approved it.
- UDP may be blocked on corporate networks. Possible fallback: QUIC-like
  framing over the ssh channel itself (later, if needed).
- A root daemon is a high-value target. Keep it small, fuzz the protocol,
  and drop privileges right after the PTY fork.

---

## Open questions

1. **Threat model.** Is this an *enforcement* control (actor may be
   untrusted, e.g. a contractor or compliance four-eyes rule), or a
   *cooperative safety net* against mistakes? This decides whether a root
   daemon + ForceCommand is needed. *Default: enforcement.*
2. **Gate granularity.** Gate every input line sent to the PTY (secure,
   no tab completion), or only shell command lines via shell integration
   (nicer UX, bypassable)? *Default: every line.*
3. **Full-screen / interactive programs** (vim, top, less, mysql REPL).
   Options: time-limited interactive grants watched live, block them
   entirely, or something else? *Default: grants.*
4. **Multiple witnesses.** Should 1 approval suffice, all, or K-of-N?
   Should one reject veto? *Default: any 1, any reject vetoes,
   configurable.*
5. **Who may witness whom.** Options: config file of users/groups, a
   unix group, a join code from the actor, or a combination?
   *Default: config file + optional join code.*
6. **No witness present.** Should requests queue until a witness joins,
   should the session refuse to start, or should there be a timeout?
   *Default: queue, optional auto-reject timeout.*
7. **Privileges.** Do actors need `sudo` / root commands? If yes, run
   sudo inside the session (the password prompt is gated as hidden
   input), or have witnesshell run the shell as a target user directly?
8. **Network.** Can you open a UDP port range on the remote hosts? Is it
   OK that the client binary must be installed locally (like mosh)?
   Is roaming (IP change mid-session) required in v1?
9. **Audit.** Are full output recordings (asciicast) required, or only
   command/approval logs? Should logs go somewhere off-box?
10. **Platforms.** Remote: Linux only? Which architectures? Client:
    Linux / macOS / Windows?
11. **Language.** Is Go OK (recommended), or do you prefer Rust?
12. **Witness powers.** Beyond approve/reject: chat messages, sending
    Ctrl-C, killing the session, taking over as actor?
13. **Session lifetime.** How long does a detached session survive, and
    what happens to running commands when it expires?
