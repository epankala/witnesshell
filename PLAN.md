# witnesshell — design & implementation plan (DRAFT v0.2)

> Status: draft. Items marked **[Q#]** depend on open questions (see end).
> Each has a recommended default so the plan is complete as written.

## 0. Decisions so far (2026-11-23)

| # | Decision |
|---|---|
| D1 | Guard against **accidental and malicious** commands *and file edits* → enforcement mode |
| D2 | Shell commands must be enforced, not just "assisted" → gate on the PTY input stream (§4) |
| D3 | Witnesses see full-screen program output (live mirror of the terminal) |
| D4 | Approval policy is **K-of-N** (e.g. 1-of-1, 2-of-3) |
| D5 | Any user with a login on the remote host can witness (except the actor's own uid) |
| D6 | Requests wait in a queue. Actor logs out → queue is purged |
| D7 | Shell runs as the target (login) user; `sudo` is used inside the session for root |
| D8 | UDP can be opened on the remote host. The client is installed locally. The remote IP is fixed; the client IP may change; a broken connection on an IP change is acceptable |
| D9 | Recording: **asciicast v2** (asciinema format), plus markers for approved commands (§8) |
| D10 | Remote: Linux only. Clients: Linux only |

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

## 3. Threat model (decided: enforcement, D1)

The actor may try to get around the gate on purpose. That forces the
following:

| Requirement | Why |
|---|---|
| Session server is a separate **daemon running as root** (or a dedicated user with CAP_SETUID), not a process owned by the actor | Same-uid processes can be ptraced or killed by the actor |
| Actor accounts get `ForceCommand witnesshell bootstrap --actor` in `sshd_config` (Match Group witnessed) | Otherwise the actor just opens a normal ssh shell |
| Gate sits on the **PTY input stream**, not inside the shell (no bash hooks) | Shell hooks (DEBUG trap, `bind -x`) can be undone by the actor |
| Actor uid ≠ witness uid, and the witness must be authorised for that actor | Prevents self-witnessing |
| No port forwarding, agent forwarding or sftp for actor accounts | Those are side channels around the gate |

**Why gating only "shell commands" can be bypassed.** Hooking the shell
(bash `DEBUG` trap, `PROMPT_COMMAND`, `bind -x` on Enter) only sees what
*that bash* parses. The actor can get around it in several ways:
- Disable the hook: `trap - DEBUG`, `bind -r`, `unset PROMPT_COMMAND`.
- Start a shell without the hook: `exec sh`, `bash --norc`, `busybox sh`.
- Run commands from inside a program the shell only saw as one command:
  `python3`, then `os.system(...)`; `vim`, then `:!rm …`; `less`, then
  `!cmd`; `mysql \!`; `gdb shell`; `git` hooks or pagers; `awk 'BEGIN{system(...)}'`.
- Edit files in vim, nano or `ed`. That is not a shell command at all.

So witnesshell does not trust the shell. Every byte sent to the PTY must be
approved, whatever program reads it. Shell integration (OSC 133 prompt
marks) is used only to label things in the UI, never for security.

**Role assignment** (follows the original idea: first one in is the actor):
- All users who may use the host get `ForceCommand witnesshell bootstrap`
  (`Match Group witnesshell`).
- Bootstrap logic:
  - No active session by another user: start a new session; this user is
    the **actor**.
  - Otherwise: offer to join an existing session as **witness** (pick one
    from a list if there are several). **[Q14]**
- A "break-glass" route for admins (console, or a separate un-forced
  admin account) stays outside witnesshell and is documented as such.

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
  password prompt, e.g. `sudo`), the witness sees `«hidden input, 14 chars»`.
  Approval is **still required**, because `stty -echo` could otherwise be
  used to switch the gate off.

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

### 4.4 Approval policy (decided: K-of-N, D4)
- `approvals_required = K` (default 1). Requests wait until K distinct
  witnesses approve. A witness's uid counts once, even if that witness is
  logged in twice.
- Whether **any rejection vetoes** is still open. **[Q15]**
- A rejection can carry a short reason, which the actor sees.
- Requests are handled one at a time (FIFO). The actor can cancel a pending
  request.
- If no witness is connected, requests wait (D6).
- **The actor logs out** (exits the shell or closes the session) →
  everything in the queue is purged, and an audit entry
  `queue_purged: n requests` is written.

### 4.5 Witnessed file edits (proposed)
Editing in vim under an interactive grant works, but the witness then has
to follow keystrokes. A cleaner flow for the "file edits" part of D1:

```
actor:   wedit /etc/nginx/nginx.conf        (itself a gated request)
server:  reads the file as the target user, sends a copy to the actor client
client:  opens $EDITOR locally on a temp copy (actor's laptop; nothing runs on the host)
client:  on save+quit, sends the new content
witness: sees a unified diff  →  approve / reject
server:  writes atomically as the target user (keeps owner and mode), logs the diff
```
For files that need root, use `wedit --sudo`. The daemon writes the file
as root only after the diff is approved, and logs that root was used.
**[Q16]**

## 5. Authorisation of witnesses (decided: any local user, D5)

- Anyone who can log in to the host (ssh auth succeeds and the user reaches
  bootstrap) may witness.
- The one exception is the actor's own uid.
- A small config file `/etc/witnesshell/config.toml` holds K, timeouts and
  grant limits:

```toml
approvals_required = 1      # K
grant_max          = "15m"
udp_port           = 60001
detach_timeout     = "30m"  # [Q13]
record_dir         = "/var/log/witnesshell/casts"
```

Known limit: one person with two accounts can witness themselves. The
host's account management has to prevent that.

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
  - QUIC handles loss and reordering. Seamless roaming is **not required**
    (D8). If the client IP changes, the connection may break.
  - When the connection breaks (IP change, laptop sleep, idle timeout), the
    client **reconnects with a resume token** to the same session. This does
    not need SSH again, as long as the session still exists. **[Q13]**
  - The server keeps a **virtual terminal (VT emulator) per session**. On
    resume, it sends the screen state as it is now, not a replay of
    everything missed, the way mosh works. Control messages carry sequence
    numbers so none are lost or duplicated.
  - Keepalive every 3 s. The UI shows "connection lost — reconnecting
    (12s)" without dropping the session.
  - Not in v1: mosh's predictive local echo. It matters less here, since
    the actor's draft is local anyway.
- A *disconnect* (network) is different from a *logout* (explicit exit).
  After a disconnect, the session lives for `detach_timeout` and the queue
  is kept. A logout purges the queue (D6). **[Q13]**

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
- Optional syslog/journald copy.

### 8.1 Session recording (decided: asciicast v2, D9)

Existing formats that can be replayed:

| Format | Tooling | Pros | Cons |
|---|---|---|---|
| **asciicast v2** (asciinema) | `asciinema play`, asciinema-player (web), `agg` (→ GIF), many converters | JSON-lines, append-friendly, so a crash loses at most the last line; easy to write from Go; supports **input (`i`) and marker (`m`) events**; widest support | Text only (fine for us) |
| asciicast v3 | asciinema CLI 3.x, recent player | Relative timestamps, an "exit" event | Newer, so fewer tools support it so far |
| `script --log-timing` + `scriptreplay` (util-linux) | Already on every Linux box | No extra install | Two files (data + timing); no metadata or markers; awkward to annotate |
| ttyrec | ttyplay, ipbt | Old and simple | Binary format, no metadata, barely maintained |
| tlog (Red Hat) | `tlog-play`, Cockpit, journald/Elasticsearch | Built for audit, ships logs off the box | Its own JSON schema; heavy and RHEL-centric; it hooks the login shell, which is a duplicate of what we already do |

**Proposal: asciicast v2**, one `.cast` file per session in `record_dir`.
- The header holds session id, actor, host, terminal size, and the
  start time.
- `o` events hold terminal output, which covers full-screen programs too.
- `m` (marker) events hold each request and its outcome, e.g.
  `"✔ bob,carol: systemctl restart nginx"`. asciinema-player shows markers
  as chapters, so a replay can jump from command to command.
- `r` events hold resizes.
- Actor keystrokes are **not** recorded as `i` events, because passwords
  would end up in the file. Approved lines are already in the audit log
  (hidden input stays masked).
- The SHA-256 of the cast file at the end of the session is written into
  the hash-chained audit log, so tampering with a recording can be detected.
- Replay with `asciinema play file.cast`, or the web player. witnesshell
  needs no player of its own. Optional later: `witnesshell replay`.

## 9. Language & dependencies **[Q11]**

**Recommendation: Go.** `CGO_ENABLED=0 go build` gives a single static
binary for linux/amd64 and linux/arm64 (D10) with no libc dependency.
All the needed libraries are pure Go:

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

Q1–Q10 are answered and recorded as D1–D10 in §0.

11. **Language.** Is Go OK (recommended: simplest static builds, mature
    pure-Go QUIC/PTY libraries), or do you prefer Rust (quinn + musl)?
12. **Witness powers.** What can a witness do beyond approve/reject?
    *Default:* chat messages to the actor, send Ctrl-C to the running
    command, revoke an interactive grant. *Not by default:* kill the
    session, take over as actor.
13. **Session lifetime after a disconnect.** How long does the session (and
    its queue and running commands) survive a broken connection before it
    counts as a logout and the queue is purged? *Default:* 30 min, then
    the shell gets SIGHUP like a normal ssh logout.
    What should a witness's disconnect mean? *Default:* their votes on
    pending requests are kept; an interactive grant ends if fewer than K
    witnesses are still watching.
14. **Role assignment.** When a user logs in while another user's session
    is active, should they **automatically** become a witness (your original
    description), or be **asked** "witness alice's session / start your own"?
    Can there be several actor sessions on the host at the same time?
    *Default:* ask, and allow several sessions.
15. **Veto.** With K-of-N, does a single rejection reject the request even if
    K others approve? *Default:* yes, any rejection vetoes.
16. **File edits.** Is the "witnessed edit" flow in §4.5 (edit locally →
    witness approves a diff → server writes) wanted in v1, or are vim/nano
    under a watched interactive grant enough to start with?
17. **Interactive grants.** Since witnesses see full-screen output live, is a
    witness-approved, time-limited grant (revocable at any moment) an
    acceptable way to use vim/top/less? Or must every keystroke in those
    programs be approved too (very slow)?
