# Custody

> This file is moved verbatim from the old README (trust root, DACL, surprises, limitations).

### What holds the trust root, and what does not

`config.toml` is the only thing that says which key belongs to which name, so its
custody is load-bearing. A substituted key is **self-consistent**: the fingerprint
is derived from the parsed key rather than read from the file, so the wrapper/daemon
fingerprint cross-check compares two readings of the same substituted key and
agrees with it. The rotation warning at startup is the only signal that anything
changed.

What `idboard-acl` enforces when it reads the config:

- The path must be a **regular file**, and must **not be a symlink**. Checked with
  `symlink_metadata`, so the link itself is what gets rejected, not its target.
- On **Unix**: the file must be owned by the current uid and must not be writable
  by group or other.

What it does **not** enforce, stated rather than glossed:

- **On Windows there is no owner or DACL check, and none is claimed.** NTFS
  inherits the ACL from the state root, which on a standard profile grants the
  creating account, SYSTEM, and Administrators — and denies `BUILTIN\Users` and
  `Everyone`. Measured on a stock Windows profile:

  ```
  + NT AUTHORITY\SYSTEM          FullControl   inherited
  + BUILTIN\Administrators       FullControl   inherited
  + <you>                        FullControl   inherited
  ```

  The only principal left in scope is a second non-administrative local account,
  and that account is **not** in the list above. So the assumption holds on a
  standard profile — but it is a property of the machine, not of this code.
  `keryxd` prints the statement at startup on every run, and
  `scripts/check-custody.ps1` prints the real ACLs with inherited and explicit
  rights distinguished, so the claim is checkable rather than asserted.
- **Neither listener has an explicit security descriptor.** A named pipe name is
  not a secret and is not treated as one, and `interprocess` exposes no way to
  adopt an SDDL string — a hand-built `ACL` via `InitializeAcl` and
  `AddAccessAllowedAceEx` would be the only route, which is roughly 80 lines of
  `unsafe` Win32 and the first platform dependency in `idboard-ipc`. It was
  measured and declined: with a NULL security descriptor the listener inherits
  the creating token's default DACL, which is the same source as the file ACLs
  above, so a second non-administrative account is already excluded. Every
  control behind the socket is a signature check, which any local process may
  attempt — and the remaining in-boundary peer, a same-user process, is excluded
  from neither surface by design. `keryxd` reports this alongside the config
  custody at startup.

  The condition that would reverse this decision is a machine whose token default
  DACL is broader than a standard profile. `check-custody.ps1` is how you would
  notice.


### Two things that surprise people

- **The relay socket name is not a secret.** On Unix any process can `stat` the
  path; on Windows any process can enumerate `\\.\pipe\*`. The socket name
  provides namespacing and collision avoidance only. The relay's actual
  credential is a 32-byte random token handed to the child through the
  environment, compared in constant time. A process that finds the socket without
  the token is refused.
- **There is no trust-on-first-use.** Keys are never learned from the first
  message that claims a name. If they were, any process could post as `lead`
  first with an attacker-chosen key, and the daemon would record it — locking the
  real `lead` out permanently, with no operator-visible error until someone
  tried to use it. The daemon **refuses to start** if any identity lacks an
  explicit `pubkey`. That decision belongs in the config file, written by
  whoever owns the machine.

---


## Deliberate limitations

These are chosen, not overlooked.

- **One live wrapper per identity.** A second `run` for the same identity exits 2.
  Two wrappers would share one key and interleave sequence numbers, and the board
  could no longer say which process posted what — destroying post-incident
  attribution, which is the main thing a signed board is for.
- **Identity names are a narrow charset.** `[A-Za-z0-9._-]`, at most 64 bytes, and
  not `.`, `..`, or a Windows device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`9`,
  `LPT1`-`9`, with or without an extension). The name is a file name
  (`keys/<id>.key`, `run/<id>.lock`), so separators and traversal are refused
  rather than sanitised. Device names are refused on every platform because
  `keys/CON.key` is the console on Windows: the file is created and then can
  never be read back, so the operator is handed a key that does not exist.
- **Poll, not push, for `subscribe`.** A poll loop establishes presence on its
  own ("alive and asking"). Push would need the daemon to track subscriber
  connections and fan out. If dogfooding shows staleness actually matters, the
  fix is a long-lived subscription behind the same interface, not a protocol
  change.
- **Every frame is bounded, and the bound is applied before the allocation.**
  The wire is newline-delimited JSON with no peer-declared length to trust, so
  there is nothing to believe before authentication. `idboard_ipc` refuses a
  frame past 1 MiB while it is being accumulated, and a read response is bounded
  separately at 256 KiB by the store, so the daemon cannot build an answer the
  transport would then refuse to write. A backlog larger than one frame is paged,
  not unreadable.
- **No I/O timeouts on Windows named pipes.** The platform has no equivalent of
  `SO_RCVTIMEO` for pipe handles, and `interprocess` reports `Unsupported`
  unconditionally — so `apply_timeouts` installs nothing there, on every call, and
  the daemon says so at startup rather than reporting a success it did not
  achieve. The bound is enforced one layer up instead: `idboard_ipc`'s
  `read_frame_deadline` does the blocking read on its own thread and gives up
  after 10s, so a peer that connects and then stalls costs one parked thread
  rather than a worker. Two consequences worth stating plainly: the parked thread
  is not cancelled (cancelling a blocked read on a Windows pipe handle is not
  exposed by `interprocess`), and a stalled peer can therefore still cost threads
  if enough of them arrive. The fixed worker pool and the 64-deep accept queue
  remain the outer bound.
- **The board mutex is not held across a peer-paced read.** The daemon has one
  `Mutex<Board>` for every identity, so a lock held while waiting on an
  unauthenticated peer would let one connect withhold the board from *other*
  identities. The guard is taken around `Board::handle` only, and the read, the
  response write, and the rejection log all happen outside it. `Board::handle`
  does bounded local work and never touches the stream, so this weakens no check.
- **`keryx subscribe` starts at the present, not at the beginning.** With no
  `--since`, the CLI asks for the current end using `SINCE_CURRENT_END`
  (`i64::MAX`), and the daemon answers with the real high-water mark. Any other
  empty read echoes the caller's own cursor so a poller does not re-scan.
- **Presence is a last-seen time, not liveness.** `keryx peers` reports when an
  identity last posted, read or handshook, and `0`/`never` for one that has not
  acted. That is a fact the store already holds; it does not mean the process is
  still running. v1 does not model what happens when an identity's process
  exits — no respawn, no cursor rehydration. That is a real and separate problem
  from identity, and identity came first.

