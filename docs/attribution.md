# Process attribution

For every observed TCP flow, SeeHandshake tries to identify the local
process that owns the socket — the same information `ss -tp` or `lsof -i`
would show. When it succeeds, the connection panel shows the process
name, PID, UID, and (for CLI programs) the full command line.

This is *not* end-to-end user-action tracing. See "Honest limits" below.

## How the lookup works (Linux)

1. On the first packet of a new flow, the tracker asks its
   [`OriginResolver`](../src/origin/mod.rs) to resolve the flow.
2. On Linux the resolver
   ([`LinuxProcResolver`](../src/origin/linux.rs)) reads
   `/proc/net/tcp` and `/proc/net/tcp6`. Only rows in state `01`
   (ESTABLISHED) are kept. That gives a map keyed on
   `(local, remote)` sockets, with an inode and UID per row.
3. The resolver looks up the flow in both orderings —
   `(seg.src, seg.dst)` and `(seg.dst, seg.src)`. The kernel only lists
   sockets whose local side is on this host, so only one ordering
   matches.
4. If a row matches, the resolver walks `/proc/<pid>/fd/` for every
   readable process, looking for a `socket:[inode]` symlink that points
   at the row's inode. When it finds one, it reads
   `/proc/<pid>/comm`, `/proc/<pid>/cmdline`, and the UID from
   `/proc/<pid>/status`.
5. Results are cached on the connection. Subsequent packets on the same
   flow skip the lookup entirely. The `/proc` snapshot itself is cached
   for 500 ms so a burst of flows opened in the same second (loading a
   web page) does one pass over `/proc`, not one per flow.

The result is stashed on `HandshakeInfo::origin` and rendered in the
metadata panel and in the detail-view record header.

## What you'll see

- **`Local(ProcessOrigin)`** — the socket is owned by a process you can
  read. UI shows `firefox (pid 12345, uid 1000)`, and for CLI programs
  the full `cmdline` line underneath (e.g. `curl https://example.com`).
- **`OtherUser { uid }`** — the row exists in `/proc/net/tcp` but no
  readable `/proc/<pid>/fd` symlink was found. Common for daemons
  running under service accounts (`systemd-resolve`, `avahi`). UI shows
  `other user (uid 193)`. Running SeeHandshake as root would upgrade
  most of these to `Local(...)`, but the tool intentionally does not
  ask for that; being honest about the limit beats silently escalating.
- **`Unknown`** — the flow was observed but no matching socket exists.
  The connection may have already closed, or the flow was routed
  through this box without a local socket (uncommon).
- **`Unsupported`** — running on a platform without an attribution
  implementation (currently anything other than Linux). The UI omits
  the row entirely.

## Honest limits

- **CLI cmdlines *are* the user action.** `curl https://example.com` is
  exactly what the user typed. `wget`, `git fetch`, `apt update`, etc.
  all show the invocation.
- **Browser processes are not.** A row that says `firefox` tells you
  Firefox opened the socket; it cannot distinguish a click, a link
  preview, a favicon fetch, a background sync, a WebPush poll, an ad
  tracker, or a certificate revocation lookup. That distinction only
  exists inside the browser. If you need it, use the browser's own
  DevTools network panel.
- **Multiplexed protocols share one process.** Two "different" HTTP
  destinations reached via the same HTTP/3 or HTTP/2 client will share
  a process; the SNI is the only per-flow discriminator.
- **Race with process exit.** If `/proc/net/tcp` still lists a socket
  whose owning process has exited between the packet and the lookup,
  you'll see `Unknown` or a stale row. This is rare in practice but
  cannot be avoided from userland.

## Turning it off

There is no runtime flag. To disable attribution, run on a platform
without a resolver, or edit
[`src/origin/mod.rs::default_resolver`](../src/origin/mod.rs) to return
[`NullOriginResolver`](../src/origin/other.rs). The rest of the UI
degrades gracefully — the Origin row is simply omitted.
