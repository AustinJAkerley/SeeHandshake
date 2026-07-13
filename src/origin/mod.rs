// SPDX-License-Identifier: MIT

//! Per-connection process attribution.
//!
//! Given the two endpoints of a TCP flow, an [`OriginResolver`] identifies
//! the local process that owns the socket. On Linux this reads
//! `/proc/net/tcp{,6}` + `/proc/*/fd/socket:[inode]`, the same technique
//! `ss -tp` uses. Other operating systems currently return
//! [`Origin::Unsupported`].
//!
//! Attribution is looked up once when a new flow is first observed and
//! cached on the connection, so a burst of handshakes to different SNIs
//! does not repeatedly walk `/proc`.
//!
//! ## Honest limits
//!
//! - Browser processes lump user actions (a click, a prefetch, an ad
//!   tracker fetch, a background sync) into one process. This layer cannot
//!   distinguish them.
//! - Sockets owned by other users (e.g. `systemd-resolved`) are not
//!   readable via `/proc/<pid>/fd`; those return
//!   [`Origin::OtherUser`] rather than a fabricated process record.
//! - If the socket has already been closed by the time we look it up, or
//!   the process exited between record and lookup, the answer is
//!   [`Origin::Unknown`]. Never a panic, never a lie.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
pub mod linux;
pub mod other;

/// Identity of a local process that owns a socket.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcessOrigin {
    /// Process id.
    pub pid: u32,
    /// Short command name from `/proc/<pid>/comm`.
    pub comm: String,
    /// Full command line (NUL bytes replaced with spaces), truncated.
    pub cmdline: String,
    /// UID that owns the socket.
    pub uid: u32,
}

/// Outcome of a per-connection attribution lookup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Origin {
    /// The socket is owned by a readable process on this machine.
    Local(ProcessOrigin),
    /// The socket exists but is owned by another user, so `/proc/<pid>/fd`
    /// is not readable. The UID from `/proc/net/tcp` is preserved.
    OtherUser {
        /// UID that owns the socket.
        uid: u32,
    },
    /// No matching socket was found. It may have already closed, or the
    /// flow is being observed passively without a corresponding local
    /// socket (routed traffic on a promiscuous interface).
    Unknown,
    /// This operating system has no origin resolver.
    Unsupported,
}

/// Look up the local process that owns a TCP flow.
///
/// Callers pass the two endpoints of the flow in either order; the
/// implementation is responsible for determining which side is local.
pub trait OriginResolver: Send {
    /// Resolve the origin of the flow between `endpoint_a` and `endpoint_b`.
    fn resolve(&mut self, endpoint_a: SocketAddr, endpoint_b: SocketAddr) -> Origin;
}

/// Construct the default resolver for the current platform.
///
/// On Linux (outside of `cfg(test)`) this is a [`linux::LinuxProcResolver`].
/// Everywhere else, and inside tests, it is [`other::NullOriginResolver`],
/// so the existing tracker tests do not depend on `/proc`.
#[must_use]
pub fn default_resolver() -> Box<dyn OriginResolver> {
    #[cfg(all(target_os = "linux", not(test)))]
    {
        Box::new(linux::LinuxProcResolver::new())
    }
    #[cfg(any(not(target_os = "linux"), test))]
    {
        Box::new(other::NullOriginResolver)
    }
}

/// A resolver that always returns the same scripted answer.
///
/// Useful in tests and for benchmarks that want to skip real `/proc` I/O.
pub struct FixedResolver(pub Origin);

impl OriginResolver for FixedResolver {
    fn resolve(&mut self, _a: SocketAddr, _b: SocketAddr) -> Origin {
        self.0.clone()
    }
}
