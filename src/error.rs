// SPDX-License-Identifier: MIT

//! Crate-wide error type.
//!
//! The library returns [`Result<T, Error>`] from every fallible operation.
//! The binary layer wraps library errors in [`anyhow::Result`] for convenient
//! propagation from [`crate::cli::run`], and extracts the exit code from the
//! underlying [`enum@Error`] before printing.
//!
//! Error variants are intentionally coarse-grained. Fine-grained context is
//! attached at call sites with `anyhow`'s `.context(...)` combinator.

use std::io;

use thiserror::Error;

/// A specialized [`Result`](std::result::Result) alias for `seehandshake`
/// library operations.
pub type Result<T> = std::result::Result<T, Error>;

/// The crate's top-level error type.
///
/// Each variant corresponds to a distinct subsystem so that consumers can
/// react appropriately (for example, a UI failure is recoverable at the
/// binary layer; a capture failure typically is not).
#[derive(Debug, Error)]
pub enum Error {
    /// A packet-capture backend reported an error.
    #[error("packet capture error: {0}")]
    Capture(String),

    /// The parser could not decode a byte buffer.
    #[error("TLS parse error: {0}")]
    Parse(String),

    /// A tracker-level invariant was violated (for example, a reassembly
    /// buffer exceeded its configured cap).
    #[error("connection tracking error: {0}")]
    Tracker(String),

    /// A UI/terminal operation failed.
    #[error("UI error: {0}")]
    Ui(String),

    /// The user supplied invalid configuration on the command line or in an
    /// environment variable.
    #[error("configuration error: {0}")]
    Config(String),

    /// An underlying I/O operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl Error {
    /// Whether this is a capture failure that looks like a missing-privilege
    /// problem (raw-socket / BPF access denied) rather than a genuine
    /// hardware or configuration fault.
    ///
    /// The check is a heuristic on the libpcap error string because pcap
    /// collapses several `errno` values into free-form text.
    #[must_use]
    pub fn is_permission_denied(&self) -> bool {
        matches!(
            self,
            Error::Capture(msg)
                if msg.contains("permission")
                    || msg.contains("Operation not permitted")
                    || msg.contains("Permission denied")
        )
    }

    /// Return the process exit code appropriate for this error variant.
    ///
    /// The mapping follows common Unix conventions (see `sysexits.h`):
    ///
    /// - `77` (`EX_NOPERM`) for a capture failure that indicates a permission
    ///   problem (heuristic: the message contains `permission` or `Operation not
    ///   permitted`).
    /// - `65` (`EX_DATAERR`) for parse failures encountered while replaying
    ///   fixed input.
    /// - `78` (`EX_CONFIG`) for configuration errors.
    /// - `1` for everything else.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            _ if self.is_permission_denied() => 77,
            Error::Parse(_) => 65,
            Error::Config(_) => 78,
            _ => 1,
        }
    }
}

/// A platform-specific remediation hint for capture permission failures.
///
/// The binary layer prints this after the raw error whenever
/// [`Error::is_permission_denied`] is true, so a user who forgot the
/// privilege step is told exactly how to fix it on their operating system
/// instead of just seeing "Permission denied".
#[must_use]
pub fn permission_denied_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "hint: live capture needs raw-socket privileges. Grant them once with:\n  \
         sudo setcap cap_net_raw,cap_net_admin=eip $(command -v seehandshake)\n\
         then re-run. Re-apply setcap after every upgrade — capabilities live on \
         the inode and are cleared when the binary is replaced."
    }
    #[cfg(target_os = "macos")]
    {
        "hint: live capture needs access to the BPF devices. Grant it with:\n  \
         sudo chown $USER /dev/bpf*\n\
         or run the binary with sudo."
    }
    #[cfg(target_os = "windows")]
    {
        "hint: live capture needs Npcap and an elevated shell. Install Npcap from \
         https://npcap.com/#download, then run seehandshake from a terminal \
         opened as Administrator."
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "hint: live capture needs elevated privileges to open a raw socket; \
         re-run with the appropriate permissions for your platform."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_capture_errors_are_detected() {
        for msg in [
            "socket: Operation not permitted",
            "You don't have permission to capture on that device",
            "Permission denied",
        ] {
            let err = Error::Capture(msg.to_string());
            assert!(err.is_permission_denied(), "should flag: {msg}");
            assert_eq!(err.exit_code(), 77);
        }
    }

    #[test]
    fn non_permission_capture_errors_are_not_flagged() {
        let err = Error::Capture("no such device exists".to_string());
        assert!(!err.is_permission_denied());
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn non_capture_errors_are_never_permission_denied() {
        assert!(!Error::Config("bad flag".to_string()).is_permission_denied());
        assert!(!Error::Parse("bad bytes".to_string()).is_permission_denied());
    }

    #[test]
    fn permission_hint_is_non_empty() {
        assert!(!permission_denied_hint().is_empty());
    }
}
