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
            Error::Capture(msg)
                if msg.contains("permission")
                    || msg.contains("Operation not permitted")
                    || msg.contains("Permission denied") =>
            {
                77
            }
            Error::Parse(_) => 65,
            Error::Config(_) => 78,
            _ => 1,
        }
    }
}
