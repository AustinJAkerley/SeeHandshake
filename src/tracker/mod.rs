// SPDX-License-Identifier: MIT

//! Per-connection state, TCP payload reassembly, and stale-connection
//! eviction.
//!
//! The [`ConnectionTracker`] is the single owner of all in-flight handshake
//! state. It receives raw TCP payload bytes tagged with a
//! [`crate::model::ConnectionKey`] and a direction, buffers them per
//! connection and per direction, feeds complete TLS records to the parser,
//! and updates the connection's [`crate::model::HandshakeInfo`] as messages
//! are decoded.

pub mod reassembly;

pub use reassembly::{unix_now_ms, ConnectionTracker, DEFAULT_STALE_TIMEOUT_MS};
