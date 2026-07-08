// SPDX-License-Identifier: MIT

//! Events consumed by the UI thread.

use crate::model::ConnectionState;

/// A discrete UI update.
#[derive(Debug)]
pub enum UiEvent {
    /// The state of a connection has been updated.
    ///
    /// Boxed to keep the enum small.
    HandshakeUpdated(Box<ConnectionState>),
    /// The tracker evicted one or more stale connections.
    StaleEvicted(usize),
}
