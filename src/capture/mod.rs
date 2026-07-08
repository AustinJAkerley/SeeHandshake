// SPDX-License-Identifier: MIT

//! Packet capture backends.
//!
//! [`PacketSource`] is the trait that connects the capture layer to
//! everything downstream. The MVP provides [`live::LivePcapSource`], a
//! libpcap-backed implementation. Future work will add a
//! `PcapFileSource` for replaying `.pcap` files and a test-only mock.

pub mod frame;
pub mod interfaces;
pub mod live;

pub use frame::{extract_tcp, Frame, TcpSegment};
pub use interfaces::{list_interfaces, Interface};
pub use live::LivePcapSource;

use crate::error::Result;

/// A source of raw link-layer frames.
///
/// Implementations must be [`Send`] so that the capture loop can run on a
/// dedicated thread.
pub trait PacketSource: Send {
    /// Return the next frame, or `Ok(None)` if the source is exhausted
    /// (e.g., a PCAP file has reached EOF).
    ///
    /// # Errors
    ///
    /// Returns any transport-layer error surfaced by the underlying
    /// backend. Transient timeouts should be surfaced as `Ok(None)` rather
    /// than errors so that the caller can loop cleanly.
    fn next_frame(&mut self) -> Result<Option<Frame>>;
}
