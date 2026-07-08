// SPDX-License-Identifier: MIT

//! Shared, dependency-free data types.
//!
//! Nothing in this module reaches for the network, the terminal, or the
//! filesystem. Every type is trivially cloneable and safe to send between
//! threads.

pub mod connection;
pub mod handshake;
pub mod tls;

pub use connection::{ConnectionKey, ConnectionState};
pub use handshake::{HandshakeInfo, HandshakeStage};
pub use tls::{AlpnProtocol, CipherSuite, NamedGroup, TlsVersion};
