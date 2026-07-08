// SPDX-License-Identifier: MIT

//! # `SeeHandshake`
//!
//! `seehandshake` is a passive TLS handshake observer for the terminal.
//!
//! This crate provides both a library (used by the `seehandshake` binary and
//! available for downstream consumers) and a binary. The library is organized
//! into loosely coupled modules that can be exercised independently of live
//! packet capture, which makes the parser and reassembly logic testable from
//! recorded byte fixtures.
//!
//! ## Modules
//!
//! - [`model`]: Shared, dependency-free data types (connection keys,
//!   handshake info, TLS enumerations).
//! - [`parser`]: TLS record and handshake decoders.
//! - [`tracker`]: Per-connection state, TCP payload reassembly, stale
//!   connection eviction.
//! - [`capture`]: The [`capture::PacketSource`] trait plus a libpcap-backed
//!   live implementation.
//! - [`ui`]: Ratatui three-panel terminal interface.
//! - [`cli`]: Command-line argument definitions and top-level dispatch.
//! - [`error`]: The crate's [`error::Error`] type.
//!
//! ## Example
//!
//! Parsing a recorded TLS `ClientHello` without any network activity:
//!
//! ```no_run
//! use seehandshake::parser::parse_client_hello;
//!
//! let bytes: &[u8] = &[/* raw TLS record bytes */];
//! if let Ok(hello) = parse_client_hello(bytes) {
//!     println!("SNI: {:?}", hello.sni);
//! }
//! ```

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(clippy::all)]

pub mod capture;
pub mod cli;
pub mod error;
pub mod model;
pub mod parser;
pub mod tracker;
pub mod ui;
pub mod util;

pub use error::{Error, Result};
