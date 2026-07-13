// SPDX-License-Identifier: MIT

//! TLS record and handshake decoders.
//!
//! The decoders here operate on borrowed byte slices and never require an
//! active network connection. Feed them recorded fixtures during tests, or
//! live reassembled TLS records at runtime.
//!
//! The public surface intentionally stays thin: [`parse_client_hello`] and
//! [`parse_server_hello`] cover the plaintext portions of a TLS 1.3
//! handshake, and [`parse_records`] chops a byte buffer into complete TLS
//! records for the tracker layer to feed to the handshake decoder.

pub mod extensions;
pub mod handshake;
pub mod record;

pub use handshake::{
    decode_client_hello, decode_server_hello, extract_client_hello, extract_server_hello,
    is_hello_retry_request, parse_client_hello, parse_server_hello, ClientHelloInfo,
    ServerHelloInfo, HELLO_RETRY_REQUEST_RANDOM,
};
pub use record::{parse_records, TlsRecord, TlsRecordType};
