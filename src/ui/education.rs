// SPDX-License-Identifier: MIT

//! Educational explanations shown when the user presses `e`.
//!
//! Copy is intentionally concise; the goal is to give the reader an
//! accurate one-paragraph sense of the message's purpose without becoming
//! a full RFC quote.

use crate::model::HandshakeStage;

/// Return the educational text for a handshake stage.
#[must_use]
pub const fn explain(stage: HandshakeStage) -> &'static str {
    match stage {
        HandshakeStage::Idle => "",
        HandshakeStage::ClientHello => concat!(
            "The client opens the handshake in the clear. It advertises the TLS versions it supports, ",
            "the cipher suites it will accept, the named groups (elliptic curves) it can use for key ",
            "exchange, and — via extensions — a Server Name Indication (SNI), an Application-Layer ",
            "Protocol Negotiation (ALPN) list, and one or more key-share public keys.",
        ),
        HandshakeStage::ServerHello => concat!(
            "The server responds, still in the clear. It picks exactly one cipher suite and one ",
            "named group from the client's offers, and returns its own key-share public value for ",
            "that group. From this point onward both endpoints can derive the handshake traffic ",
            "keys, and every following record is encrypted.",
        ),
        HandshakeStage::EncryptedExtensions => concat!(
            "Now encrypted under the freshly derived handshake keys. Contains extensions that ",
            "were not needed to establish the keys — for example, the server's chosen ALPN ",
            "protocol. A passive observer without keys cannot read this record.",
        ),
        HandshakeStage::Certificate => concat!(
            "The server presents its certificate chain, encrypted under the handshake keys. ",
            "This is where the server proves its identity. Because TLS 1.3 encrypts this stage, ",
            "a passive observer cannot see the certificate subject or issuer without the keys.",
        ),
        HandshakeStage::CertificateVerify => concat!(
            "The server signs a transcript hash of the handshake so far with the private key ",
            "corresponding to the certificate. This proves possession of the private key — a ",
            "static certificate alone is not enough.",
        ),
        HandshakeStage::Finished => concat!(
            "Both endpoints exchange a Finished message: an HMAC over the entire handshake ",
            "transcript, keyed with a secret derived from the handshake key schedule. This ",
            "prevents downgrade and tampering attacks on the negotiation itself.",
        ),
        HandshakeStage::SecureConnection => concat!(
            "The handshake is complete. Both sides switch to application-traffic keys and can ",
            "begin exchanging protected application data (HTTP/2 frames, for example).",
        ),
        HandshakeStage::Errored => concat!(
            "The parser reported a fatal error for this connection. This is usually a truncated ",
            "capture or a non-TLS payload on port 443; occasionally it is a malformed handshake.",
        ),
    }
}
