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
            "exchange, and, via extensions, a Server Name Indication (SNI), an Application-Layer ",
            "Protocol Negotiation (ALPN) list, and one or more key-share public keys.",
        ),
        HandshakeStage::ServerHello => concat!(
            "The server responds, still in the clear. It picks exactly one cipher suite and one ",
            "named group from the client's offers, and returns its own key-share public value for ",
            "that group. From this point onward both endpoints can derive the handshake traffic ",
            "keys, and every following record is encrypted.",
        ),
        HandshakeStage::Certificate => concat!(
            "The server sends three encrypted records in a single flight: EncryptedExtensions ",
            "(containing extensions such as the chosen ALPN protocol), Certificate (the server's ",
            "certificate chain proving its identity), and CertificateVerify (a signature over the ",
            "handshake transcript proving possession of the private key). A passive observer without ",
            "the session keys cannot read any of these records.",
        ),
        HandshakeStage::ServerCertificate => concat!(
            "In TLS 1.2 the server sends its certificate chain in the clear. A passive observer can ",
            "read the full certificate, extract the subject and issuer DN, and verify the chain. ",
            "This is one of the key differences from TLS 1.3, which encrypts the certificate.",
        ),
        HandshakeStage::ServerKeyExchange => concat!(
            "For cipher suites using ephemeral Diffie-Hellman (DHE or ECDHE), the server sends its ",
            "public key share in the clear. This message is omitted for RSA key-exchange suites. ",
            "The server signs the parameters to prove possession of the private key.",
        ),
        HandshakeStage::ServerHelloDone => concat!(
            "ServerHelloDone is a one-byte marker the server sends to signal the end of its ",
            "initial plaintext flight (ServerHello + optional Certificate + optional ",
            "ServerKeyExchange). It tells the client the server is ready for the client's response.",
        ),
        HandshakeStage::ClientKeyExchange => concat!(
            "In TLS 1.2 the client sends its key material in the clear (for RSA: the pre-master ",
            "secret encrypted with the server's public key; for DHE/ECDHE: the client's public ",
            "share). Both sides can now independently derive the master secret and session keys.",
        ),
        HandshakeStage::ClientFinished => concat!(
            "The client sends its encrypted Finished message, an HMAC over the entire handshake ",
            "transcript, keyed with a secret derived from the handshake key schedule. This confirms ",
            "that the client received and authenticated the server's messages, and prevents downgrade ",
            "and tampering attacks on the negotiation.",
        ),
        HandshakeStage::ServerFinished => concat!(
            "The server sends its encrypted Finished message, an HMAC over the handshake transcript ",
            "analogous to the client's. Once both Finished messages have been exchanged and verified, ",
            "both sides derive the application-traffic keys and the handshake is complete.",
        ),
        HandshakeStage::ApplicationData => concat!(
            "The handshake is complete. Both sides have switched to application-traffic keys and are ",
            "exchanging protected application data (for example, HTTP/2 frames). Every record from ",
            "this point forward is encrypted with the negotiated cipher suite.",
        ),
        HandshakeStage::Errored => concat!(
            "The parser reported a fatal error for this connection. This is usually a truncated ",
            "capture or a non-TLS payload on port 443; occasionally it is a malformed handshake.",
        ),
    }
}
