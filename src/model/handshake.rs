// SPDX-License-Identifier: MIT

//! High-level handshake state.
//!
//! [`HandshakeStage`] enumerates the six steps of a TLS 1.3 handshake as
//! depicted in the canonical flow diagram:
//!
//! ```text
//! ① ClientHello    — client → server, plaintext
//! ② ServerHello    — server → client, plaintext
//! ③ Certificate    — server → client, encrypted (EncryptedExtensions +
//!                    Certificate + CertificateVerify)
//! ④ ClientFinished — client → server, encrypted
//! ⑤ ServerFinished — server → client, encrypted
//! ⑥ ApplicationData — bidirectional, encrypted
//! ```
//!
//! Because TLS 1.3 encrypts everything after `ServerHello`, stages beyond
//! [`HandshakeStage::ServerHello`] are inferred from encrypted record
//! boundaries rather than decoded. See `docs/tls13-visibility.md`.
//!
//! [`HandshakeInfo`] aggregates extracted fields, using [`Option`] pervasively
//! because a passive observer sees fields at different times (or not at all,
//! for encrypted sections of TLS 1.3).

use serde::{Deserialize, Serialize};

use crate::model::tls::{AlpnProtocol, CipherSuite, NamedGroup, TlsVersion};

/// The six observable stages of a TLS 1.3 handshake, mirroring the diagram.
///
/// Because TLS 1.3 encrypts everything after `ServerHello`, stages beyond
/// [`HandshakeStage::ServerHello`] are inferred from encrypted record
/// boundaries rather than decoded. See `docs/tls13-visibility.md`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum HandshakeStage {
    /// No handshake bytes have been observed yet.
    #[default]
    Idle,
    /// ① The client has sent `ClientHello` (plaintext, client → server).
    ClientHello,
    /// ② The server has sent `ServerHello` (plaintext, server → client).
    ServerHello,
    /// ③ Encrypted server flight: `EncryptedExtensions`, `Certificate`, and
    /// `CertificateVerify` records have been observed (server → client).
    /// Contents are opaque to a passive observer.
    Certificate,
    /// ④ The client has sent its encrypted `Finished` message (client → server).
    ClientFinished,
    /// ⑤ The server has sent its encrypted `Finished` message (server → client).
    ServerFinished,
    /// ⑥ Application data is flowing — the handshake is complete (bidirectional).
    ApplicationData,
    /// The connection saw a fatal condition (bad record, connection reset,
    /// or a parser error). Details are recorded in [`HandshakeInfo::error`].
    Errored,
}

impl HandshakeStage {
    /// Ordered display list used by the UI center panel (matches diagram step order).
    #[must_use]
    pub const fn ordered() -> &'static [HandshakeStage] {
        &[
            HandshakeStage::ClientHello,
            HandshakeStage::ServerHello,
            HandshakeStage::Certificate,
            HandshakeStage::ClientFinished,
            HandshakeStage::ServerFinished,
            HandshakeStage::ApplicationData,
        ]
    }

    /// Short, human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            HandshakeStage::Idle => "Idle",
            HandshakeStage::ClientHello => "ClientHello",
            HandshakeStage::ServerHello => "ServerHello",
            HandshakeStage::Certificate => "Certificate",
            HandshakeStage::ClientFinished => "Client Finished",
            HandshakeStage::ServerFinished => "Server Finished",
            HandshakeStage::ApplicationData => "Application Data",
            HandshakeStage::Errored => "Errored",
        }
    }
}

impl std::fmt::Display for HandshakeStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Aggregated view of a single TLS handshake as extracted by the parser.
///
/// Fields are populated incrementally as messages arrive. All slots are
/// [`Option`] to reflect the passive-observer reality: some fields (the
/// certificate Subject, for example) may never be visible for pure TLS 1.3
/// connections.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HandshakeInfo {
    /// The current stage of the handshake.
    pub stage: HandshakeStage,

    /// Server Name Indication extracted from `ClientHello`.
    pub sni: Option<String>,

    /// ALPN protocols offered by the client.
    pub alpn_offered: Vec<AlpnProtocol>,

    /// ALPN protocol selected by the server. Only observable in TLS 1.2 or
    /// via `SSLKEYLOGFILE` decryption for TLS 1.3.
    pub alpn_selected: Option<AlpnProtocol>,

    /// Cipher suites offered by the client.
    pub cipher_suites_offered: Vec<CipherSuite>,

    /// Cipher suite selected by the server.
    pub cipher_suite_selected: Option<CipherSuite>,

    /// Named groups (curves) offered by the client.
    pub groups_offered: Vec<NamedGroup>,

    /// The group for which the client actually sent a key share.
    pub key_share_group: Option<NamedGroup>,

    /// TLS version selected by the server (from the `supported_versions`
    /// extension in the server's `ServerHello`).
    pub tls_version: Option<TlsVersion>,

    /// Certificate subject common name / DN. Not available for TLS 1.3
    /// without decryption.
    pub certificate_subject: Option<String>,

    /// Certificate issuer common name / DN. Not available for TLS 1.3
    /// without decryption.
    pub certificate_issuer: Option<String>,

    /// The last error reported by the parser, if any.
    pub error: Option<String>,
}

impl HandshakeInfo {
    /// Create an empty handshake in the [`HandshakeStage::Idle`] state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
