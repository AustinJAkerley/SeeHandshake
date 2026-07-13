// SPDX-License-Identifier: MIT

//! Per-record timeline events for the detail view.
//!
//! [`RecordEvent`] is a snapshot of one TLS record as it was observed on the
//! wire: direction, timestamp, outer type, and, where possible, a decoded
//! body. Records that carry a plaintext handshake message (`ClientHello`,
//! `ServerHello`, `HelloRetryRequest`) get a fully-broken-out
//! [`DecodedHandshake`]. Records that are AEAD-encrypted (outer type
//! `ApplicationData` during the handshake flight) get an honest label + a
//! ciphertext preview, because a passive observer cannot see inside them.

use serde::{Deserialize, Serialize};

use crate::model::tls::{CipherSuite, NamedGroup};
use crate::parser::record::TlsRecordType;

/// Direction of a TLS record relative to the canonical connection key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecordDirection {
    /// Client-to-server.
    ClientToServer,
    /// Server-to-client.
    ServerToClient,
}

impl RecordDirection {
    /// Arrow glyph pointing from source to destination in the timeline.
    #[must_use]
    pub const fn arrow(self) -> &'static str {
        match self {
            RecordDirection::ClientToServer => "\u{2192}",
            RecordDirection::ServerToClient => "\u{2190}",
        }
    }

    /// Short "C\u{2192}S" / "S\u{2192}C" label used in the detail header.
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            RecordDirection::ClientToServer => "C\u{2192}S",
            RecordDirection::ServerToClient => "S\u{2192}C",
        }
    }
}

/// A single TLS record observed on the wire.
#[derive(Clone, Debug, Serialize)]
pub struct RecordEvent {
    /// Direction of the record.
    pub direction: RecordDirection,
    /// Millisecond timestamp when the record was fully assembled.
    pub timestamp_ms: u64,
    /// Position of this record in the connection's timeline (1-based, across
    /// both directions).
    pub sequence: u32,
    /// Wire-level record type (`Handshake`, `ApplicationData`, ...).
    pub outer_type: TlsRecordType,
    /// Length of the record payload as advertised by the record header.
    pub outer_length: u16,
    /// The full `TLSPlaintext` bytes, header + payload.
    ///
    /// Kept so the detail view can render an authoritative hex dump. Capped
    /// implicitly by the record-layer maximum of 16 KiB.
    pub raw: Vec<u8>,
    /// Decoded body.
    pub body: RecordBody,
}

/// Body of a [`RecordEvent`].
#[derive(Clone, Debug, Serialize)]
pub enum RecordBody {
    /// A plaintext handshake message.
    Handshake(DecodedHandshake),
    /// An AEAD-encrypted record. In TLS 1.3 the outer type is
    /// `application_data`; the inner content type is not observable without
    /// keys. In TLS 1.2 this is also emitted for `handshake` records that
    /// follow a `ChangeCipherSpec` in the same direction. The encrypted
    /// Finished (and subsequent server tickets) fall into this bucket.
    EncryptedHandshake {
        /// Best-effort label based on the record's position in the handshake
        /// flight (e.g. "likely EncryptedExtensions + Certificate"). Always
        /// hedged; see `docs/tls13-visibility.md`.
        inferred_label: &'static str,
        /// The first bytes of the AEAD payload (ciphertext), for the hex
        /// dump in the detail view. Capped at 64 bytes.
        ciphertext_preview: Vec<u8>,
    },
    /// A `ChangeCipherSpec` record (`type = 20`). One byte of payload
    /// (always `0x01`) that signals "everything I send after this is
    /// encrypted with the newly negotiated keys" in TLS 1.2, or a legacy
    /// middlebox-compatibility no-op in TLS 1.3.
    ChangeCipherSpec,
}

/// Fully-decoded plaintext handshake message.
#[derive(Clone, Debug, Serialize)]
pub enum DecodedHandshake {
    /// A `ClientHello` (msg_type = 1).
    ClientHello(Box<DecodedClientHello>),
    /// A `ServerHello` (msg_type = 2), not a `HelloRetryRequest`.
    ServerHello(Box<DecodedServerHello>),
    /// A `HelloRetryRequest`. Wire-format identical to a `ServerHello`, but
    /// its `random` field is a specific magic constant.
    HelloRetryRequest(Box<DecodedServerHello>),
    /// A handshake message the decoder did not recognize (or that failed to
    /// decode into a stronger variant).
    Unknown {
        /// Handshake message type byte (from `HandshakeType`).
        msg_type: u8,
        /// Raw message body (excluding the 4-byte handshake header).
        raw: Vec<u8>,
    },
}

impl DecodedHandshake {
    /// One-line label for the timeline row.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            DecodedHandshake::ClientHello(_) => "ClientHello",
            DecodedHandshake::ServerHello(_) => "ServerHello",
            DecodedHandshake::HelloRetryRequest(_) => "HelloRetryRequest",
            DecodedHandshake::Unknown { msg_type, .. } => handshake_type_name(*msg_type),
        }
    }
}

/// Look up the human name for an IANA `HandshakeType` code.
///
/// Covers TLS 1.2 plaintext-flight messages (Certificate, ServerKeyExchange,
/// ServerHelloDone, ClientKeyExchange, Finished, NewSessionTicket,
/// CertificateRequest, CertificateVerify, CertificateStatus) plus the TLS 1.3
/// message types that could appear in the clear on a broken or midstream
/// capture. Returns `"Unknown handshake"` for unregistered codepoints.
#[must_use]
pub const fn handshake_type_name(msg_type: u8) -> &'static str {
    match msg_type {
        1 => "ClientHello",
        2 => "ServerHello",
        4 => "NewSessionTicket",
        5 => "EndOfEarlyData",
        8 => "EncryptedExtensions",
        11 => "Certificate",
        12 => "ServerKeyExchange",
        13 => "CertificateRequest",
        14 => "ServerHelloDone",
        15 => "CertificateVerify",
        16 => "ClientKeyExchange",
        20 => "Finished",
        22 => "CertificateStatus",
        24 => "KeyUpdate",
        254 => "MessageHash",
        _ => "Unknown handshake",
    }
}

/// Fully decoded `ClientHello`.
#[derive(Clone, Debug, Serialize)]
pub struct DecodedClientHello {
    /// `legacy_version` from the wire. In TLS 1.3 clients hard-code `0x0303`.
    pub legacy_version: u16,
    /// The 32-byte `client_random`.
    #[serde(with = "serde_bytes_array32")]
    pub random: [u8; 32],
    /// Legacy `session_id` (up to 32 bytes). TLS 1.3 clients may echo a
    /// non-empty value to help the middlebox-compatibility mode.
    pub session_id: Vec<u8>,
    /// Cipher suites offered, in order. Each entry is `(wire_code, decoded)`.
    pub cipher_suites: Vec<(u16, Option<CipherSuite>)>,
    /// Legacy compression methods (TLS 1.3 requires `[0]`).
    pub compression_methods: Vec<u8>,
    /// Every extension, in wire order.
    pub extensions: Vec<DecodedExtension>,
}

/// Fully decoded `ServerHello` (or `HelloRetryRequest`).
#[derive(Clone, Debug, Serialize)]
pub struct DecodedServerHello {
    /// `legacy_version` from the wire. In TLS 1.3 servers set this to
    /// `0x0303` and put the real version in `supported_versions`.
    pub legacy_version: u16,
    /// The 32-byte `server_random`. For a `HelloRetryRequest` this is the
    /// specific magic value `CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
    /// C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C`.
    #[serde(with = "serde_bytes_array32")]
    pub random: [u8; 32],
    /// Echoed `session_id` from the client's `ClientHello`.
    pub session_id_echo: Vec<u8>,
    /// The cipher suite the server chose.
    pub cipher_suite: (u16, Option<CipherSuite>),
    /// Legacy compression method (TLS 1.3 requires `0`).
    pub compression_method: u8,
    /// Every extension, in wire order.
    pub extensions: Vec<DecodedExtension>,
}

/// A single TLS extension.
#[derive(Clone, Debug, Serialize)]
pub struct DecodedExtension {
    /// IANA-assigned extension type code.
    pub ext_type: u16,
    /// Human-readable name (`"server_name"`, ...) or `"unknown(0xNNNN)"`.
    pub name: &'static str,
    /// Raw extension body bytes (excluding the 2+2 header).
    pub raw: Vec<u8>,
    /// Decoded body, if the extension type is one of the decoders we
    /// implement. Otherwise [`ExtensionBody::Opaque`], and the raw bytes are
    /// still available on `raw`.
    pub body: ExtensionBody,
}

/// Decoded extension body.
#[derive(Clone, Debug, Serialize)]
pub enum ExtensionBody {
    /// `server_name` (0). List of server-name entries.
    ServerName(Vec<ServerNameEntry>),
    /// `supported_versions` (43). List of TLS versions, high-to-low
    /// preference.
    SupportedVersions(Vec<u16>),
    /// `signature_algorithms` (13) or `signature_algorithms_cert` (50). List
    /// of raw scheme codes.
    SignatureAlgorithms(Vec<u16>),
    /// `key_share` (51). One or more `(group, public_key)` entries.
    KeyShare(Vec<KeyShareEntry>),
    /// `supported_groups` (10). List of curves / DH groups.
    SupportedGroups(Vec<NamedGroup>),
    /// `application_layer_protocol_negotiation` (16). Ordered list of
    /// protocols as raw octet strings.
    Alpn(Vec<Vec<u8>>),
    /// `psk_key_exchange_modes` (45).
    PskKeyExchangeModes(Vec<u8>),
    /// `cookie` (44).
    Cookie(Vec<u8>),
    /// `pre_shared_key` (41). Only the identity list is decoded; binder
    /// content is opaque.
    PreSharedKey {
        /// Offered PSK identities.
        identities: Vec<PskIdentity>,
        /// Total length of the binders list.
        binders_len: usize,
    },
    /// `early_data` (42). Body is empty in `ClientHello`.
    EarlyData,
    /// Extension type we do not (yet) decode. The raw bytes are on
    /// [`DecodedExtension::raw`].
    Opaque,
}

/// One entry from a `server_name` extension.
#[derive(Clone, Debug, Serialize)]
pub struct ServerNameEntry {
    /// Name type. `0 = host_name` per RFC 6066.
    pub name_type: u8,
    /// Raw name bytes (typically UTF-8 hostname).
    pub name: Vec<u8>,
}

/// One entry from a `key_share` extension.
#[derive(Clone, Debug, Serialize)]
pub struct KeyShareEntry {
    /// Group / curve.
    pub group: NamedGroup,
    /// Raw group code (in case `NamedGroup::Other` is used).
    pub group_code: u16,
    /// Public key bytes, exactly as they appeared on the wire.
    pub key_exchange: Vec<u8>,
}

/// One entry from a `pre_shared_key` extension's identity list.
#[derive(Clone, Debug, Serialize)]
pub struct PskIdentity {
    /// Opaque identity bytes.
    pub identity: Vec<u8>,
    /// `obfuscated_ticket_age` from the wire.
    pub obfuscated_ticket_age: u32,
}

// Serde helper: `[u8; 32]` doesn't derive Serialize out of the box for stable
// serde. Use a small module that emits it as a byte array. Only used for the
// `random` fields.
mod serde_bytes_array32 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    // Deserialize is provided for completeness even though the type is only
    // serialized in practice.
    #[allow(dead_code)]
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        use serde::de::Error;
        let v: Vec<u8> = serde::Deserialize::deserialize(d)?;
        v.try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}
