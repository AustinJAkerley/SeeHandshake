// SPDX-License-Identifier: MIT

//! TLS handshake message decoders (TLS 1.3 `ClientHello`, `ServerHello`).
//!
//! Uses the [`tls_parser`] crate for the low-level wire decode.
//! Extraction of individual extensions (SNI, ALPN, `supported_groups`,
//! `key_share`, `supported_versions`) is done here so that the parser owns
//! the mapping from raw wire values to the crate's canonical [`crate::model`]
//! types.
//!
//! Two levels of decoding are exposed:
//!
//! - [`decode_client_hello`] / [`decode_server_hello`] walk the raw wire
//!   bytes and return the full structure (random, session_id, every cipher
//!   suite, every extension with a decoded body). Used by the detail view.
//! - [`parse_client_hello`] / [`parse_server_hello`] return the compact
//!   [`ClientHelloInfo`] / [`ServerHelloInfo`] summaries used by the tracker
//!   to populate [`crate::model::HandshakeInfo`]. These are now derived from
//!   the full-decode functions above so there is a single source of truth.

use tls_parser::{
    parse_tls_message_handshake, TlsClientHelloContents, TlsExtension, TlsMessage,
    TlsMessageHandshake, TlsServerHelloContents,
};

use crate::error::{Error, Result};
use crate::model::record::{DecodedClientHello, DecodedExtension, DecodedServerHello};
use crate::model::tls::{AlpnProtocol, CipherSuite, NamedGroup, TlsVersion};
use crate::parser::extensions::decode_extension;

/// The `random` value a server sends in a `HelloRetryRequest` per
/// RFC 8446 §4.1.3.
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Fields extracted from a `ClientHello`.
#[derive(Clone, Debug, Default)]
pub struct ClientHelloInfo {
    /// Server Name Indication from the `server_name` extension.
    pub sni: Option<String>,
    /// ALPN protocols offered by the client.
    pub alpn_offered: Vec<AlpnProtocol>,
    /// Cipher suites offered by the client, in the order they appear on the
    /// wire.
    pub cipher_suites: Vec<CipherSuite>,
    /// Named groups offered by the client (from the `supported_groups`
    /// extension).
    pub groups_offered: Vec<NamedGroup>,
    /// The group for which the client actually sent a public key share
    /// (from the `key_share` extension).
    pub key_share_group: Option<NamedGroup>,
    /// The highest TLS version the client is willing to negotiate, taken
    /// from the `supported_versions` extension when present.
    pub max_version: Option<TlsVersion>,
}

/// Fields extracted from a `ServerHello`.
#[derive(Clone, Debug, Default)]
pub struct ServerHelloInfo {
    /// TLS version selected by the server. For TLS 1.3 this comes from the
    /// `supported_versions` extension; for older versions it comes from the
    /// `legacy_version` field.
    pub tls_version: Option<TlsVersion>,
    /// The cipher suite chosen by the server.
    pub cipher_suite_selected: Option<CipherSuite>,
    /// The group of the key share the server responded with.
    pub key_share_group: Option<NamedGroup>,
    /// The ALPN protocol chosen by the server, if visible.
    ///
    /// In TLS 1.3 the server's ALPN choice lives inside
    /// `EncryptedExtensions` and is therefore *not* observable to a passive
    /// observer. In TLS 1.2 it appears in `ServerHello` and is populated
    /// here.
    pub alpn_selected: Option<AlpnProtocol>,
}

/// Parse the bytes of a single TLS handshake message expected to be a
/// `ClientHello`.
///
/// # Errors
///
/// Returns [`Error::Parse`] if the buffer is not a well-formed
/// `ClientHello`.
pub fn parse_client_hello(bytes: &[u8]) -> Result<ClientHelloInfo> {
    let (_, msg) = parse_tls_message_handshake(bytes)
        .map_err(|e| Error::Parse(format!("client hello: {e:?}")))?;

    match msg {
        TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => {
            Ok(extract_client_hello(&ch))
        }
        _ => Err(Error::Parse(
            "expected ClientHello handshake message".into(),
        )),
    }
}

/// Parse the bytes of a single TLS handshake message expected to be a
/// `ServerHello`.
///
/// # Errors
///
/// Returns [`Error::Parse`] if the buffer is not a well-formed
/// `ServerHello`.
pub fn parse_server_hello(bytes: &[u8]) -> Result<ServerHelloInfo> {
    let (_, msg) = parse_tls_message_handshake(bytes)
        .map_err(|e| Error::Parse(format!("server hello: {e:?}")))?;

    match msg {
        TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) => {
            Ok(extract_server_hello(&sh))
        }
        _ => Err(Error::Parse(
            "expected ServerHello handshake message".into(),
        )),
    }
}

/// Extract [`ClientHelloInfo`] from an already-decoded
/// [`TlsClientHelloContents`].
///
/// Used by the tracker when it iterates over handshake messages inside a
/// TLS record payload. It has the parsed handshake in hand and does not
/// need [`parse_client_hello`] to reparse the bytes.
#[must_use]
pub fn extract_client_hello(ch: &TlsClientHelloContents<'_>) -> ClientHelloInfo {
    let mut info = ClientHelloInfo {
        cipher_suites: ch
            .ciphers
            .iter()
            .map(|c| CipherSuite::from_u16(c.0))
            .collect(),
        ..Default::default()
    };

    if let Some(ext_bytes) = ch.ext {
        walk_extensions(ext_bytes, |ext| apply_client_extension(&mut info, ext));
    }

    info
}

/// Extract [`ServerHelloInfo`] from an already-decoded
/// [`TlsServerHelloContents`].
///
/// Companion to [`extract_client_hello`] for the tracker's inner loop.
#[must_use]
pub fn extract_server_hello(sh: &TlsServerHelloContents<'_>) -> ServerHelloInfo {
    let mut info = ServerHelloInfo {
        cipher_suite_selected: Some(CipherSuite::from_u16(sh.cipher.0)),
        tls_version: Some(TlsVersion::from_u16(sh.version.0)),
        ..Default::default()
    };

    if let Some(ext_bytes) = sh.ext {
        walk_extensions(ext_bytes, |ext| apply_server_extension(&mut info, ext));
    }

    info
}

/// Fully decode a `ClientHello` handshake-message body.
///
/// `bytes` must start with the 4-byte handshake header
/// (`msg_type=1 || length(u24)`) followed by the `ClientHello` body.
///
/// # Errors
///
/// Returns [`Error::Parse`] if the buffer is truncated or the header does
/// not advertise a `ClientHello`.
pub fn decode_client_hello(bytes: &[u8]) -> Result<DecodedClientHello> {
    let body = strip_handshake_header(bytes, 1)?;
    let mut cursor = body;

    let legacy_version = read_u16(&mut cursor)?;
    let random = read_array32(&mut cursor)?;

    let session_id_len = usize::from(read_u8(&mut cursor)?);
    let session_id = read_bytes(&mut cursor, session_id_len)?.to_vec();

    let cipher_suites_len = usize::from(read_u16(&mut cursor)?);
    if cipher_suites_len % 2 != 0 {
        return Err(Error::Parse(
            "client hello: odd cipher suites length".into(),
        ));
    }
    let cipher_bytes = read_bytes(&mut cursor, cipher_suites_len)?;
    let cipher_suites: Vec<(u16, Option<CipherSuite>)> = cipher_bytes
        .chunks_exact(2)
        .map(|c| {
            let code = u16::from_be_bytes([c[0], c[1]]);
            let known = match CipherSuite::from_u16(code) {
                CipherSuite::Other(_) => None,
                other => Some(other),
            };
            (code, known)
        })
        .collect();

    let compression_len = usize::from(read_u8(&mut cursor)?);
    let compression_methods = read_bytes(&mut cursor, compression_len)?.to_vec();

    // `extensions` is optional (only present in TLS 1.2+); a bare TLS 1.0
    // ClientHello has no extensions field. If we've run out of bytes, treat
    // that as an empty extension list.
    let extensions = if cursor.is_empty() {
        Vec::new()
    } else {
        let ext_len = usize::from(read_u16(&mut cursor)?);
        let ext_bytes = read_bytes(&mut cursor, ext_len)?;
        walk_extension_bodies(ext_bytes)
    };

    Ok(DecodedClientHello {
        legacy_version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        extensions,
    })
}

/// Fully decode a `ServerHello` handshake-message body.
///
/// Distinguishes a plain `ServerHello` from a `HelloRetryRequest` by
/// comparing the random against [`HELLO_RETRY_REQUEST_RANDOM`]. Both share
/// the same wire format; the caller can inspect the returned structure to
/// tell them apart if needed.
///
/// # Errors
///
/// Returns [`Error::Parse`] if the buffer is truncated or the header does
/// not advertise a `ServerHello`.
pub fn decode_server_hello(bytes: &[u8]) -> Result<DecodedServerHello> {
    let body = strip_handshake_header(bytes, 2)?;
    let mut cursor = body;

    let legacy_version = read_u16(&mut cursor)?;
    let random = read_array32(&mut cursor)?;

    let session_id_len = usize::from(read_u8(&mut cursor)?);
    let session_id_echo = read_bytes(&mut cursor, session_id_len)?.to_vec();

    let cipher_code = read_u16(&mut cursor)?;
    let cipher_known = match CipherSuite::from_u16(cipher_code) {
        CipherSuite::Other(_) => None,
        other => Some(other),
    };

    let compression_method = read_u8(&mut cursor)?;

    let extensions = if cursor.is_empty() {
        Vec::new()
    } else {
        let ext_len = usize::from(read_u16(&mut cursor)?);
        let ext_bytes = read_bytes(&mut cursor, ext_len)?;
        walk_extension_bodies(ext_bytes)
    };

    Ok(DecodedServerHello {
        legacy_version,
        random,
        session_id_echo,
        cipher_suite: (cipher_code, cipher_known),
        compression_method,
        extensions,
    })
}

/// Whether a decoded `ServerHello`-shaped message is actually a
/// `HelloRetryRequest`.
#[must_use]
pub fn is_hello_retry_request(sh: &DecodedServerHello) -> bool {
    sh.random == HELLO_RETRY_REQUEST_RANDOM
}

// ---------------------------------------------------------------------------
// Small byte-slice cursor helpers
// ---------------------------------------------------------------------------

fn strip_handshake_header(bytes: &[u8], expected_type: u8) -> Result<&[u8]> {
    if bytes.len() < 4 {
        return Err(Error::Parse("handshake header truncated".into()));
    }
    if bytes[0] != expected_type {
        return Err(Error::Parse(format!(
            "unexpected handshake type: {:#04x} (want {:#04x})",
            bytes[0], expected_type
        )));
    }
    let length = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as usize;
    if bytes.len() < 4 + length {
        return Err(Error::Parse("handshake body truncated".into()));
    }
    Ok(&bytes[4..4 + length])
}

fn read_u8(cursor: &mut &[u8]) -> Result<u8> {
    let (first, rest) = cursor
        .split_first()
        .ok_or_else(|| Error::Parse("truncated u8".into()))?;
    *cursor = rest;
    Ok(*first)
}

fn read_u16(cursor: &mut &[u8]) -> Result<u16> {
    if cursor.len() < 2 {
        return Err(Error::Parse("truncated u16".into()));
    }
    let out = u16::from_be_bytes([cursor[0], cursor[1]]);
    *cursor = &cursor[2..];
    Ok(out)
}

fn read_array32(cursor: &mut &[u8]) -> Result<[u8; 32]> {
    if cursor.len() < 32 {
        return Err(Error::Parse("truncated [u8; 32]".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&cursor[..32]);
    *cursor = &cursor[32..];
    Ok(out)
}

fn read_bytes<'a>(cursor: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if cursor.len() < n {
        return Err(Error::Parse(format!("truncated {n}-byte slice")));
    }
    let (head, tail) = cursor.split_at(n);
    *cursor = tail;
    Ok(head)
}

fn walk_extension_bodies(ext_bytes: &[u8]) -> Vec<DecodedExtension> {
    let mut out = Vec::new();
    let mut cursor = ext_bytes;
    while cursor.len() >= 4 {
        let ext_type = u16::from_be_bytes([cursor[0], cursor[1]]);
        let body_len = usize::from(u16::from_be_bytes([cursor[2], cursor[3]]));
        if cursor.len() < 4 + body_len {
            break;
        }
        let body = &cursor[4..4 + body_len];
        out.push(decode_extension(ext_type, body));
        cursor = &cursor[4 + body_len..];
    }
    out
}

fn walk_extensions<F>(ext_bytes: &[u8], mut visit: F)
where
    F: FnMut(&TlsExtension<'_>),
{
    let mut remaining = ext_bytes;
    while !remaining.is_empty() {
        match tls_parser::parse_tls_extension(remaining) {
            Ok((rest, ext)) => {
                visit(&ext);
                remaining = rest;
            }
            Err(_) => break,
        }
    }
}

fn apply_client_extension(info: &mut ClientHelloInfo, ext: &TlsExtension<'_>) {
    match ext {
        TlsExtension::SNI(entries) => {
            if let Some((_, name)) = entries.first() {
                info.sni = Some(String::from_utf8_lossy(name).into_owned());
            }
        }
        TlsExtension::ALPN(protocols) => {
            info.alpn_offered = protocols
                .iter()
                .map(|p| AlpnProtocol::from_bytes(p))
                .collect();
        }
        TlsExtension::EllipticCurves(groups) => {
            info.groups_offered = groups.iter().map(|g| NamedGroup::from_u16(g.0)).collect();
        }
        TlsExtension::KeyShare(bytes) => {
            info.key_share_group = first_key_share_group(bytes);
        }
        TlsExtension::SupportedVersions(vs) => {
            info.max_version = vs
                .iter()
                .map(|v| TlsVersion::from_u16(v.0))
                .max_by_key(preferred_version_rank);
        }
        _ => {}
    }
}

fn apply_server_extension(info: &mut ServerHelloInfo, ext: &TlsExtension<'_>) {
    match ext {
        TlsExtension::KeyShare(bytes) => {
            info.key_share_group = first_key_share_group(bytes);
        }
        TlsExtension::SupportedVersions(vs) => {
            if let Some(v) = vs.first() {
                info.tls_version = Some(TlsVersion::from_u16(v.0));
            }
        }
        TlsExtension::ALPN(protocols) => {
            info.alpn_selected = protocols.first().map(|p| AlpnProtocol::from_bytes(p));
        }
        _ => {}
    }
}

fn first_key_share_group(bytes: &[u8]) -> Option<NamedGroup> {
    // A KeyShareEntry is: NamedGroup group (u16) || opaque key_exchange<1..2^16-1> (u16 length).
    // The client's key_share extension is: length (u16) || KeyShareEntry...
    // The server's key_share extension is: KeyShareEntry (single entry).
    // We try the "list" form first, fall back to the "single entry" form.
    if bytes.len() < 4 {
        return None;
    }
    let list_len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    if list_len + 2 == bytes.len() && bytes.len() >= 4 {
        // Client form.
        let group = u16::from_be_bytes([bytes[2], bytes[3]]);
        return Some(NamedGroup::from_u16(group));
    }
    // Server form: first two bytes are the group.
    let group = u16::from_be_bytes([bytes[0], bytes[1]]);
    Some(NamedGroup::from_u16(group))
}

fn preferred_version_rank(v: &TlsVersion) -> u8 {
    match *v {
        TlsVersion::Tls13 => 5,
        TlsVersion::Tls12 => 4,
        TlsVersion::Tls11 => 3,
        TlsVersion::Tls10 => 2,
        TlsVersion::Ssl30 => 1,
        TlsVersion::Other(_) => 0,
    }
}
