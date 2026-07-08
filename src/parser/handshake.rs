// SPDX-License-Identifier: MIT

//! TLS handshake message decoders (TLS 1.3 `ClientHello`, `ServerHello`).
//!
//! Powered by the [`tls_parser`] crate for the low-level wire decode.
//! Extraction of individual extensions (SNI, ALPN, `supported_groups`,
//! `key_share`, `supported_versions`) is done here so that the parser owns
//! the mapping from raw wire values to the crate's canonical [`crate::model`]
//! types.

use tls_parser::{
    parse_tls_message_handshake, TlsClientHelloContents, TlsExtension, TlsMessage,
    TlsMessageHandshake, TlsServerHelloContents,
};

use crate::error::{Error, Result};
use crate::model::tls::{AlpnProtocol, CipherSuite, NamedGroup, TlsVersion};

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
/// TLS record payload — it has the parsed handshake in hand and does not
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
