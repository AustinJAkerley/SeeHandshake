// SPDX-License-Identifier: MIT

//! Field-by-field TLS extension decoders.
//!
//! Given the raw extension body bytes and the extension type code, produce a
//! [`ExtensionBody`] variant. Malformed bodies fall back to
//! [`ExtensionBody::Opaque`] rather than erroring — the raw bytes remain on
//! the [`DecodedExtension::raw`] field, so the detail view can still render
//! them.

use crate::model::record::{
    DecodedExtension, ExtensionBody, KeyShareEntry, PskIdentity, ServerNameEntry,
};
use crate::model::tls::NamedGroup;

/// Build a [`DecodedExtension`] from its wire pieces.
///
/// `ext_type` is the IANA extension type code; `body` is the extension body
/// (already stripped of the 2+2-byte type/length header).
#[must_use]
pub fn decode_extension(ext_type: u16, body: &[u8]) -> DecodedExtension {
    DecodedExtension {
        ext_type,
        name: extension_name(ext_type),
        raw: body.to_vec(),
        body: decode_body(ext_type, body).unwrap_or(ExtensionBody::Opaque),
    }
}

/// Human-readable extension name, or `"unknown(0xNNNN)"` for unregistered
/// codes.
#[must_use]
pub fn extension_name(ext_type: u16) -> &'static str {
    match ext_type {
        0 => "server_name",
        1 => "max_fragment_length",
        4 => "trusted_ca_keys",
        5 => "status_request",
        6 => "user_mapping",
        7 => "client_authz",
        8 => "server_authz",
        9 => "cert_type",
        10 => "supported_groups",
        11 => "ec_point_formats",
        13 => "signature_algorithms",
        14 => "use_srtp",
        15 => "heartbeat",
        16 => "application_layer_protocol_negotiation",
        17 => "status_request_v2",
        18 => "signed_certificate_timestamp",
        19 => "client_certificate_type",
        20 => "server_certificate_type",
        21 => "padding",
        22 => "encrypt_then_mac",
        23 => "extended_master_secret",
        27 => "compress_certificate",
        28 => "record_size_limit",
        35 => "session_ticket",
        41 => "pre_shared_key",
        42 => "early_data",
        43 => "supported_versions",
        44 => "cookie",
        45 => "psk_key_exchange_modes",
        47 => "certificate_authorities",
        48 => "oid_filters",
        49 => "post_handshake_auth",
        50 => "signature_algorithms_cert",
        51 => "key_share",
        57 => "quic_transport_parameters",
        65281 => "renegotiation_info",
        _ => "unknown",
    }
}

fn decode_body(ext_type: u16, body: &[u8]) -> Option<ExtensionBody> {
    match ext_type {
        0 => decode_server_name(body).map(ExtensionBody::ServerName),
        10 => decode_supported_groups(body).map(ExtensionBody::SupportedGroups),
        13 | 50 => decode_signature_algorithms(body).map(ExtensionBody::SignatureAlgorithms),
        16 => decode_alpn(body).map(ExtensionBody::Alpn),
        41 => decode_pre_shared_key(body),
        42 => Some(ExtensionBody::EarlyData),
        43 => decode_supported_versions(body).map(ExtensionBody::SupportedVersions),
        44 => Some(ExtensionBody::Cookie(read_opaque_u16(body)?.to_vec())),
        45 => decode_psk_key_exchange_modes(body).map(ExtensionBody::PskKeyExchangeModes),
        51 => decode_key_share(body).map(ExtensionBody::KeyShare),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// individual decoders
// ---------------------------------------------------------------------------

fn decode_server_name(body: &[u8]) -> Option<Vec<ServerNameEntry>> {
    if body.len() < 2 {
        return None;
    }
    let list_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    if body.len() < 2 + list_len {
        return None;
    }
    let mut cursor = &body[2..2 + list_len];
    let mut entries = Vec::new();
    while cursor.len() >= 3 {
        let name_type = cursor[0];
        let name_len = usize::from(u16::from_be_bytes([cursor[1], cursor[2]]));
        if cursor.len() < 3 + name_len {
            return None;
        }
        entries.push(ServerNameEntry {
            name_type,
            name: cursor[3..3 + name_len].to_vec(),
        });
        cursor = &cursor[3 + name_len..];
    }
    Some(entries)
}

fn decode_supported_groups(body: &[u8]) -> Option<Vec<NamedGroup>> {
    let list = read_opaque_u16(body)?;
    if list.len() % 2 != 0 {
        return None;
    }
    Some(
        list.chunks_exact(2)
            .map(|c| NamedGroup::from_u16(u16::from_be_bytes([c[0], c[1]])))
            .collect(),
    )
}

fn decode_signature_algorithms(body: &[u8]) -> Option<Vec<u16>> {
    let list = read_opaque_u16(body)?;
    if list.len() % 2 != 0 {
        return None;
    }
    Some(
        list.chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect(),
    )
}

fn decode_alpn(body: &[u8]) -> Option<Vec<Vec<u8>>> {
    let list = read_opaque_u16(body)?;
    let mut cursor = list;
    let mut out = Vec::new();
    while !cursor.is_empty() {
        let (len, rest) = cursor.split_first()?;
        let len = usize::from(*len);
        if rest.len() < len {
            return None;
        }
        out.push(rest[..len].to_vec());
        cursor = &rest[len..];
    }
    Some(out)
}

fn decode_supported_versions(body: &[u8]) -> Option<Vec<u16>> {
    // In ClientHello: 1-byte length prefix; in ServerHello: bare 2 bytes.
    // We accept either.
    if body.len() == 2 {
        return Some(vec![u16::from_be_bytes([body[0], body[1]])]);
    }
    if body.is_empty() {
        return None;
    }
    let list_len = usize::from(body[0]);
    if body.len() != 1 + list_len || list_len % 2 != 0 {
        return None;
    }
    Some(
        body[1..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect(),
    )
}

fn decode_psk_key_exchange_modes(body: &[u8]) -> Option<Vec<u8>> {
    if body.is_empty() {
        return None;
    }
    let len = usize::from(body[0]);
    if body.len() != 1 + len {
        return None;
    }
    Some(body[1..].to_vec())
}

fn decode_key_share(body: &[u8]) -> Option<Vec<KeyShareEntry>> {
    // ClientHello form: list_len (u16) || KeyShareEntry...
    // ServerHello form: single KeyShareEntry.
    // We distinguish by checking whether the u16 prefix accounts for the
    // whole remaining buffer.
    if body.len() >= 4 {
        let list_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
        if body.len() == 2 + list_len {
            return parse_key_share_entries(&body[2..]);
        }
    }
    // ServerHello (or HRR) form: exactly one entry.
    parse_key_share_entries(body)
}

fn parse_key_share_entries(mut cursor: &[u8]) -> Option<Vec<KeyShareEntry>> {
    let mut out = Vec::new();
    while cursor.len() >= 4 {
        let group_code = u16::from_be_bytes([cursor[0], cursor[1]]);
        let key_len = usize::from(u16::from_be_bytes([cursor[2], cursor[3]]));
        if cursor.len() < 4 + key_len {
            return None;
        }
        out.push(KeyShareEntry {
            group: NamedGroup::from_u16(group_code),
            group_code,
            key_exchange: cursor[4..4 + key_len].to_vec(),
        });
        cursor = &cursor[4 + key_len..];
    }
    if cursor.is_empty() {
        Some(out)
    } else {
        None
    }
}

fn decode_pre_shared_key(body: &[u8]) -> Option<ExtensionBody> {
    // ClientHello form: identities<u16> ... || binders<u16> ...
    // ServerHello form: selected_identity (u16). We only decode the client
    // form here; the server form is captured as Opaque (which the caller
    // handles) via a length check.
    if body.len() < 2 {
        return None;
    }
    let identities_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    if body.len() < 2 + identities_len + 2 {
        return None;
    }
    let identities_bytes = &body[2..2 + identities_len];
    let mut cursor = identities_bytes;
    let mut identities = Vec::new();
    while cursor.len() >= 2 {
        let id_len = usize::from(u16::from_be_bytes([cursor[0], cursor[1]]));
        if cursor.len() < 2 + id_len + 4 {
            return None;
        }
        let identity = cursor[2..2 + id_len].to_vec();
        let age = u32::from_be_bytes([
            cursor[2 + id_len],
            cursor[3 + id_len],
            cursor[4 + id_len],
            cursor[5 + id_len],
        ]);
        identities.push(PskIdentity {
            identity,
            obfuscated_ticket_age: age,
        });
        cursor = &cursor[2 + id_len + 4..];
    }
    let binders_start = 2 + identities_len;
    let binders_len = usize::from(u16::from_be_bytes([
        body[binders_start],
        body[binders_start + 1],
    ]));
    Some(ExtensionBody::PreSharedKey {
        identities,
        binders_len,
    })
}

fn read_opaque_u16(body: &[u8]) -> Option<&[u8]> {
    if body.len() < 2 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    if body.len() != 2 + len {
        return None;
    }
    Some(&body[2..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_name_extracts_hostname() {
        // list_len=00 0b, name_type=00, name_len=00 08, "hostname"
        let body = [
            0x00, 0x0b, 0x00, 0x00, 0x08, b'h', b'o', b's', b't', b'n', b'a', b'm', b'e',
        ];
        let entries = decode_server_name(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name_type, 0);
        assert_eq!(&entries[0].name, b"hostname");
    }

    #[test]
    fn supported_groups_reads_x25519_and_p256() {
        // list_len=00 04, groups=00 1d, 00 17
        let body = [0x00, 0x04, 0x00, 0x1d, 0x00, 0x17];
        let groups = decode_supported_groups(&body).unwrap();
        assert_eq!(groups, vec![NamedGroup::X25519, NamedGroup::Secp256r1]);
    }

    #[test]
    fn signature_algorithms_reads_codes() {
        // list_len=00 04, entries=04 03, 08 04
        let body = [0x00, 0x04, 0x04, 0x03, 0x08, 0x04];
        let sigs = decode_signature_algorithms(&body).unwrap();
        assert_eq!(sigs, vec![0x0403, 0x0804]);
    }

    #[test]
    fn alpn_reads_h2_and_http11() {
        // list_len=00 0c, entries=02 "h2", 08 "http/1.1"
        let body = [
            0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ];
        let alpns = decode_alpn(&body).unwrap();
        assert_eq!(alpns, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn supported_versions_client_form() {
        // list_len=02, versions=03 04
        let body = [0x02, 0x03, 0x04];
        let versions = decode_supported_versions(&body).unwrap();
        assert_eq!(versions, vec![0x0304]);
    }

    #[test]
    fn supported_versions_server_form() {
        // Bare two bytes.
        let body = [0x03, 0x04];
        let versions = decode_supported_versions(&body).unwrap();
        assert_eq!(versions, vec![0x0304]);
    }

    #[test]
    fn key_share_client_form_with_x25519() {
        // list_len=00 24 (36 = 4 header + 32 key), group=00 1d,
        // key_len=00 20, 32 bytes of key.
        let mut body = vec![0x00, 0x24, 0x00, 0x1d, 0x00, 0x20];
        body.extend_from_slice(&[0xaa; 32]);
        let entries = decode_key_share(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].group, NamedGroup::X25519);
        assert_eq!(entries[0].key_exchange.len(), 32);
    }

    #[test]
    fn key_share_server_form_with_x25519() {
        // Single entry: group=00 1d, key_len=00 20, 32 bytes.
        let mut body = vec![0x00, 0x1d, 0x00, 0x20];
        body.extend_from_slice(&[0xbb; 32]);
        let entries = decode_key_share(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].group, NamedGroup::X25519);
    }

    #[test]
    fn psk_key_exchange_modes_reads_psk_dhe_ke() {
        let body = [0x01, 0x01];
        let modes = decode_psk_key_exchange_modes(&body).unwrap();
        assert_eq!(modes, vec![0x01]);
    }

    #[test]
    fn malformed_falls_back_to_opaque_via_decode_extension() {
        // A server_name with an inconsistent list length.
        let ext = decode_extension(0, &[0xff, 0xff, 0x00, 0x00]);
        assert_eq!(ext.name, "server_name");
        assert!(matches!(ext.body, ExtensionBody::Opaque));
    }

    #[test]
    fn unknown_extension_type_is_opaque() {
        let ext = decode_extension(0xabcd, &[1, 2, 3]);
        assert_eq!(ext.name, "unknown");
        assert_eq!(ext.raw, vec![1, 2, 3]);
        assert!(matches!(ext.body, ExtensionBody::Opaque));
    }
}
