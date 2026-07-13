// SPDX-License-Identifier: MIT

//! Sectioned, educational breakdown of a single TLS record.
//!
//! [`sections_for`] takes a [`RecordEvent`] and returns a list of
//! [`Section`]s the right-pane renderer walks over. The tool is framed as
//! a crypto education aid: sections are ordered crypto-first (cipher
//! suite, key_share, signature_algorithms, supported_versions, random...)
//! and legacy compatibility fields (session_id, compression, legacy
//! version) are grouped into a single "Legacy fields" section at the
//! bottom rather than getting one row each.
//!
//! Each section carries:
//! - `value_lines` — the decoded bytes / values;
//! - `edu_short` — one line always shown;
//! - `edu_details` — labeled sub-topics (Purpose / Keys involved / Where
//!   the private key lives / Why it matters / ...) rendered as a small
//!   Q&A block when the section is selected or globally expanded via `e`.
//!
//! Adding a new extension decoder is a localized change: a new arm in
//! `section_for_extension` with matching `EDU_*_DETAILS`.

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

use crate::model::record::{
    handshake_type_name, DecodedClientHello, DecodedExtension, DecodedHandshake,
    DecodedServerHello, ExtensionBody, KeyShareEntry, RecordBody, RecordDirection, RecordEvent,
    ServerNameEntry,
};
use crate::model::tls::{AlpnProtocol, NamedGroup, TlsVersion};
use crate::parser::record::TlsRecordType;
use crate::util::{hex_dump, hex_inline};

/// A labeled sub-topic of a section's educational text.
///
/// Rendered as `Label: body`. Keeping the copy split lets the right pane
/// present it as a small Q&A rather than a wall of prose.
#[derive(Clone, Copy, Debug)]
pub struct EduDetail {
    /// Short label rendered in bold before the body (e.g. `"Purpose"`).
    pub label: &'static str,
    /// One-sentence explanation shown after the label.
    pub body: &'static str,
}

/// One navigable section of a record.
#[derive(Clone, Debug)]
pub struct Section {
    /// Section title, e.g. `"Cipher suites offered"` or `"key_share"`.
    pub title: String,
    /// Whose message this is, framed from the local machine's perspective.
    pub direction_hint: &'static str,
    /// Decoded value lines (already styled).
    pub value_lines: Vec<Line<'static>>,
    /// One-line blurb always shown under the value.
    pub edu_short: &'static str,
    /// Structured sub-topics shown when the section is selected or the
    /// global `e` toggle is on.
    pub edu_details: &'static [EduDetail],
}

/// Break a record into navigable sections.
#[must_use]
pub fn sections_for(r: &RecordEvent) -> Vec<Section> {
    let dir = direction_hint(r.direction);
    let mut out = Vec::new();

    match &r.body {
        RecordBody::Handshake(DecodedHandshake::ClientHello(ch)) => {
            push_client_hello(&mut out, ch, dir);
        }
        RecordBody::Handshake(DecodedHandshake::ServerHello(sh))
        | RecordBody::Handshake(DecodedHandshake::HelloRetryRequest(sh)) => {
            push_server_hello(&mut out, sh, dir);
        }
        RecordBody::Handshake(DecodedHandshake::Unknown { msg_type, raw }) => {
            let name = handshake_type_name(*msg_type);
            out.push(Section {
                title: format!("{name} (msg_type 0x{msg_type:02x})"),
                direction_hint: dir,
                value_lines: {
                    let mut v = vec![kv_wire_line(
                        "msg_type",
                        format!("0x{msg_type:02x}  {name}"),
                    )];
                    v.extend(hex_lines(raw));
                    v
                },
                edu_short: edu_short_for_msg_type(*msg_type),
                edu_details: edu_details_for_msg_type(*msg_type),
            });
        }
        RecordBody::EncryptedHandshake {
            inferred_label,
            ciphertext_preview,
        } => {
            out.push(Section {
                title: "Encrypted flight (inferred)".into(),
                direction_hint: dir,
                value_lines: vec![kv_line("guess", (*inferred_label).to_string())],
                edu_short: EDU_ENCRYPTED_STAGE_SHORT,
                edu_details: EDU_ENCRYPTED_STAGE_DETAILS,
            });
            out.push(Section {
                title: "Ciphertext preview".into(),
                direction_hint: dir,
                value_lines: hex_lines(ciphertext_preview),
                edu_short: EDU_ENCRYPTED_CIPHERTEXT_SHORT,
                edu_details: EDU_ENCRYPTED_CIPHERTEXT_DETAILS,
            });
        }
        RecordBody::ChangeCipherSpec => {
            out.push(Section {
                title: "ChangeCipherSpec".into(),
                direction_hint: dir,
                value_lines: vec![wire_line(
                    "1 byte payload: 0x01 (activate negotiated cipher)".into(),
                )],
                edu_short: EDU_CCS_SHORT,
                edu_details: EDU_CCS_DETAILS,
            });
        }
    }

    // Framing / record header always goes last as reference material.
    out.push(framing_section(r, dir));
    out
}

fn direction_hint(d: RecordDirection) -> &'static str {
    match d {
        RecordDirection::ClientToServer => "You sent this",
        RecordDirection::ServerToClient => "The server sent you this",
    }
}

fn framing_section(r: &RecordEvent, dir: &'static str) -> Section {
    let header_len = r.raw.len().min(5);
    let value_lines = vec![
        kv_line("outer type", outer_name(r.outer_type).to_string()),
        kv_line("length", format!("{} bytes", r.outer_length)),
        kv_line("sequence", format!("#{}", r.sequence)),
        kv_wire_line("record header", hex_inline(&r.raw[..header_len])),
    ];
    Section {
        title: "Record framing".into(),
        direction_hint: dir,
        value_lines,
        edu_short: EDU_FRAMING_SHORT,
        edu_details: EDU_FRAMING_DETAILS,
    }
}

// ---------------------------------------------------------------------------
// ClientHello — crypto-first ordering.
// ---------------------------------------------------------------------------

fn push_client_hello(out: &mut Vec<Section>, ch: &DecodedClientHello, dir: &'static str) {
    // 1. Cipher suites (AEAD + hash) — the algorithm menu.
    out.push(cipher_suites_offered_section(ch, dir));

    // 2. Crypto-relevant extensions in a fixed pedagogical order.
    push_key_share_if_present(out, ch.extensions.iter(), dir, /* is_client */ true);
    push_extension_if_present(out, ch.extensions.iter(), dir, 43); // supported_versions
    push_extension_if_present(out, ch.extensions.iter(), dir, 13); // signature_algorithms
    push_extension_if_present(out, ch.extensions.iter(), dir, 10); // supported_groups
    push_extension_if_present(out, ch.extensions.iter(), dir, 45); // psk_key_exchange_modes
    push_extension_if_present(out, ch.extensions.iter(), dir, 41); // pre_shared_key
    push_extension_if_present(out, ch.extensions.iter(), dir, 42); // early_data

    // 3. Entropy.
    out.push(Section {
        title: "Client random (32 bytes)".into(),
        direction_hint: dir,
        value_lines: vec![wire_line(hex_inline(&ch.random))],
        edu_short: EDU_CLIENT_RANDOM_SHORT,
        edu_details: EDU_CLIENT_RANDOM_DETAILS,
    });

    // 4. Metadata that ends up on the wire in the clear.
    push_extension_if_present(out, ch.extensions.iter(), dir, 0); // server_name
    push_extension_if_present(out, ch.extensions.iter(), dir, 16); // alpn

    // 5. Anything else the parser recognized, in wire order.
    for ext in &ch.extensions {
        if !PROMOTED_EXTENSIONS.contains(&ext.ext_type) {
            out.push(section_for_extension(ext, dir));
        }
    }

    // 6. Legacy compatibility knobs folded into one section.
    out.push(client_legacy_section(ch, dir));
}

// ---------------------------------------------------------------------------
// ServerHello — same crypto-first ordering.
// ---------------------------------------------------------------------------

fn push_server_hello(out: &mut Vec<Section>, sh: &DecodedServerHello, dir: &'static str) {
    let (code, known) = &sh.cipher_suite;
    let name = known
        .as_ref()
        .map(std::string::ToString::to_string)
        .unwrap_or_else(|| "unknown".into());
    out.push(Section {
        title: "Cipher suite (chosen)".into(),
        direction_hint: dir,
        value_lines: vec![wire_line(format!("0x{code:04x}  {name}"))],
        edu_short: EDU_CIPHER_CHOSEN_SHORT,
        edu_details: EDU_CIPHER_CHOSEN_DETAILS,
    });

    push_key_share_if_present(out, sh.extensions.iter(), dir, /* is_client */ false);
    push_extension_if_present(out, sh.extensions.iter(), dir, 43); // supported_versions

    out.push(Section {
        title: "Server random (32 bytes)".into(),
        direction_hint: dir,
        value_lines: vec![wire_line(hex_inline(&sh.random))],
        edu_short: EDU_SERVER_RANDOM_SHORT,
        edu_details: EDU_SERVER_RANDOM_DETAILS,
    });

    push_extension_if_present(out, sh.extensions.iter(), dir, 41); // pre_shared_key echo

    for ext in &sh.extensions {
        if !PROMOTED_EXTENSIONS.contains(&ext.ext_type) {
            out.push(section_for_extension(ext, dir));
        }
    }

    out.push(server_legacy_section(sh, dir));
}

/// Extension types that get pinned to specific positions in the section
/// order by [`push_client_hello`] / [`push_server_hello`]. Any extension
/// not in this list is emitted in wire order after the promoted ones.
const PROMOTED_EXTENSIONS: &[u16] = &[
    0,  // server_name
    10, // supported_groups
    13, // signature_algorithms
    16, // alpn
    41, // pre_shared_key
    42, // early_data
    43, // supported_versions
    45, // psk_key_exchange_modes
    51, // key_share
];

fn push_extension_if_present<'a, I>(
    out: &mut Vec<Section>,
    exts: I,
    dir: &'static str,
    ext_type: u16,
) where
    I: IntoIterator<Item = &'a DecodedExtension>,
{
    if let Some(ext) = exts.into_iter().find(|e| e.ext_type == ext_type) {
        out.push(section_for_extension(ext, dir));
    }
}

/// Emit a key_share section with a title that distinguishes the client's
/// list of offers from the single key the server picked. Falls back to the
/// generic renderer if the extension body isn't decoded as a `KeyShare` (a
/// parser quirk — the wire type still lands here).
fn push_key_share_if_present<'a, I>(
    out: &mut Vec<Section>,
    exts: I,
    dir: &'static str,
    is_client: bool,
) where
    I: IntoIterator<Item = &'a DecodedExtension>,
{
    let Some(ext) = exts.into_iter().find(|e| e.ext_type == 51) else {
        return;
    };
    let ExtensionBody::KeyShare(entries) = &ext.body else {
        out.push(section_for_extension(ext, dir));
        return;
    };
    let title = if is_client {
        format!(
            "key_share \u{2014} offered by client ({} offer{})",
            entries.len(),
            if entries.len() == 1 { "" } else { "s" }
        )
    } else {
        "key_share \u{2014} chosen by server".to_string()
    };
    out.push(Section {
        title,
        direction_hint: dir,
        value_lines: key_share_lines(entries, is_client),
        edu_short: EDU_KEY_SHARE_SHORT,
        edu_details: EDU_KEY_SHARE_DETAILS,
    });
}

fn cipher_suites_offered_section(ch: &DecodedClientHello, dir: &'static str) -> Section {
    let mut value_lines = Vec::new();
    for (code, known) in &ch.cipher_suites {
        let name = known
            .as_ref()
            .map(std::string::ToString::to_string)
            .unwrap_or_else(|| "unknown".into());
        value_lines.push(wire_line(format!("0x{code:04x}  {name}")));
    }
    Section {
        title: format!("Cipher suites offered ({})", ch.cipher_suites.len()),
        direction_hint: dir,
        value_lines,
        edu_short: EDU_CIPHER_OFFERED_SHORT,
        edu_details: EDU_CIPHER_OFFERED_DETAILS,
    }
}

fn client_legacy_section(ch: &DecodedClientHello, dir: &'static str) -> Section {
    let value_lines = vec![
        kv_wire_line("legacy_version", format!("0x{:04x}", ch.legacy_version)),
        kv_wire_line("session_id", session_id_display(&ch.session_id)),
        kv_wire_line("compression", hex_inline(&ch.compression_methods)),
    ];
    Section {
        title: "Legacy fields (TLS 1.2 compatibility)".into(),
        direction_hint: dir,
        value_lines,
        edu_short: EDU_LEGACY_SHORT,
        edu_details: EDU_LEGACY_DETAILS,
    }
}

fn server_legacy_section(sh: &DecodedServerHello, dir: &'static str) -> Section {
    let value_lines = vec![
        kv_wire_line("legacy_version", format!("0x{:04x}", sh.legacy_version)),
        kv_wire_line("session_id_echo", session_id_display(&sh.session_id_echo)),
        kv_wire_line("compression", format!("0x{:02x}", sh.compression_method)),
    ];
    Section {
        title: "Legacy fields (TLS 1.2 compatibility)".into(),
        direction_hint: dir,
        value_lines,
        edu_short: EDU_LEGACY_SHORT,
        edu_details: EDU_LEGACY_DETAILS,
    }
}

fn section_for_extension(ext: &DecodedExtension, dir: &'static str) -> Section {
    let title = format!("{} (0x{:04x})", ext.name, ext.ext_type);
    let (value_lines, edu_short, edu_details) = match &ext.body {
        ExtensionBody::ServerName(entries) => (sni_lines(entries), EDU_SNI_SHORT, EDU_SNI_DETAILS),
        ExtensionBody::SupportedVersions(versions) => {
            let s = versions
                .iter()
                .map(|v| format!("{}", TlsVersion::from_u16(*v)))
                .collect::<Vec<_>>()
                .join(", ");
            (
                vec![wire_line(format!("versions: {s}"))],
                EDU_SUPPORTED_VERSIONS_SHORT,
                EDU_SUPPORTED_VERSIONS_DETAILS,
            )
        }
        ExtensionBody::SignatureAlgorithms(codes) => {
            let s = codes
                .iter()
                .map(|c| format!("0x{c:04x}"))
                .collect::<Vec<_>>()
                .join(", ");
            (
                vec![wire_line(format!("schemes: {s}"))],
                EDU_SIG_ALGS_SHORT,
                EDU_SIG_ALGS_DETAILS,
            )
        }
        ExtensionBody::KeyShare(entries) => (
            key_share_lines(entries, /* is_client */ true),
            EDU_KEY_SHARE_SHORT,
            EDU_KEY_SHARE_DETAILS,
        ),
        ExtensionBody::SupportedGroups(groups) => {
            let s = groups
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            (
                vec![wire_line(format!("groups: {s}"))],
                EDU_SUPPORTED_GROUPS_SHORT,
                EDU_SUPPORTED_GROUPS_DETAILS,
            )
        }
        ExtensionBody::Alpn(protos) => {
            let s = protos
                .iter()
                .map(|p| AlpnProtocol::from_bytes(p).to_string())
                .collect::<Vec<_>>()
                .join(", ");
            (
                vec![wire_line(format!("protocols: {s}"))],
                EDU_ALPN_SHORT,
                EDU_ALPN_DETAILS,
            )
        }
        ExtensionBody::PskKeyExchangeModes(modes) => {
            let s = modes
                .iter()
                .map(|m| match *m {
                    0 => "psk_ke".to_string(),
                    1 => "psk_dhe_ke".to_string(),
                    other => format!("mode(0x{other:02x})"),
                })
                .collect::<Vec<_>>()
                .join(", ");
            (
                vec![wire_line(format!("modes: {s}"))],
                EDU_PSK_MODES_SHORT,
                EDU_PSK_MODES_DETAILS,
            )
        }
        ExtensionBody::Cookie(bytes) => (
            vec![wire_line(format!(
                "cookie ({} B): {}",
                bytes.len(),
                hex_inline(bytes)
            ))],
            EDU_COOKIE_SHORT,
            EDU_COOKIE_DETAILS,
        ),
        ExtensionBody::PreSharedKey {
            identities,
            binders_len,
        } => {
            let mut lines = vec![wire_line(format!(
                "identities: {}, binders_len: {} B",
                identities.len(),
                binders_len
            ))];
            for id in identities {
                lines.push(wire_line(format!(
                    "  identity ({} B) age=0x{:08x}: {}",
                    id.identity.len(),
                    id.obfuscated_ticket_age,
                    hex_inline(&id.identity)
                )));
            }
            (lines, EDU_PSK_SHORT, EDU_PSK_DETAILS)
        }
        ExtensionBody::EarlyData => (
            vec![raw_line("(empty body)".into())],
            EDU_EARLY_DATA_SHORT,
            EDU_EARLY_DATA_DETAILS,
        ),
        ExtensionBody::Opaque => {
            let mut lines = Vec::new();
            if ext.raw.is_empty() {
                lines.push(raw_line("(empty body)".into()));
            } else {
                lines.push(wire_line(format!("raw: {}", hex_inline(&ext.raw))));
            }
            (lines, EDU_OPAQUE_SHORT, EDU_OPAQUE_DETAILS)
        }
    };
    Section {
        title,
        direction_hint: dir,
        value_lines,
        edu_short,
        edu_details,
    }
}

fn sni_lines(entries: &[ServerNameEntry]) -> Vec<Line<'static>> {
    entries
        .iter()
        .map(|e| {
            let name = String::from_utf8_lossy(&e.name);
            wire_line(format!("name_type=0x{:02x}  name={name}", e.name_type))
        })
        .collect()
}

fn key_share_lines(entries: &[KeyShareEntry], is_client: bool) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            out.push(raw_line(String::new()));
        }
        let header = if is_client {
            format!(
                "\u{25CF} Offer #{}: {} (0x{:04x})  \u{2014}  key_len {} B",
                i + 1,
                e.group,
                e.group_code,
                e.key_exchange.len()
            )
        } else {
            format!(
                "\u{25CF} Server pick: {} (0x{:04x})  \u{2014}  key_len {} B",
                e.group,
                e.group_code,
                e.key_exchange.len()
            )
        };
        out.push(header_line(header));
        for KeyShareLine { text, is_bytes } in key_share_structure(e) {
            if is_bytes {
                out.push(wire_line(text));
            } else {
                out.push(raw_line(text));
            }
        }
    }
    out
}

/// Structured line emitted by [`key_share_structure`]. Wire bytes render in
/// green; format/curve annotations render in the default color so they read
/// as commentary about the bytes, not part of them.
struct KeyShareLine {
    text: String,
    is_bytes: bool,
}

impl KeyShareLine {
    fn text(s: impl Into<String>) -> Self {
        Self {
            text: s.into(),
            is_bytes: false,
        }
    }
    fn bytes(s: impl Into<String>) -> Self {
        Self {
            text: s.into(),
            is_bytes: true,
        }
    }
}

/// Interpret the `key_exchange` bytes of a [`KeyShareEntry`] as the
/// mathematical object the group actually defines.
///
/// Every TLS `NamedGroup` fixes both a public-key type and a wire encoding,
/// so once we know the group we can label the bytes rather than dumping
/// opaque hex. Falls back to a single `raw` line for groups we don't have
/// a decoder for.
fn key_share_structure(e: &KeyShareEntry) -> Vec<KeyShareLine> {
    let bytes = &e.key_exchange;
    match e.group {
        NamedGroup::X25519 => x25519_structure(bytes),
        NamedGroup::X448 => x448_structure(bytes),
        NamedGroup::Secp256r1 => sec1_point_structure(bytes, 32, "secp256r1 (NIST P-256)"),
        NamedGroup::Secp384r1 => sec1_point_structure(bytes, 48, "secp384r1 (NIST P-384)"),
        NamedGroup::Secp521r1 => sec1_point_structure(bytes, 66, "secp521r1 (NIST P-521)"),
        NamedGroup::Ffdhe2048 => ffdhe_structure(bytes, 256, "ffdhe2048"),
        NamedGroup::Ffdhe3072 => ffdhe_structure(bytes, 384, "ffdhe3072"),
        NamedGroup::Ffdhe4096 => ffdhe_structure(bytes, 512, "ffdhe4096"),
        NamedGroup::X25519MlKem768 => hybrid_pq_structure(bytes, 32, 1184, "X25519", "ML-KEM-768"),
        NamedGroup::SecP256r1MlKem768 => {
            hybrid_pq_structure(bytes, 65, 1184, "secp256r1", "ML-KEM-768")
        }
        NamedGroup::X25519Kyber768Draft00 => {
            hybrid_pq_structure(bytes, 32, 1184, "X25519", "Kyber768-draft00")
        }
        NamedGroup::Other(_) => vec![KeyShareLine::bytes(format!(
            "public key ({} B): {}",
            bytes.len(),
            hex_inline(bytes)
        ))],
    }
}

fn x25519_structure(bytes: &[u8]) -> Vec<KeyShareLine> {
    let mut out = vec![
        KeyShareLine::text("format: Curve25519 Montgomery u-coordinate, 32 bytes little-endian"),
        KeyShareLine::text("curve : y^2 = x^3 + 486662*x^2 + x  over GF(2^255 - 19)"),
    ];
    if bytes.len() == 32 {
        out.push(KeyShareLine::bytes(format!(
            "u ({} B): {}",
            bytes.len(),
            hex_inline(bytes)
        )));
    } else {
        out.push(KeyShareLine::text(format!(
            "expected 32 B, got {} B \u{2014} non-standard encoding",
            bytes.len()
        )));
        out.push(KeyShareLine::bytes(format!("raw: {}", hex_inline(bytes))));
    }
    out
}

fn x448_structure(bytes: &[u8]) -> Vec<KeyShareLine> {
    let mut out = vec![
        KeyShareLine::text("format: Curve448 Montgomery u-coordinate, 56 bytes little-endian"),
        KeyShareLine::text("curve : y^2 = x^3 + 156326*x^2 + x  over GF(2^448 - 2^224 - 1)"),
    ];
    if bytes.len() == 56 {
        out.push(KeyShareLine::bytes(format!(
            "u ({} B): {}",
            bytes.len(),
            hex_inline(bytes)
        )));
    } else {
        out.push(KeyShareLine::text(format!(
            "expected 56 B, got {} B \u{2014} non-standard encoding",
            bytes.len()
        )));
        out.push(KeyShareLine::bytes(format!("raw: {}", hex_inline(bytes))));
    }
    out
}

/// SEC1 point encoding: `0x04 || X || Y` uncompressed, or `0x02/0x03 || X`
/// compressed. Each coordinate is `coord_len` bytes big-endian.
fn sec1_point_structure(bytes: &[u8], coord_len: usize, curve_desc: &str) -> Vec<KeyShareLine> {
    let uncompressed_len = 1 + 2 * coord_len;
    let compressed_len = 1 + coord_len;
    let mut out = vec![KeyShareLine::text(format!(
        "format: SEC1 point on {curve_desc}, big-endian coordinates"
    ))];
    match bytes.first().copied() {
        Some(0x04) if bytes.len() == uncompressed_len => {
            out.push(KeyShareLine::text(format!(
                "encoding: uncompressed (0x04 || X || Y), 1+2*{coord_len} = {uncompressed_len} bytes"
            )));
            out.push(KeyShareLine::bytes("prefix: 0x04".to_string()));
            let x = &bytes[1..1 + coord_len];
            let y = &bytes[1 + coord_len..];
            out.push(KeyShareLine::bytes(format!(
                "X ({} B): {}",
                x.len(),
                hex_inline(x)
            )));
            out.push(KeyShareLine::bytes(format!(
                "Y ({} B): {}",
                y.len(),
                hex_inline(y)
            )));
        }
        Some(p @ (0x02 | 0x03)) if bytes.len() == compressed_len => {
            let sign = if p == 0x02 { "even" } else { "odd" };
            out.push(KeyShareLine::text(format!(
                "encoding: compressed (0x{p:02x} || X), Y is the {sign} root of the curve equation"
            )));
            let x = &bytes[1..];
            out.push(KeyShareLine::bytes(format!(
                "X ({} B): {}",
                x.len(),
                hex_inline(x)
            )));
        }
        _ => {
            out.push(KeyShareLine::text(format!(
                "unrecognized SEC1 prefix; expected 0x04/0x02/0x03 \u{2014} length {} B",
                bytes.len()
            )));
            out.push(KeyShareLine::bytes(format!("raw: {}", hex_inline(bytes))));
        }
    }
    out
}

/// Finite-field DH: a `p_bytes`-long big-endian integer, the value g^x mod p.
fn ffdhe_structure(bytes: &[u8], p_bytes: usize, group_name: &str) -> Vec<KeyShareLine> {
    let mut out = vec![
        KeyShareLine::text(format!(
            "format: {group_name} public value y = g^x mod p, big-endian"
        )),
        KeyShareLine::text(format!(
            "expected size: {p_bytes} B (p is a {}-bit safe prime)",
            p_bytes * 8
        )),
    ];
    if bytes.len() == p_bytes {
        out.push(KeyShareLine::bytes(format!(
            "y ({} B): {}",
            bytes.len(),
            hex_inline(bytes)
        )));
    } else {
        out.push(KeyShareLine::text(format!(
            "size mismatch: got {} B \u{2014} stripped leading zeros?",
            bytes.len()
        )));
        out.push(KeyShareLine::bytes(format!("raw: {}", hex_inline(bytes))));
    }
    out
}

/// Post-quantum hybrid: `classical || pq`. `X25519MLKEM768` (draft-13+) is
/// the concatenation of a 32-byte X25519 public key followed by an 1184-byte
/// ML-KEM-768 encapsulation key (draft-kwiatkowski-tls-ecdhe-mlkem).
fn hybrid_pq_structure(
    bytes: &[u8],
    classical_len: usize,
    pq_len: usize,
    classical_name: &str,
    pq_name: &str,
) -> Vec<KeyShareLine> {
    let total = classical_len + pq_len;
    let mut out = vec![
        KeyShareLine::text(format!(
            "format: hybrid = {classical_name} pubkey ({classical_len} B) || {pq_name} encapsulation key ({pq_len} B)"
        )),
        KeyShareLine::text(format!(
            "why hybrid: {classical_name} is safe against classical attackers; {pq_name} is safe against quantum attackers. Both must break for the session to be broken."
        )),
        KeyShareLine::text(format!("expected total: {total} B")),
    ];
    if bytes.len() == total {
        let (classical, pq) = bytes.split_at(classical_len);
        out.push(KeyShareLine::bytes(format!(
            "{classical_name} ({} B): {}",
            classical.len(),
            hex_inline(classical)
        )));
        // ML-KEM keys are large; show the head and tail rather than the full 1184 bytes inline.
        out.push(KeyShareLine::bytes(format!(
            "{pq_name} ({} B): {}",
            pq.len(),
            preview_head_tail(pq, 16, 16)
        )));
    } else {
        out.push(KeyShareLine::text(format!(
            "size mismatch: got {} B \u{2014} draft version may not match",
            bytes.len()
        )));
        out.push(KeyShareLine::bytes(format!(
            "raw head: {}",
            hex_inline(&bytes[..bytes.len().min(48)])
        )));
    }
    out
}

/// Preview a long byte slice as `head... ... tail` when it is longer than
/// `head + tail`. Used to keep multi-KB PQ keys readable.
fn preview_head_tail(bytes: &[u8], head: usize, tail: usize) -> String {
    if bytes.len() <= head + tail {
        return hex_inline(bytes);
    }
    format!(
        "{} ... ({} B elided) ... {}",
        hex_inline(&bytes[..head]),
        bytes.len() - head - tail,
        hex_inline(&bytes[bytes.len() - tail..])
    )
}

fn hex_lines(bytes: &[u8]) -> Vec<Line<'static>> {
    if bytes.is_empty() {
        return vec![Line::from(Span::styled(
            "(empty)",
            Style::default().fg(Color::DarkGray),
        ))];
    }
    hex_dump(bytes, 16)
        .lines()
        .map(|row| Line::from(Span::styled(row.to_string(), wire_style())))
        .collect()
}

fn session_id_display(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "(empty)".into()
    } else {
        format!("{} bytes: {}", bytes.len(), hex_inline(bytes))
    }
}

fn outer_name(t: TlsRecordType) -> &'static str {
    match t {
        TlsRecordType::Handshake => "Handshake",
        TlsRecordType::ApplicationData => "ApplicationData (encrypted)",
        TlsRecordType::ChangeCipherSpec => "ChangeCipherSpec",
        TlsRecordType::Alert => "Alert",
        TlsRecordType::Other(_) => "Other",
    }
}

fn kv_line(k: &'static str, v: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{k:<16}"), Style::default().fg(Color::DarkGray)),
        Span::raw(v),
    ])
}

/// Like [`kv_line`] but the value renders in [`wire_style`] — use for
/// fields whose value is raw wire bytes (hex dumps, session_id, etc.).
fn kv_wire_line(k: &'static str, v: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{k:<16}"), Style::default().fg(Color::DarkGray)),
        Span::styled(v, wire_style()),
    ])
}

fn raw_line(s: String) -> Line<'static> {
    Line::from(s)
}

/// Style used for anything that came directly off the wire — hex dumps,
/// decoded byte values, and code-point literals. Green because it visually
/// separates "the message" from the surrounding commentary.
fn wire_style() -> Style {
    Style::default().fg(Color::Green)
}

/// Single-line wire-bytes value. Renders in [`wire_style`].
fn wire_line(s: String) -> Line<'static> {
    Line::from(Span::styled(s, wire_style()))
}

/// Bold header inside a section body — used to separate multiple offered
/// key_shares (client) or introduce the server's single chosen entry.
fn header_line(s: String) -> Line<'static> {
    Line::from(Span::styled(
        s,
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(ratatui::style::Modifier::BOLD),
    ))
}

// ---------------------------------------------------------------------------
// Educational copy.
//
// Each section has a one-line `edu_short` and a slice of labeled details.
// The right-pane renderer paints details as `Label: body` rows, which is
// much easier to read than a wall of prose.
//
// Crypto framing to keep consistent across sections:
//   - "Purpose" — what problem this field solves.
//   - "Key type" / "Keys involved" — public/private, ephemeral vs long-term,
//     symmetric vs asymmetric.
//   - "Where the private key lives" — always on the endpoint that generated
//     it, never on the wire.
//   - "Why it matters" — security property this enables (forward secrecy,
//     authentication, replay protection, ...).
// ---------------------------------------------------------------------------

// -- Cipher suites ----------------------------------------------------------

const EDU_CIPHER_OFFERED_SHORT: &str =
    "The AEAD + hash pairs the client will accept, in preference order.";
const EDU_CIPHER_OFFERED_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "Names one symmetric AEAD (bulk encryption) and one hash (key schedule) per entry. The server picks exactly one.",
    },
    EduDetail {
        label: "Key type",
        body: "None here. This is the algorithm menu. The actual symmetric keys are derived later via HKDF.",
    },
    EduDetail {
        label: "AEAD role",
        body: "Encrypts and authenticates every record after ServerHello. AES-GCM, AES-CCM, ChaCha20-Poly1305.",
    },
    EduDetail {
        label: "Hash role",
        body: "SHA-256 or SHA-384. Feeds HKDF-Extract / HKDF-Expand, which turn the DH shared secret into traffic keys.",
    },
    EduDetail {
        label: "TLS 1.3 change",
        body: "Only 5 suites in the base spec. TLS 1.2 had hundreds because it bundled key exchange + auth + MAC + cipher into one code.",
    },
];

const EDU_CIPHER_CHOSEN_SHORT: &str =
    "The one AEAD + hash pair the server picked from the client's list.";
const EDU_CIPHER_CHOSEN_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "Locks in the algorithms that protect every record after this ServerHello.",
    },
    EduDetail {
        label: "AEAD",
        body: "Produces (ciphertext, tag) from (key, nonce, plaintext, associated_data). The tag catches any bit-flip.",
    },
    EduDetail {
        label: "Hash",
        body: "Used by HKDF to derive handshake-traffic keys, then application-traffic keys, from the shared secret.",
    },
    EduDetail {
        label: "Keys involved",
        body: "Symmetric only. Distinct write keys for each direction, plus IVs, all derived per-connection.",
    },
];

// -- key_share --------------------------------------------------------------

const EDU_KEY_SHARE_SHORT: &str =
    "Ephemeral Diffie-Hellman public key(s). This is the actual key material on the wire.";
const EDU_KEY_SHARE_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "What's here",
        body: "One or more ephemeral public keys, each tagged with its Diffie-Hellman group. The private half stays on the sender; only the public half is on the wire.",
    },
    EduDetail {
        label: "Byte encoding",
        body: "Fixed by the group. X25519: 32-byte little-endian u-coordinate. secp256r1: 0x04 || X || Y, each 32 bytes big-endian. ffdhe2048: 256-byte big-endian y = g^x mod p. Hybrid PQ: classical pubkey || ML-KEM encapsulation key.",
    },
    EduDetail {
        label: "Shared secret",
        body: "Client's private * Server's public == Server's private * Client's public (ECDH). Both sides compute the same secret without exchanging it. Forward-secret: the ephemeral keys are discarded after the handshake, so stealing the server's cert key later cannot decrypt captured traffic.",
    },
];

// -- supported_versions -----------------------------------------------------

const EDU_SUPPORTED_VERSIONS_SHORT: &str = "Where the real TLS version negotiation happens in 1.3.";
const EDU_SUPPORTED_VERSIONS_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "Lists every TLS version the sender speaks. Server picks one and echoes it back in its own supported_versions.",
    },
    EduDetail {
        label: "Why an extension?",
        body: "Middleboxes reject unfamiliar values in the legacy_version field. Moving the real version list into an extension keeps TLS 1.3 wire-compatible with those boxes.",
    },
    EduDetail {
        label: "Keys involved",
        body: "None. Pure negotiation.",
    },
];

// -- signature_algorithms ---------------------------------------------------

const EDU_SIG_ALGS_SHORT: &str =
    "Signature schemes the client can verify. Constrains what the server signs with.";
const EDU_SIG_ALGS_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "Tells the server which signature schemes are acceptable in CertificateVerify. The server must pick one on this list or the handshake fails.",
    },
    EduDetail {
        label: "Key type",
        body: "Asymmetric long-term. The server signs with the private key that matches its certificate.",
    },
    EduDetail {
        label: "Where the private key lives",
        body: "On the server, typically in an HSM, key file, or platform key store. Never on the wire.",
    },
    EduDetail {
        label: "What's signed",
        body: "A hash of the handshake transcript so far. This is what proves the server owns the certificate.",
    },
    EduDetail {
        label: "Common schemes",
        body: "rsa_pss_rsae_sha256 (RSA-PSS), ecdsa_secp256r1_sha256 (ECDSA/P-256), ed25519 (EdDSA).",
    },
];

// -- supported_groups -------------------------------------------------------

const EDU_SUPPORTED_GROUPS_SHORT: &str =
    "Every Diffie-Hellman group the client can use, key_share sent or not.";
const EDU_SUPPORTED_GROUPS_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "If the server prefers a group the client did not speculatively send a key for, it can respond with HelloRetryRequest naming a group from this list.",
    },
    EduDetail {
        label: "Keys involved",
        body: "None directly. This is the menu; key_share carries the actual ephemeral public keys for the groups the client bet on.",
    },
    EduDetail {
        label: "Common groups",
        body: "X25519 (Curve25519, fast and constant-time), secp256r1 (NIST P-256), secp384r1 (NIST P-384).",
    },
];

// -- Client / Server random -------------------------------------------------

const EDU_CLIENT_RANDOM_SHORT: &str =
    "32 bytes of client-side entropy. Feeds the key schedule as public salt.";
const EDU_CLIENT_RANDOM_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Source",
        body: "Cryptographic RNG on the client (getrandom/urandom, RtlGenRandom, ...).",
    },
    EduDetail {
        label: "Purpose",
        body: "Mixed into HKDF so two handshakes with identical parameters still derive different traffic keys.",
    },
    EduDetail {
        label: "Public or secret?",
        body: "Public. It appears on the wire in the clear and is not itself a key.",
    },
    EduDetail {
        label: "TLS 1.2 legacy",
        body: "The first 4 bytes used to be a Unix timestamp; TLS 1.3 dropped that convention — all 32 bytes are now uniform random.",
    },
];

const EDU_SERVER_RANDOM_SHORT: &str =
    "32 bytes of server-side entropy. Also public salt into the key schedule.";
const EDU_SERVER_RANDOM_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Source",
        body: "Cryptographic RNG on the server.",
    },
    EduDetail {
        label: "Purpose",
        body: "Mixed into HKDF alongside client_random and the DH shared secret. Ensures uniqueness even across replayed ClientHellos.",
    },
    EduDetail {
        label: "Public or secret?",
        body: "Public. Not a key.",
    },
    EduDetail {
        label: "HelloRetryRequest",
        body: "HRR is wire-encoded as a ServerHello whose random is SHA-256(\"HelloRetryRequest\"). That fixed value is how the client tells the two apart.",
    },
];

// -- SNI --------------------------------------------------------------------

const EDU_SNI_SHORT: &str =
    "The hostname the client wants. Sent in the clear — the biggest metadata leak in TLS 1.3.";
const EDU_SNI_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "Lets one IP address host many TLS sites: the server picks the certificate matching this name.",
    },
    EduDetail {
        label: "Visibility",
        body: "Plaintext. Anyone on-path (ISPs, corporate proxies, coffee-shop wifi) can see which host you asked for even though the rest of the handshake is encrypted.",
    },
    EduDetail {
        label: "Keys involved",
        body: "None. Pure routing information.",
    },
    EduDetail {
        label: "ECH",
        body: "Encrypted Client Hello (draft) wraps SNI and other sensitive extensions in an outer ClientHello using a public key published in DNS. Not yet universal.",
    },
];

// -- ALPN -------------------------------------------------------------------

const EDU_ALPN_SHORT: &str = "Which application protocols the client speaks inside the TLS tunnel.";
const EDU_ALPN_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "The client and server agree on what to run on top of TLS — h2, http/1.1, something custom — before any data flows.",
    },
    EduDetail {
        label: "Visibility",
        body: "Client's offers are in the clear. Server's selected value is inside EncryptedExtensions, so a passive observer sees the menu but not the answer.",
    },
    EduDetail {
        label: "Keys involved",
        body: "None.",
    },
];

// -- PSK modes / pre_shared_key / early_data --------------------------------

const EDU_PSK_MODES_SHORT: &str =
    "Whether resumption should also run a fresh Diffie-Hellman for forward secrecy.";
const EDU_PSK_MODES_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "psk_ke",
        body: "Pure PSK. Keys are derived from the resumption secret alone. No forward secrecy against loss of that secret.",
    },
    EduDetail {
        label: "psk_dhe_ke",
        body: "PSK + (EC)DHE. Keys mix the resumption secret with a fresh ephemeral shared secret. Preserves forward secrecy; almost always what real deployments use.",
    },
    EduDetail {
        label: "Keys involved",
        body: "Symmetric resumption PSK, plus ephemeral DH keys when psk_dhe_ke is picked.",
    },
];

const EDU_PSK_SHORT: &str =
    "Resumption tickets from a previous handshake. Also carries the MAC that proves possession.";
const EDU_PSK_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "TLS 1.3's session-resumption mechanism (and how 0-RTT early data is authenticated).",
    },
    EduDetail {
        label: "Key type",
        body: "Symmetric. Each identity is an opaque ticket the server previously issued via NewSessionTicket; the shared PSK is derived from it.",
    },
    EduDetail {
        label: "Binders",
        body: "MACs over the transcript, keyed with a secret derived from the resumption PSK. Proves the client actually holds the PSK, not just the ticket bytes.",
    },
    EduDetail {
        label: "Where the PSK lives",
        body: "In the client's TLS session cache and, in some form, on the server. Never on the wire.",
    },
];

const EDU_EARLY_DATA_SHORT: &str =
    "Client wants to piggyback application data on the ClientHello (0-RTT).";
const EDU_EARLY_DATA_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "Cuts a round trip: the client attaches request data to the ClientHello, encrypted under a key derived from a resumption PSK.",
    },
    EduDetail {
        label: "Security cost",
        body: "0-RTT data is not forward-secret against loss of the PSK, and it is replayable by an attacker. Clients typically only use it for safe idempotent requests.",
    },
    EduDetail {
        label: "Keys involved",
        body: "A symmetric early-traffic key derived from the resumption PSK — separate from the handshake and application traffic keys.",
    },
];

// -- cookie -----------------------------------------------------------------

const EDU_COOKIE_SHORT: &str = "A stateless liveness token, echoed on the retried ClientHello.";
const EDU_COOKIE_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "Lets a server force a round trip before doing expensive key-exchange work — useful against amplification attacks.",
    },
    EduDetail {
        label: "Flow",
        body: "Server sends HelloRetryRequest with a cookie; client repeats the ClientHello including the cookie; server verifies it (usually via a MAC keyed with server state) without keeping per-client memory.",
    },
    EduDetail {
        label: "Keys involved",
        body: "None on the wire. The server may MAC the cookie with a local key, but that key is server-side only.",
    },
];

// -- opaque / unknown -------------------------------------------------------

const EDU_OPAQUE_SHORT: &str =
    "SeeHandshake does not decode this extension. Raw bytes are shown as-is.";
const EDU_OPAQUE_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "What to do",
        body: "Look up the extension type code in RFC 8446 or the IANA TLS ExtensionType Values registry.",
    },
    EduDetail {
        label: "Are these bytes trustworthy?",
        body: "Yes. The parser hands the extension body through verbatim; only the interpretation is missing.",
    },
];

const EDU_UNKNOWN_SHORT: &str =
    "A handshake message whose msg_type didn't match anything expected in the clear.";
const EDU_UNKNOWN_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Expected here",
        body: "Only ClientHello (1) and ServerHello / HelloRetryRequest (2) appear in the clear in TLS 1.3.",
    },
    EduDetail {
        label: "Likely causes",
        body: "A non-TLS payload on the same port, a truncated capture, or a version mismatch where TLS 1.2 messages arrived unexpectedly.",
    },
];

/// Pick the one-line blurb for a TLS handshake `msg_type` byte.
fn edu_short_for_msg_type(msg_type: u8) -> &'static str {
    match msg_type {
        4 => "Server hands the client a resumption ticket for a faster future handshake.",
        11 => "Server's X.509 certificate chain, proving identity to the client.",
        12 => "Server's ephemeral (EC)DH public key, signed with its long-term certificate key.",
        13 => "Server asks the client for its own certificate (mutual TLS).",
        14 => "Server signals its flight is complete — client's turn now.",
        15 => "Signature over the transcript proving possession of the private key.",
        16 => "Client's contribution to the (EC)DH key exchange.",
        20 => "MAC over the whole transcript. First message under the newly derived keys.",
        22 => "Server-stapled OCSP response for its certificate.",
        24 => "TLS 1.3 in-connection key rotation. Rekeys the application-traffic keys.",
        _ => EDU_UNKNOWN_SHORT,
    }
}

/// Pick the labeled sub-topics for a TLS handshake `msg_type` byte.
fn edu_details_for_msg_type(msg_type: u8) -> &'static [EduDetail] {
    match msg_type {
        4 => EDU_NEW_SESSION_TICKET_DETAILS,
        11 => EDU_CERTIFICATE_DETAILS,
        12 => EDU_SERVER_KEY_EXCHANGE_DETAILS,
        13 => EDU_CERTIFICATE_REQUEST_DETAILS,
        14 => EDU_SERVER_HELLO_DONE_DETAILS,
        15 => EDU_CERTIFICATE_VERIFY_DETAILS,
        16 => EDU_CLIENT_KEY_EXCHANGE_DETAILS,
        20 => EDU_FINISHED_DETAILS,
        22 => EDU_CERT_STATUS_DETAILS,
        24 => EDU_KEY_UPDATE_DETAILS,
        _ => EDU_UNKNOWN_DETAILS,
    }
}

const EDU_CERTIFICATE_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "The server's identity: an X.509 chain the client will verify against its trust store (system CAs, browser roots, etc.).",
    },
    EduDetail {
        label: "Key type",
        body: "Asymmetric, long-term. The certificate carries a public key; the matching private key stays on the server.",
    },
    EduDetail {
        label: "Visibility",
        body: "Plaintext in TLS 1.2 — anyone on-path can see the certificate. TLS 1.3 encrypts it inside the handshake flight.",
    },
    EduDetail {
        label: "Trust check",
        body: "Client verifies the signature chain up to a trusted root, then checks the name in the leaf matches the SNI it sent.",
    },
];

const EDU_SERVER_KEY_EXCHANGE_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "Carries the server's ephemeral (EC)DH public key so the two sides can derive a shared secret for this session only.",
    },
    EduDetail {
        label: "Signature",
        body: "The (EC)DH parameters are signed with the certificate's private key. That binds this ephemeral key to the server's long-term identity.",
    },
    EduDetail {
        label: "Why it matters",
        body: "This is what gives TLS 1.2 forward secrecy: the ephemeral key is discarded after use, so capturing the traffic and later stealing the cert key does not decrypt it.",
    },
    EduDetail {
        label: "TLS 1.3 change",
        body: "TLS 1.3 dropped this message — the server's key_share goes in ServerHello, and the signature moves to CertificateVerify.",
    },
];

const EDU_CERTIFICATE_REQUEST_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "Signals mutual TLS: the server wants a client certificate too, and lists which CAs and signature schemes it will accept.",
    },
    EduDetail {
        label: "Keys involved",
        body: "None here. The client must present its own X.509 chain in a subsequent Certificate message and prove ownership with CertificateVerify.",
    },
];

const EDU_SERVER_HELLO_DONE_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "TLS 1.2 marker: the server's plaintext flight is done. The client should now respond with ClientKeyExchange, CCS, Finished.",
    },
    EduDetail {
        label: "Wire format",
        body: "Four bytes exactly: 0x0e 0x00 0x00 0x00 (msg_type + zero-length body).",
    },
    EduDetail {
        label: "TLS 1.3 change",
        body: "Removed. The server's flight is delimited by its Finished message instead.",
    },
];

const EDU_CERTIFICATE_VERIFY_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "A signature over the handshake transcript hash, made with the certificate's private key. Proves the sender actually holds that private key.",
    },
    EduDetail {
        label: "Keys involved",
        body: "Asymmetric long-term (signature). Uses one of the schemes offered in signature_algorithms.",
    },
    EduDetail {
        label: "Where the private key lives",
        body: "On the endpoint that owns the certificate — usually an HSM, TPM, or protected key file. Never on the wire.",
    },
];

const EDU_CLIENT_KEY_EXCHANGE_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "Client's half of the (EC)DH exchange (ECDHE) or an RSA-encrypted premaster secret (legacy RSA suites).",
    },
    EduDetail {
        label: "Forward secrecy",
        body: "Only preserved with ECDHE/DHE suites. Pure-RSA key exchange has been deprecated because a stolen server key can decrypt past captures.",
    },
    EduDetail {
        label: "TLS 1.3 change",
        body: "Removed. The client sends its key_share in ClientHello, so the DH exchange is complete after ServerHello.",
    },
];

const EDU_FINISHED_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "HMAC over the full handshake transcript. Proves the sender saw the same handshake as the receiver — catches man-in-the-middle tampering.",
    },
    EduDetail {
        label: "Visibility",
        body: "Encrypted. TLS 1.2 sends it as a Handshake record right after ChangeCipherSpec; TLS 1.3 wraps it in an application_data record.",
    },
    EduDetail {
        label: "Keys involved",
        body: "The verify_data is a MAC keyed with a secret derived from the master secret plus the transcript hash. Symmetric only.",
    },
];

const EDU_NEW_SESSION_TICKET_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "An opaque ticket the client can present on a future ClientHello to skip most of the handshake (session resumption).",
    },
    EduDetail {
        label: "TLS 1.2 vs 1.3",
        body: "TLS 1.2 sends it once, immediately after the server CCS. TLS 1.3 can send it any time after Finished, inside encrypted application_data records.",
    },
    EduDetail {
        label: "Keys involved",
        body: "The ticket is opaque to the client. Internally the server derives a resumption PSK from it and its own long-term ticket-encryption key.",
    },
];

const EDU_CERT_STATUS_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "Server-stapled OCSP response — proof from the CA (or its responder) that the certificate has not been revoked.",
    },
    EduDetail {
        label: "Why staple",
        body: "Saves the client from having to fetch OCSP itself (which leaks browsing to the CA and is often blocked).",
    },
];

const EDU_KEY_UPDATE_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Purpose",
        body: "TLS 1.3 mid-connection rekey. Rotates the application-traffic secret via HKDF so long-lived connections don't reuse keys indefinitely.",
    },
    EduDetail {
        label: "Directions",
        body: "Each side rekeys its own send direction. An `update_requested` flag can ask the peer to rekey theirs too.",
    },
];

const EDU_CCS_SHORT: &str =
    "TLS 1.2: 'everything I send after this is encrypted with the new keys.' TLS 1.3: legacy no-op.";
const EDU_CCS_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Wire format",
        body: "One byte of payload: 0x01. That's the whole message.",
    },
    EduDetail {
        label: "TLS 1.2 role",
        body: "Cutover signal. The next record in the same direction is protected with the newly negotiated write key.",
    },
    EduDetail {
        label: "TLS 1.3 role",
        body: "None functional. It's kept purely so middleboxes that expect it in the flow don't drop the connection.",
    },
    EduDetail {
        label: "Keys involved",
        body: "None here. The keys are already derived at both ends; this message just tells the peer to start using them.",
    },
];

// -- Legacy fields ----------------------------------------------------------

const EDU_LEGACY_SHORT: &str =
    "Non-crypto compatibility knobs kept so TLS 1.3 wire packets look like TLS 1.2 to middleboxes.";
const EDU_LEGACY_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "legacy_version",
        body: "Frozen at 0x0303 (TLS 1.2). Real version negotiation moved into the supported_versions extension.",
    },
    EduDetail {
        label: "session_id",
        body: "TLS 1.2 used this for stateful resumption. TLS 1.3 does resumption via pre_shared_key, so this field carries no protocol meaning — clients send a random 32 bytes purely to look like TLS 1.2 on the wire.",
    },
    EduDetail {
        label: "compression",
        body: "Always 0x00. TLS-layer compression was removed after CRIME (2012) showed it leaks secrets when attacker-controlled and secret data are compressed together.",
    },
    EduDetail {
        label: "Keys involved",
        body: "None. This whole section is presentation, not security.",
    },
];

// -- Record framing ---------------------------------------------------------

const EDU_FRAMING_SHORT: &str =
    "The 5-byte TLS record envelope. Same shape regardless of what's inside.";
const EDU_FRAMING_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Fields",
        body: "1 byte content type, 2 bytes legacy version (always 0x0303 on TLS 1.3), 2 bytes length. Then the payload.",
    },
    EduDetail {
        label: "Content type",
        body: "handshake, application_data, change_cipher_spec, alert. Everything post-ServerHello is wrapped in application_data even when the plaintext underneath is a handshake message.",
    },
    EduDetail {
        label: "Keys involved",
        body: "None in the header. The payload may or may not be AEAD-encrypted depending on where in the handshake we are.",
    },
];

// -- Encrypted flight -------------------------------------------------------

const EDU_ENCRYPTED_STAGE_SHORT: &str =
    "AEAD-encrypted. The label is inferred from flight position, not from decryption.";
const EDU_ENCRYPTED_STAGE_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "Why encrypted",
        body: "Everything after ServerHello is protected by handshake-traffic keys derived from the DH shared secret. A passive observer cannot see the inner content type or messages.",
    },
    EduDetail {
        label: "How the label is picked",
        body: "By position: 1st server encrypted = likely EncryptedExtensions + Certificate, 2nd = CertificateVerify + Finished, 3rd = NewSessionTicket. Client's 1st encrypted = Finished.",
    },
    EduDetail {
        label: "Keys involved",
        body: "Symmetric handshake-traffic keys, one per direction, derived by HKDF from the DH shared secret plus the transcript hash.",
    },
    EduDetail {
        label: "Caveat",
        body: "The label matches common OpenSSL/BoringSSL fragmentation. Servers that fragment differently will produce misleading labels; the tool cannot verify.",
    },
];

const EDU_ENCRYPTED_CIPHERTEXT_SHORT: &str =
    "The first bytes of the AEAD payload. Opaque without the handshake traffic keys.";
const EDU_ENCRYPTED_CIPHERTEXT_DETAILS: &[EduDetail] = &[
    EduDetail {
        label: "What it is",
        body: "Real ciphertext as observed on the wire. AEAD output: ciphertext followed by a 16-byte authentication tag.",
    },
    EduDetail {
        label: "How to decrypt",
        body: "You need the handshake traffic secret for this direction. It is derived inside each endpoint and never sent. A cooperating client can export it via SSLKEYLOGFILE — SeeHandshake does not yet consume that, but it is on the roadmap.",
    },
    EduDetail {
        label: "Keys involved",
        body: "Symmetric AEAD key + per-record IV, both derived per-direction from the handshake or application traffic secret.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::record::{RecordBody, RecordDirection, RecordEvent};
    use crate::parser::record::TlsRecordType;
    use crate::parser::{decode_client_hello, decode_server_hello, parse_records};

    const CLIENT_HELLO_RECORD: &[u8] = include_bytes!("../../tests/data/client_hello_tls13.bin");
    const SERVER_HELLO_RECORD: &[u8] = include_bytes!("../../tests/data/server_hello_tls13.bin");

    fn build_client_hello_event() -> RecordEvent {
        let (records, _) = parse_records(CLIENT_HELLO_RECORD).unwrap();
        let ch = decode_client_hello(records[0].payload).unwrap();
        RecordEvent {
            direction: RecordDirection::ClientToServer,
            timestamp_ms: 0,
            sequence: 1,
            outer_type: TlsRecordType::Handshake,
            outer_length: records[0].payload.len() as u16,
            raw: CLIENT_HELLO_RECORD.to_vec(),
            body: RecordBody::Handshake(DecodedHandshake::ClientHello(Box::new(ch))),
        }
    }

    fn build_server_hello_event() -> RecordEvent {
        let (records, _) = parse_records(SERVER_HELLO_RECORD).unwrap();
        let sh = decode_server_hello(records[0].payload).unwrap();
        RecordEvent {
            direction: RecordDirection::ServerToClient,
            timestamp_ms: 5,
            sequence: 2,
            outer_type: TlsRecordType::Handshake,
            outer_length: records[0].payload.len() as u16,
            raw: SERVER_HELLO_RECORD.to_vec(),
            body: RecordBody::Handshake(DecodedHandshake::ServerHello(Box::new(sh))),
        }
    }

    #[test]
    fn client_hello_leads_with_cipher_suites_then_key_share() {
        let ev = build_client_hello_event();
        let sections = sections_for(&ev);

        for s in &sections {
            assert_eq!(s.direction_hint, "You sent this");
        }

        let titles: Vec<&str> = sections.iter().map(|s| s.title.as_str()).collect();
        assert!(titles[0].starts_with("Cipher suites offered"));
        // key_share must appear before Client random.
        let ks = titles
            .iter()
            .position(|t| t.starts_with("key_share"))
            .expect("key_share");
        let rand = titles
            .iter()
            .position(|t| t.starts_with("Client random"))
            .expect("Client random");
        assert!(ks < rand, "key_share must precede Client random");
    }

    #[test]
    fn client_hello_no_standalone_compression_or_session_id() {
        let ev = build_client_hello_event();
        let sections = sections_for(&ev);
        let titles: Vec<&str> = sections.iter().map(|s| s.title.as_str()).collect();
        // Neither should appear as its own section; both live inside the
        // combined "Legacy fields" section at the bottom.
        assert!(!titles.contains(&"Compression methods"));
        assert!(!titles.contains(&"Session ID"));
        assert!(titles.iter().any(|t| t.starts_with("Legacy fields")));
    }

    #[test]
    fn server_hello_leads_with_chosen_suite() {
        let ev = build_server_hello_event();
        let sections = sections_for(&ev);
        for s in &sections {
            assert_eq!(s.direction_hint, "The server sent you this");
        }
        assert_eq!(sections[0].title, "Cipher suite (chosen)");
    }

    #[test]
    fn encrypted_record_produces_stage_and_ciphertext_sections() {
        let ev = RecordEvent {
            direction: RecordDirection::ServerToClient,
            timestamp_ms: 10,
            sequence: 3,
            outer_type: TlsRecordType::ApplicationData,
            outer_length: 32,
            raw: vec![0x17, 0x03, 0x03, 0x00, 0x1c],
            body: RecordBody::EncryptedHandshake {
                inferred_label: "likely EncryptedExtensions + Certificate",
                ciphertext_preview: vec![0xde, 0xad, 0xbe, 0xef],
            },
        };
        let sections = sections_for(&ev);
        let titles: Vec<&str> = sections.iter().map(|s| s.title.as_str()).collect();
        assert!(titles.contains(&"Encrypted flight (inferred)"));
        assert!(titles.contains(&"Ciphertext preview"));
        assert!(titles.contains(&"Record framing"));
    }

    #[test]
    fn every_section_has_edu_short_and_details() {
        let ev = build_client_hello_event();
        for s in sections_for(&ev) {
            assert!(!s.edu_short.is_empty(), "empty edu_short for {}", s.title);
            assert!(
                !s.edu_details.is_empty(),
                "empty edu_details for {}",
                s.title
            );
            for d in s.edu_details {
                assert!(!d.label.is_empty(), "empty detail label in {}", s.title);
                assert!(!d.body.is_empty(), "empty detail body in {}", s.title);
            }
        }
    }
}
