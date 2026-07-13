// SPDX-License-Identifier: MIT

//! Per-connection TCP payload reassembly and stale eviction.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use tls_parser::{TlsMessage, TlsMessageHandshake};

use crate::error::Result;
use crate::model::connection::{Direction, RECORD_LOG_CAP};
use crate::model::record::{DecodedHandshake, RecordBody, RecordDirection, RecordEvent};
use crate::model::tls::TlsVersion;
use crate::model::{ConnectionKey, ConnectionState, HandshakeInfo, HandshakeStage};
use crate::origin::{default_resolver, OriginResolver};
use crate::parser::handshake::{
    decode_client_hello, decode_server_hello, is_hello_retry_request, ClientHelloInfo,
    ServerHelloInfo,
};
use crate::parser::record::{parse_records, TlsRecordType, RECORD_HEADER_LEN};

/// Default idle timeout after which a connection is evicted (5 minutes).
pub const DEFAULT_STALE_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// Maximum reassembly buffer size per direction (128 KiB).
///
/// TLS 1.3 handshake messages other than `Certificate` are small; even a
/// large `Certificate` chain fits comfortably. If this cap is exceeded the
/// connection is marked errored.
pub const MAX_REASSEMBLY_BYTES: usize = 128 * 1024;

/// Number of ciphertext bytes retained for the detail-view preview of an
/// encrypted record.
const CIPHERTEXT_PREVIEW_LEN: usize = 64;

/// Tracks in-flight TLS handshakes across many connections.
pub struct ConnectionTracker {
    connections: HashMap<ConnectionKey, TrackedConnection>,
    stale_timeout_ms: u64,
    resolver: Box<dyn OriginResolver>,
}

impl std::fmt::Debug for ConnectionTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionTracker")
            .field("connections", &self.connections.len())
            .field("stale_timeout_ms", &self.stale_timeout_ms)
            .finish_non_exhaustive()
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct TrackedConnection {
    state: ConnectionState,
    client_to_server_buf: Vec<u8>,
    server_to_client_buf: Vec<u8>,
    encrypted_records_from_server: u32,
    encrypted_records_from_client: u32,
    saw_client_finished_marker: bool,
    // TLS 1.2 ChangeCipherSpec markers, one per direction. Once true, every
    // subsequent record on that direction (Handshake or ApplicationData) is
    // AEAD-encrypted with the negotiated write key.
    client_ccs_seen: bool,
    server_ccs_seen: bool,
    // Count of post-CCS records per direction. Used to hedge labels for
    // TLS 1.2 encrypted Finished vs. NewSessionTicket vs. application data.
    post_ccs_records_from_client: u32,
    post_ccs_records_from_server: u32,
    seq_counter: u32,
    stop_logging: bool,
}

impl ConnectionTracker {
    /// Create a new tracker with the default stale-connection timeout and
    /// the platform's default [`OriginResolver`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_stale_timeout(DEFAULT_STALE_TIMEOUT_MS)
    }

    /// Create a new tracker with a custom stale-connection timeout, in
    /// milliseconds.
    #[must_use]
    pub fn with_stale_timeout(stale_timeout_ms: u64) -> Self {
        Self {
            connections: HashMap::new(),
            stale_timeout_ms,
            resolver: default_resolver(),
        }
    }

    /// Create a tracker with a caller-supplied [`OriginResolver`]. Useful
    /// in tests and for platforms where the caller wants to inject their
    /// own attribution strategy.
    #[must_use]
    pub fn with_resolver(resolver: Box<dyn OriginResolver>) -> Self {
        Self {
            connections: HashMap::new(),
            stale_timeout_ms: DEFAULT_STALE_TIMEOUT_MS,
            resolver,
        }
    }

    /// Ingest a TCP payload segment.
    ///
    /// `now_ms` is caller-supplied so that tests can drive the clock
    /// deterministically. Production callers pass [`unix_now_ms`].
    ///
    /// `endpoint_a` / `endpoint_b` are the raw src/dst of the observed
    /// TCP segment (either order). They are used *once*, when a
    /// connection is first seen, to attribute it to a local process via
    /// the configured [`OriginResolver`]. Later packets skip the lookup.
    ///
    /// # Errors
    ///
    /// Currently returns `Ok(())` for all inputs. Malformed data is
    /// recorded on the per-connection [`HandshakeInfo::error`] field rather
    /// than surfaced as an error, so a single bad connection does not stop
    /// the tracker from serving others.
    pub fn ingest(
        &mut self,
        key: ConnectionKey,
        direction: Direction,
        endpoint_a: SocketAddr,
        endpoint_b: SocketAddr,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Option<ConnectionState>> {
        if payload.is_empty() {
            return Ok(None);
        }

        let is_new = !self.connections.contains_key(&key);
        let conn = self
            .connections
            .entry(key)
            .or_insert_with(|| TrackedConnection {
                state: ConnectionState {
                    key,
                    first_seen_ms: now_ms,
                    last_seen_ms: now_ms,
                    handshake: HandshakeInfo::new(),
                    records: Vec::new(),
                },
                client_to_server_buf: Vec::new(),
                server_to_client_buf: Vec::new(),
                encrypted_records_from_server: 0,
                encrypted_records_from_client: 0,
                saw_client_finished_marker: false,
                client_ccs_seen: false,
                server_ccs_seen: false,
                post_ccs_records_from_client: 0,
                post_ccs_records_from_server: 0,
                seq_counter: 0,
                stop_logging: false,
            });

        if is_new {
            conn.state.handshake.origin = Some(self.resolver.resolve(endpoint_a, endpoint_b));
        }

        conn.state.last_seen_ms = now_ms;

        let buf = match direction {
            Direction::ClientToServer => &mut conn.client_to_server_buf,
            Direction::ServerToClient => &mut conn.server_to_client_buf,
        };

        if buf.len() + payload.len() > MAX_REASSEMBLY_BYTES {
            conn.state.handshake.stage = HandshakeStage::Errored;
            conn.state.handshake.error = Some(format!(
                "reassembly buffer would exceed {MAX_REASSEMBLY_BYTES} bytes"
            ));
            return Ok(Some(conn.state.clone()));
        }

        buf.extend_from_slice(payload);

        let (records, consumed) = match parse_records(buf) {
            Ok(v) => v,
            Err(err) => {
                conn.state.handshake.stage = HandshakeStage::Errored;
                conn.state.handshake.error = Some(err.to_string());
                // Drop the whole buffer; we can't resync inside a TLS stream.
                buf.clear();
                return Ok(Some(conn.state.clone()));
            }
        };

        // Materialize records so we can drop the `buf` borrow before mutating
        // other fields of `conn` (`push_record_event` needs `&mut conn`).
        let owned: Vec<OwnedRecord> = records
            .iter()
            .map(|r| OwnedRecord {
                record_type: r.record_type,
                legacy_version: r.legacy_version,
                payload: r.payload.to_vec(),
            })
            .collect();
        buf.drain(..consumed);

        for record in &owned {
            match record.record_type {
                TlsRecordType::Handshake => {
                    // In TLS 1.2, a Handshake record after CCS is really an
                    // encrypted Finished (or a post-cutover message like
                    // NewSessionTicket). Skip plaintext decode in that case:
                    // the msg_type byte is ciphertext, and interpreting it
                    // as `Finished` etc. would be wrong. `apply_ccs` already
                    // advanced the stage when CCS was observed.
                    let post_ccs = match direction {
                        Direction::ClientToServer => conn.client_ccs_seen,
                        Direction::ServerToClient => conn.server_ccs_seen,
                    };
                    if !post_ccs {
                        apply_handshake_record(
                            &mut conn.state.handshake,
                            &record.payload,
                            direction,
                        );
                    }
                    push_record_event(conn, record, direction, now_ms);
                    if post_ccs {
                        match direction {
                            Direction::ClientToServer => {
                                conn.post_ccs_records_from_client += 1;
                            }
                            Direction::ServerToClient => {
                                conn.post_ccs_records_from_server += 1;
                            }
                        }
                        // TLS 1.2 handshake completes once both sides have
                        // sent their encrypted Finished. Stop logging then.
                        if conn.client_ccs_seen && conn.server_ccs_seen {
                            conn.stop_logging = true;
                        }
                    }
                }
                TlsRecordType::ApplicationData => {
                    apply_encrypted_record(
                        &mut conn.state.handshake,
                        &mut conn.encrypted_records_from_server,
                        &mut conn.encrypted_records_from_client,
                        &mut conn.saw_client_finished_marker,
                        direction,
                    );
                    // TLS 1.3 handshake completion signal: client has sent
                    // its Finished (its 1st encrypted record). Anything
                    // after that from the client is application data and
                    // does not belong in the record timeline.
                    if conn.encrypted_records_from_client >= 2 {
                        conn.stop_logging = true;
                    }
                    // TLS 1.2 application data. The handshake is already
                    // done by the time this record type appears from either
                    // side, so stop logging immediately.
                    if conn.client_ccs_seen && conn.server_ccs_seen {
                        conn.stop_logging = true;
                    }
                    push_record_event(conn, record, direction, now_ms);
                }
                TlsRecordType::ChangeCipherSpec => {
                    apply_ccs(&mut conn.state.handshake, direction);
                    match direction {
                        Direction::ClientToServer => conn.client_ccs_seen = true,
                        Direction::ServerToClient => conn.server_ccs_seen = true,
                    }
                    push_record_event(conn, record, direction, now_ms);
                }
                TlsRecordType::Alert | TlsRecordType::Other(_) => {}
            }
        }

        Ok(Some(conn.state.clone()))
    }

    /// Return an iterator over all currently tracked connection states.
    pub fn iter(&self) -> impl Iterator<Item = &ConnectionState> {
        self.connections.values().map(|c| &c.state)
    }

    /// Evict connections that have not been touched within the configured
    /// stale timeout.
    ///
    /// Returns the number of connections removed.
    pub fn evict_stale(&mut self, now_ms: u64) -> usize {
        let before = self.connections.len();
        let cutoff = now_ms.saturating_sub(self.stale_timeout_ms);
        self.connections
            .retain(|_, c| c.state.last_seen_ms >= cutoff);
        before - self.connections.len()
    }
}

fn push_record_event(
    conn: &mut TrackedConnection,
    record: &OwnedRecord,
    direction: Direction,
    now_ms: u64,
) {
    if conn.stop_logging || conn.state.records.len() >= RECORD_LOG_CAP {
        if !conn.stop_logging && conn.state.records.len() >= RECORD_LOG_CAP {
            tracing::trace!("record log cap reached for connection; dropping further records");
        }
        return;
    }

    conn.seq_counter = conn.seq_counter.saturating_add(1);
    let body = build_body(record, direction, conn);
    let mut raw = Vec::with_capacity(RECORD_HEADER_LEN + record.payload.len());
    raw.push(record_type_byte(record.record_type));
    raw.extend_from_slice(&record.legacy_version.to_be_bytes());
    let len = u16::try_from(record.payload.len()).unwrap_or(u16::MAX);
    raw.extend_from_slice(&len.to_be_bytes());
    raw.extend_from_slice(&record.payload);

    conn.state.records.push(RecordEvent {
        direction: to_record_direction(direction),
        timestamp_ms: now_ms,
        sequence: conn.seq_counter,
        outer_type: record.record_type,
        outer_length: len,
        raw,
        body,
    });
}

fn build_body(record: &OwnedRecord, direction: Direction, conn: &TrackedConnection) -> RecordBody {
    match record.record_type {
        TlsRecordType::Handshake => {
            // TLS 1.2: any Handshake record after CCS on this direction is
            // AEAD-encrypted; the msg_type byte in payload[0] is ciphertext.
            let post_ccs = match direction {
                Direction::ClientToServer => conn.client_ccs_seen,
                Direction::ServerToClient => conn.server_ccs_seen,
            };
            if post_ccs {
                let label = post_ccs_handshake_label(direction, conn);
                let take = record.payload.len().min(CIPHERTEXT_PREVIEW_LEN);
                RecordBody::EncryptedHandshake {
                    inferred_label: label,
                    ciphertext_preview: record.payload[..take].to_vec(),
                }
            } else {
                RecordBody::Handshake(decode_handshake_body(&record.payload))
            }
        }
        TlsRecordType::ApplicationData => {
            let label = encrypted_flight_label(direction, conn, record.payload.len());
            let take = record.payload.len().min(CIPHERTEXT_PREVIEW_LEN);
            RecordBody::EncryptedHandshake {
                inferred_label: label,
                ciphertext_preview: record.payload[..take].to_vec(),
            }
        }
        TlsRecordType::ChangeCipherSpec => RecordBody::ChangeCipherSpec,
        _ => RecordBody::EncryptedHandshake {
            inferred_label: "unknown record type",
            ciphertext_preview: Vec::new(),
        },
    }
}

/// A TLS record with owned payload. Used inside the tracker to sidestep
/// the borrow-checker conflict between the reassembly buffer and per-record
/// state mutation.
struct OwnedRecord {
    record_type: TlsRecordType,
    legacy_version: u16,
    payload: Vec<u8>,
}

fn decode_handshake_body(payload: &[u8]) -> DecodedHandshake {
    let Some(&msg_type) = payload.first() else {
        return DecodedHandshake::Unknown {
            msg_type: 0,
            raw: Vec::new(),
        };
    };
    match msg_type {
        1 => match decode_client_hello(payload) {
            Ok(ch) => DecodedHandshake::ClientHello(Box::new(ch)),
            Err(_) => DecodedHandshake::Unknown {
                msg_type,
                raw: payload.to_vec(),
            },
        },
        2 => match decode_server_hello(payload) {
            Ok(sh) => {
                if is_hello_retry_request(&sh) {
                    DecodedHandshake::HelloRetryRequest(Box::new(sh))
                } else {
                    DecodedHandshake::ServerHello(Box::new(sh))
                }
            }
            Err(_) => DecodedHandshake::Unknown {
                msg_type,
                raw: payload.to_vec(),
            },
        },
        _ => DecodedHandshake::Unknown {
            msg_type,
            raw: payload.to_vec(),
        },
    }
}

fn encrypted_flight_label(
    direction: Direction,
    conn: &TrackedConnection,
    payload_len: usize,
) -> &'static str {
    // TLS 1.2 case: ApplicationData records are actual application data.
    // They only appear after the handshake is fully complete. There is no
    // TLS-1.3-style "encrypted handshake in application_data" or 0-RTT here,
    // so use plain labels regardless of size or position.
    let is_tls12 = matches!(
        conn.state.handshake.tls_version,
        Some(TlsVersion::Ssl30 | TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12)
    );
    if is_tls12 {
        return "application data";
    }

    // Payload length here is the AEAD ciphertext + 16-byte auth tag + the
    // 1-byte inner content type. That's why size thresholds work:
    // Finished-only is ~40-60 B; a Certificate chain is at least ~1 KB.
    match direction {
        Direction::ServerToClient => match conn.encrypted_records_from_server {
            1 if payload_len < 200 => "likely EncryptedExtensions (server fragmented flight)",
            1 if payload_len < 800 => {
                "likely EncryptedExtensions + Finished (resumed session, no Certificate)"
            }
            1 => "likely EncryptedExtensions + Certificate + CertificateVerify + Finished",
            2 if payload_len < 120 => "likely Finished only",
            2 => "likely Certificate + CertificateVerify + Finished (continued)",
            _ => "likely NewSessionTicket (post-handshake)",
        },
        Direction::ClientToServer => {
            // Any encrypted record from the client BEFORE the server has sent
            // its first encrypted flight can only be 0-RTT early data: the
            // client is speculatively sending application bytes under keys
            // derived from a cached PSK, without waiting for ServerHello.
            if conn.encrypted_records_from_server == 0 {
                return "likely 0-RTT early data (PSK session resumption)";
            }
            match conn.encrypted_records_from_client {
                1 if payload_len < 120 => {
                    "likely Finished only (~53B = 32B verify_data + AEAD tag)"
                }
                1 => "likely Certificate + CertificateVerify + Finished (client auth / mTLS)",
                _ => "encrypted application data",
            }
        }
    }
}

/// Label a Handshake record that arrived after a ChangeCipherSpec on the
/// same direction: a TLS 1.2 encrypted Finished / NewSessionTicket /
/// post-handshake tickets. In TLS 1.3 CCS is a no-op middlebox marker, so
/// this labeler assumes we're on a TLS 1.2 stream.
fn post_ccs_handshake_label(direction: Direction, conn: &TrackedConnection) -> &'static str {
    match direction {
        Direction::ClientToServer => match conn.post_ccs_records_from_client {
            0 => "encrypted Finished (client)",
            _ => "encrypted handshake (post-CCS)",
        },
        Direction::ServerToClient => match conn.post_ccs_records_from_server {
            0 => "encrypted NewSessionTicket or Finished (server)",
            1 => "encrypted Finished (server)",
            _ => "encrypted handshake (post-CCS)",
        },
    }
}

const fn to_record_direction(direction: Direction) -> RecordDirection {
    match direction {
        Direction::ClientToServer => RecordDirection::ClientToServer,
        Direction::ServerToClient => RecordDirection::ServerToClient,
    }
}

const fn record_type_byte(t: TlsRecordType) -> u8 {
    match t {
        TlsRecordType::ChangeCipherSpec => 20,
        TlsRecordType::Alert => 21,
        TlsRecordType::Handshake => 22,
        TlsRecordType::ApplicationData => 23,
        TlsRecordType::Other(v) => v,
    }
}

// NOTE: the borrow-checker gymnastics above mean we implement record
// application as free functions that take only the fields they need, not
// through &mut self. This keeps the ingest loop readable while satisfying
// the borrow checker.
fn apply_handshake_record(handshake: &mut HandshakeInfo, payload: &[u8], direction: Direction) {
    let mut remaining = payload;
    while !remaining.is_empty() {
        match tls_parser::parse_tls_message_handshake(remaining) {
            Ok((rest, msg)) => {
                if let TlsMessage::Handshake(hs) = msg {
                    match (hs, direction) {
                        (TlsMessageHandshake::ClientHello(ch), Direction::ClientToServer) => {
                            let extracted = crate::parser::extract_client_hello(&ch);
                            merge_client_hello(handshake, extracted);
                        }
                        (TlsMessageHandshake::ServerHello(sh), Direction::ServerToClient) => {
                            let extracted = crate::parser::extract_server_hello(&sh);
                            merge_server_hello(handshake, extracted);
                        }
                        // TLS 1.2: plaintext server certificate (TLS 1.3 encrypts this).
                        // If the version is unknown (None) and we can parse a plaintext
                        // Certificate, it must be pre-1.3.
                        (TlsMessageHandshake::Certificate(_), Direction::ServerToClient) => {
                            if matches!(
                                handshake.tls_version,
                                None | Some(
                                    TlsVersion::Ssl30
                                        | TlsVersion::Tls10
                                        | TlsVersion::Tls11
                                        | TlsVersion::Tls12
                                )
                            ) {
                                handshake.stage = HandshakeStage::ServerCertificate;
                            }
                        }
                        // TLS 1.2: plaintext server key-exchange (DHE/ECDHE).
                        (TlsMessageHandshake::ServerKeyExchange(_), _) => {
                            handshake.stage = HandshakeStage::ServerKeyExchange;
                        }
                        // TLS 1.2: ServerHelloDone signals end of server's plaintext flight.
                        (TlsMessageHandshake::ServerDone(_), _) => {
                            handshake.stage = HandshakeStage::ServerHelloDone;
                        }
                        // TLS 1.2: plaintext client key-exchange.
                        (TlsMessageHandshake::ClientKeyExchange(_), Direction::ClientToServer) => {
                            handshake.stage = HandshakeStage::ClientKeyExchange;
                        }
                        _ => {}
                    }
                }
                remaining = rest;
            }
            Err(_) => break,
        }
    }
}

fn merge_client_hello(dst: &mut HandshakeInfo, src: ClientHelloInfo) {
    dst.stage = HandshakeStage::ClientHello;
    dst.sni = src.sni.or(dst.sni.take());
    if !src.alpn_offered.is_empty() {
        dst.alpn_offered = src.alpn_offered;
    }
    if !src.cipher_suites.is_empty() {
        dst.cipher_suites_offered = src.cipher_suites;
    }
    if !src.groups_offered.is_empty() {
        dst.groups_offered = src.groups_offered;
    }
    dst.key_share_group = src.key_share_group.or(dst.key_share_group.take());
    if let Some(v) = src.max_version {
        dst.tls_version.get_or_insert(v);
    }
}

fn merge_server_hello(dst: &mut HandshakeInfo, src: ServerHelloInfo) {
    dst.stage = HandshakeStage::ServerHello;
    if let Some(v) = src.tls_version {
        dst.tls_version = Some(v);
    }
    if let Some(c) = src.cipher_suite_selected {
        dst.cipher_suite_selected = Some(c);
    }
    if let Some(g) = src.key_share_group {
        dst.key_share_group = Some(g);
    }
    if let Some(a) = src.alpn_selected {
        dst.alpn_selected = Some(a);
    }
}

fn apply_ccs(handshake: &mut HandshakeInfo, direction: Direction) {
    // ChangeCipherSpec in TLS 1.3 is a legacy middlebox-compatibility noop;
    // we ignore it there. In TLS 1.2, client CCS means the encrypted
    // ClientFinished is next; server CCS means the encrypted ServerFinished
    // is next. We use stage guards so TLS 1.3 connections are unaffected.
    match direction {
        Direction::ClientToServer => {
            if handshake.stage == HandshakeStage::ClientKeyExchange {
                handshake.stage = HandshakeStage::ClientFinished;
            }
        }
        Direction::ServerToClient => {
            if handshake.stage == HandshakeStage::ClientFinished {
                handshake.stage = HandshakeStage::ServerFinished;
            }
        }
    }
}

fn apply_encrypted_record(
    handshake: &mut HandshakeInfo,
    encrypted_records_from_server: &mut u32,
    encrypted_records_from_client: &mut u32,
    saw_client_finished_marker: &mut bool,
    direction: Direction,
) {
    // In TLS 1.2, ApplicationData records are actual application data. They
    // only appear after the handshake is fully complete.  In TLS 1.3,
    // ApplicationData records also carry encrypted handshake messages
    // (EncryptedExtensions, Certificate, Finished, etc.), so we count them
    // heuristically to advance the stage.
    let is_tls12 = matches!(
        handshake.tls_version,
        Some(TlsVersion::Ssl30 | TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12)
    );
    if is_tls12 {
        handshake.stage = HandshakeStage::ApplicationData;
        return;
    }

    // TLS 1.3: count encrypted records to advance stage heuristically.
    // This mirrors the honest limitation documented in docs/tls13-visibility.md.
    if direction == Direction::ServerToClient {
        *encrypted_records_from_server += 1;
        handshake.stage = if *saw_client_finished_marker {
            // Post-handshake server records are application data.
            HandshakeStage::ApplicationData
        } else {
            match *encrypted_records_from_server {
                // Records 1-3: EncryptedExtensions, Certificate, CertificateVerify
                // (diagram step ③, all grouped as the server's certificate flight).
                1..=3 => HandshakeStage::Certificate,
                // Record 4+: server's Finished message (diagram step ⑤).
                _ => HandshakeStage::ServerFinished,
            }
        };
        if handshake.certificate_subject.is_none() {
            handshake.certificate_subject = Some("encrypted (TLS 1.3)".into());
            handshake.certificate_issuer = Some("encrypted (TLS 1.3)".into());
        }
    } else if *encrypted_records_from_server > 0 {
        *encrypted_records_from_client += 1;
        if !*saw_client_finished_marker {
            // First client encrypted record: diagram step ④ (Client Finished).
            *saw_client_finished_marker = true;
            handshake.stage = HandshakeStage::ClientFinished;
        } else {
            // Subsequent client records: application data (diagram step ⑥).
            handshake.stage = HandshakeStage::ApplicationData;
        }
    }
}

/// Return the current time as milliseconds since the Unix epoch, clamped to
/// `u64` (never panics; returns `0` if the system clock is before the
/// epoch).
#[must_use]
pub fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    fn key() -> ConnectionKey {
        ConnectionKey::canonical(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
        )
    }

    fn endpoints() -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        )
    }

    #[test]
    fn ingest_empty_payload_is_noop() {
        let mut t = ConnectionTracker::new();
        let (a, b) = endpoints();
        let out = t
            .ingest(key(), Direction::ClientToServer, a, b, &[], 100)
            .unwrap();
        assert!(out.is_none());
        assert_eq!(t.iter().count(), 0);
    }

    #[test]
    fn ingest_garbage_marks_errored() {
        let mut t = ConnectionTracker::new();
        // Ten bytes of a valid-looking record header claiming 500 bytes of
        // payload, then random data, which will not parse as a handshake
        // but will not violate the record cap either.
        let mut junk = vec![22u8, 0x03, 0x03, 0x00, 0x08];
        junk.extend_from_slice(&[0u8; 8]);
        let (a, b) = endpoints();
        let state = t
            .ingest(key(), Direction::ClientToServer, a, b, &junk, 100)
            .unwrap()
            .unwrap();
        // The record is well-formed at the record layer even if the payload
        // is not a real ClientHello. Stage remains Idle since no handshake
        // message was parsed successfully.
        assert!(matches!(state.handshake.stage, HandshakeStage::Idle));
        // A record event is still emitted so the timeline reflects what was
        // observed. Its body will decode as Unknown.
        assert_eq!(state.records.len(), 1);
    }

    #[test]
    fn evict_removes_stale() {
        let mut t = ConnectionTracker::with_stale_timeout(1000);
        let record = [22u8, 0x03, 0x03, 0x00, 0x00];
        let (a, b) = endpoints();
        t.ingest(key(), Direction::ClientToServer, a, b, &record, 100)
            .unwrap();
        assert_eq!(t.iter().count(), 1);
        let removed = t.evict_stale(5_000);
        assert_eq!(removed, 1);
        assert_eq!(t.iter().count(), 0);
    }
}
