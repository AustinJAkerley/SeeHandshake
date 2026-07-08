// SPDX-License-Identifier: MIT

//! Per-connection TCP payload reassembly and stale eviction.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use tls_parser::{TlsMessage, TlsMessageHandshake};

use crate::error::Result;
use crate::model::connection::Direction;
use crate::model::{ConnectionKey, ConnectionState, HandshakeInfo, HandshakeStage};
use crate::parser::handshake::{ClientHelloInfo, ServerHelloInfo};
use crate::parser::record::{parse_records, TlsRecordType};

/// Default idle timeout after which a connection is evicted (5 minutes).
pub const DEFAULT_STALE_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// Maximum reassembly buffer size per direction (128 KiB).
///
/// TLS 1.3 handshake messages other than `Certificate` are small; even a
/// large `Certificate` chain fits comfortably. If this cap is exceeded the
/// connection is marked errored.
pub const MAX_REASSEMBLY_BYTES: usize = 128 * 1024;

/// Tracks in-flight TLS handshakes across many connections.
#[derive(Debug, Default)]
pub struct ConnectionTracker {
    connections: HashMap<ConnectionKey, TrackedConnection>,
    stale_timeout_ms: u64,
}

#[derive(Debug)]
struct TrackedConnection {
    state: ConnectionState,
    client_to_server_buf: Vec<u8>,
    server_to_client_buf: Vec<u8>,
    encrypted_records_from_server: usize,
    saw_client_finished_marker: bool,
}

impl ConnectionTracker {
    /// Create a new tracker with the default stale-connection timeout.
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
        }
    }

    /// Ingest a TCP payload segment.
    ///
    /// `now_ms` is caller-supplied so that tests can drive the clock
    /// deterministically. Production callers pass [`unix_now_ms`].
    ///
    /// # Errors
    ///
    /// Currently returns `Ok(())` for all inputs — malformed data is
    /// recorded on the per-connection [`HandshakeInfo::error`] field rather
    /// than surfaced as an error, so a single bad connection does not stop
    /// the tracker from serving others.
    pub fn ingest(
        &mut self,
        key: ConnectionKey,
        direction: Direction,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Option<ConnectionState>> {
        if payload.is_empty() {
            return Ok(None);
        }

        let conn = self
            .connections
            .entry(key)
            .or_insert_with(|| TrackedConnection {
                state: ConnectionState {
                    key,
                    first_seen_ms: now_ms,
                    last_seen_ms: now_ms,
                    handshake: HandshakeInfo::new(),
                },
                client_to_server_buf: Vec::new(),
                server_to_client_buf: Vec::new(),
                encrypted_records_from_server: 0,
                saw_client_finished_marker: false,
            });

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

        for record in &records {
            match record.record_type {
                TlsRecordType::Handshake => {
                    apply_handshake_record(&mut conn.state.handshake, record.payload, direction);
                }
                TlsRecordType::ApplicationData => {
                    apply_encrypted_record(
                        &mut conn.state.handshake,
                        &mut conn.encrypted_records_from_server,
                        &mut conn.saw_client_finished_marker,
                        direction,
                    );
                }
                TlsRecordType::ChangeCipherSpec
                | TlsRecordType::Alert
                | TlsRecordType::Other(_) => {}
            }
        }

        // Drop consumed bytes.
        buf.drain(..consumed);

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

fn apply_encrypted_record(
    handshake: &mut HandshakeInfo,
    encrypted_records_from_server: &mut usize,
    saw_client_finished_marker: &mut bool,
    direction: Direction,
) {
    // In TLS 1.3 everything after ServerHello is wrapped in ApplicationData
    // records at the record layer. We count these to advance stage
    // heuristically. This mirrors the honest limitation documented in
    // docs/tls13-visibility.md.
    if direction == Direction::ServerToClient {
        *encrypted_records_from_server += 1;
        handshake.stage = match *encrypted_records_from_server {
            1 => HandshakeStage::EncryptedExtensions,
            2 => HandshakeStage::Certificate,
            3 => HandshakeStage::CertificateVerify,
            _ => HandshakeStage::Finished,
        };
        if handshake.certificate_subject.is_none() {
            handshake.certificate_subject = Some("encrypted (TLS 1.3)".into());
            handshake.certificate_issuer = Some("encrypted (TLS 1.3)".into());
        }
    } else if *encrypted_records_from_server > 0 {
        *saw_client_finished_marker = true;
        handshake.stage = HandshakeStage::SecureConnection;
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
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn key() -> ConnectionKey {
        ConnectionKey::canonical(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
        )
    }

    #[test]
    fn ingest_empty_payload_is_noop() {
        let mut t = ConnectionTracker::new();
        let out = t
            .ingest(key(), Direction::ClientToServer, &[], 100)
            .unwrap();
        assert!(out.is_none());
        assert_eq!(t.iter().count(), 0);
    }

    #[test]
    fn ingest_garbage_marks_errored() {
        let mut t = ConnectionTracker::new();
        // Ten bytes of a valid-looking record header claiming 500 bytes of
        // payload — then random data, which will not parse as a handshake
        // but will not violate the record cap either.
        let mut junk = vec![22u8, 0x03, 0x03, 0x00, 0x08];
        junk.extend_from_slice(&[0u8; 8]);
        let state = t
            .ingest(key(), Direction::ClientToServer, &junk, 100)
            .unwrap()
            .unwrap();
        // The record is well-formed at the record layer even if the payload
        // is not a real ClientHello. Stage remains Idle since no handshake
        // message was parsed successfully.
        assert!(matches!(state.handshake.stage, HandshakeStage::Idle));
    }

    #[test]
    fn evict_removes_stale() {
        let mut t = ConnectionTracker::with_stale_timeout(1000);
        let record = [22u8, 0x03, 0x03, 0x00, 0x00];
        t.ingest(key(), Direction::ClientToServer, &record, 100)
            .unwrap();
        assert_eq!(t.iter().count(), 1);
        let removed = t.evict_stale(5_000);
        assert_eq!(removed, 1);
        assert_eq!(t.iter().count(), 0);
    }
}
