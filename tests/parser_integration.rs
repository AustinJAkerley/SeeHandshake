// SPDX-License-Identifier: MIT

//! End-to-end tests that exercise `parse_records` + `parse_client_hello` /
//! `parse_server_hello` and the tracker's reassembly path against real
//! TLS 1.3 handshake bytes from RFC 8448.

use std::net::{IpAddr, Ipv4Addr};

use seehandshake::model::connection::Direction;
use seehandshake::model::tls::{CipherSuite, NamedGroup, TlsVersion};
use seehandshake::model::{ConnectionKey, HandshakeStage};
use seehandshake::parser::{parse_client_hello, parse_records, parse_server_hello, TlsRecordType};
use seehandshake::tracker::ConnectionTracker;

const CLIENT_HELLO_RECORD: &[u8] = include_bytes!("data/client_hello_tls13.bin");
const SERVER_HELLO_RECORD: &[u8] = include_bytes!("data/server_hello_tls13.bin");

fn key() -> ConnectionKey {
    ConnectionKey::canonical(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        54321,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
    )
}

#[test]
fn records_frame_cleanly() {
    let (records, consumed) = parse_records(CLIENT_HELLO_RECORD).expect("parse ok");
    assert_eq!(consumed, CLIENT_HELLO_RECORD.len());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_type, TlsRecordType::Handshake);

    let (records, consumed) = parse_records(SERVER_HELLO_RECORD).expect("parse ok");
    assert_eq!(consumed, SERVER_HELLO_RECORD.len());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_type, TlsRecordType::Handshake);
}

#[test]
fn client_hello_extracts_expected_fields() {
    let (records, _) = parse_records(CLIENT_HELLO_RECORD).unwrap();
    let info = parse_client_hello(records[0].payload).expect("parse client hello");

    assert_eq!(info.sni.as_deref(), Some("server"));
    assert!(info.cipher_suites.contains(&CipherSuite::Aes128GcmSha256));
    assert!(info
        .cipher_suites
        .contains(&CipherSuite::Chacha20Poly1305Sha256));
    assert!(info.cipher_suites.contains(&CipherSuite::Aes256GcmSha384));
    assert!(info.groups_offered.contains(&NamedGroup::X25519));
    assert_eq!(info.key_share_group, Some(NamedGroup::X25519));
    assert_eq!(info.max_version, Some(TlsVersion::Tls13));
}

#[test]
fn server_hello_extracts_expected_fields() {
    let (records, _) = parse_records(SERVER_HELLO_RECORD).unwrap();
    let info = parse_server_hello(records[0].payload).expect("parse server hello");

    assert_eq!(info.tls_version, Some(TlsVersion::Tls13));
    assert_eq!(
        info.cipher_suite_selected,
        Some(CipherSuite::Aes128GcmSha256)
    );
    assert_eq!(info.key_share_group, Some(NamedGroup::X25519));
}

#[test]
fn tracker_walks_stages_from_client_to_server_hello() {
    let mut tracker = ConnectionTracker::new();
    let k = key();

    let state = tracker
        .ingest(k, Direction::ClientToServer, CLIENT_HELLO_RECORD, 1_000)
        .unwrap()
        .unwrap();
    assert_eq!(state.handshake.stage, HandshakeStage::ClientHello);
    assert_eq!(state.handshake.sni.as_deref(), Some("server"));

    let state = tracker
        .ingest(k, Direction::ServerToClient, SERVER_HELLO_RECORD, 1_100)
        .unwrap()
        .unwrap();
    assert_eq!(state.handshake.stage, HandshakeStage::ServerHello);
    assert_eq!(state.handshake.tls_version, Some(TlsVersion::Tls13));
    assert_eq!(
        state.handshake.cipher_suite_selected,
        Some(CipherSuite::Aes128GcmSha256)
    );
    assert_eq!(state.handshake.key_share_group, Some(NamedGroup::X25519));
}

#[test]
fn tracker_reassembles_client_hello_across_three_segments() {
    let mut tracker = ConnectionTracker::new();
    let k = key();

    let third = CLIENT_HELLO_RECORD.len() / 3;
    let (a, rest) = CLIENT_HELLO_RECORD.split_at(third);
    let (b, c) = rest.split_at(third);

    let s = tracker.ingest(k, Direction::ClientToServer, a, 10).unwrap();
    // Partial: stage should remain Idle until a whole record has arrived.
    assert!(s.is_some());
    assert_eq!(s.unwrap().handshake.stage, HandshakeStage::Idle);

    let s = tracker.ingest(k, Direction::ClientToServer, b, 11).unwrap();
    assert!(s.is_some());
    assert_eq!(s.unwrap().handshake.stage, HandshakeStage::Idle);

    let s = tracker
        .ingest(k, Direction::ClientToServer, c, 12)
        .unwrap()
        .unwrap();
    assert_eq!(s.handshake.stage, HandshakeStage::ClientHello);
    assert_eq!(s.handshake.sni.as_deref(), Some("server"));
}

#[test]
fn parser_never_panics_on_random_bytes() {
    // Fuzz-lite: feed a deterministic PRNG stream of increasing length; the
    // parser must always return either Ok(...) or Err(_) — never panic.
    let mut state: u64 = 0xDEAD_BEEF_CAFE_F00D;
    for len in 0..10_000usize {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let mut buf = vec![0u8; len % 512];
        for (i, byte) in buf.iter_mut().enumerate() {
            let mix = state ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            *byte = u8::try_from(mix & 0xff).unwrap_or(0);
        }
        let _ = parse_records(&buf);
        let _ = parse_client_hello(&buf);
        let _ = parse_server_hello(&buf);
    }
}
