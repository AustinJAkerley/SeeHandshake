// SPDX-License-Identifier: MIT

//! End-to-end tests that exercise `parse_records` + `parse_client_hello` /
//! `parse_server_hello` and the tracker's reassembly path against real
//! TLS 1.3 handshake bytes from RFC 8448.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use seehandshake::model::connection::Direction;
use seehandshake::model::record::{DecodedHandshake, RecordBody, RecordDirection};
use seehandshake::model::tls::{CipherSuite, NamedGroup, TlsVersion};
use seehandshake::model::{ConnectionKey, HandshakeStage};
use seehandshake::origin::{FixedResolver, Origin, ProcessOrigin};
use seehandshake::parser::{
    decode_client_hello, decode_server_hello, parse_client_hello, parse_records,
    parse_server_hello, TlsRecordType,
};
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

fn endpoints() -> (SocketAddr, SocketAddr) {
    (
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 54321),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
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
    let (a, b) = endpoints();

    let state = tracker
        .ingest(
            k,
            Direction::ClientToServer,
            a,
            b,
            CLIENT_HELLO_RECORD,
            1_000,
        )
        .unwrap()
        .unwrap();
    assert_eq!(state.handshake.stage, HandshakeStage::ClientHello);
    assert_eq!(state.handshake.sni.as_deref(), Some("server"));
    // The record is logged into the timeline for the detail view.
    assert_eq!(state.records.len(), 1);
    assert_eq!(state.records[0].direction, RecordDirection::ClientToServer);
    assert!(matches!(
        state.records[0].body,
        RecordBody::Handshake(DecodedHandshake::ClientHello(_))
    ));

    let state = tracker
        .ingest(
            k,
            Direction::ServerToClient,
            b,
            a,
            SERVER_HELLO_RECORD,
            1_100,
        )
        .unwrap()
        .unwrap();
    assert_eq!(state.handshake.stage, HandshakeStage::ServerHello);
    assert_eq!(state.handshake.tls_version, Some(TlsVersion::Tls13));
    assert_eq!(
        state.handshake.cipher_suite_selected,
        Some(CipherSuite::Aes128GcmSha256)
    );
    assert_eq!(state.handshake.key_share_group, Some(NamedGroup::X25519));
    assert!(state.records.len() >= 2);
    assert_eq!(state.records[1].direction, RecordDirection::ServerToClient);
    assert!(matches!(
        state.records[1].body,
        RecordBody::Handshake(DecodedHandshake::ServerHello(_))
    ));
}

#[test]
fn tracker_reassembles_client_hello_across_three_segments() {
    let mut tracker = ConnectionTracker::new();
    let k = key();
    let (a, b) = endpoints();

    let third = CLIENT_HELLO_RECORD.len() / 3;
    let (p1, rest) = CLIENT_HELLO_RECORD.split_at(third);
    let (p2, p3) = rest.split_at(third);

    let s = tracker
        .ingest(k, Direction::ClientToServer, a, b, p1, 10)
        .unwrap();
    // Partial: stage should remain Idle until a whole record has arrived.
    assert!(s.is_some());
    assert_eq!(s.unwrap().handshake.stage, HandshakeStage::Idle);

    let s = tracker
        .ingest(k, Direction::ClientToServer, a, b, p2, 11)
        .unwrap();
    assert!(s.is_some());
    assert_eq!(s.unwrap().handshake.stage, HandshakeStage::Idle);

    let s = tracker
        .ingest(k, Direction::ClientToServer, a, b, p3, 12)
        .unwrap()
        .unwrap();
    assert_eq!(s.handshake.stage, HandshakeStage::ClientHello);
    assert_eq!(s.handshake.sni.as_deref(), Some("server"));
}

#[test]
fn tracker_resolves_origin_once_from_supplied_resolver() {
    let expected = Origin::Local(ProcessOrigin {
        pid: 4242,
        comm: "curl".into(),
        cmdline: "curl https://example.com".into(),
        uid: 1000,
    });
    let mut tracker = ConnectionTracker::with_resolver(Box::new(FixedResolver(expected.clone())));
    let k = key();
    let (a, b) = endpoints();

    let state = tracker
        .ingest(k, Direction::ClientToServer, a, b, CLIENT_HELLO_RECORD, 1)
        .unwrap()
        .unwrap();
    assert_eq!(state.handshake.origin.as_ref(), Some(&expected));

    // A second packet on the same connection does NOT re-resolve; the
    // cached answer persists even if the resolver would now say something
    // else. (FixedResolver returns the same thing, but the shape of this
    // assertion documents the caching invariant.)
    let state = tracker
        .ingest(k, Direction::ServerToClient, b, a, SERVER_HELLO_RECORD, 2)
        .unwrap()
        .unwrap();
    assert_eq!(state.handshake.origin.as_ref(), Some(&expected));
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
        let _ = decode_client_hello(&buf);
        let _ = decode_server_hello(&buf);
    }
}

#[test]
fn decode_client_hello_breaks_out_extensions() {
    let (records, _) = parse_records(CLIENT_HELLO_RECORD).unwrap();
    let ch = decode_client_hello(records[0].payload).expect("decode client hello");

    assert_eq!(ch.legacy_version, 0x0303);
    assert_eq!(ch.random.len(), 32);
    // At least three cipher suites offered, including AES128-GCM.
    assert!(ch.cipher_suites.len() >= 3);
    assert!(ch.cipher_suites.iter().any(|(code, _)| *code == 0x1301));
    // Extensions include server_name, supported_versions, key_share.
    let names: Vec<&str> = ch.extensions.iter().map(|e| e.name).collect();
    assert!(names.contains(&"server_name"));
    assert!(names.contains(&"supported_versions"));
    assert!(names.contains(&"key_share"));
}

#[test]
fn decode_server_hello_breaks_out_extensions() {
    let (records, _) = parse_records(SERVER_HELLO_RECORD).unwrap();
    let sh = decode_server_hello(records[0].payload).expect("decode server hello");

    assert_eq!(sh.legacy_version, 0x0303);
    assert_eq!(sh.cipher_suite.0, 0x1301);
    let names: Vec<&str> = sh.extensions.iter().map(|e| e.name).collect();
    assert!(names.contains(&"supported_versions"));
    assert!(names.contains(&"key_share"));
}
