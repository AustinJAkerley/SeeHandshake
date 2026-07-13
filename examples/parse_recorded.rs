// SPDX-License-Identifier: MIT

//! Read a recorded TLS handshake message from disk and print the extracted
//! fields.
//!
//! Usage:
//!
//! ```sh
//! cargo run --example parse_recorded -- tests/data/client_hello_tls13.bin
//! cargo run --example parse_recorded -- tests/data/server_hello_tls13.bin
//! ```
//!
//! Input is a raw `TLSPlaintext` record (five-byte header followed by the
//! handshake payload). The example dispatches on the handshake message type
//! and prints a human-readable summary.

use std::env;
use std::fs;
use std::process::ExitCode;

use seehandshake::parser::{parse_client_hello, parse_records, parse_server_hello, TlsRecordType};

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: parse_recorded <path-to-tls-record.bin>");
        return ExitCode::from(64);
    };

    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read {path}: {e}");
            return ExitCode::from(66);
        }
    };

    let (records, consumed) = match parse_records(&bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("record parse error: {e}");
            return ExitCode::from(65);
        }
    };
    println!(
        "parsed {} record(s), {consumed}/{} bytes consumed",
        records.len(),
        bytes.len()
    );

    for (i, record) in records.iter().enumerate() {
        println!("\n--- record #{i} ---");
        println!("type:           {:?}", record.record_type);
        println!("legacy version: 0x{:04x}", record.legacy_version);
        println!("payload len:    {}", record.payload.len());

        if record.record_type != TlsRecordType::Handshake {
            continue;
        }
        if let Ok(ch) = parse_client_hello(record.payload) {
            println!("kind:           ClientHello");
            println!("sni:            {:?}", ch.sni);
            println!("alpn offered:   {:?}", ch.alpn_offered);
            println!("cipher suites:  {:?}", ch.cipher_suites);
            println!("groups offered: {:?}", ch.groups_offered);
            println!("key share:      {:?}", ch.key_share_group);
            println!("max version:    {:?}", ch.max_version);
        } else if let Ok(sh) = parse_server_hello(record.payload) {
            println!("kind:           ServerHello");
            println!("tls version:    {:?}", sh.tls_version);
            println!("cipher:         {:?}", sh.cipher_suite_selected);
            println!("key share:      {:?}", sh.key_share_group);
            println!("alpn:           {:?}", sh.alpn_selected);
        } else {
            println!("kind:           (unrecognized handshake payload)");
        }
    }

    ExitCode::SUCCESS
}
