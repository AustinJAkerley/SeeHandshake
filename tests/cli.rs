// SPDX-License-Identifier: MIT

//! CLI-level integration tests.
//!
//! Live packet capture is not exercised here — that requires elevated
//! privileges and a network interface, neither of which is portable across
//! CI environments. What we do cover:
//!
//! - `--help` prints usage and exits 0.
//! - `--version` prints a semver and exits 0.
//! - Unknown flags exit non-zero with an error message on stderr.
//!
//! `--list-interfaces` is not asserted on because on hardened CI runners
//! `pcap_findalldevs` may return an empty list rather than an error, which
//! would make the test flaky across platforms.

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("seehandshake").expect("bin exists")
}

#[test]
fn help_prints_usage() {
    bin()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"))
        .stdout(predicate::str::contains("--interface"))
        .stdout(predicate::str::contains("--bpf"));
}

#[test]
fn version_prints_semver() {
    bin()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"\d+\.\d+\.\d+").unwrap());
}

#[test]
fn unknown_flag_errors() {
    bin()
        .arg("--this-flag-does-not-exist")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}
