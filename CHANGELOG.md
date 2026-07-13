# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] — 2026-07-12

### Fixed
- Release CI: aarch64 (Linux ARM64) cross-compile job failed on Ubuntu 24.04
  runners because the apt source rewrite targeted the legacy
  `/etc/apt/sources.list`; noble uses the deb822 `ubuntu.sources` file, so the
  default mirrors were queried for arm64 indexes and returned 404. The default
  mirrors are now pinned to amd64 and arm64 packages come from
  `ports.ubuntu.com`.

## [1.0.0] — 2026-07-12

### Added
- Project scaffolding, license, contributor documentation.
- Library + binary crate layout targeting future Debian packaging.
- CLI surface: `--interface`, `--list-interfaces`, `--bpf`, `--log-level`,
  `--help`, `--version`.
- TLS record and handshake parser for TLS 1.3 `ClientHello` and `ServerHello`,
  including SNI, ALPN, cipher suites, supported groups, and key share group
  extraction.
- Per-connection TCP payload reassembly.
- Connection tracker with stale-connection eviction.
- Live packet capture via `libpcap` with a `PacketSource` trait for future
  offline PCAP replay and testing.
- Three-panel Ratatui interface: connections list, animated handshake flow,
  metadata pane.
- Educational mode toggle (`e`).
- Continuous integration on Ubuntu, macOS, and Windows.
- Release automation for Linux x86_64, Linux ARM64, macOS Intel, macOS Apple
  Silicon, and Windows x64.

[Unreleased]: https://github.com/OWNER/SeeHandshake/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/OWNER/SeeHandshake/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/OWNER/SeeHandshake/releases/tag/v1.0.0
