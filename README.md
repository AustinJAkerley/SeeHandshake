# SeeHandshake

> Visualize TLS handshakes in your terminal, in real time.

`seehandshake` is a passive TLS handshake observer. It captures packets on a
chosen network interface, reassembles TLS records off the TCP stream, parses
the plaintext portions of the handshake (TLS 1.3 `ClientHello` and
`ServerHello`), and renders each connection in a three-panel Ratatui interface
with an optional educational overlay that explains what each message does and
why it exists.

Think of it as *htop meets Wireshark meets an interactive TLS textbook.*

## Status

Early development. The MVP targets TLS 1.3 visualization; see the
[roadmap](#roadmap) for what is coming next.

## Screenshots

*(Screenshots will land here once the UI stabilizes.)*

## What you can see, and what you cannot

TLS 1.3 encrypts every handshake message *after* `ServerHello` under keys
derived from the server's ephemeral private key. A passive observer without
those keys cannot decrypt `EncryptedExtensions`, `Certificate`,
`CertificateVerify`, or `Finished`.

`seehandshake` is honest about this:

- `ClientHello` and `ServerHello` are parsed in full (SNI, ALPN offered/chosen,
  cipher suites offered/chosen, supported groups, key share group, TLS
  version).
- Later stages are detected from encrypted record boundaries and labeled
  accordingly. The certificate Subject/Issuer fields display
  `encrypted (TLS 1.3)` for pure TLS 1.3 connections.

See [`docs/tls13-visibility.md`](docs/tls13-visibility.md) for the full
explanation. Support for `SSLKEYLOGFILE`-based decryption and for TLS 1.2
(where the certificate is sent in plaintext) is planned.

## Install

### From source (Cargo)

```
cargo install --path .
```

Requires:

- Rust 1.74 or newer
- `libpcap` development headers
  - Debian/Ubuntu: `sudo apt install libpcap-dev`
  - Fedora: `sudo dnf install libpcap-devel`
  - macOS: preinstalled with the system; no action needed
  - Windows: install the [Npcap SDK](https://npcap.com/#download)

### From apt (planned)

The project is being designed with eventual submission to the Debian
repositories in mind; once accepted this will become `sudo apt install
seehandshake`.

### From Homebrew (planned)

A tap will be published once the release process stabilizes.

## Permissions

Live packet capture requires elevated privileges.

- **Linux**: either run as root, or grant the binary the required
  capabilities:

  ```
  sudo setcap cap_net_raw,cap_net_admin=eip $(which seehandshake)
  ```

- **macOS**: `/dev/bpf*` devices must be readable by the invoking user, or
  run with `sudo`.
- **Windows**: install Npcap and run from an Administrator terminal.

## Quickstart

```
seehandshake --list-interfaces        # list available interfaces
seehandshake --interface en0          # capture on en0
seehandshake                          # capture on the default interface
```

Then, in another terminal:

```
curl https://example.com
```

The connection will appear in the left panel, the center panel animates the
handshake progression, and the right panel populates the negotiated
parameters. Press `e` to toggle educational explanations. Press `q` to quit.

## Architecture

```
┌──────────┐   frames    ┌───────────────┐   updates    ┌────────┐
│ capture  │────────────▶│ parser+track  │─────────────▶│   UI   │
│ (pcap)   │             │ (etherparse + │              │(Ratatui)│
│          │             │  tls-parser)  │              │        │
└──────────┘             └───────────────┘              └────────┘
      ▲                          │                           │
      │                          │                           │
   PacketSource              HandshakeInfo               keyboard
   trait (swappable          (serde::Serialize:          (crossterm)
   for pcap files,           export-ready)
   test mocks)
```

Three threads, connected by `std::sync::mpsc` channels — no global mutable
state, no async runtime. See [`docs/architecture.md`](docs/architecture.md).

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — module and threading model
- [`docs/tls13-visibility.md`](docs/tls13-visibility.md) — what a passive
  observer can and cannot see
- [`docs/development.md`](docs/development.md) — building, testing, and
  running the TUI locally
- [`docs/packaging.md`](docs/packaging.md) — cutting releases and shipping
  through crates.io, apt, Homebrew, AUR, Nix, MacPorts, and winget
- `cargo doc --open` — full API reference

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Security

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## Roadmap

Design decisions in the MVP already leave room for:

- TLS 1.2 support (plaintext certificate parsing)
- `SSLKEYLOGFILE` decryption
- PCAP file import (offline analysis)
- JSON, Markdown, and Mermaid export
- Certificate chain visualization
- Live traffic statistics
- Session resumption visualization
- Terminal themes
- Plugin architecture

## License

MIT — see [`LICENSE`](LICENSE).
