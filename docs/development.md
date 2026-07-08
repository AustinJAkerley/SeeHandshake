# Local Development, Testing, and Running

This document walks a new contributor from a fresh checkout to a running
binary. It complements [`CONTRIBUTING.md`](../CONTRIBUTING.md), which covers
the social side of the project (commit style, PR checklist, DCO).

## Prerequisites

| Requirement | Debian/Ubuntu | Fedora | macOS | Windows |
|---|---|---|---|---|
| Rust toolchain (>= 1.74) | [`rustup`](https://rustup.rs) | [`rustup`](https://rustup.rs) | [`rustup`](https://rustup.rs) | [`rustup`](https://rustup.rs) |
| C compiler + pkg-config | `sudo apt install build-essential pkg-config` | `sudo dnf install @development-tools pkgconf` | Xcode Command Line Tools (`xcode-select --install`) | MSVC via Visual Studio Build Tools |
| libpcap headers | `sudo apt install libpcap-dev` | `sudo dnf install libpcap-devel` | preinstalled | [Npcap SDK](https://npcap.com/#download) |

Verify the toolchain:

```
rustc --version    # >= 1.74.0
cargo --version
```

## Clone and build

```
git clone https://github.com/<owner>/SeeHandshake.git
cd SeeHandshake
cargo build
```

The first build downloads and compiles every dependency (a few minutes on a
warm laptop). Subsequent incremental builds finish in seconds.

## Running the test suite

The full test matrix is fast — under one second on typical hardware — because
no test touches the network or requires elevated privileges.

```
cargo test
```

That command runs, in order:

1. **Unit tests** (`src/**/tests` — 19 tests): decoder edge cases,
   `ConnectionKey` canonicalization, tracker eviction, cipher-suite display
   formatting.
2. **CLI tests** (`tests/cli.rs` — 3 tests, via `assert_cmd`): `--help`,
   `--version`, and an unknown-flag failure path.
3. **Parser integration tests** (`tests/parser_integration.rs` — 6 tests):
   full record → handshake → tracker pipeline against the RFC 8448
   `ClientHello` / `ServerHello` fixtures in [`tests/data/`](../tests/data/),
   plus a 10 000-iteration fuzz-lite loop that asserts the parser never
   panics on random bytes.
4. **Doc-tests**: any executable examples in rustdoc.

### Running one test

```
cargo test client_hello_extracts_expected_fields
cargo test --test parser_integration
cargo test --lib parser::record
```

### Verbose output

```
cargo test -- --nocapture             # show println! output
RUST_LOG=trace cargo test -- --nocapture
```

## Lint gates

Every one of these must pass locally before opening a PR. CI runs the same
commands on Linux/macOS/Windows.

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

To apply formatting fixes in place:

```
cargo fmt --all
```

## Running the example (no root, no network)

The [`examples/parse_recorded.rs`](../examples/parse_recorded.rs) helper
decodes a raw `TLSPlaintext` record from disk and prints the extracted
fields. Use it to sanity-check the parser without needing a live capture:

```
cargo run --example parse_recorded -- tests/data/client_hello_tls13.bin
cargo run --example parse_recorded -- tests/data/server_hello_tls13.bin
```

Expected output ends with lines like:

```
sni:            Some("server")
cipher suites:  [Aes128GcmSha256, Chacha20Poly1305Sha256, Aes256GcmSha384]
key share:      Some(X25519)
max version:    Some(Tls13)
```

## Running the live TUI

Live packet capture requires elevated privileges. Pick one of the strategies
below rather than routinely running Rust builds as root — that avoids
`target/` ending up owned by root and forcing `sudo cargo clean`.

### Linux — grant capabilities to the binary

```
cargo build
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/seehandshake
./target/debug/seehandshake --list-interfaces
./target/debug/seehandshake --interface <iface>
```

Re-run `setcap` after every rebuild; capabilities are stored on the inode and
are cleared when Cargo replaces the file.

### macOS — grant BPF device access

Either open the BPF devices to the invoking user (recommended for a dev
loop):

```
sudo chown $USER /dev/bpf*
./target/debug/seehandshake --interface en0
```

or run with `sudo`:

```
sudo ./target/debug/seehandshake --interface en0
```

### Windows — run from an Administrator terminal

Install [Npcap](https://npcap.com/#download) with the "Support raw 802.11
traffic" option unchecked (unless you know you want it). Open PowerShell as
Administrator, then:

```
.\target\debug\seehandshake.exe --list-interfaces
.\target\debug\seehandshake.exe --interface "Ethernet"
```

### Generating traffic

With the TUI running, generate a handshake from another terminal:

```
curl https://example.com
```

You should see:

- A new row in the **Connections** panel (left).
- The **Handshake** panel (center) animate through `ClientHello`,
  `ServerHello`, then encrypted stages.
- The **Metadata** panel (right) populate `SNI=example.com`, cipher, key
  exchange group. Certificate fields will read `encrypted (TLS 1.3)` — see
  [`tls13-visibility.md`](tls13-visibility.md) for why.

Keyboard controls:

| Key | Action |
|---|---|
| `↑` / `↓` | Select previous / next connection |
| `e` | Toggle the educational overlay |
| `q` or `Esc` | Quit |

## Troubleshooting

**`error: linking with cc failed` mentioning `-lpcap`** — libpcap headers or
library are missing. Install per the prerequisites table.

**`pcap::Error::PermissionDenied`** — the binary lacks the privilege needed
to open a raw socket. Re-check the platform-specific steps above.

**`--list-interfaces` prints nothing** — the pcap backend enumerated zero
interfaces. On Linux this usually means `CAP_NET_RAW` is missing; on
containerized environments (e.g. Flatpak, Snap, some Docker configs), raw
sockets may be filtered entirely.

**TUI renders garbled characters** — the terminal is not reporting UTF-8 or
lacks the box-drawing font glyphs. Set `LANG=C.UTF-8` and use a modern
terminal (Alacritty, WezTerm, iTerm2, Windows Terminal).

## Useful cargo invocations

```
cargo build --release              # optimized binary at target/release/seehandshake
cargo doc --no-deps --open         # build and open API docs in a browser
cargo tree                         # inspect the dependency graph
cargo audit                        # (needs cargo-install cargo-audit) check for advisories
cargo deny check                   # (needs cargo-install cargo-deny) license + advisory gate
```

## Directory map

```
Cargo.toml
src/
├── lib.rs, main.rs, error.rs      # crate root, thin binary, error type
├── model/                          # ConnectionKey, HandshakeInfo, TLS enums
├── parser/                         # record framer + ClientHello/ServerHello decoders
├── tracker/                        # per-connection reassembly + eviction
├── capture/                        # PacketSource trait + libpcap backend
├── cli.rs                          # clap definitions + dispatch
├── ui/                             # Ratatui three-panel TUI
└── util/                           # small helpers
tests/
├── cli.rs                          # assert_cmd smoke tests
├── parser_integration.rs           # fixtures + tracker pipeline
└── data/                           # RFC 8448 record fixtures
examples/
└── parse_recorded.rs               # standalone parser demo
docs/
├── architecture.md                 # module + threading model
├── tls13-visibility.md             # what a passive observer can and cannot see
├── development.md                  # this document
└── packaging.md                    # release + distribution guide
```
