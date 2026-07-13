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

The full test matrix is fast, under one second on typical hardware, because
no test touches the network or requires elevated privileges.

```
cargo test
```

That command runs, in order:

1. **Unit tests** (`src/**/tests`, 19 tests): decoder edge cases,
   `ConnectionKey` canonicalization, tracker eviction, cipher-suite display
   formatting.
2. **CLI tests** (`tests/cli.rs`, 3 tests, via `assert_cmd`): `--help`,
   `--version`, and an unknown-flag failure path.
3. **Parser integration tests** (`tests/parser_integration.rs`, 6 tests):
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
below rather than routinely running Rust builds as root. That avoids
`target/` ending up owned by root and forcing `sudo cargo clean`.

### Linux: grant capabilities to the binary

```
cargo build
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/seehandshake
./target/debug/seehandshake --list-interfaces
./target/debug/seehandshake --interface <iface>
```

Re-run `setcap` after every rebuild; capabilities are stored on the inode and
are cleared when Cargo replaces the file.

#### Resuming local testing (Linux, release build)

Coming back to a checkout and just want the three commands to build, grant
capture privileges, and run the release binary:

```
cargo build --release
sudo setcap cap_net_raw,cap_net_admin=eip target/release/seehandshake
./target/release/seehandshake --interface <iface>
```

Run `./target/release/seehandshake --list-interfaces` first if you need the
interface name, and re-run the `setcap` line after every rebuild.

Process attribution (the Origin row) needs no extra caps. SeeHandshake
walks `/proc/net/tcp` and `/proc/*/fd` as the invoking user. See
[`attribution.md`](attribution.md) for what shows up and why.

### macOS: grant BPF device access

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

### Windows: run from an Administrator terminal

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
- The **Handshake** panel (center) list each TLS record on the wire in
  order: `ClientHello`, `ServerHello`, then encrypted stages.
- The **Metadata** panel (right) populate `SNI=example.com`, cipher, key
  exchange group. Certificate fields will read `encrypted (TLS 1.3)`; see
  [`tls13-visibility.md`](tls13-visibility.md) for why. Arrowing through
  records in the Handshake panel flips the right panel into a sectioned,
  educational breakdown of the selected record.

Keyboard controls:

| Key | Action |
|---|---|
| `\u{2190}` / `\u{2192}` | Move focus one pane left / right (Connections \u{2194} Handshake \u{2194} Metadata/Sections) |
| `\u{2191}` / `\u{2193}` | Select within the focused pane (connection / record / section) |
| `enter` | Same as `\u{2192}`; on a highlighted section, expand its long-form educational text |
| `esc` | Same as `\u{2190}` (no-op at the leftmost pane; does not quit) |
| `tab` | Cycle focus L\u{2192}C\u{2192}R\u{2192}L |
| `f` | Toggle the center pane between the record list and the Client\u{2194}Server flow diagram |
| `d` | Toggle the full-screen reference-diagram overlay |
| `e` | Toggle the global educational overlay (expand every section's long-form text) |
| `w` | Clear all tracked connections (the evicted counter is preserved) |
| `q` | Quit (always) |

## Cross-platform testing checklist

Before a release, smoke-test the live path on each OS. Linux is the primary
development platform; macOS and Windows need a manual pass because CI only
cross-*builds* them; it never runs a live capture.

Every platform follows the same shape: **build → grant capture privilege →
list interfaces → run → generate a handshake → verify the panels populate →
confirm the permission-denied hint fires when privileges are withheld.**

### Linux (reference platform)

- [ ] `cargo build --release` succeeds.
- [ ] `sudo setcap cap_net_raw,cap_net_admin=eip target/release/seehandshake`.
- [ ] `./target/release/seehandshake --list-interfaces` lists a usable NIC.
- [ ] `./target/release/seehandshake --interface <iface>` launches the TUI.
- [ ] `curl https://example.com` adds a row and populates SNI/cipher/group.
- [ ] Running **without** `setcap` prints the raw error **and** the
      `setcap` hint, and exits `77`.

### macOS

- [ ] Toolchain via `rustup`; Xcode CLT installed
      (`xcode-select --install`). `libpcap` is preinstalled.
- [ ] `cargo build --release` succeeds on both `x86_64-apple-darwin`
      (Intel) and `aarch64-apple-darwin` (Apple Silicon) if you have access
      to both; otherwise note which arch was tested.
- [ ] Grant BPF access: `sudo chown $USER /dev/bpf*` **or** plan to run with
      `sudo`.
- [ ] `./target/release/seehandshake --list-interfaces` shows `en0`
      (Wi-Fi/Ethernet) and loopback.
- [ ] `./target/release/seehandshake --interface en0` launches the TUI.
- [ ] `curl https://example.com` from another terminal adds a connection row
      and populates the Metadata panel.
- [ ] Box-drawing + circled-digit glyphs render (no `LANG` tweak should be
      needed in Terminal.app / iTerm2).
- [ ] Run **without** BPF access (fresh boot, before `chown`) and confirm
      the macOS-specific `/dev/bpf*` hint prints and the process exits `77`.
- [ ] `Ctrl-C` / `q` restores the terminal cleanly (no stuck raw mode).

### Windows

- [ ] Toolchain via `rustup` (MSVC), Visual Studio Build Tools present.
- [ ] Install [Npcap](https://npcap.com/#download) (runtime) and, to build,
      set `LIB` to the Npcap SDK `Lib\x64` (mirrors the release workflow).
- [ ] `cargo build --release` succeeds for `x86_64-pc-windows-msvc`.
- [ ] Open an **Administrator** PowerShell / Windows Terminal.
- [ ] `.\target\release\seehandshake.exe --list-interfaces` lists adapters
      by their friendly names (e.g. `Ethernet`, `Wi-Fi`).
- [ ] `.\target\release\seehandshake.exe --interface "Ethernet"` launches
      the TUI.
- [ ] `curl.exe https://example.com` (or a browser) adds a connection row.
- [ ] Glyphs render in Windows Terminal (legacy `conhost` may need a font
      change; note if so).
- [ ] Run from a **non-elevated** shell and confirm the Windows-specific
      Npcap/Administrator hint prints and the process exits `77`.
- [ ] `q` exits and the console is restored (no leftover alternate screen).

## Troubleshooting

**`rust-lld: error: unable to find library -lpcap` (Debian/Ubuntu/Pop!_OS)**
Recent Rust releases default to `rust-lld` on Linux, which does not
honour Debian's multi-arch library path (`/usr/lib/x86_64-linux-gnu/`) the
way GNU `ld.bfd` does. The repo ships a
[`.cargo/config.toml`](../.cargo/config.toml) that forces `bfd` for
`x86_64-unknown-linux-gnu`, which is why `cargo build` "just works" out of
the box. If you prefer a different linker (mold, lld, or the default),
delete or edit that block. To reproduce or diagnose the raw failure:

```
RUSTFLAGS="" cargo build          # takes the config override away temporarily
```

**`error: linking with cc failed` mentioning `-lpcap`** libpcap headers or
library are missing. Install per the prerequisites table.

**`error while loading shared libraries: libpcap.so.0.8: cannot open shared
object file` when running the binary from a Flatpak'd editor's terminal**
The Freedesktop SDK runtime that VS Code / Codium / Cursor Flatpaks are
built on does not ship libpcap. You can build inside the sandbox (headers
are proxied through), but the resulting binary is linked against the
sandbox's glibc and cannot dlopen the host's libpcap (that would mix two
incompatible glibcs and blow up with `GLIBC_PRIVATE` symbol errors).

The fix is to run `cargo` on the host, not in the sandbox. Add this to
`~/.bashrc` (or `~/.zshrc`) inside the sandbox to route the Rust toolchain
through `flatpak-spawn`:

```bash
if [ -n "$FLATPAK_ID" ]; then
    cargo()  { flatpak-spawn --host bash -lc "cd \"$PWD\" && cargo $*"; }
    rustc()  { flatpak-spawn --host bash -lc "cd \"$PWD\" && rustc $*"; }
    rustup() { flatpak-spawn --host bash -lc "cd \"$PWD\" && rustup $*"; }
fi
```

After sourcing that, `cargo test` from the sandboxed terminal transparently
runs on the host and finds `libpcap.so.0.8` normally.

**`pcap::Error::PermissionDenied`** the binary lacks the privilege needed
to open a raw socket. Re-check the platform-specific steps above.

**`--list-interfaces` prints nothing** the pcap backend enumerated zero
interfaces. On Linux this usually means `CAP_NET_RAW` is missing; on
containerized environments (e.g. Flatpak, Snap, some Docker configs), raw
sockets may be filtered entirely.

**TUI renders garbled characters** the terminal is not reporting UTF-8 or
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
