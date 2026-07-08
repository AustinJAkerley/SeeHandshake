# Contributing to SeeHandshake

Thanks for your interest in improving `seehandshake`. This project is designed
for long-term maintainability and eventual inclusion in the Debian archive,
so contributions are held to a professional bar.

## Ground rules

- Be kind. This project follows the
  [Contributor Covenant](CODE_OF_CONDUCT.md).
- Every change ships with tests, documentation, and a `CHANGELOG.md` entry
  under `## [Unreleased]`.
- Public API additions require rustdoc comments with an example where useful.
- Dependencies are added sparingly. Justify each new crate in the PR
  description; prefer widely-packaged, permissively-licensed crates.

## Development environment

You will need:

- Rust 1.74 or newer (`rustup toolchain install stable`)
- `libpcap` development headers
  - Debian/Ubuntu: `sudo apt install libpcap-dev pkg-config build-essential`
  - Fedora: `sudo dnf install libpcap-devel`
  - macOS: preinstalled
  - Windows: [Npcap SDK](https://npcap.com/#download)

For a step-by-step guide covering build, test, and running the live TUI
with the right privileges on each platform, see
[`docs/development.md`](docs/development.md).

## Build, lint, test

```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps
```

Every one of the above must pass before you open a pull request. CI runs the
same commands on Ubuntu, macOS, and Windows.

## Manual UI verification

Because packet capture requires elevated privileges, the UI is not exercised
in CI. Before submitting UI changes, verify locally:

```
cargo build
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/seehandshake
./target/debug/seehandshake --interface <iface>
# In another terminal:
curl https://example.com
```

## Commit style

- One logical change per commit.
- Commit subject in the imperative mood, 72 characters or fewer
  (`parser: extract SNI from server_name extension`).
- Body wraps at 72 characters and explains *why*, not *what*.
- Sign your commits with `git commit -s` (Developer Certificate of Origin).

## Pull request checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --all-features` passes
- [ ] `cargo doc --no-deps` produces no warnings
- [ ] New public items have rustdoc
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]`
- [ ] Commits are signed (`-s`)

## Security-sensitive changes

Anything that touches the packet-capture or parser modules should include
fuzz-style tests that feed random bytes and assert the code returns an error
rather than panicking. Malformed inputs from the network are the norm, not
the exception.

## Reporting vulnerabilities

Do not open a public issue for security problems. See
[`SECURITY.md`](SECURITY.md).
