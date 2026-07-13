# Packaging and Distribution Guide

This document describes how to cut a `seehandshake` release and get it into
the hands of users through each supported channel. It is written for the
project maintainer(s); most contributors will not need to touch anything
here.

The workflow is intentionally boring: cut a tag, let CI upload binaries,
then submit or refresh downstream packaging repos.

---

## Release checklist

Before tagging, verify from a clean checkout:

```
git clean -fdx
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo build --release
./target/release/seehandshake --version
```

Then:

1. Bump `version` in `Cargo.toml` (SemVer — breaking changes bump major even
   pre-1.0, per project policy).
2. Move the `## [Unreleased]` block in `CHANGELOG.md` under a new
   `## [X.Y.Z] — YYYY-MM-DD` heading, and open a fresh empty `[Unreleased]`.
3. Commit: `release: X.Y.Z`.
4. Tag: `git tag -s vX.Y.Z -m "seehandshake X.Y.Z"`.
5. Push: `git push origin main --follow-tags`.

The `.github/workflows/release.yml` workflow triggers on the tag and:

- Creates the GitHub release with auto-generated notes.
- Cross-builds and uploads binaries for the five supported targets
  (`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
  `x86_64-apple-darwin`, `aarch64-apple-darwin`,
  `x86_64-pc-windows-msvc`) with SHA-256 checksums.

Once the GitHub release exists, proceed through the channels below.

---

## crates.io — the source-of-truth publish

Every release is published to crates.io. Downstream package managers (some
of which build from source) key off the crates.io tarball.

### One-time setup

```
cargo login          # paste the token from https://crates.io/settings/tokens
```

The account publishing releases should own the `seehandshake` crate name.

### Per-release

```
cargo publish --dry-run
cargo publish
```

`cargo publish` refuses if the working tree is dirty or the tag is missing;
that is desired. If you need to yank a broken release:

```
cargo yank --version X.Y.Z
```

### Ensure the manifest is complete

crates.io shows only what `Cargo.toml` declares. Before the first publish,
double-check:

- `description`, `license`, `readme`, `repository`, `homepage`,
  `documentation`, `keywords` (max 5), `categories` are all set.
- The included files are minimal: add an `include = [...]` list if the
  default packs extra data (`docs/`, `tests/data/*.bin`, screenshots) that
  are useful for downstream builders but bloat the tarball.

Verify the tarball contents before publishing:

```
cargo package --list
```

---

## Debian and derivatives (apt)

The end goal is inclusion in the official Debian archive
(`sudo apt install seehandshake`). This is a multi-step process; expect it
to take weeks for the first upload.

### Prerequisites

- The project must be MIT (or another DFSG-free license) — ✅ we are MIT.
- Every dependency must already be packaged in Debian, or must be uploaded
  first. Check with `apt-cache search 'librust-<crate>-dev'`. The largest
  risks in our dep tree are `ratatui` and `tls-parser`, which are packaged
  under `librust-ratatui-dev` and `librust-tls-parser-dev` (verify version
  match against Debian testing before each cycle).
- Rust MSRV must be satisfied by Debian's `rustc` (we pin to 1.74 to align
  with trixie).

### Building a `.deb` locally with `cargo-deb`

For unofficial `.deb` distribution (e.g., a project APT repo hosted on GitHub
Pages), `cargo-deb` is the fastest path and does not require the full
Debian toolchain:

```
cargo install cargo-deb
cargo deb                    # produces target/debian/seehandshake_X.Y.Z_amd64.deb
```

Add a `[package.metadata.deb]` section to `Cargo.toml` to control the
generated control file:

```toml
[package.metadata.deb]
section = "net"
priority = "optional"
depends = "$auto, libpcap0.8"
extended-description = """\
seehandshake is a passive TLS handshake observer for the terminal.
It captures packets on a chosen network interface, reassembles TLS
records off the TCP stream, and renders each connection in a three-panel
Ratatui interface with an optional educational overlay."""
assets = [
    ["target/release/seehandshake", "usr/bin/", "755"],
    ["README.md", "usr/share/doc/seehandshake/README", "644"],
    ["LICENSE", "usr/share/doc/seehandshake/copyright", "644"],
    ["CHANGELOG.md", "usr/share/doc/seehandshake/changelog", "644"],
]
```

Test the resulting `.deb` in a clean container:

```
docker run --rm -it -v $PWD/target/debian:/pkg debian:trixie bash -c \
  "apt-get update && apt-get install -y /pkg/seehandshake_*_amd64.deb && seehandshake --version"
```

### Official Debian upload path

For inclusion in the Debian archive itself, follow the [Debian Rust Team's
packaging guide](https://wiki.debian.org/Teams/RustPackaging):

1. Introduce yourself on `debian-rust@lists.debian.org` and ask for
   sponsorship (you cannot upload without being a Debian Developer, but any
   DD can sponsor you).
2. Package with `debcargo`:
   ```
   cargo install debcargo
   debcargo package seehandshake X.Y.Z
   ```
3. Fill in the resulting `debian/` directory (control, copyright,
   changelog) and submit an ITP (Intent To Package) bug against
   `wnpp` on the Debian BTS.
4. Upload to `mentors.debian.net` and coordinate the sponsored upload.

Once accepted, Ubuntu automatically syncs from Debian on each release cycle
(unless a delta is required).

### Third-party APT repository (interim solution)

Until Debian inclusion lands, publish an APT repo alongside the GitHub
releases:

```
# On the release runner, after cargo-deb has produced the .deb:
mkdir -p apt-repo/pool/main/s/seehandshake
cp target/debian/seehandshake_*.deb apt-repo/pool/main/s/seehandshake/
cd apt-repo
apt-ftparchive packages pool > dists/stable/main/binary-amd64/Packages
gzip -k dists/stable/main/binary-amd64/Packages
apt-ftparchive release dists/stable > dists/stable/Release
gpg --detach-sign --armor -o dists/stable/Release.gpg dists/stable/Release
```

Publish `apt-repo/` to GitHub Pages or an S3 bucket. Users then:

```
curl -fsSL https://seehandshake.example/apt/pubkey.gpg | sudo tee /etc/apt/trusted.gpg.d/seehandshake.asc
echo "deb https://seehandshake.example/apt stable main" | sudo tee /etc/apt/sources.list.d/seehandshake.list
sudo apt update && sudo apt install seehandshake
```

---

## Homebrew (macOS + Linuxbrew)

Homebrew is the fastest of the third-party channels — a single formula PR
against a tap repo.

### Option A: a project-owned tap (recommended for early releases)

Create `homebrew-tap` under the same GitHub org and add
`Formula/seehandshake.rb`:

```ruby
class Seehandshake < Formula
  desc "Visualize TLS handshakes in your terminal, in real time"
  homepage "https://github.com/<owner>/SeeHandshake"
  url "https://github.com/<owner>/SeeHandshake/archive/refs/tags/vX.Y.Z.tar.gz"
  sha256 "<sha256-of-tarball>"
  license "MIT"
  head "https://github.com/<owner>/SeeHandshake.git", branch: "main"

  depends_on "rust" => :build
  depends_on "libpcap"

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "seehandshake", shell_output("#{bin}/seehandshake --version")
  end
end
```

Users install via:

```
brew tap <owner>/tap
brew install seehandshake
```

### Option B: homebrew-core

Once the project has ~75 GitHub stars and a stable release cadence (a rough
guideline Homebrew maintainers use), open a PR against
[Homebrew/homebrew-core](https://github.com/Homebrew/homebrew-core) with the
same formula. The audit is stricter — expect requests to tighten test blocks
and remove `head`.

### Automating formula updates

Bump the tap formula automatically on each release by adding a job to
`.github/workflows/release.yml`:

```yaml
  update-homebrew:
    needs: upload-binaries
    runs-on: ubuntu-latest
    steps:
      - uses: mislav/bump-homebrew-formula-action@v3
        with:
          formula-name: seehandshake
          homebrew-tap: <owner>/homebrew-tap
        env:
          COMMITTER_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}
```

`HOMEBREW_TAP_TOKEN` is a fine-grained PAT scoped to the tap repo.

---

## Arch Linux (AUR)

The AUR does not host binaries — it hosts `PKGBUILD` scripts that build from
source on the user's machine. Publish two packages:

- `seehandshake` — builds the latest tagged release from source.
- `seehandshake-git` (optional) — builds `main`, for early adopters.

### `PKGBUILD` template

```bash
# Maintainer: <name> <email>
pkgname=seehandshake
pkgver=X.Y.Z
pkgrel=1
pkgdesc="Visualize TLS handshakes in your terminal, in real time"
arch=('x86_64' 'aarch64')
url="https://github.com/<owner>/SeeHandshake"
license=('MIT')
depends=('libpcap')
makedepends=('cargo')
source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")
sha256sums=('<sha256>')

prepare() {
    cd "SeeHandshake-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    cargo fetch --locked --target "$(rustc -vV | sed -n 's/host: //p')"
}

build() {
    cd "SeeHandshake-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    export CARGO_TARGET_DIR=target
    cargo build --frozen --release --all-features
}

check() {
    cd "SeeHandshake-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    cargo test --frozen --all-features
}

package() {
    cd "SeeHandshake-$pkgver"
    install -Dm755 "target/release/$pkgname" "$pkgdir/usr/bin/$pkgname"
    install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}
```

Submit with `git push` to `ssh://aur@aur.archlinux.org/seehandshake.git`
after registering an account on aur.archlinux.org and uploading your SSH
key. The [`aurpublish`](https://github.com/eli-schwartz/aurpublish) helper
scripts the round-trip.

Automate `pkgver` bumps with `.github/workflows/release.yml`:

```yaml
  update-aur:
    needs: upload-binaries
    runs-on: ubuntu-latest
    steps:
      - uses: ATiltedTree/create-aur-release@v1
        with:
          package_name: seehandshake
          commit_username: <name>
          commit_email: <email>
          ssh_private_key: ${{ secrets.AUR_SSH_KEY }}
```

---

## Nixpkgs

Nix users expect an entry in `nixpkgs/pkgs/tools/networking/seehandshake/default.nix`:

```nix
{ lib, rustPlatform, fetchFromGitHub, libpcap, pkg-config }:

rustPlatform.buildRustPackage rec {
  pname = "seehandshake";
  version = "X.Y.Z";

  src = fetchFromGitHub {
    owner = "<owner>";
    repo = "SeeHandshake";
    rev = "v${version}";
    hash = "sha256-...";
  };

  cargoHash = "sha256-...";

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ libpcap ];

  meta = with lib; {
    description = "Visualize TLS handshakes in your terminal, in real time";
    homepage = "https://github.com/<owner>/SeeHandshake";
    license = licenses.mit;
    mainProgram = "seehandshake";
    maintainers = with maintainers; [ /* your handle */ ];
    platforms = platforms.unix;
  };
}
```

Add a line to `pkgs/top-level/all-packages.nix`:

```nix
  seehandshake = callPackage ../tools/networking/seehandshake { };
```

Open the PR against [`NixOS/nixpkgs`](https://github.com/NixOS/nixpkgs) and
respond to review. The initial `cargoHash` will be `lib.fakeHash`; Nix will
tell you the correct value on the first build.

Get the `hash` for `fetchFromGitHub` via:

```
nix-prefetch-github <owner> SeeHandshake --rev vX.Y.Z
```

---

## MacPorts

Some macOS users prefer MacPorts over Homebrew. Add a `Portfile` under
`ports/net/seehandshake/`:

```
PortSystem       1.0
PortGroup        cargo 1.0

name             seehandshake
version          X.Y.Z
categories       net security
license          MIT
maintainers      github.com:<owner>
description      Visualize TLS handshakes in your terminal, in real time
long_description ${description}
homepage         https://github.com/<owner>/SeeHandshake
master_sites     ${homepage}/archive/refs/tags
distname         v${version}
checksums        rmd160  <rmd160>  sha256  <sha256>

depends_lib      port:libpcap
```

Submit the port via a PR against
[`macports/macports-ports`](https://github.com/macports/macports-ports).

---

## Winget (Windows Package Manager)

For Windows users who don't want to install Npcap manually, publish to
winget. The manifest format is YAML under
[`microsoft/winget-pkgs`](https://github.com/microsoft/winget-pkgs).

Use [`wingetcreate`](https://github.com/microsoft/winget-create) to bootstrap:

```
wingetcreate new https://github.com/<owner>/SeeHandshake/releases/download/vX.Y.Z/seehandshake-x86_64-pc-windows-msvc.zip
```

It generates three files under
`manifests/<letter>/<owner>/seehandshake/X.Y.Z/`. Add
`Dependencies:` referencing Npcap so users get prompted to install it:

```yaml
Dependencies:
  PackageDependencies:
    - PackageIdentifier: Insecure.Npcap
```

Submit via `wingetcreate submit` (creates the PR).

Users then install with:

```
winget install <owner>.SeeHandshake
```

---

## Chocolatey (Windows)

Many Windows developers and sysadmins — a good chunk of this tool's
audience — live in Chocolatey rather than winget. The community repository
([community.chocolatey.org](https://community.chocolatey.org)) is one of the
more rigorously gated channels: every submitted version goes through
automated validation, a VirusTotal scan, and human moderator review before
it is published, so expect the first submission (and updates) to sit in a
`pending` queue for a while.

A Chocolatey package does not host the binary; it ships a `.nuspec` plus a
PowerShell install script that downloads the Windows release zip from the
GitHub release and verifies it against a pinned checksum. Reuse the
`SHA256SUMS` that `release.yml` already produces.

### One-time setup

```
choco apikey --key <your-api-key> --source https://push.chocolatey.org/
```

Register on community.chocolatey.org to obtain the API key; the account that
pushes should own the `seehandshake` package id.

### Package layout

```
seehandshake/
├── seehandshake.nuspec
└── tools/
    ├── chocolateyinstall.ps1
    └── chocolateyuninstall.ps1
```

`seehandshake.nuspec`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>seehandshake</id>
    <version>X.Y.Z</version>
    <title>SeeHandshake</title>
    <authors>SeeHandshake contributors</authors>
    <projectUrl>https://github.com/<owner>/SeeHandshake</projectUrl>
    <licenseUrl>https://github.com/<owner>/SeeHandshake/blob/main/LICENSE</licenseUrl>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <projectSourceUrl>https://github.com/<owner>/SeeHandshake</projectSourceUrl>
    <docsUrl>https://github.com/<owner>/SeeHandshake/blob/main/README.md</docsUrl>
    <tags>tls network handshake tui security cli</tags>
    <summary>Visualize TLS handshakes in your terminal, in real time</summary>
    <description>
      SeeHandshake is a passive TLS handshake observer for the terminal. It
      captures packets on a chosen network interface, reassembles TLS records
      off the TCP stream, and renders each connection in a three-panel
      interface with an optional educational overlay.
    </description>
    <dependencies>
      <dependency id="npcap" />
    </dependencies>
  </metadata>
  <files>
    <file src="tools\**" target="tools" />
  </files>
</package>
```

`tools/chocolateyinstall.ps1` (pins the checksum from `SHA256SUMS`):

```powershell
$ErrorActionPreference = 'Stop'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$version  = 'X.Y.Z'

$packageArgs = @{
  packageName    = 'seehandshake'
  unzipLocation  = $toolsDir
  url64bit       = "https://github.com/<owner>/SeeHandshake/releases/download/v$version/seehandshake-x86_64-pc-windows-msvc.zip"
  checksum64     = '<sha256-of-windows-zip>'
  checksumType64 = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

# Put seehandshake.exe on the PATH via a shim (Chocolatey auto-shims .exe
# files it finds under tools, so no extra work is usually needed).
```

`tools/chocolateyuninstall.ps1`:

```powershell
$ErrorActionPreference = 'Stop'
# Install-ChocolateyZipPackage records the extracted files; Chocolatey
# removes the shim and tools directory automatically on uninstall. Nothing
# extra to do unless the install writes outside $toolsDir.
```

The `npcap` dependency pulls Npcap in as a prerequisite so live capture
works out of the box. Live capture still requires an **Administrator**
terminal — Chocolatey cannot grant raw-socket access.

### Per-release

```
cd seehandshake
choco pack                                   # produces seehandshake.X.Y.Z.nupkg
choco push seehandshake.X.Y.Z.nupkg --source https://push.chocolatey.org/
```

The push enters the moderation queue; respond to any moderator comments.
Automate the `version` and `checksum64` bumps from the release workflow the
same way the other channels are automated.

---

## Flatpak (optional)

Because live packet capture requires host-level privileges, a sandboxed
Flatpak build is of limited practical value — the app would only work with
`--device=all` and specific portal permissions that most Flatpak users
would rather not grant. If we ship a Flatpak anyway (for the demo mode
against recorded PCAPs), it lives under
[`flathub/io.github.owner.SeeHandshake`](https://github.com/flathub) with a
`sdk: org.freedesktop.Sdk // 25.08` and `finish-args: [--share=network]`.
Not recommended as a primary distribution channel.

---

## Update matrix

After each release, run through this list and check each channel:

- [ ] `cargo publish` succeeded (crates.io)
- [ ] GitHub release has all five binary artifacts + `SHA256SUMS`
- [ ] `homebrew-tap` PR merged (or auto-bumped)
- [ ] AUR `seehandshake` bumped
- [ ] Nixpkgs PR opened
- [ ] winget-pkgs PR opened
- [ ] Chocolatey `choco push` submitted (clears moderation queue)
- [ ] Debian: `uscan` in the `debian/watch` file will notice the new tag; if
      the Debian package is under our control, run `gbp import-orig` and
      upload. If sponsored, ping the sponsor.
- [ ] MacPorts PR opened
- [ ] `CHANGELOG.md` reflects the release date
- [ ] Announcement posted (project blog, mastodon, r/rust)

## When a channel breaks

Downstream packaging goes stale. If a user reports `apt install seehandshake`
giving them version 0.3 when 1.2 is current, the fix is at the packaging
layer — not in this repo. Direct users to `cargo install seehandshake` or a
GitHub release binary as an immediate workaround, then chase the downstream
package.

Do not delete a published `crates.io` version or a GitHub release binary;
older tags may still be linked from downstream package specs and must
continue to resolve.
