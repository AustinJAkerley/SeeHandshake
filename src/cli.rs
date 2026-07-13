// SPDX-License-Identifier: MIT

//! Command-line interface for `seehandshake`.
//!
//! [`Args`] holds the parsed [`clap`] configuration. [`run`] is the top-level
//! dispatch entry point invoked from `main`.

use anyhow::Context;
use clap::Parser;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

use crate::capture::interfaces::list_interfaces;

/// Default Berkeley Packet Filter expression: TCP on port 443.
///
/// Overridable via `--bpf`. Kept as a public constant so that downstream
/// consumers of the library can reuse the same default.
pub const DEFAULT_BPF: &str = "tcp port 443";

/// Parsed command-line arguments.
#[derive(Debug, Parser)]
#[command(
    name = "seehandshake",
    version,
    about = "Visualize TLS handshakes in your terminal, in real time.",
    long_about = None,
)]
pub struct Args {
    /// Network interface to capture on.
    ///
    /// When omitted, the operating system's default interface (as reported by
    /// `pcap`) is used. See `--list-interfaces` for the available names.
    #[arg(short, long, value_name = "NAME")]
    pub interface: Option<String>,

    /// List available network interfaces and exit.
    #[arg(long)]
    pub list_interfaces: bool,

    /// Berkeley Packet Filter expression applied to the capture handle.
    ///
    /// Defaults to `tcp port 443`. Override to broaden or narrow the scope
    /// (for example, `tcp port 443 or tcp port 8443`).
    #[arg(long, value_name = "FILTER", default_value = DEFAULT_BPF)]
    pub bpf: String,

    /// Log level for diagnostic tracing.
    ///
    /// Log output is written to stderr and never interferes with the TUI.
    /// Overridden by the `RUST_LOG` environment variable if set.
    #[arg(long, value_name = "LEVEL", default_value = "warn")]
    pub log_level: String,
}

/// Configure the global [`tracing`] subscriber.
///
/// Reads `RUST_LOG` if present; otherwise falls back to the value of
/// `--log-level`. Errors are returned rather than panicking so `main` can
/// surface them cleanly on stderr.
///
/// # Errors
///
/// Returns an error if the supplied level string cannot be parsed as an
/// [`EnvFilter`] directive.
pub fn init_logging(level: impl AsRef<str>) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::builder()
            .with_default_directive(LevelFilter::WARN.into())
            .parse_lossy(level.as_ref())
    });

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(())
}

/// Dispatch on the parsed [`Args`] and run the appropriate subcommand.
///
/// # Errors
///
/// Returns any error produced by the subcommand. Errors are wrapped in
/// [`anyhow::Error`] so call sites can attach context; the underlying
/// [`crate::Error`] can be recovered via [`anyhow::Error::downcast_ref`] to
/// obtain a semantic exit code.
pub fn run(args: Args) -> anyhow::Result<()> {
    if args.list_interfaces {
        return print_interfaces();
    }

    // Live TUI capture. The heavy lifting is delegated to the ui module,
    // which owns the thread orchestration.
    crate::ui::run_live(&args).context("running the terminal UI")
}

fn print_interfaces() -> anyhow::Result<()> {
    let interfaces = list_interfaces().context("enumerating network interfaces")?;
    for iface in interfaces {
        println!("{}\t{}", iface.name, iface.description.unwrap_or_default());
    }
    Ok(())
}
