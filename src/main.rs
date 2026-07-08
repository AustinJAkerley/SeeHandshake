// SPDX-License-Identifier: MIT

//! The `seehandshake` command-line entry point.
//!
//! This binary is intentionally thin: it parses arguments with [`clap`],
//! configures logging, and hands off to [`seehandshake::cli::run`].

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let args = seehandshake::cli::Args::parse();

    if let Err(err) = seehandshake::cli::init_logging(&args.log_level) {
        eprintln!("seehandshake: failed to initialize logging: {err}");
        return ExitCode::from(1);
    }

    match seehandshake::cli::run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("seehandshake: {err:#}");
            ExitCode::from(
                err.downcast_ref::<seehandshake::Error>()
                    .map_or(1, |e| e.exit_code()),
            )
        }
    }
}
