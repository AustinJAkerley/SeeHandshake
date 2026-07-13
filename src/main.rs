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
            if let Some(e) = err.downcast_ref::<seehandshake::Error>() {
                if e.is_permission_denied() {
                    eprintln!("{}", seehandshake::permission_denied_hint());
                }
                return ExitCode::from(e.exit_code());
            }
            ExitCode::from(1)
        }
    }
}
