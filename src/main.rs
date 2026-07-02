//! vpn binary entry point.

use std::process::ExitCode;

use clap::Parser;
use vpn::cli::Cli;

fn main() -> ExitCode {
    vpn::run_cli(Cli::parse())
}
