//! `vpn` — an agent-first, provider-agnostic WireGuard tunnel manager.
//!
//! The library exposes the full command logic so it can be driven in-process
//! (see [`execute`]) with any [`CommandRunner`](runner::CommandRunner),
//! including a mock, which is how the crate reaches full test coverage without
//! root privileges or real network interfaces.

#![deny(missing_docs)]

pub mod backend;
pub mod cidr;
pub mod cli;
pub mod config;
pub mod error;
pub mod lint;
pub mod output;
pub mod probe;
pub mod runner;
pub mod settings;
pub mod status;

#[cfg(test)]
pub(crate) mod testutil;

use std::process::ExitCode;

use crate::backend::Backend;
use crate::cli::Cli;
use crate::runner::{CommandRunner, SystemRunner};

/// The outcome of running a command: what to print and the exit code.
#[derive(Debug, PartialEq, Eq)]
pub struct Execution {
    /// Rendered output (report on success, error text on failure).
    pub message: String,
    /// Process exit code.
    pub code: i32,
    /// Whether `message` describes an error (and belongs on stderr).
    pub is_error: bool,
}

/// Run the parsed CLI against an arbitrary runner, returning what to emit.
///
/// Reads `<config_dir>/config.toml` (if present) to resolve effective settings,
/// then dispatches. The only I/O beyond the runner is that config read and the
/// tunnel-file discovery already performed by the backend, keeping it testable.
pub fn execute<R: CommandRunner>(runner: R, cli: &Cli) -> Execution {
    let file = match settings::load(&cli.resolved_config_dir()) {
        Ok(file) => file,
        Err(err) => {
            return Execution {
                message: output::render_error(&err, cli.json),
                code: err.exit_code(),
                is_error: true,
            }
        }
    };
    let effective = cli.settings(&file);
    let backend = Backend::new(runner, effective.config_dir, effective.sudo).with_programs(
        effective.wg,
        effective.wg_quick,
        effective.curl,
    );
    match cli::dispatch(&backend, &cli.command) {
        // exec: the child's output already streamed through — emit nothing on
        // stdout (a report would corrupt piped output) and pass its code on.
        // A restore warning is the only thing worth saying, on stderr.
        Ok(output::Report::Exec {
            exit_code, warning, ..
        }) => Execution {
            is_error: warning.is_some(),
            message: warning.unwrap_or_default(),
            code: exit_code,
        },
        Ok(report) => Execution {
            message: output::render_report(&report, cli.json),
            // 0 for every report except a probe with failures (7).
            code: report.exit_code(),
            is_error: false,
        },
        Err(err) => Execution {
            message: output::render_error(&err, cli.json),
            code: err.exit_code(),
            is_error: true,
        },
    }
}

/// Run the CLI against the real system, print the result, and return the exit
/// code. This is the single entry point used by `main`.
#[must_use]
pub fn run_cli(cli: Cli) -> ExitCode {
    let execution = execute(SystemRunner, &cli);
    if execution.message.is_empty() {
        // exec success: the child's output was the output.
    } else if execution.is_error {
        eprintln!("{}", execution.message);
    } else {
        println!("{}", execution.message);
    }
    ExitCode::from(u8::try_from(execution.code).unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::MockRunner;
    use clap::Parser;
    use std::fs;
    use tempfile::tempdir;

    const CONF: &str = "[Peer]\nPublicKey = PEERKEY\nAllowedIPs = 0.0.0.0/0\n";

    #[test]
    fn execute_success_returns_report_and_zero() {
        let cfg = tempdir().unwrap();
        fs::write(cfg.path().join("home.conf"), CONF).unwrap();
        let cli = Cli::try_parse_from([
            "vpn",
            "--json",
            "--config-dir",
            cfg.path().to_str().unwrap(),
            "current",
        ])
        .unwrap();

        let runner = MockRunner::new();
        runner.ok(""); // wg show all dump: nothing live
        let ex = execute(runner, &cli);
        assert_eq!(ex.code, 0);
        assert!(!ex.is_error);
        assert!(ex.message.contains("\"command\": \"current\""));
    }

    #[test]
    fn execute_error_returns_message_and_code() {
        let cfg = tempdir().unwrap();
        let cli = Cli::try_parse_from([
            "vpn",
            "--config-dir",
            cfg.path().to_str().unwrap(),
            "up",
            "ghost",
        ])
        .unwrap();

        let ex = execute(MockRunner::new(), &cli);
        assert_eq!(ex.code, 3);
        assert!(ex.is_error);
        assert!(ex.message.contains("ghost"));
    }

    #[test]
    fn execute_reads_config_file_and_reports_parse_errors() {
        let cfg = tempdir().unwrap();
        fs::write(cfg.path().join("config.toml"), "bogus = 1\n").unwrap();
        let cli = Cli::try_parse_from([
            "vpn",
            "--config-dir",
            cfg.path().to_str().unwrap(),
            "current",
        ])
        .unwrap();

        let ex = execute(MockRunner::new(), &cli);
        assert_eq!(ex.code, 1);
        assert!(ex.is_error);
        assert!(ex.message.contains("unknown key 'bogus'"));
    }

    #[test]
    fn execute_exec_passes_child_code_and_stays_silent() {
        let cfg = tempdir().unwrap();
        fs::write(cfg.path().join("home.conf"), CONF).unwrap();
        let cli = Cli::try_parse_from([
            "vpn",
            "--config-dir",
            cfg.path().to_str().unwrap(),
            "exec",
            "home",
            "--",
            "some-command",
        ])
        .unwrap();

        let runner = MockRunner::new();
        runner.ok(""); // all_dump: down
        runner.ok(""); // wg-quick up
        runner.fail(9, ""); // child exits 9
        runner.ok(""); // restore
        let ex = execute(runner, &cli);
        assert_eq!(ex.code, 9);
        assert!(!ex.is_error);
        assert!(ex.message.is_empty(), "exec emits nothing of its own");
    }

    #[test]
    fn execute_exec_restore_warning_goes_to_stderr() {
        let cfg = tempdir().unwrap();
        fs::write(cfg.path().join("home.conf"), CONF).unwrap();
        let cli = Cli::try_parse_from([
            "vpn",
            "--config-dir",
            cfg.path().to_str().unwrap(),
            "exec",
            "home",
            "--",
            "some-command",
        ])
        .unwrap();

        let runner = MockRunner::new();
        runner.ok(""); // down
        runner.ok(""); // up
        runner.ok(""); // child ok
        runner.fail(1, "boom"); // restore fails
        let ex = execute(runner, &cli);
        assert_eq!(ex.code, 0, "child's code wins even with a warning");
        assert!(ex.is_error, "warning goes to stderr");
        assert!(ex.message.contains("failed to restore"));
    }

    #[test]
    fn execute_probe_failure_exits_7_on_stdout() {
        let cfg = tempdir().unwrap();
        fs::write(cfg.path().join("home.conf"), CONF).unwrap();
        let cli = Cli::try_parse_from([
            "vpn",
            "--json",
            "--config-dir",
            cfg.path().to_str().unwrap(),
            "probe",
            "home",
        ])
        .unwrap();

        let runner = MockRunner::new();
        runner.ok(""); // all_dump: down
        runner.ok(""); // wg-quick up
        runner.ok(""); // info dump
        runner.fail(7, "curl: (7) Failed to connect"); // curl fails
        runner.ok(""); // restore down
        let ex = execute(runner, &cli);
        assert_eq!(ex.code, 7);
        assert!(!ex.is_error, "probe report goes to stdout, not stderr");
        assert!(ex.message.contains("\"command\": \"probe\""));
        assert!(ex.message.contains("Failed to connect"));
    }
}
