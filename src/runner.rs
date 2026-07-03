//! Abstraction over launching external commands.
//!
//! All contact with `wg-quick`/`wg` goes through [`CommandRunner`]. Production
//! code uses [`SystemRunner`]; tests inject a mock so the full command-building
//! and output-parsing logic can be exercised without root or real interfaces.

use std::io;
use std::process::Command;

/// The captured result of running a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Exit code, or `None` if the process was killed by a signal.
    pub code: Option<i32>,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}

impl CommandOutput {
    /// Whether the command exited with code `0`.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// Launches an external program and captures its output.
pub trait CommandRunner {
    /// Run `program` with `args`, waiting for it to finish.
    ///
    /// Returns `Err` only when the process could not be launched; a program
    /// that runs and exits non-zero is still `Ok` with a non-zero
    /// [`CommandOutput::code`].
    fn run(&self, program: &str, args: &[String]) -> io::Result<CommandOutput>;

    /// Run `program` with `args` with stdio inherited from this process, so
    /// its output streams directly to the user (used by `vpn exec`).
    ///
    /// Returns the exit code, or `None` if the process was killed by a signal.
    /// `Err` only when the process could not be launched.
    fn run_passthrough(&self, program: &str, args: &[String]) -> io::Result<Option<i32>>;
}

/// The real runner, backed by [`std::process::Command`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[String]) -> io::Result<CommandOutput> {
        let output = Command::new(program).args(args).output()?;
        Ok(CommandOutput {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn run_passthrough(&self, program: &str, args: &[String]) -> io::Result<Option<i32>> {
        let status = Command::new(program).args(args).status()?;
        Ok(status.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_reflects_exit_code() {
        let ok = CommandOutput {
            code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        };
        assert!(ok.success());
        let bad = CommandOutput {
            code: Some(1),
            stdout: String::new(),
            stderr: String::new(),
        };
        assert!(!bad.success());
        let killed = CommandOutput {
            code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
        assert!(!killed.success());
    }

    #[test]
    fn system_runner_captures_stdout_and_exit_zero() {
        let out = SystemRunner
            .run("sh", &["-c".into(), "printf hello".into()])
            .expect("spawn");
        assert!(out.success());
        assert_eq!(out.stdout, "hello");
    }

    #[test]
    fn system_runner_captures_nonzero_exit_and_stderr() {
        let out = SystemRunner
            .run("sh", &["-c".into(), "printf oops 1>&2; exit 3".into()])
            .expect("spawn");
        assert_eq!(out.code, Some(3));
        assert_eq!(out.stderr, "oops");
        assert!(!out.success());
    }

    #[test]
    fn system_runner_reports_spawn_failure() {
        let err = SystemRunner
            .run("vpn-no-such-binary-zzz", &[])
            .expect_err("should fail to spawn");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn passthrough_returns_exit_code() {
        let code = SystemRunner
            .run_passthrough("sh", &["-c".into(), "exit 7".into()])
            .expect("spawn");
        assert_eq!(code, Some(7));
        let code = SystemRunner
            .run_passthrough("sh", &["-c".into(), "true".into()])
            .expect("spawn");
        assert_eq!(code, Some(0));
    }

    #[test]
    fn passthrough_reports_spawn_failure() {
        let err = SystemRunner
            .run_passthrough("vpn-no-such-binary-zzz", &[])
            .expect_err("should fail to spawn");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
