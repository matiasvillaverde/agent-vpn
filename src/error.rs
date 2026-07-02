//! Error type and the stable, agent-facing exit-code contract.

use std::io;
use std::path::PathBuf;

/// All failures surfaced by vpn.
///
/// Each variant maps to a fixed process exit code (see [`Error::exit_code`]) so
/// that automation can branch on the outcome without parsing text.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A named tunnel has no matching `<name>.conf` in the config directory.
    #[error("tunnel '{0}' not found in config directory")]
    TunnelNotFound(String),

    /// A tunnel name is not a legal WireGuard interface name.
    #[error("invalid tunnel name '{0}' (allowed: letters, digits and _=+.- up to 15 chars)")]
    InvalidName(String),

    /// The config directory exists but could not be read.
    #[error("config directory '{0}' could not be read: {1}")]
    ConfigDir(PathBuf, #[source] io::Error),

    /// The `config.toml` settings file could not be parsed.
    #[error("config file '{path}' is invalid: {message}")]
    ConfigParse {
        /// Path to the offending file.
        path: PathBuf,
        /// Human-readable parse error.
        message: String,
    },

    /// A tunnel config file exists but could not be read.
    #[error("tunnel config '{path}' could not be read: {source}")]
    TunnelConfRead {
        /// Path to the tunnel config.
        path: PathBuf,
        /// The underlying OS error.
        #[source]
        source: io::Error,
    },

    /// A tunnel config has no `[Peer]` section with a `PublicKey`.
    #[error("tunnel config '{path}' has no [Peer] PublicKey")]
    TunnelConfPeer {
        /// Path to the tunnel config.
        path: PathBuf,
    },

    /// The backend command ran but exited non-zero.
    #[error("{program} failed (exit {code}): {stderr}")]
    Backend {
        /// The program that failed (e.g. `wg-quick`).
        program: String,
        /// Its exit status, or `-1` if it was terminated by a signal.
        code: i32,
        /// Captured diagnostic output.
        stderr: String,
    },

    /// The backend command could not be launched at all.
    #[error("failed to run '{program}': {source} (is it installed and on PATH?)")]
    Spawn {
        /// The program we tried to launch.
        program: String,
        /// The underlying OS error.
        #[source]
        source: io::Error,
    },
}

impl Error {
    /// The process exit code associated with this error.
    ///
    /// The mapping is part of vpn's public contract:
    ///
    /// | code | meaning                              |
    /// |------|--------------------------------------|
    /// | 1    | I/O / config file failure            |
    /// | 3    | tunnel not found                     |
    /// | 4    | invalid tunnel name                  |
    /// | 5    | backend command exited non-zero      |
    /// | 6    | backend command could not be spawned |
    ///
    /// (Exit code 7 — probe request failed — is produced by a successful
    /// `probe` report, not by this error type.)
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::ConfigDir(..)
            | Error::ConfigParse { .. }
            | Error::TunnelConfRead { .. }
            | Error::TunnelConfPeer { .. } => 1,
            Error::TunnelNotFound(_) => 3,
            Error::InvalidName(_) => 4,
            Error::Backend { .. } => 5,
            Error::Spawn { .. } => 6,
        }
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(Error::TunnelNotFound("x".into()).exit_code(), 3);
        assert_eq!(Error::InvalidName("x".into()).exit_code(), 4);
        assert_eq!(
            Error::Backend {
                program: "wg-quick".into(),
                code: 1,
                stderr: "boom".into(),
            }
            .exit_code(),
            5
        );
        assert_eq!(
            Error::Spawn {
                program: "wg".into(),
                source: io::Error::new(io::ErrorKind::NotFound, "nope"),
            }
            .exit_code(),
            6
        );
        assert_eq!(
            Error::ConfigDir(
                PathBuf::from("/x"),
                io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
            )
            .exit_code(),
            1
        );
        assert_eq!(
            Error::ConfigParse {
                path: PathBuf::from("/x/config.toml"),
                message: "bad".into(),
            }
            .exit_code(),
            1
        );
        assert_eq!(
            Error::TunnelConfRead {
                path: PathBuf::from("/x/t.conf"),
                source: io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
            }
            .exit_code(),
            1
        );
        assert_eq!(
            Error::TunnelConfPeer {
                path: PathBuf::from("/x/t.conf"),
            }
            .exit_code(),
            1
        );
    }

    #[test]
    fn messages_are_descriptive() {
        assert!(Error::TunnelNotFound("home".into())
            .to_string()
            .contains("home"));
        assert!(Error::InvalidName("bad name".into())
            .to_string()
            .contains("bad name"));
        assert!(Error::Backend {
            program: "wg-quick".into(),
            code: 2,
            stderr: "denied".into(),
        }
        .to_string()
        .contains("denied"));
        assert!(Error::Spawn {
            program: "wg".into(),
            source: io::Error::new(io::ErrorKind::NotFound, "nope"),
        }
        .to_string()
        .contains("wg"));
        assert!(Error::ConfigDir(
            PathBuf::from("/etc/x"),
            io::Error::new(io::ErrorKind::NotFound, "gone"),
        )
        .to_string()
        .contains("/etc/x"));
        assert!(Error::ConfigParse {
            path: PathBuf::from("/etc/vpn/config.toml"),
            message: "unknown key 'foo'".into(),
        }
        .to_string()
        .contains("unknown key 'foo'"));
        assert!(Error::TunnelConfRead {
            path: PathBuf::from("/x/proton.conf"),
            source: io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
        }
        .to_string()
        .contains("proton.conf"));
        assert!(Error::TunnelConfPeer {
            path: PathBuf::from("/x/proton.conf"),
        }
        .to_string()
        .contains("[Peer] PublicKey"));
    }
}
