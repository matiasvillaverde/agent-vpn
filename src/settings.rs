//! Optional `config.toml` settings file for agent-friendly, flag-free use.
//!
//! Living at `<config_dir>/config.toml`, it lets `sudo`, `wg`, `wg_quick`, and
//! `curl` be configured once so agents can call `vpn up <name>` with no flags.
//! Precedence is always: command-line flag / env var → file → built-in default
//! (see [`crate::cli::Cli::settings`]).
//!
//! A deliberately tiny `key = value` subset is parsed (no external TOML crate),
//! but the accepted syntax is valid TOML:
//!
//! ```toml
//! sudo = true
//! wg = "/opt/homebrew/bin/wg"
//! wg_quick = "/opt/homebrew/bin/wg-quick"
//! curl = "/usr/bin/curl"
//! ```

use std::fs;
use std::io;
use std::path::Path;

use crate::error::{Error, Result};

/// Values parsed from `config.toml`. Every field is optional; unset fields fall
/// through to the built-in default.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileConfig {
    /// Prefix privileged commands with `sudo`.
    pub sudo: Option<bool>,
    /// Path to the `wg` binary.
    pub wg: Option<String>,
    /// Path to the `wg-quick` binary.
    pub wg_quick: Option<String>,
    /// Path to the `curl` binary used by `probe`.
    pub curl: Option<String>,
}

/// Load and parse `<config_dir>/config.toml`.
///
/// A missing file is not an error — it yields an empty [`FileConfig`]. A file
/// that exists but cannot be read or parsed is an error.
pub fn load(config_dir: &Path) -> Result<FileConfig> {
    let path = config_dir.join("config.toml");
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(FileConfig::default()),
        Err(e) => return Err(Error::ConfigDir(path, e)),
    };
    parse(&text).map_err(|message| Error::ConfigParse { path, message })
}

/// Parse the config text, returning a human-readable error message on failure.
pub fn parse(text: &str) -> std::result::Result<FileConfig, String> {
    let mut config = FileConfig::default();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lineno = index + 1;
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {lineno}: expected `key = value`"))?;
        let key = key.trim();
        let value = unquote(value.trim());
        match key {
            "sudo" => config.sudo = Some(parse_bool(value, lineno)?),
            "wg" => config.wg = Some(value.to_string()),
            "wg_quick" => config.wg_quick = Some(value.to_string()),
            "curl" => config.curl = Some(value.to_string()),
            other => return Err(format!("line {lineno}: unknown key '{other}'")),
        }
    }
    Ok(config)
}

/// Strip a single pair of matching surrounding quotes, if present.
fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn parse_bool(value: &str, lineno: usize) -> std::result::Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!(
            "line {lineno}: expected `true` or `false`, found '{other}'"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_full_config() {
        let cfg = parse(
            "# comment\n\
             sudo = true\n\
             wg = \"/opt/homebrew/bin/wg\"\n\
             wg_quick = '/opt/homebrew/bin/wg-quick'\n\
             \n\
             curl = /usr/bin/curl\n",
        )
        .unwrap();
        assert_eq!(cfg.sudo, Some(true));
        assert_eq!(cfg.wg.as_deref(), Some("/opt/homebrew/bin/wg"));
        assert_eq!(cfg.wg_quick.as_deref(), Some("/opt/homebrew/bin/wg-quick"));
        assert_eq!(cfg.curl.as_deref(), Some("/usr/bin/curl"));
    }

    #[test]
    fn parse_empty_is_default() {
        assert_eq!(
            parse("\n#only comments\n   \n").unwrap(),
            FileConfig::default()
        );
    }

    #[test]
    fn parse_sudo_false() {
        assert_eq!(parse("sudo = false").unwrap().sudo, Some(false));
    }

    #[test]
    fn parse_rejects_missing_equals() {
        let err = parse("sudo true").unwrap_err();
        assert!(err.contains("line 1"));
        assert!(err.contains("key = value"));
    }

    #[test]
    fn parse_rejects_unknown_key() {
        let err = parse("bogus = 1").unwrap_err();
        assert!(err.contains("unknown key 'bogus'"));
    }

    #[test]
    fn parse_rejects_bad_bool() {
        let err = parse("sudo = yes").unwrap_err();
        assert!(err.contains("true") && err.contains("yes"));
    }

    #[test]
    fn unquote_variants() {
        assert_eq!(unquote("\"x\""), "x");
        assert_eq!(unquote("'x'"), "x");
        assert_eq!(unquote("x"), "x");
        assert_eq!(unquote("\"mismatch'"), "\"mismatch'");
        assert_eq!(unquote("\""), "\"");
    }

    #[test]
    fn load_missing_file_is_default() {
        let dir = tempdir().unwrap();
        assert_eq!(load(dir.path()).unwrap(), FileConfig::default());
    }

    #[test]
    fn load_parses_existing_file() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("config.toml"), "sudo = true\n").unwrap();
        assert_eq!(load(dir.path()).unwrap().sudo, Some(true));
    }

    #[test]
    fn load_reports_parse_error() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("config.toml"), "nope = 1\n").unwrap();
        let err = load(dir.path()).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("unknown key 'nope'"));
    }

    #[test]
    fn load_reports_unreadable_file() {
        // A directory named config.toml exists but cannot be read as a file.
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("config.toml")).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("could not be read"));
    }
}
