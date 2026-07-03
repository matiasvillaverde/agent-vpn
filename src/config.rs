//! Discovery and validation of WireGuard tunnel config files.
//!
//! A "tunnel" is simply a `<name>.conf` file in the config directory. The stem
//! becomes the tunnel name and, via `wg-quick`, the interface name — so it must
//! satisfy WireGuard's interface-name rules.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Maximum length of a tunnel/interface name (Linux `IFNAMSIZ` limit, applied
/// everywhere for portability).
pub const MAX_NAME_LEN: usize = 15;

/// Whether `name` is a legal WireGuard interface name.
#[must_use]
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '=' | '+' | '.' | '-'))
}

/// A discovered tunnel: its name and the config file backing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunnel {
    /// Tunnel name (the file stem).
    pub name: String,
    /// Absolute or relative path to the `.conf` file.
    pub path: PathBuf,
}

/// List every valid tunnel in `config_dir`, sorted by name.
///
/// A missing directory yields an empty list (nothing is deployed yet), which is
/// friendlier for `list`/`current`/`status` than an error. Files without a
/// `.conf` extension, or whose stem is not a valid name, are ignored.
pub fn discover(config_dir: &Path) -> Result<Vec<Tunnel>> {
    let entries = match fs::read_dir(config_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::ConfigDir(config_dir.to_path_buf(), e)),
    };

    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::ConfigDir(config_dir.to_path_buf(), e))?;
        paths.push(entry.path());
    }
    Ok(tunnels_from_paths(paths))
}

/// Filter a set of paths to valid tunnels and sort them by name.
fn tunnels_from_paths(paths: Vec<PathBuf>) -> Vec<Tunnel> {
    let mut tunnels: Vec<Tunnel> = paths.into_iter().filter_map(tunnel_from_path).collect();
    tunnels.sort_by(|a, b| a.name.cmp(&b.name));
    tunnels
}

/// Interpret a single path as a tunnel, or `None` if it is not a valid
/// `<name>.conf` file (wrong extension, non-UTF-8 name, or illegal name).
fn tunnel_from_path(path: PathBuf) -> Option<Tunnel> {
    if path.extension().and_then(|s| s.to_str()) != Some("conf") {
        return None;
    }
    let stem = path.file_stem().and_then(|s| s.to_str())?;
    if !is_valid_name(stem) {
        return None;
    }
    Some(Tunnel {
        name: stem.to_string(),
        path,
    })
}

/// The identifying details of a tunnel's first `[Peer]` section.
///
/// A tunnel's live interface is located by matching these against
/// `wg show all dump`. The allowed-IPs matter because sibling configs for the
/// same server (e.g. full-tunnel vs. split-tunnel) share a public key and
/// differ only in routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The peer's base64 public key.
    pub public_key: String,
    /// Normalized allowed-IPs (see [`crate::status::normalize_allowed`]).
    pub allowed_ips: Vec<String>,
}

/// Extract the first peer's public key and allowed-IPs from a tunnel config.
///
/// Comments (`#` to end of line) are ignored and keys are matched
/// case-insensitively, mirroring `wg-quick`'s own parsing. Repeated
/// `AllowedIPs` lines within the peer are cumulative.
pub fn peer_identity(path: &Path) -> Result<PeerIdentity> {
    let text = fs::read_to_string(path).map_err(|source| Error::TunnelConfRead {
        path: path.to_path_buf(),
        source,
    })?;
    let mut in_first_peer = false;
    let mut seen_peer = false;
    let mut public_key: Option<String> = None;
    let mut allowed: Vec<String> = Vec::new();
    for raw in text.lines() {
        // Values (base64 keys, CIDRs, endpoints) can never contain '#'.
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let is_peer = line.eq_ignore_ascii_case("[peer]");
            in_first_peer = is_peer && !seen_peer;
            seen_peer = seen_peer || is_peer;
            continue;
        }
        if !in_first_peer {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case("publickey") && public_key.is_none() {
            public_key = Some(value.to_string());
        } else if key.eq_ignore_ascii_case("allowedips") {
            allowed.extend(value.split(',').map(str::to_string));
        }
    }
    match public_key {
        Some(public_key) => Ok(PeerIdentity {
            public_key,
            allowed_ips: crate::status::normalize_allowed(&allowed),
        }),
        None => Err(Error::TunnelConfPeer {
            path: path.to_path_buf(),
        }),
    }
}

/// A structural summary of a tunnel config, used by `lint` and `split`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfSummary {
    /// Whether `[Interface]` has a `PrivateKey`.
    pub has_private_key: bool,
    /// The first peer's `PublicKey`, if any.
    pub peer_public_key: Option<String>,
    /// The first peer's raw `AllowedIPs` entries (trimmed, unnormalized).
    pub allowed_ips: Vec<String>,
    /// The first peer's `Endpoint`, if any.
    pub endpoint: Option<String>,
    /// Whether `[Interface]` sets `DNS`.
    pub has_dns: bool,
}

#[derive(Clone, Copy)]
enum Section {
    None,
    Interface,
    FirstPeer,
}

/// Parse the structural summary of a tunnel config. Uses the same comment and
/// case-insensitivity rules as [`peer_identity`].
pub fn conf_summary(path: &Path) -> Result<ConfSummary> {
    let text = fs::read_to_string(path).map_err(|source| Error::TunnelConfRead {
        path: path.to_path_buf(),
        source,
    })?;
    let mut summary = ConfSummary::default();
    let mut section = Section::None;
    let mut seen_peer = false;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = if line.eq_ignore_ascii_case("[interface]") {
                Section::Interface
            } else if line.eq_ignore_ascii_case("[peer]") && !seen_peer {
                seen_peer = true;
                Section::FirstPeer
            } else {
                Section::None
            };
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match section {
            Section::Interface => {
                if key.eq_ignore_ascii_case("privatekey") && !value.is_empty() {
                    summary.has_private_key = true;
                } else if key.eq_ignore_ascii_case("dns") {
                    summary.has_dns = true;
                }
            }
            Section::FirstPeer => {
                if key.eq_ignore_ascii_case("publickey") && summary.peer_public_key.is_none() {
                    summary.peer_public_key = Some(value.to_string());
                } else if key.eq_ignore_ascii_case("allowedips") {
                    summary
                        .allowed_ips
                        .extend(value.split(',').map(|s| s.trim().to_string()));
                } else if key.eq_ignore_ascii_case("endpoint") && summary.endpoint.is_none() {
                    summary.endpoint = Some(value.to_string());
                }
            }
            Section::None => {}
        }
    }
    Ok(summary)
}

/// Resolve a single named tunnel to its config file.
///
/// Errors with [`Error::InvalidName`] for an illegal name and
/// [`Error::TunnelNotFound`] when no matching file exists.
pub fn resolve(config_dir: &Path, name: &str) -> Result<Tunnel> {
    if !is_valid_name(name) {
        return Err(Error::InvalidName(name.to_string()));
    }
    let path = config_dir.join(format!("{name}.conf"));
    if path.is_file() {
        Ok(Tunnel {
            name: name.to_string(),
            path,
        })
    } else {
        Err(Error::TunnelNotFound(name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn name_validation_rules() {
        assert!(is_valid_name("home"));
        assert!(is_valid_name("proton-nl-1"));
        assert!(is_valid_name("wg_0=+.-"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("has space"));
        assert!(!is_valid_name("bad/slash"));
        assert!(!is_valid_name("a".repeat(MAX_NAME_LEN + 1).as_str()));
        assert!(is_valid_name("a".repeat(MAX_NAME_LEN).as_str()));
    }

    #[test]
    fn discover_missing_dir_is_empty() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert_eq!(discover(&missing).unwrap(), Vec::new());
    }

    #[test]
    fn discover_filters_and_sorts() {
        let dir = tempdir().unwrap();
        File::create(dir.path().join("beta.conf")).unwrap();
        File::create(dir.path().join("alpha.conf")).unwrap();
        File::create(dir.path().join("notes.txt")).unwrap(); // wrong extension
        File::create(dir.path().join("bad name.conf")).unwrap(); // invalid stem
        let found = discover(dir.path()).unwrap();
        let names: Vec<_> = found.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta"]);
        assert_eq!(found[0].path, dir.path().join("alpha.conf"));
    }

    #[test]
    #[cfg(unix)]
    fn tunnel_from_path_rejects_non_utf8_stem() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        // A `.conf` path whose stem is not valid UTF-8 yields no tunnel. This is
        // tested in memory because APFS rejects such names on disk.
        let path = PathBuf::from(OsStr::from_bytes(b"\xff\xfe.conf"));
        assert!(tunnel_from_path(path).is_none());
    }

    #[test]
    fn tunnel_from_path_rejects_wrong_extension() {
        assert!(tunnel_from_path(PathBuf::from("/x/notes.txt")).is_none());
    }

    #[test]
    fn discover_errors_on_unreadable_dir() {
        // A path whose parent is a file cannot be read as a directory.
        let dir = tempdir().unwrap();
        let file = dir.path().join("iamafile");
        File::create(&file).unwrap();
        let not_a_dir = file.join("configs");
        let err = discover(&not_a_dir).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn resolve_found() {
        let dir = tempdir().unwrap();
        File::create(dir.path().join("home.conf")).unwrap();
        let t = resolve(dir.path(), "home").unwrap();
        assert_eq!(t.name, "home");
        assert_eq!(t.path, dir.path().join("home.conf"));
    }

    #[test]
    fn resolve_invalid_name() {
        let dir = tempdir().unwrap();
        let err = resolve(dir.path(), "bad name").unwrap_err();
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn resolve_not_found() {
        let dir = tempdir().unwrap();
        let err = resolve(dir.path(), "ghost").unwrap_err();
        assert_eq!(err.exit_code(), 3);
    }

    fn write_conf(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(format!("{name}.conf"));
        fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn peer_identity_parses_key_and_allowed_ips() {
        let dir = tempdir().unwrap();
        let path = write_conf(
            dir.path(),
            "t",
            "[Interface]\nPrivateKey = PRIV=\nAddress = 10.0.0.2/32\n\n\
             # US-MA#93\n[Peer]\nPublicKey = PEER=\nAllowedIPs = 0.0.0.0/0, ::/0\n\
             Endpoint = 1.2.3.4:51820\n",
        );
        let id = peer_identity(&path).unwrap();
        assert_eq!(id.public_key, "PEER=");
        assert_eq!(id.allowed_ips, vec!["0.0.0.0/0", "::/0"]);
    }

    #[test]
    fn peer_identity_is_case_insensitive_and_strips_comments() {
        let dir = tempdir().unwrap();
        let path = write_conf(
            dir.path(),
            "t",
            "[peer] # inline comment\npublickey = KEY # trailing\nallowedips = 10.0.0.0/8\n",
        );
        let id = peer_identity(&path).unwrap();
        assert_eq!(id.public_key, "KEY");
        assert_eq!(id.allowed_ips, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn peer_identity_accumulates_repeated_allowed_ips() {
        let dir = tempdir().unwrap();
        let path = write_conf(
            dir.path(),
            "t",
            "[Peer]\nPublicKey = K\nAllowedIPs = 10.0.0.0/8\nAllowedIPs = 172.16.0.0/12, 192.168.0.0/16\n",
        );
        let id = peer_identity(&path).unwrap();
        assert_eq!(
            id.allowed_ips,
            vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        );
    }

    #[test]
    fn peer_identity_uses_only_first_peer_section() {
        let dir = tempdir().unwrap();
        let path = write_conf(
            dir.path(),
            "t",
            "[Peer]\nPublicKey = FIRST\nAllowedIPs = 10.0.0.0/8\n\n\
             [Peer]\nPublicKey = SECOND\nAllowedIPs = 0.0.0.0/0\n",
        );
        let id = peer_identity(&path).unwrap();
        assert_eq!(id.public_key, "FIRST");
        assert_eq!(id.allowed_ips, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn peer_identity_allows_missing_allowed_ips() {
        let dir = tempdir().unwrap();
        let path = write_conf(dir.path(), "t", "[Peer]\nPublicKey = K\n");
        let id = peer_identity(&path).unwrap();
        assert!(id.allowed_ips.is_empty());
    }

    #[test]
    fn peer_identity_errors_without_peer_public_key() {
        let dir = tempdir().unwrap();
        let path = write_conf(
            dir.path(),
            "t",
            "[Interface]\nPrivateKey = P\nnot-a-kv-line\n",
        );
        let err = peer_identity(&path).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("[Peer] PublicKey"));
    }

    #[test]
    fn peer_identity_skips_non_kv_lines_inside_peer() {
        let dir = tempdir().unwrap();
        let path = write_conf(
            dir.path(),
            "t",
            "[Peer]\nnoise without equals\nPublicKey = K\n",
        );
        assert_eq!(peer_identity(&path).unwrap().public_key, "K");
    }

    #[test]
    fn peer_identity_errors_on_unreadable_file() {
        let dir = tempdir().unwrap();
        let err = peer_identity(&dir.path().join("missing.conf")).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("could not be read"));
    }

    #[test]
    fn conf_summary_full_config() {
        let dir = tempdir().unwrap();
        let path = write_conf(
            dir.path(),
            "t",
            "[Interface]\nPrivateKey = PRIV=\nAddress = 10.0.0.2/32\nDNS = 10.2.0.1\n\n\
             [Peer]\nPublicKey = PEER=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 1.2.3.4:51820\n",
        );
        let s = conf_summary(&path).unwrap();
        assert!(s.has_private_key);
        assert!(s.has_dns);
        assert_eq!(s.peer_public_key.as_deref(), Some("PEER="));
        assert_eq!(s.allowed_ips, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(s.endpoint.as_deref(), Some("1.2.3.4:51820"));
    }

    #[test]
    fn conf_summary_minimal_and_second_peer_ignored() {
        let dir = tempdir().unwrap();
        let path = write_conf(
            dir.path(),
            "t",
            "[Peer]\nPublicKey = FIRST\n\n[Peer]\nPublicKey = SECOND\nEndpoint = 9.9.9.9:1\n",
        );
        let s = conf_summary(&path).unwrap();
        assert!(!s.has_private_key);
        assert!(!s.has_dns);
        assert_eq!(s.peer_public_key.as_deref(), Some("FIRST"));
        assert!(s.allowed_ips.is_empty());
        assert_eq!(s.endpoint, None, "second peer's endpoint must not leak in");
    }

    #[test]
    fn conf_summary_empty_private_key_does_not_count() {
        let dir = tempdir().unwrap();
        let path = write_conf(dir.path(), "t", "[Interface]\nPrivateKey =\n");
        assert!(!conf_summary(&path).unwrap().has_private_key);
    }

    #[test]
    fn conf_summary_unreadable_file_errors() {
        let dir = tempdir().unwrap();
        let err = conf_summary(&dir.path().join("missing.conf")).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn conf_summary_skips_non_kv_lines() {
        let dir = tempdir().unwrap();
        let path = write_conf(dir.path(), "t", "[Peer]\nnoise line\nPublicKey = K\n");
        assert_eq!(
            conf_summary(&path).unwrap().peer_public_key.as_deref(),
            Some("K")
        );
    }
}
