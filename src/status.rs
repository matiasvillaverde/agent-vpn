//! Tunnel status model and parsing of `wg show all dump` output.
//!
//! Live tunnels are observed exclusively through `wg show all dump`: one
//! privileged call that reports every interface and peer. Tunnels are matched
//! to interfaces by peer identity (see [`crate::config::peer_identity`]) rather
//! than via `wg-quick`'s `<name>.name` mapping file, which is written root-only
//! on macOS and therefore unreadable to the unprivileged CLI.

use serde::Serialize;

/// A single WireGuard peer as reported by `wg`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Peer {
    /// The peer's base64 public key.
    pub public_key: String,
    /// Current endpoint `host:port`, if the peer has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Unix timestamp of the last handshake, or `None` if none has happened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_handshake: Option<u64>,
    /// Bytes received from this peer.
    pub transfer_rx: u64,
    /// Bytes sent to this peer.
    pub transfer_tx: u64,
    /// Allowed IP ranges routed to this peer.
    pub allowed_ips: Vec<String>,
}

/// The status of one tunnel.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TunnelStatus {
    /// Tunnel (config) name.
    pub name: String,
    /// Whether the tunnel is currently up.
    pub up: bool,
    /// The kernel interface backing it (e.g. `utun4`), when up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Peers, when up.
    pub peers: Vec<Peer>,
}

impl TunnelStatus {
    /// A status value representing a tunnel that is not up.
    #[must_use]
    pub fn down(name: &str) -> Self {
        Self {
            name: name.to_string(),
            up: false,
            interface: None,
            peers: Vec::new(),
        }
    }
}

/// A compact entry used by the `list` command.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ListEntry {
    /// Tunnel name.
    pub name: String,
    /// Whether it is currently up.
    pub up: bool,
}

/// One peer row from `wg show all dump`, tagged with the interface it lives on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpPeer {
    /// Kernel interface name (e.g. `utun4` on macOS, `wg0` on Linux).
    pub interface: String,
    /// The peer's reported state.
    pub peer: Peer,
}

/// Parse the tab-separated output of `wg show all dump`.
///
/// Interface rows (5 fields) are skipped; peer rows (9 fields, the first being
/// the interface name) become [`DumpPeer`]s. Malformed lines are ignored. Empty
/// output — no interfaces — yields an empty list.
#[must_use]
pub fn parse_all_dump(dump: &str) -> Vec<DumpPeer> {
    let mut peers = Vec::new();
    for line in dump.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 9 {
            continue; // interface row (5 fields) or malformed
        }
        let endpoint = match fields[3] {
            "(none)" => None,
            other => Some(other.to_string()),
        };
        let latest_handshake = fields[5].parse::<u64>().ok().filter(|&h| h != 0);
        let allowed_ips = match fields[4] {
            "(none)" => Vec::new(),
            other => other.split(',').map(|s| s.trim().to_string()).collect(),
        };
        peers.push(DumpPeer {
            interface: fields[0].to_string(),
            peer: Peer {
                public_key: fields[1].to_string(),
                endpoint,
                latest_handshake,
                transfer_rx: fields[6].parse().unwrap_or(0),
                transfer_tx: fields[7].parse().unwrap_or(0),
                allowed_ips,
            },
        });
    }
    peers
}

/// Normalize allowed-IP entries for comparison: trim, lowercase, drop empties,
/// sort, dedup. Two allowed-IP lists describe the same routing set iff their
/// normalized forms are equal.
#[must_use]
pub fn normalize_allowed<S: AsRef<str>>(items: &[S]) -> Vec<String> {
    let mut out: Vec<String> = items
        .iter()
        .map(|s| s.as_ref().trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_DUMP: &str = "utun7\tIFPRIV\tIFPUB\t51820\toff\n\
        utun7\tPEERKEY\t(none)\t203.0.113.1:51820\t0.0.0.0/0,::/0\t1700000000\t1024\t2048\t25\n\
        utun9\tIFPRIV2\tIFPUB2\t51821\toff\n\
        utun9\tPEER2\tPSK\t(none)\t(none)\t0\t0\t0\toff\n";

    #[test]
    fn down_helper() {
        let s = TunnelStatus::down("home");
        assert!(!s.up);
        assert_eq!(s.name, "home");
        assert!(s.interface.is_none());
        assert!(s.peers.is_empty());
    }

    #[test]
    fn parse_all_dump_extracts_tagged_peers() {
        let peers = parse_all_dump(ALL_DUMP);
        assert_eq!(peers.len(), 2);

        let p0 = &peers[0];
        assert_eq!(p0.interface, "utun7");
        assert_eq!(p0.peer.public_key, "PEERKEY");
        assert_eq!(p0.peer.endpoint.as_deref(), Some("203.0.113.1:51820"));
        assert_eq!(p0.peer.latest_handshake, Some(1_700_000_000));
        assert_eq!(p0.peer.transfer_rx, 1024);
        assert_eq!(p0.peer.transfer_tx, 2048);
        assert_eq!(p0.peer.allowed_ips, vec!["0.0.0.0/0", "::/0"]);

        let p1 = &peers[1];
        assert_eq!(p1.interface, "utun9");
        assert_eq!(p1.peer.endpoint, None);
        assert_eq!(p1.peer.latest_handshake, None);
        assert!(p1.peer.allowed_ips.is_empty());
    }

    #[test]
    fn parse_all_dump_skips_malformed_and_empty() {
        assert!(parse_all_dump("").is_empty());
        assert!(parse_all_dump("just one field\n\nTOO\tFEW\tFIELDS\n").is_empty());
    }

    #[test]
    fn parse_all_dump_defaults_bad_numbers_to_zero() {
        let dump = "wg0\tK\tP\te:1\t10.0.0.0/8\tnotanum\tx\ty\toff\n";
        let peers = parse_all_dump(dump);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].peer.latest_handshake, None);
        assert_eq!(peers[0].peer.transfer_rx, 0);
        assert_eq!(peers[0].peer.transfer_tx, 0);
    }

    #[test]
    fn normalize_allowed_sorts_trims_and_dedups() {
        let norm = normalize_allowed(&[" ::/0", "0.0.0.0/0 ", "::/0", ""]);
        assert_eq!(norm, vec!["0.0.0.0/0", "::/0"]);
        // Conf-style with spaces equals dump-style without.
        assert_eq!(
            normalize_allowed(&["0.0.0.0/0", " ::/0"]),
            normalize_allowed(&["::/0", "0.0.0.0/0"]),
        );
        assert!(normalize_allowed::<&str>(&[]).is_empty());
    }

    #[test]
    fn normalize_allowed_lowercases_ipv6() {
        assert_eq!(
            normalize_allowed(&["2A07:B944::2:2/128"]),
            vec!["2a07:b944::2:2/128"]
        );
    }
}
