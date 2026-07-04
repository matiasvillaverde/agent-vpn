//! Static safety checks over tunnel configs.
//!
//! The headline check catches the split-tunnel routing loop found in live
//! testing: an `AllowedIPs` CIDR that covers the tunnel's own `Endpoint`
//! routes the encrypted packets into the tunnel itself, and the handshake
//! silently times out. `wg-quick` only installs an endpoint bypass route for
//! exact-`0.0.0.0/0` configs, so anything else must exclude the endpoint.

use serde::Serialize;

use crate::cidr::{self, Cidr4};
use crate::config::ConfSummary;

/// How serious a finding is. Errors make a config unusable or broken;
/// warnings are advisory.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// The config will not work (or will break routing) as written.
    Error,
    /// Worth knowing; the config can still work.
    Warning,
}

/// One lint finding.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    /// Severity of the finding.
    pub severity: Severity,
    /// Human-readable explanation.
    pub message: String,
}

/// The lint outcome for one tunnel config.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LintResult {
    /// Tunnel name.
    pub name: String,
    /// `true` when no error-severity findings exist.
    pub ok: bool,
    /// All findings, errors first.
    pub findings: Vec<Finding>,
}

/// Lint a config summary.
#[must_use]
pub fn lint(name: &str, summary: &ConfSummary) -> LintResult {
    let mut findings = Vec::new();
    if !summary.has_private_key {
        findings.push(Finding {
            severity: Severity::Error,
            message: "no [Interface] PrivateKey — wg-quick cannot bring this up".to_string(),
        });
    }
    if summary.peer_public_key.is_none() {
        findings.push(Finding {
            severity: Severity::Error,
            message: "no [Peer] PublicKey — not a usable WireGuard peer".to_string(),
        });
    }
    match summary.endpoint.as_deref() {
        None => findings.push(Finding {
            severity: Severity::Warning,
            message: "no Endpoint — unusable as a VPN client config".to_string(),
        }),
        Some(endpoint) => {
            if let Some(finding) = check_routing_loop(endpoint, &summary.allowed_ips) {
                findings.push(finding);
            }
        }
    }
    findings.sort_by_key(|f| match f.severity {
        Severity::Error => 0,
        Severity::Warning => 1,
    });
    LintResult {
        name: name.to_string(),
        ok: !findings.iter().any(|f| f.severity == Severity::Error),
        findings,
    }
}

/// Extract the IPv4 host from an `Endpoint` value (`host:port`). Hostnames
/// and IPv6 endpoints return `None` — they cannot be checked statically.
fn endpoint_v4(endpoint: &str) -> Option<u32> {
    let host = endpoint.rsplit_once(':').map_or(endpoint, |(host, _)| host);
    cidr::parse_ip4(host).ok()
}

/// The routing-loop check: a non-default-route AllowedIPs set must not cover
/// the endpoint's own address.
fn check_routing_loop(endpoint: &str, allowed_ips: &[String]) -> Option<Finding> {
    let ip = endpoint_v4(endpoint)?;
    let entries: Vec<Cidr4> = allowed_ips
        .iter()
        .filter_map(|s| Cidr4::parse(s).ok())
        .collect();
    // wg-quick special-cases an exact default route with an endpoint bypass.
    if entries.iter().any(|c| c.prefix == 0) {
        return None;
    }
    let covering = entries.iter().find(|c| c.contains_ip(ip))?;
    Some(Finding {
        severity: Severity::Error,
        message: format!(
            "routing loop: AllowedIPs {covering} covers the Endpoint ({endpoint}) — the tunnel's \
             own packets would route into the tunnel; exclude the endpoint /32 \
             (`vpn split` does this automatically)"
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfSummary;

    fn good_summary() -> ConfSummary {
        ConfSummary {
            has_private_key: true,
            peer_public_key: Some("PEER=".to_string()),
            allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
            endpoint: Some("79.127.160.216:51820".to_string()),
            has_dns: false,
            dns_servers: Vec::new(),
        }
    }

    #[test]
    fn clean_config_is_ok() {
        let result = lint("proton", &good_summary());
        assert!(result.ok);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn missing_keys_are_errors() {
        let summary = ConfSummary {
            has_private_key: false,
            peer_public_key: None,
            ..good_summary()
        };
        let result = lint("bad", &summary);
        assert!(!result.ok);
        assert_eq!(result.findings.len(), 2);
        assert!(result
            .findings
            .iter()
            .all(|f| f.severity == Severity::Error));
    }

    #[test]
    fn missing_endpoint_is_a_warning_only() {
        let summary = ConfSummary {
            endpoint: None,
            ..good_summary()
        };
        let result = lint("srv", &summary);
        assert!(result.ok, "warnings alone keep ok=true");
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert!(result.findings[0].message.contains("no Endpoint"));
    }

    #[test]
    fn detects_the_live_routing_loop() {
        // The exact broken config from live testing: split AllowedIPs where
        // 64.0.0.0/3 covered the 79.127.160.216 endpoint.
        let summary = ConfSummary {
            allowed_ips: vec![
                "0.0.0.0/2".to_string(),
                "64.0.0.0/3".to_string(),
                "96.0.0.0/6".to_string(),
                "::/0".to_string(),
            ],
            ..good_summary()
        };
        let result = lint("proton-ts", &summary);
        assert!(!result.ok);
        let msg = &result.findings[0].message;
        assert!(msg.contains("routing loop"));
        assert!(msg.contains("64.0.0.0/3"));
        assert!(msg.contains("79.127.160.216"));
    }

    #[test]
    fn full_tunnel_default_route_is_not_a_loop() {
        // 0.0.0.0/0 covers every endpoint, but wg-quick adds a bypass.
        let result = lint("proton", &good_summary());
        assert!(result.ok);
    }

    #[test]
    fn split_tunnel_excluding_endpoint_is_ok() {
        let summary = ConfSummary {
            allowed_ips: vec![
                "0.0.0.0/2".to_string(),
                "64.0.0.0/5".to_string(), // 64-71: does NOT cover 79.x
                "128.0.0.0/1".to_string(),
                "::/0".to_string(),
            ],
            ..good_summary()
        };
        assert!(lint("split", &summary).ok);
    }

    #[test]
    fn hostname_and_v6_endpoints_skip_the_static_check() {
        for endpoint in ["vpn.example.com:51820", "[2a07:b944::1]:51820"] {
            let summary = ConfSummary {
                endpoint: Some(endpoint.to_string()),
                allowed_ips: vec!["64.0.0.0/3".to_string()],
                ..good_summary()
            };
            assert!(lint("host", &summary).ok, "cannot verify {endpoint}");
        }
    }

    #[test]
    fn unparseable_allowed_entries_are_skipped() {
        let summary = ConfSummary {
            allowed_ips: vec!["not-a-cidr".to_string(), "2a07:b944::/32".to_string()],
            ..good_summary()
        };
        assert!(lint("odd", &summary).ok);
    }

    #[test]
    fn findings_sort_errors_first() {
        let summary = ConfSummary {
            has_private_key: false, // error
            endpoint: None,         // warning
            ..good_summary()
        };
        let result = lint("mixed", &summary);
        assert_eq!(result.findings[0].severity, Severity::Error);
        assert_eq!(result.findings.last().unwrap().severity, Severity::Warning);
    }
}
