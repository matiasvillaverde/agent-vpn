//! Structural comparison of an HTTP response fetched through many VPN exits.
//!
//! `vpn diff <url>` requests the same URL from every location and reports where
//! the responses differ — the CDN/geo-debugging workflow ("is the São Paulo
//! edge serving stale content? does Australia get a different redirect?") as a
//! single call. This module holds the pure, testable pieces: parsing curl's
//! header dump and computing which headers vary across locations.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::probe::OUTPUT_MARKER;

/// The status line and headers captured from one response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Head {
    /// HTTP status code, if parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Response headers, keys lower-cased for stable comparison.
    pub headers: BTreeMap<String, String>,
}

/// Parse curl output of the form `<header dump>` + [`OUTPUT_MARKER`] +
/// `%{http_code}`. The header dump is what `curl -D -` writes: an HTTP status
/// line followed by `Key: Value` lines. Header keys are lower-cased; on a
/// repeated header (or a redirect chain) the last value wins.
#[must_use]
pub fn parse_head(stdout: &str) -> Head {
    let (headers_blob, status_str) = match stdout.rfind(OUTPUT_MARKER) {
        Some(pos) => (&stdout[..pos], &stdout[pos + OUTPUT_MARKER.len()..]),
        None => (stdout, ""),
    };
    let status = status_str.trim().parse::<u16>().ok();
    let mut headers = BTreeMap::new();
    for line in headers_blob.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with("HTTP/") {
            continue; // blank separators and status lines
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    Head { status, headers }
}

/// One location's fetch result, ready to compare and serialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocationResult {
    /// Tunnel name.
    pub name: String,
    /// Whether the fetch succeeded.
    pub ok: bool,
    /// HTTP status, when the fetch succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Response headers, when the fetch succeeded.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Exit IP the request appeared to come from (proof of egress), if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_ip: Option<String>,
    /// Failure message, when the fetch failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One header (or the status) whose value is not identical across all
/// successful locations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldDiff {
    /// Field name (`status`, or a lower-cased header name).
    pub field: String,
    /// Per-location value; `None` where that location did not send the field.
    pub values: BTreeMap<String, Option<String>>,
}

/// Compute the fields (status + headers) that differ across the successful
/// locations. A field is included iff at least two locations disagree on its
/// value (treating "absent" as its own value). Locations that failed are
/// ignored. Returns an empty vec when every location agreed.
#[must_use]
pub fn diff_fields(results: &[LocationResult]) -> Vec<FieldDiff> {
    let ok: Vec<&LocationResult> = results.iter().filter(|r| r.ok).collect();
    if ok.len() < 2 {
        return Vec::new();
    }
    let mut diffs = Vec::new();

    // Status.
    let statuses: BTreeSet<Option<u16>> = ok.iter().map(|r| r.status).collect();
    if statuses.len() > 1 {
        diffs.push(FieldDiff {
            field: "status".to_string(),
            values: ok
                .iter()
                .map(|r| (r.name.clone(), r.status.map(|s| s.to_string())))
                .collect(),
        });
    }

    // Every header key seen at any location.
    let keys: BTreeSet<&String> = ok.iter().flat_map(|r| r.headers.keys()).collect();
    for key in keys {
        let values: BTreeMap<String, Option<String>> = ok
            .iter()
            .map(|r| (r.name.clone(), r.headers.get(key).cloned()))
            .collect();
        let distinct: BTreeSet<&Option<String>> = values.values().collect();
        if distinct.len() > 1 {
            diffs.push(FieldDiff {
                field: key.clone(),
                values,
            });
        }
    }
    diffs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(stdout: &str) -> Head {
        parse_head(stdout)
    }

    #[test]
    fn parse_head_extracts_status_and_lowercased_headers() {
        let out = format!(
            "HTTP/2 200 \nContent-Type: text/html\nCF-Cache-Status: HIT\n\n{OUTPUT_MARKER}200"
        );
        let h = head(&out);
        assert_eq!(h.status, Some(200));
        assert_eq!(h.headers.get("content-type").unwrap(), "text/html");
        assert_eq!(h.headers.get("cf-cache-status").unwrap(), "HIT");
    }

    #[test]
    fn parse_head_tolerates_missing_marker_and_values_with_colons() {
        let h = head("HTTP/1.1 302 Found\nLocation: https://x.example/a:b\n\n");
        assert_eq!(h.status, None);
        assert_eq!(h.headers.get("location").unwrap(), "https://x.example/a:b");
    }

    fn loc(name: &str, status: u16, hs: &[(&str, &str)]) -> LocationResult {
        LocationResult {
            name: name.to_string(),
            ok: true,
            status: Some(status),
            headers: hs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            exit_ip: None,
            error: None,
        }
    }

    #[test]
    fn diff_fields_reports_only_varying_fields() {
        let results = vec![
            loc(
                "us",
                200,
                &[("cf-cache-status", "HIT"), ("server", "cloudflare")],
            ),
            loc(
                "br",
                200,
                &[("cf-cache-status", "MISS"), ("server", "cloudflare")],
            ),
        ];
        let diffs = diff_fields(&results);
        assert_eq!(diffs.len(), 1, "only cf-cache-status varies");
        assert_eq!(diffs[0].field, "cf-cache-status");
        assert_eq!(diffs[0].values["us"].as_deref(), Some("HIT"));
        assert_eq!(diffs[0].values["br"].as_deref(), Some("MISS"));
    }

    #[test]
    fn diff_fields_flags_status_and_absent_headers() {
        let results = vec![
            loc("us", 200, &[("x-geo", "us")]),
            loc("au", 302, &[]), // different status, and x-geo absent
        ];
        let diffs = diff_fields(&results);
        let fields: BTreeSet<&str> = diffs.iter().map(|d| d.field.as_str()).collect();
        assert!(fields.contains("status"));
        assert!(fields.contains("x-geo"));
        let geo = diffs.iter().find(|d| d.field == "x-geo").unwrap();
        assert_eq!(geo.values["au"], None, "absent header recorded as None");
    }

    #[test]
    fn diff_fields_empty_when_all_identical() {
        let results = vec![
            loc("us", 200, &[("server", "nginx")]),
            loc("br", 200, &[("server", "nginx")]),
        ];
        assert!(diff_fields(&results).is_empty());
    }

    #[test]
    fn diff_fields_ignores_failures_and_needs_two_successes() {
        let mut failed = loc("br", 0, &[]);
        failed.ok = false;
        failed.status = None;
        failed.error = Some("timeout".into());
        let results = vec![loc("us", 200, &[("server", "nginx")]), failed];
        // Only one successful location → nothing to compare.
        assert!(diff_fields(&results).is_empty());
    }
}
