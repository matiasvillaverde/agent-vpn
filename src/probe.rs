//! Latency probing: timed HTTP requests through a tunnel.
//!
//! A probe brings the tunnel up if needed, issues one or more timed `curl`
//! requests (`--count N`), then restores the tunnel to its prior state.
//! Probing every configured tunnel in sequence compares latency across VPN
//! locations; multi-sample stats smooth out single-request jitter.

use serde::Serialize;

/// The curl `--write-out` format used for probes (comma-separated fields, all
/// times in seconds).
pub const CURL_FORMAT: &str = "%{time_namelookup},%{time_connect},%{time_appconnect},%{time_starttransfer},%{time_total},%{remote_ip},%{http_code}";

/// Separator emitted between the (optional) response body and the write-out
/// metadata, so both can travel over curl's stdout.
pub const OUTPUT_MARKER: &str = "<<<VPNPROBE>>>";

/// Exit-location evidence parsed from a `cdn-cgi/trace` response body.
///
/// `ip` is the address the edge saw the request come from — i.e. the VPN
/// exit's public IP — and `colo`/`loc` identify the answering PoP and its
/// country. Together they prove *where* the probe actually egressed.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TraceInfo {
    /// Public IP the request appeared to come from (the tunnel exit).
    pub ip: String,
    /// Country code reported by the edge, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loc: Option<String>,
    /// CDN point-of-presence that answered, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub colo: Option<String>,
}

/// Parse a `cdn-cgi/trace`-style `key=value` body into [`TraceInfo`].
///
/// Returns `None` unless an `ip=` line is present — anything else is not
/// usable exit evidence.
#[must_use]
pub fn parse_trace_body(body: &str) -> Option<TraceInfo> {
    let mut ip = None;
    let mut loc = None;
    let mut colo = None;
    for line in body.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "ip" => ip = Some(value.to_string()),
            "loc" => loc = Some(value.to_string()),
            "colo" => colo = Some(value.to_string()),
            _ => {}
        }
    }
    ip.map(|ip| TraceInfo { ip, loc, colo })
}

/// One fully parsed probe sample.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// Timing breakdown.
    pub timings: Timings,
    /// Server IP the request connected to.
    pub remote_ip: Option<String>,
    /// HTTP status of the response.
    pub http_code: Option<u16>,
    /// Exit-location evidence, when the response body was a trace.
    pub trace: Option<TraceInfo>,
}

/// Parse curl's combined stdout: `[body]` + [`OUTPUT_MARKER`] + write-out
/// metadata. A missing marker is tolerated (the whole output is treated as
/// metadata) so plain write-out output still parses.
pub fn parse_probe_output(stdout: &str) -> Result<Sample, String> {
    let (body, meta) = match stdout.rfind(OUTPUT_MARKER) {
        Some(pos) => (&stdout[..pos], &stdout[pos + OUTPUT_MARKER.len()..]),
        None => ("", stdout),
    };
    let (timings, remote_ip, http_code) = parse_curl_output(meta.trim())?;
    Ok(Sample {
        timings,
        remote_ip,
        http_code,
        trace: parse_trace_body(body),
    })
}

/// Timing breakdown of a probe request, in milliseconds. All values are
/// cumulative from the start of the request, matching curl's semantics.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Timings {
    /// DNS resolution completed.
    pub dns_ms: f64,
    /// TCP connection established.
    pub connect_ms: f64,
    /// TLS handshake completed (0 for plain HTTP).
    pub tls_ms: f64,
    /// First response byte received.
    pub ttfb_ms: f64,
    /// Request fully completed.
    pub total_ms: f64,
}

/// Aggregate statistics over a multi-sample probe (`--count N`).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Stats {
    /// Fastest total time across successful samples.
    pub min_total_ms: f64,
    /// Median total time across successful samples.
    pub median_total_ms: f64,
    /// Slowest total time across successful samples.
    pub max_total_ms: f64,
    /// Time-to-first-byte of the median sample.
    pub median_ttfb_ms: f64,
}

/// Compute [`Stats`] over successful samples, returning the stats and the
/// index of the median sample (by total time; upper-middle for even counts).
/// Returns `None` for an empty slice.
#[must_use]
pub fn compute_stats(samples: &[Timings]) -> Option<(Stats, usize)> {
    if samples.is_empty() {
        return None;
    }
    let mut order: Vec<usize> = (0..samples.len()).collect();
    order.sort_by(|&a, &b| {
        samples[a]
            .total_ms
            .partial_cmp(&samples[b].total_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let median_idx = order[order.len() / 2];
    let stats = Stats {
        min_total_ms: samples[order[0]].total_ms,
        median_total_ms: samples[median_idx].total_ms,
        max_total_ms: samples[order[order.len() - 1]].total_ms,
        median_ttfb_ms: samples[median_idx].ttfb_ms,
    };
    Some((stats, median_idx))
}

/// The outcome of probing one tunnel.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ProbeResult {
    /// Tunnel name.
    pub name: String,
    /// URL that was requested.
    pub url: String,
    /// Whether the probe completed (at least one sample succeeded).
    pub ok: bool,
    /// Whether the tunnel was brought up for this probe (and torn down after).
    pub activated: bool,
    /// Number of requests attempted.
    pub samples: u32,
    /// Number of requests that failed.
    pub failures: u32,
    /// Aggregate timing statistics (present when any sample succeeded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<Stats>,
    /// Interface the tunnel ran on during the probe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// HTTP status of the median sample's response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_code: Option<u16>,
    /// Server IP the median sample actually connected to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    /// Exit-location evidence from the median sample (trace URLs only): the
    /// tunnel's public exit IP and the answering PoP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<TraceInfo>,
    /// Timing breakdown of the median sample.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timings: Option<Timings>,
    /// Why the probe failed (first failure message).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Non-fatal problem (e.g. the tunnel state could not be restored).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

impl ProbeResult {
    /// A not-yet-successful result for `name`; fields are filled in as the
    /// probe progresses.
    #[must_use]
    pub fn new(name: &str, url: &str, activated: bool) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
            ok: false,
            activated,
            samples: 0,
            failures: 0,
            stats: None,
            interface: None,
            http_code: None,
            remote_ip: None,
            exit: None,
            timings: None,
            error: None,
            warning: None,
        }
    }

    /// Median total time in ms, or `+inf` when the probe failed — so sorting
    /// by this value puts failures last.
    #[must_use]
    pub fn total_ms(&self) -> f64 {
        self.timings.as_ref().map_or(f64::INFINITY, |t| t.total_ms)
    }
}

/// Parse curl's write-out output per [`CURL_FORMAT`].
///
/// Returns the timings plus the remote IP and HTTP status when present, or a
/// human-readable message describing the mismatch.
pub fn parse_curl_output(s: &str) -> Result<(Timings, Option<String>, Option<u16>), String> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 7 {
        return Err(format!("expected 7 fields, got {}", parts.len()));
    }
    let secs = |i: usize| -> Result<f64, String> {
        parts[i]
            .trim()
            .parse::<f64>()
            .map_err(|_| format!("field {i} is not a number: '{}'", parts[i]))
    };
    // Seconds -> milliseconds, rounded to one decimal for stable output.
    let ms = |v: f64| (v * 10_000.0).round() / 10.0;
    let timings = Timings {
        dns_ms: ms(secs(0)?),
        connect_ms: ms(secs(1)?),
        tls_ms: ms(secs(2)?),
        ttfb_ms: ms(secs(3)?),
        total_ms: ms(secs(4)?),
    };
    let remote_ip = Some(parts[5].trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let http_code = parts[6].trim().parse::<u16>().ok().filter(|&c| c != 0);
    Ok((timings, remote_ip, http_code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_output() {
        let (t, ip, code) =
            parse_curl_output("0.004000,0.012000,0.140000,0.290000,0.291000,104.16.132.229,200")
                .unwrap();
        assert_eq!(t.dns_ms, 4.0);
        assert_eq!(t.connect_ms, 12.0);
        assert_eq!(t.tls_ms, 140.0);
        assert_eq!(t.ttfb_ms, 290.0);
        assert_eq!(t.total_ms, 291.0);
        assert_eq!(ip.as_deref(), Some("104.16.132.229"));
        assert_eq!(code, Some(200));
    }

    #[test]
    fn parse_absent_ip_and_code() {
        let (_, ip, code) = parse_curl_output("0,0,0,0,0,,000").unwrap();
        assert_eq!(ip, None);
        assert_eq!(code, None);
    }

    #[test]
    fn parse_rejects_wrong_field_count() {
        let err = parse_curl_output("1,2,3").unwrap_err();
        assert!(err.contains("expected 7 fields"));
    }

    #[test]
    fn parse_rejects_non_numeric_time() {
        let err = parse_curl_output("a,0,0,0,0,,200").unwrap_err();
        assert!(err.contains("not a number"));
    }

    #[test]
    fn total_ms_is_infinite_for_failures() {
        let r = ProbeResult::new("x", "https://example.com", true);
        assert!(r.total_ms().is_infinite());
        assert!(!r.ok);
        assert!(r.activated);
        assert_eq!(r.samples, 0);
        assert_eq!(r.failures, 0);
    }

    fn t(total: f64, ttfb: f64) -> Timings {
        Timings {
            dns_ms: 1.0,
            connect_ms: 2.0,
            tls_ms: 3.0,
            ttfb_ms: ttfb,
            total_ms: total,
        }
    }

    #[test]
    fn parse_trace_body_extracts_exit_evidence() {
        let body =
            "fl=123abc\nip=203.0.113.99\nts=1700000000\nloc=US\ncolo=EWR\nvisit_scheme=https\n";
        let trace = parse_trace_body(body).unwrap();
        assert_eq!(trace.ip, "203.0.113.99");
        assert_eq!(trace.loc.as_deref(), Some("US"));
        assert_eq!(trace.colo.as_deref(), Some("EWR"));
    }

    #[test]
    fn parse_trace_body_requires_ip() {
        assert!(parse_trace_body("loc=US\ncolo=EWR\n").is_none());
        assert!(parse_trace_body("").is_none());
        assert!(parse_trace_body("<html>not a trace</html>").is_none());
        assert!(parse_trace_body("ip=\nloc=US\n").is_none());
    }

    #[test]
    fn parse_probe_output_with_body_and_marker() {
        let stdout = format!(
            "ip=1.2.3.4\nloc=JP\ncolo=NRT\n{OUTPUT_MARKER}0.001,0.002,0.003,0.100,0.101,9.9.9.9,200"
        );
        let sample = parse_probe_output(&stdout).unwrap();
        assert_eq!(sample.timings.total_ms, 101.0);
        assert_eq!(sample.remote_ip.as_deref(), Some("9.9.9.9"));
        assert_eq!(sample.http_code, Some(200));
        let trace = sample.trace.unwrap();
        assert_eq!(trace.ip, "1.2.3.4");
        assert_eq!(trace.colo.as_deref(), Some("NRT"));
    }

    #[test]
    fn parse_probe_output_without_marker_is_metadata_only() {
        let sample = parse_probe_output("0.001,0.002,0.003,0.100,0.101,9.9.9.9,200").unwrap();
        assert_eq!(sample.timings.total_ms, 101.0);
        assert!(sample.trace.is_none());
    }

    #[test]
    fn parse_probe_output_empty_body_has_no_trace() {
        let stdout = format!("\n{OUTPUT_MARKER}0,0,0,0,0,,200");
        let sample = parse_probe_output(&stdout).unwrap();
        assert!(sample.trace.is_none());
    }

    #[test]
    fn parse_probe_output_rejects_garbage_metadata() {
        let stdout = format!("ip=1.2.3.4\n{OUTPUT_MARKER}<html>portal</html>");
        assert!(parse_probe_output(&stdout).is_err());
    }

    #[test]
    fn compute_stats_empty_is_none() {
        assert!(compute_stats(&[]).is_none());
    }

    #[test]
    fn compute_stats_single_sample() {
        let (stats, idx) = compute_stats(&[t(100.0, 90.0)]).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(stats.min_total_ms, 100.0);
        assert_eq!(stats.median_total_ms, 100.0);
        assert_eq!(stats.max_total_ms, 100.0);
        assert_eq!(stats.median_ttfb_ms, 90.0);
    }

    #[test]
    fn compute_stats_odd_count_picks_true_median() {
        // Out of order on purpose: 300, 100, 200 -> median 200 at index 2.
        let samples = [t(300.0, 290.0), t(100.0, 90.0), t(200.0, 190.0)];
        let (stats, idx) = compute_stats(&samples).unwrap();
        assert_eq!(idx, 2);
        assert_eq!(stats.min_total_ms, 100.0);
        assert_eq!(stats.median_total_ms, 200.0);
        assert_eq!(stats.max_total_ms, 300.0);
        assert_eq!(stats.median_ttfb_ms, 190.0);
    }

    #[test]
    fn compute_stats_even_count_picks_upper_middle() {
        let samples = [
            t(100.0, 90.0),
            t(400.0, 390.0),
            t(200.0, 190.0),
            t(300.0, 290.0),
        ];
        let (stats, idx) = compute_stats(&samples).unwrap();
        // Sorted totals: 100,200,300,400 -> upper-middle 300 at index 3.
        assert_eq!(idx, 3);
        assert_eq!(stats.median_total_ms, 300.0);
        assert_eq!(stats.min_total_ms, 100.0);
        assert_eq!(stats.max_total_ms, 400.0);
    }
}
