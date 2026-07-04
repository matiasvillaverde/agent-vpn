//! Command results and their JSON / human renderings.

use serde::Serialize;

use crate::backend::Check;
use crate::error::Error;
use crate::lint::{LintResult, Severity};
use crate::probe::ProbeResult;
use crate::status::{ListEntry, TunnelStatus};

/// The result of a successful command, ready to render.
///
/// The `command` tag is emitted in JSON so consumers can dispatch on it.
#[derive(Debug, Serialize, PartialEq)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Report {
    /// Result of `list`.
    List {
        /// The directory that was scanned.
        config_dir: String,
        /// One entry per discovered tunnel.
        tunnels: Vec<ListEntry>,
    },
    /// Result of `up`.
    Up {
        /// Tunnel name.
        name: String,
        /// `true` if this call changed state (was down, now up).
        changed: bool,
        /// Post-condition status.
        status: TunnelStatus,
    },
    /// Result of `down`.
    Down {
        /// Tunnel name.
        name: String,
        /// `true` if this call changed state (was up, now down).
        changed: bool,
        /// Network services whose stale VPN DNS was cleared (reset to DHCP)
        /// after the teardown.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        dns_cleared: Vec<String>,
        /// Non-fatal DNS-guard problem (stale DNS seen but not cleanly
        /// cleared).
        #[serde(skip_serializing_if = "Option::is_none")]
        dns_warning: Option<String>,
    },
    /// Result of `status`.
    Status {
        /// One entry per requested tunnel.
        tunnels: Vec<TunnelStatus>,
    },
    /// Result of `current`.
    Current {
        /// Names of tunnels that are currently up.
        active: Vec<String>,
    },
    /// Result of `probe`.
    Probe {
        /// One entry per probed tunnel, successes first (fastest first).
        results: Vec<ProbeResult>,
    },
    /// Result of `exec`. The child's output has already streamed through, so
    /// this report is never printed — only its exit code and warning are used.
    Exec {
        /// Tunnel name the command ran through.
        name: String,
        /// Whether the tunnel was brought up for the run.
        activated: bool,
        /// The child's exit code, passed through as vpn's exit code.
        exit_code: i32,
        /// Non-fatal problem (e.g. tunnel state could not be restored).
        #[serde(skip_serializing_if = "Option::is_none")]
        warning: Option<String>,
    },
    /// Result of `lint`.
    Lint {
        /// One entry per linted config.
        results: Vec<LintResult>,
    },
    /// Result of `add`.
    Add {
        /// Installed tunnel name.
        name: String,
        /// Destination path.
        path: String,
        /// Lint outcome for the installed config.
        lint: LintResult,
    },
    /// Result of `split`.
    Split {
        /// Source tunnel name.
        source: String,
        /// New tunnel name.
        name: String,
        /// Destination path.
        path: String,
        /// Number of AllowedIPs entries written.
        entries: usize,
    },
    /// Result of `doctor`.
    Doctor {
        /// One entry per environment check.
        checks: Vec<Check>,
    },
    /// Result of `recover`.
    Recover {
        /// Tunnels/interfaces restored (empty when nothing needed fixing).
        recovered: Vec<crate::backend::Recovered>,
        /// Host health *after* recovery — proves the repair worked, or lists
        /// what it could not fix.
        health: crate::backend::HealthReport,
    },
    /// Result of `verify`.
    Verify {
        /// Host-health assessment.
        health: crate::backend::HealthReport,
    },
    /// Result of `diff`.
    Diff {
        /// URL that was fetched.
        url: String,
        /// One entry per location.
        results: Vec<crate::diff::LocationResult>,
        /// Fields (status/headers) that differ across locations.
        diffs: Vec<crate::diff::FieldDiff>,
    },
}

impl Report {
    /// The process exit code for this (successful) report.
    ///
    /// All reports exit `0` except a probe report containing at least one
    /// failed probe (`7`, so automation can detect partial failures without
    /// parsing the results) and `exec`, which passes the child's code through.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Report::Probe { results } if results.iter().any(|r| !r.ok) => 7,
            Report::Exec { exit_code, .. } => *exit_code,
            Report::Lint { results } if results.iter().any(|r| !r.ok) => 1,
            Report::Doctor { checks } if checks.iter().any(|c| !c.ok) => 1,
            Report::Verify { health } if !health.healthy => 8,
            // Recovery ran but the host is still inconsistent: signal it.
            Report::Recover { health, .. } if !health.healthy => 8,
            Report::Diff { results, .. } if results.iter().any(|r| !r.ok) => 7,
            _ => 0,
        }
    }
}

/// Render a successful report as JSON or human text.
#[must_use]
pub fn render_report(report: &Report, json: bool) -> String {
    if json {
        serde_json::to_string_pretty(report).expect("Report is always serializable")
    } else {
        human_report(report)
    }
}

/// Render an error as JSON or human text.
#[must_use]
pub fn render_error(err: &Error, json: bool) -> String {
    if json {
        serde_json::json!({
            "ok": false,
            "error": err.to_string(),
            "code": err.exit_code(),
        })
        .to_string()
    } else {
        format!("error: {err}")
    }
}

fn human_report(report: &Report) -> String {
    match report {
        Report::List {
            config_dir,
            tunnels,
        } => {
            if tunnels.is_empty() {
                return format!("no tunnels found in {config_dir}");
            }
            tunnels
                .iter()
                .map(|t| format!("{}  {}", state_word(t.up), t.name))
                .collect::<Vec<_>>()
                .join("\n")
        }
        Report::Up {
            name,
            changed,
            status,
        } => {
            let verb = if *changed { "brought up" } else { "already up" };
            format!("{name}: {verb} ({})", status_line(status))
        }
        Report::Down {
            name,
            changed,
            dns_cleared,
            dns_warning,
        } => {
            let verb = if *changed {
                "brought down"
            } else {
                "already down"
            };
            let mut text = format!("{name}: {verb}");
            if !dns_cleared.is_empty() {
                text.push_str(&format!(
                    " (cleared stale VPN DNS from {})",
                    dns_cleared.join(", ")
                ));
            }
            if let Some(warning) = dns_warning {
                text.push_str(&format!("\nwarning: {warning}"));
            }
            text
        }
        Report::Status { tunnels } => {
            if tunnels.is_empty() {
                return "no tunnels".to_string();
            }
            tunnels
                .iter()
                .map(|t| format!("{}: {}", t.name, status_line(t)))
                .collect::<Vec<_>>()
                .join("\n")
        }
        Report::Current { active } => {
            if active.is_empty() {
                "none".to_string()
            } else {
                active.join("\n")
            }
        }
        Report::Probe { results } => {
            if results.is_empty() {
                return "no tunnels".to_string();
            }
            results
                .iter()
                .map(probe_line)
                .collect::<Vec<_>>()
                .join("\n")
        }
        // Never printed in practice (see `execute`); rendered for completeness.
        Report::Exec {
            name, exit_code, ..
        } => format!("{name}: command exited {exit_code}"),
        Report::Lint { results } => {
            if results.is_empty() {
                return "no tunnels".to_string();
            }
            results
                .iter()
                .map(lint_lines)
                .collect::<Vec<_>>()
                .join("\n")
        }
        Report::Add { name, path, lint } => {
            let mut out = format!("added {name} ({path})");
            for finding in &lint.findings {
                out.push_str(&format!("\n  note: {}", finding.message));
            }
            out
        }
        Report::Split {
            source,
            name,
            path,
            entries,
        } => format!(
            "{name}: split tunnel of {source} written to {path} \
             ({entries} AllowedIPs entries, endpoint excluded)"
        ),
        Report::Doctor { checks } => checks
            .iter()
            .map(|c| {
                format!(
                    "{} {:<14} {}",
                    if c.ok { "ok  " } else { "FAIL" },
                    c.name,
                    c.detail
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Report::Diff {
            url,
            results,
            diffs,
        } => {
            let mut lines = vec![format!(
                "diff of {url} across {} location(s):",
                results.len()
            )];
            for r in results {
                if r.ok {
                    lines.push(format!(
                        "  {:<14} {} ({} headers)",
                        r.name,
                        r.status.map_or("?".to_string(), |s| s.to_string()),
                        r.headers.len()
                    ));
                } else {
                    lines.push(format!(
                        "  {:<14} FAILED: {}",
                        r.name,
                        r.error.as_deref().unwrap_or("unknown error")
                    ));
                }
            }
            let ok_count = results.iter().filter(|r| r.ok).count();
            if ok_count < 2 {
                lines.push("(need at least two successful locations to compare)".to_string());
            } else if diffs.is_empty() {
                lines.push(format!(
                    "all {ok_count} locations returned identical status and headers"
                ));
            } else {
                lines.push(format!("{} field(s) differ:", diffs.len()));
                for d in diffs {
                    lines.push(format!("  {}:", d.field));
                    for (loc, val) in &d.values {
                        lines.push(format!(
                            "    {:<14} {}",
                            loc,
                            val.as_deref().unwrap_or("(absent)")
                        ));
                    }
                }
            }
            lines.join("\n")
        }
        Report::Verify { health } => {
            if health.healthy {
                return "ok — host network is consistent".to_string();
            }
            let mut lines = vec!["FAIL — host network needs repair:".to_string()];
            lines.extend(
                health
                    .issues
                    .iter()
                    .map(|i| format!("  [{}] {}", i.kind, i.detail)),
            );
            lines.join("\n")
        }
        Report::Recover { recovered, health } => {
            let mut lines: Vec<String> = if recovered.is_empty() {
                vec!["nothing to recover — host state is clean".to_string()]
            } else {
                recovered
                    .iter()
                    .map(|r| {
                        let mut line = format!("recovered {} ({})", r.tunnel, r.reason);
                        if !r.dns_cleared.is_empty() {
                            line.push_str(&format!(
                                "; restored DNS on {}",
                                r.dns_cleared.join(", ")
                            ));
                        }
                        if let Some(w) = &r.dns_warning {
                            line.push_str(&format!("; warning: {w}"));
                        }
                        line
                    })
                    .collect()
            };
            if !health.healthy {
                lines.push("WARNING — host still inconsistent after recovery:".to_string());
                lines.extend(
                    health
                        .issues
                        .iter()
                        .map(|i| format!("  [{}] {}", i.kind, i.detail)),
                );
            }
            lines.join("\n")
        }
    }
}

fn lint_lines(r: &LintResult) -> String {
    if r.findings.is_empty() {
        return format!("ok    {}", r.name);
    }
    let mut out = format!("{}{}", if r.ok { "warn  " } else { "FAIL  " }, r.name);
    for finding in &r.findings {
        let tag = match finding.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        out.push_str(&format!("\n      {tag}: {}", finding.message));
    }
    out
}

fn state_word(up: bool) -> &'static str {
    if up {
        "up  "
    } else {
        "down"
    }
}

fn status_line(status: &TunnelStatus) -> String {
    if !status.up {
        return "down".to_string();
    }
    let iface = status.interface.as_deref().unwrap_or("?");
    format!("up on {iface} ({} peer(s))", status.peers.len())
}

fn probe_line(r: &ProbeResult) -> String {
    let mut line = if r.ok {
        let t = r.timings.as_ref().expect("ok probes carry timings");
        let mut line = match &r.stats {
            // Multi-sample: lead with the median and show the spread.
            Some(s) if r.samples > 1 => format!(
                "{:<14} median {:>8.1} ms   (min {:.1}, max {:.1}, n={})   ttfb {:>8.1} ms",
                r.name, s.median_total_ms, s.min_total_ms, s.max_total_ms, r.samples, t.ttfb_ms
            ),
            _ => format!(
                "{:<14} total {:>8.1} ms   ttfb {:>8.1} ms",
                r.name, t.total_ms, t.ttfb_ms
            ),
        };
        if let Some(code) = r.http_code {
            line.push_str(&format!("   http {code}"));
        }
        if let Some(exit) = &r.exit {
            line.push_str(&format!("   exit {}", exit.ip));
            match (&exit.loc, &exit.colo) {
                (Some(loc), Some(colo)) => line.push_str(&format!(" ({loc}/{colo})")),
                (Some(loc), None) => line.push_str(&format!(" ({loc})")),
                (None, Some(colo)) => line.push_str(&format!(" ({colo})")),
                (None, None) => {}
            }
        } else if let Some(ip) = &r.remote_ip {
            line.push_str(&format!("   via {ip}"));
        }
        if r.failures > 0 {
            line.push_str(&format!("   ({}/{} failed)", r.failures, r.samples));
        }
        line
    } else {
        format!(
            "{:<14} FAILED: {}",
            r.name,
            r.error.as_deref().unwrap_or("unknown error")
        )
    };
    if let Some(warning) = &r.warning {
        line.push_str(&format!("   [warning: {warning}]"));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::Timings;
    use serde_json::Value;

    fn up_status() -> TunnelStatus {
        TunnelStatus {
            name: "home".into(),
            up: true,
            interface: Some("utun4".into()),
            peers: vec![],
        }
    }

    #[test]
    fn json_report_is_tagged() {
        let report = Report::Current {
            active: vec!["home".into()],
        };
        let v: Value = serde_json::from_str(&render_report(&report, true)).unwrap();
        assert_eq!(v["command"], "current");
        assert_eq!(v["active"][0], "home");
    }

    #[test]
    fn json_error_shape() {
        let v: Value =
            serde_json::from_str(&render_error(&Error::TunnelNotFound("x".into()), true)).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["code"], 3);
        assert!(v["error"].as_str().unwrap().contains('x'));
    }

    #[test]
    fn human_error() {
        let text = render_error(&Error::InvalidName("bad".into()), false);
        assert!(text.starts_with("error:"));
        assert!(text.contains("bad"));
    }

    #[test]
    fn human_list_populated_and_empty() {
        let populated = Report::List {
            config_dir: "/cfg".into(),
            tunnels: vec![
                ListEntry {
                    name: "home".into(),
                    up: true,
                },
                ListEntry {
                    name: "work".into(),
                    up: false,
                },
            ],
        };
        let text = render_report(&populated, false);
        assert!(text.contains("up  ") && text.contains("home"));
        assert!(text.contains("down") && text.contains("work"));

        let empty = Report::List {
            config_dir: "/cfg".into(),
            tunnels: vec![],
        };
        assert_eq!(render_report(&empty, false), "no tunnels found in /cfg");
    }

    #[test]
    fn human_up_changed_and_unchanged() {
        let changed = Report::Up {
            name: "home".into(),
            changed: true,
            status: up_status(),
        };
        assert!(render_report(&changed, false).contains("brought up"));
        assert!(render_report(&changed, false).contains("up on utun4"));

        let unchanged = Report::Up {
            name: "home".into(),
            changed: false,
            status: up_status(),
        };
        assert!(render_report(&unchanged, false).contains("already up"));
    }

    #[test]
    fn human_up_without_interface() {
        let mut status = up_status();
        status.interface = None;
        let report = Report::Up {
            name: "home".into(),
            changed: true,
            status,
        };
        assert!(render_report(&report, false).contains("up on ?"));
    }

    #[test]
    fn human_down_changed_and_unchanged() {
        assert!(render_report(
            &Report::Down {
                name: "home".into(),
                changed: true,
                dns_cleared: Vec::new(),
                dns_warning: None,
            },
            false,
        )
        .contains("brought down"));
        assert!(render_report(
            &Report::Down {
                name: "home".into(),
                changed: false,
                dns_cleared: Vec::new(),
                dns_warning: None,
            },
            false,
        )
        .contains("already down"));
    }

    #[test]
    fn human_down_reports_dns_repair() {
        let text = render_report(
            &Report::Down {
                name: "proton".into(),
                changed: true,
                dns_cleared: vec!["Wi-Fi".into(), "Thunderbolt Bridge".into()],
                dns_warning: Some("could not reset DNS on 'iPhone USB'".into()),
            },
            false,
        );
        assert!(text.contains("cleared stale VPN DNS from Wi-Fi, Thunderbolt Bridge"));
        assert!(text.contains("warning: could not reset DNS on 'iPhone USB'"));
    }

    #[test]
    fn json_down_omits_empty_dns_fields() {
        let clean = render_report(
            &Report::Down {
                name: "proton".into(),
                changed: true,
                dns_cleared: Vec::new(),
                dns_warning: None,
            },
            true,
        );
        assert!(!clean.contains("dns_cleared") && !clean.contains("dns_warning"));
        let repaired = render_report(
            &Report::Down {
                name: "proton".into(),
                changed: false,
                dns_cleared: vec!["Wi-Fi".into()],
                dns_warning: None,
            },
            true,
        );
        assert!(repaired.contains("\"dns_cleared\""));
    }

    #[test]
    fn human_status_populated_and_empty() {
        let populated = Report::Status {
            tunnels: vec![up_status(), TunnelStatus::down("work")],
        };
        let text = render_report(&populated, false);
        assert!(text.contains("home: up on utun4"));
        assert!(text.contains("work: down"));

        let empty = Report::Status { tunnels: vec![] };
        assert_eq!(render_report(&empty, false), "no tunnels");
    }

    #[test]
    fn human_current_populated_and_empty() {
        let populated = Report::Current {
            active: vec!["home".into(), "work".into()],
        };
        assert_eq!(render_report(&populated, false), "home\nwork");
        let empty = Report::Current { active: vec![] };
        assert_eq!(render_report(&empty, false), "none");
    }

    fn ok_probe(name: &str, total_ms: f64) -> ProbeResult {
        ProbeResult {
            timings: Some(Timings {
                dns_ms: 4.0,
                connect_ms: 12.0,
                tls_ms: 140.0,
                ttfb_ms: 290.0,
                total_ms,
            }),
            ok: true,
            http_code: Some(200),
            remote_ip: Some("104.16.132.229".into()),
            interface: Some("utun7".into()),
            ..ProbeResult::new(name, "https://1.1.1.1/cdn-cgi/trace", true)
        }
    }

    fn failed_probe(name: &str) -> ProbeResult {
        ProbeResult {
            error: Some("curl: (7) Failed to connect".into()),
            ..ProbeResult::new(name, "https://1.1.1.1/cdn-cgi/trace", true)
        }
    }

    #[test]
    fn json_probe_report() {
        let report = Report::Probe {
            results: vec![ok_probe("proton", 291.0)],
        };
        let v: Value = serde_json::from_str(&render_report(&report, true)).unwrap();
        assert_eq!(v["command"], "probe");
        assert_eq!(v["results"][0]["name"], "proton");
        assert_eq!(v["results"][0]["ok"], true);
        assert_eq!(v["results"][0]["timings"]["total_ms"], 291.0);
        assert_eq!(v["results"][0]["http_code"], 200);
    }

    #[test]
    fn human_probe_success_failure_and_warning() {
        let mut warned = ok_probe("slow", 500.0);
        warned.warning = Some("failed to restore tunnel state: boom".into());
        let report = Report::Probe {
            results: vec![ok_probe("proton", 291.0), warned, failed_probe("broken")],
        };
        let text = render_report(&report, false);
        assert!(text.contains("proton"));
        assert!(text.contains("291.0 ms"));
        assert!(text.contains("http 200"));
        assert!(text.contains("via 104.16.132.229"));
        assert!(text.contains("broken"));
        assert!(text.contains("FAILED: curl: (7)"));
        assert!(text.contains("[warning: failed to restore"));
    }

    #[test]
    fn human_probe_shows_exit_evidence_over_remote_ip() {
        let mut r = ok_probe("proton-jp", 291.0);
        r.exit = Some(crate::probe::TraceInfo {
            ip: "103.5.140.1".into(),
            loc: Some("JP".into()),
            colo: Some("NRT".into()),
        });
        let text = render_report(&Report::Probe { results: vec![r] }, false);
        assert!(text.contains("exit 103.5.140.1 (JP/NRT)"));
        assert!(!text.contains("via 104.16"), "exit evidence replaces via");

        // Partial evidence renders gracefully.
        let mut r = ok_probe("x", 1.0);
        r.exit = Some(crate::probe::TraceInfo {
            ip: "1.2.3.4".into(),
            loc: None,
            colo: Some("EWR".into()),
        });
        assert!(render_report(&Report::Probe { results: vec![r] }, false)
            .contains("exit 1.2.3.4 (EWR)"));
        let mut r = ok_probe("y", 1.0);
        r.exit = Some(crate::probe::TraceInfo {
            ip: "1.2.3.4".into(),
            loc: Some("US".into()),
            colo: None,
        });
        assert!(
            render_report(&Report::Probe { results: vec![r] }, false).contains("exit 1.2.3.4 (US)")
        );
        let mut r = ok_probe("z", 1.0);
        r.exit = Some(crate::probe::TraceInfo {
            ip: "1.2.3.4".into(),
            loc: None,
            colo: None,
        });
        let text = render_report(&Report::Probe { results: vec![r] }, false);
        assert!(text.contains("exit 1.2.3.4"));
        assert!(!text.contains('('));
    }

    #[test]
    fn human_probe_multisample_shows_median_and_spread() {
        let mut r = ok_probe("proton", 291.0);
        r.samples = 5;
        r.failures = 1;
        r.stats = Some(crate::probe::Stats {
            min_total_ms: 250.0,
            median_total_ms: 291.0,
            max_total_ms: 400.0,
            median_ttfb_ms: 290.0,
        });
        let text = render_report(&Report::Probe { results: vec![r] }, false);
        assert!(text.contains("median"));
        assert!(text.contains("min 250.0"));
        assert!(text.contains("max 400.0"));
        assert!(text.contains("n=5"));
        assert!(text.contains("(1/5 failed)"));
    }

    #[test]
    fn human_probe_empty() {
        let report = Report::Probe { results: vec![] };
        assert_eq!(render_report(&report, false), "no tunnels");
    }

    #[test]
    fn human_probe_failure_without_message() {
        let mut r = failed_probe("x");
        r.error = None;
        let report = Report::Probe { results: vec![r] };
        assert!(render_report(&report, false).contains("unknown error"));
    }

    #[test]
    fn exec_report_renders_and_passes_code() {
        let report = Report::Exec {
            name: "home".into(),
            activated: true,
            exit_code: 42,
            warning: None,
        };
        assert_eq!(report.exit_code(), 42);
        assert!(render_report(&report, false).contains("exited 42"));
        let v: Value = serde_json::from_str(&render_report(&report, true)).unwrap();
        assert_eq!(v["command"], "exec");
        assert_eq!(v["exit_code"], 42);
    }

    #[test]
    fn lint_report_renders_and_exit_codes() {
        use crate::lint::{Finding, LintResult, Severity};
        let clean = LintResult {
            name: "good".into(),
            ok: true,
            findings: vec![],
        };
        let warned = LintResult {
            name: "meh".into(),
            ok: true,
            findings: vec![Finding {
                severity: Severity::Warning,
                message: "no Endpoint".into(),
            }],
        };
        let broken = LintResult {
            name: "bad".into(),
            ok: false,
            findings: vec![Finding {
                severity: Severity::Error,
                message: "routing loop: X".into(),
            }],
        };

        let ok_report = Report::Lint {
            results: vec![clean.clone(), warned.clone()],
        };
        assert_eq!(ok_report.exit_code(), 0, "warnings alone pass");
        let text = render_report(&ok_report, false);
        assert!(text.contains("ok    good"));
        assert!(text.contains("warn  meh"));
        assert!(text.contains("warning: no Endpoint"));

        let bad_report = Report::Lint {
            results: vec![clean, broken],
        };
        assert_eq!(bad_report.exit_code(), 1);
        let text = render_report(&bad_report, false);
        assert!(text.contains("FAIL  bad"));
        assert!(text.contains("error: routing loop"));

        let v: Value = serde_json::from_str(&render_report(&bad_report, true)).unwrap();
        assert_eq!(v["command"], "lint");
        assert_eq!(v["results"][1]["ok"], false);
        assert_eq!(v["results"][1]["findings"][0]["severity"], "error");

        assert_eq!(
            render_report(&Report::Lint { results: vec![] }, false),
            "no tunnels"
        );
    }

    #[test]
    fn add_and_split_reports_render() {
        use crate::lint::{Finding, LintResult, Severity};
        let add = Report::Add {
            name: "proton-jp".into(),
            path: "/cfg/proton-jp.conf".into(),
            lint: LintResult {
                name: "proton-jp".into(),
                ok: true,
                findings: vec![Finding {
                    severity: Severity::Warning,
                    message: "no Endpoint".into(),
                }],
            },
        };
        let text = render_report(&add, false);
        assert!(text.contains("added proton-jp (/cfg/proton-jp.conf)"));
        assert!(text.contains("note: no Endpoint"));
        let v: Value = serde_json::from_str(&render_report(&add, true)).unwrap();
        assert_eq!(v["command"], "add");
        assert_eq!(v["lint"]["ok"], true);

        let split = Report::Split {
            source: "proton-jp".into(),
            name: "proton-jp-ts".into(),
            path: "/cfg/proton-jp-ts.conf".into(),
            entries: 39,
        };
        let text = render_report(&split, false);
        assert!(text.contains("proton-jp-ts: split tunnel of proton-jp"));
        assert!(text.contains("39 AllowedIPs entries"));
        let v: Value = serde_json::from_str(&render_report(&split, true)).unwrap();
        assert_eq!(v["command"], "split");
        assert_eq!(v["entries"], 39);

        assert_eq!(add.exit_code(), 0);
        assert_eq!(split.exit_code(), 0);
    }

    #[test]
    fn doctor_report_renders_and_exit_codes() {
        use crate::backend::Check;
        let report = Report::Doctor {
            checks: vec![
                Check {
                    name: "wg".into(),
                    ok: true,
                    detail: "wireguard-tools v1".into(),
                },
                Check {
                    name: "sudo".into(),
                    ok: false,
                    detail: "add a NOPASSWD rule".into(),
                },
            ],
        };
        assert_eq!(report.exit_code(), 1);
        let text = render_report(&report, false);
        assert!(text.contains("ok   wg"));
        assert!(text.contains("FAIL sudo"));
        assert!(text.contains("NOPASSWD"));
        let v: Value = serde_json::from_str(&render_report(&report, true)).unwrap();
        assert_eq!(v["command"], "doctor");
        assert_eq!(v["checks"][1]["ok"], false);

        let healthy = Report::Doctor {
            checks: vec![Check {
                name: "wg".into(),
                ok: true,
                detail: "x".into(),
            }],
        };
        assert_eq!(healthy.exit_code(), 0);
    }

    fn healthy() -> crate::backend::HealthReport {
        crate::backend::HealthReport {
            healthy: true,
            issues: vec![],
        }
    }

    #[test]
    fn human_recover_clean_and_populated() {
        let clean = Report::Recover {
            recovered: vec![],
            health: healthy(),
        };
        assert!(render_report(&clean, false).contains("nothing to recover"));

        let populated = Report::Recover {
            recovered: vec![crate::backend::Recovered {
                tunnel: "proton".into(),
                reason: "interrupted while bringing the tunnel up".into(),
                dns_cleared: vec!["Wi-Fi".into()],
                dns_warning: None,
            }],
            health: healthy(),
        };
        let text = render_report(&populated, false);
        assert!(text.contains("recovered proton"));
        assert!(text.contains("interrupted"));
        assert!(text.contains("restored DNS on Wi-Fi"));
        // JSON carries the structured list.
        let v: Value = serde_json::from_str(&render_report(&populated, true)).unwrap();
        assert_eq!(v["command"], "recover");
        assert_eq!(v["recovered"][0]["tunnel"], "proton");
    }

    #[test]
    fn recover_exit_8_when_still_unhealthy() {
        let report = Report::Recover {
            recovered: vec![],
            health: crate::backend::HealthReport {
                healthy: false,
                issues: vec![crate::backend::HealthIssue {
                    kind: "orphan",
                    detail: "utun7 orphaned".into(),
                }],
            },
        };
        assert_eq!(report.exit_code(), 8);
        assert!(render_report(&report, false).contains("still inconsistent"));
    }

    #[test]
    fn human_diff_reports_differences_and_json() {
        use std::collections::BTreeMap;
        let mk = |name: &str, cache: &str| crate::diff::LocationResult {
            name: name.into(),
            ok: true,
            status: Some(200),
            headers: BTreeMap::from([("cf-cache-status".to_string(), cache.to_string())]),
            exit_ip: None,
            error: None,
        };
        let results = vec![mk("proton-us", "HIT"), mk("proton-br", "MISS")];
        let diffs = crate::diff::diff_fields(&results);
        let report = Report::Diff {
            url: "https://x.example".into(),
            results,
            diffs,
        };
        let text = render_report(&report, false);
        assert!(text.contains("1 field(s) differ"));
        assert!(text.contains("cf-cache-status"));
        assert!(text.contains("HIT") && text.contains("MISS"));
        assert_eq!(report.exit_code(), 0);
        let v: Value = serde_json::from_str(&render_report(&report, true)).unwrap();
        assert_eq!(v["command"], "diff");
        assert_eq!(v["diffs"][0]["field"], "cf-cache-status");
    }

    #[test]
    fn diff_exit_7_on_any_failure() {
        let report = Report::Diff {
            url: "u".into(),
            results: vec![crate::diff::LocationResult {
                name: "x".into(),
                ok: false,
                status: None,
                headers: Default::default(),
                exit_ip: None,
                error: Some("boom".into()),
            }],
            diffs: vec![],
        };
        assert_eq!(report.exit_code(), 7);
    }

    #[test]
    fn human_verify_healthy_and_unhealthy() {
        let ok = Report::Verify { health: healthy() };
        assert!(render_report(&ok, false).contains("consistent"));
        assert_eq!(ok.exit_code(), 0);

        let bad = Report::Verify {
            health: crate::backend::HealthReport {
                healthy: false,
                issues: vec![crate::backend::HealthIssue {
                    kind: "dns",
                    detail: "stale VPN DNS pinned on Wi-Fi".into(),
                }],
            },
        };
        assert_eq!(bad.exit_code(), 8);
        let text = render_report(&bad, false);
        assert!(text.contains("needs repair"));
        assert!(text.contains("[dns]"));
    }

    #[test]
    fn report_exit_codes() {
        assert_eq!(Report::Current { active: vec![] }.exit_code(), 0);
        assert_eq!(
            Report::Probe {
                results: vec![ok_probe("a", 1.0)],
            }
            .exit_code(),
            0
        );
        assert_eq!(
            Report::Probe {
                results: vec![ok_probe("a", 1.0), failed_probe("b")],
            }
            .exit_code(),
            7
        );
        assert_eq!(Report::Probe { results: vec![] }.exit_code(), 0);
    }
}
