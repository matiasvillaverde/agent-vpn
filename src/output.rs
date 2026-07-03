//! Command results and their JSON / human renderings.

use serde::Serialize;

use crate::error::Error;
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
        Report::Down { name, changed } => {
            let verb = if *changed {
                "brought down"
            } else {
                "already down"
            };
            format!("{name}: {verb}")
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
    }
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
            },
            false,
        )
        .contains("brought down"));
        assert!(render_report(
            &Report::Down {
                name: "home".into(),
                changed: false,
            },
            false,
        )
        .contains("already down"));
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
