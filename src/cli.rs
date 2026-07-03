//! Command-line interface definition and dispatch.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::backend::Backend;
use crate::error::Result;
use crate::output::Report;
use crate::runner::CommandRunner;
use crate::settings::FileConfig;

/// Agent-first, provider-agnostic WireGuard tunnel manager.
#[derive(Parser, Debug)]
#[command(name = "vpn", version, about, long_about = None)]
pub struct Cli {
    /// Emit machine-readable JSON instead of human text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Directory holding `<name>.conf` WireGuard files
    /// (default: `$HOME/.config/vpn`).
    #[arg(long, env = "VPN_CONFIG_DIR", global = true)]
    pub config_dir: Option<PathBuf>,

    /// Prefix privileged commands with `sudo -n`.
    #[arg(long, env = "VPN_SUDO", global = true)]
    pub sudo: bool,

    /// Path to the `wg` binary (use an absolute path when running under `sudo`).
    /// [default: wg]
    #[arg(long, env = "VPN_WG", global = true)]
    pub wg: Option<String>,

    /// Path to the `wg-quick` binary (absolute is safest under `sudo`).
    /// [default: wg-quick]
    #[arg(long, env = "VPN_WG_QUICK", global = true)]
    pub wg_quick: Option<String>,

    /// Path to the `curl` binary used by `probe`. [default: curl]
    #[arg(long, env = "VPN_CURL", global = true)]
    pub curl: Option<String>,

    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Effective settings after layering flags/env over the config file over the
/// built-in defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Resolved config directory.
    pub config_dir: PathBuf,
    /// Whether to prefix privileged commands with `sudo -n`.
    pub sudo: bool,
    /// Resolved `wg` binary path.
    pub wg: String,
    /// Resolved `wg-quick` binary path.
    pub wg_quick: String,
    /// Resolved `curl` binary path.
    pub curl: String,
}

impl Cli {
    /// The config directory to use, applying the `$HOME`-based default.
    #[must_use]
    pub fn resolved_config_dir(&self) -> PathBuf {
        self.config_dir.clone().unwrap_or_else(default_config_dir)
    }

    /// Resolve effective settings. Precedence for each value: command-line flag
    /// or env var (already merged by clap) → config file → built-in default.
    #[must_use]
    pub fn settings(&self, file: &FileConfig) -> Settings {
        Settings {
            config_dir: self.resolved_config_dir(),
            sudo: self.sudo || file.sudo.unwrap_or(false),
            wg: self
                .wg
                .clone()
                .or_else(|| file.wg.clone())
                .unwrap_or_else(|| "wg".to_string()),
            wg_quick: self
                .wg_quick
                .clone()
                .or_else(|| file.wg_quick.clone())
                .unwrap_or_else(|| "wg-quick".to_string()),
            curl: self
                .curl
                .clone()
                .or_else(|| file.curl.clone())
                .unwrap_or_else(|| "curl".to_string()),
        }
    }
}

/// The subcommands vpn understands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// List available tunnels and whether each is up.
    List,
    /// Bring a tunnel up (idempotent).
    Up {
        /// Tunnel name (config file stem).
        name: String,
    },
    /// Bring a tunnel down (idempotent).
    Down {
        /// Tunnel name (config file stem).
        name: String,
    },
    /// Show detailed status for one tunnel, or all tunnels.
    Status {
        /// Tunnel name; omit for every tunnel.
        name: Option<String>,
    },
    /// Print the names of currently-active tunnels.
    Current,
    /// Send timed requests through a tunnel (or each tunnel in turn) and
    /// report latency; tunnel state is restored afterwards.
    Probe {
        /// Tunnel name; omit to probe every tunnel sequentially and compare.
        name: Option<String>,
        /// URL to request. The anycast default reaches the exit's nearest
        /// Cloudflare edge, making totals comparable across locations.
        #[arg(long, default_value = "https://1.1.1.1/cdn-cgi/trace")]
        url: String,
        /// Per-request timeout in seconds.
        #[arg(long, default_value_t = 10)]
        max_time: u64,
        /// Requests per tunnel; medians over N samples smooth out jitter.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=100))]
        count: u32,
    },
    /// Run a command with the tunnel up (activating it if needed, restoring
    /// afterwards); the command's stdio streams through and its exit code
    /// becomes vpn's exit code. Usage: `vpn exec <name> -- <command...>`.
    Exec {
        /// Tunnel name (config file stem).
        name: String,
        /// The command to run (after `--`); always runs unprivileged.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Statically check tunnel configs for problems (missing keys, and
    /// split-tunnel AllowedIPs that cover their own Endpoint — a routing
    /// loop). Exits 1 if any config has errors.
    Lint {
        /// Tunnel name; omit to lint every config.
        name: Option<String>,
    },
    /// Validate a WireGuard config file and install it into the config
    /// directory with owner-only permissions.
    Add {
        /// Path to the downloaded `.conf` file.
        path: PathBuf,
        /// Tunnel name; defaults to the file's stem.
        #[arg(long)]
        name: Option<String>,
        /// Overwrite an existing tunnel / ignore lint errors.
        #[arg(long)]
        force: bool,
    },
    /// Generate a split-tunnel sibling config: route everything except the
    /// --exclude CIDRs, always also excluding the server's own endpoint (the
    /// routing-loop guard wg-quick lacks for non-default routes).
    Split {
        /// Source tunnel name.
        name: String,
        /// IPv4 CIDRs to keep OUT of the tunnel (e.g. Tailscale's
        /// 100.64.0.0/10); repeatable.
        #[arg(long)]
        exclude: Vec<String>,
        /// Output tunnel name; defaults to `<name>-split`.
        #[arg(long)]
        output: Option<String>,
        /// Keep the DNS override (dropped by default so mesh-VPN DNS keeps
        /// working alongside).
        #[arg(long)]
        keep_dns: bool,
        /// Overwrite an existing output config.
        #[arg(long)]
        force: bool,
    },
    /// Diagnose the environment: binaries, passwordless sudo, WireGuard
    /// state access, and config validity/permissions. Exits 1 if anything
    /// fails, with a fix hint per check.
    Doctor,
}

/// The default config directory, `$HOME/.config/vpn`.
#[must_use]
pub fn default_config_dir() -> PathBuf {
    config_dir_for_home(std::env::var_os("HOME"))
}

/// Compute the default config directory from an explicit `$HOME` value, falling
/// back to a relative `.config/vpn` when `$HOME` is unset.
fn config_dir_for_home(home: Option<std::ffi::OsString>) -> PathBuf {
    match home {
        Some(home) => PathBuf::from(home).join(".config").join("vpn"),
        None => PathBuf::from(".config").join("vpn"),
    }
}

/// Execute `command` against `backend`, producing a [`Report`].
pub fn dispatch<R: CommandRunner>(backend: &Backend<R>, command: &Command) -> Result<Report> {
    match command {
        Command::List => Ok(Report::List {
            config_dir: backend.config_dir().display().to_string(),
            tunnels: backend.list()?,
        }),
        Command::Up { name } => {
            let (changed, status) = backend.up(name)?;
            Ok(Report::Up {
                name: name.clone(),
                changed,
                status,
            })
        }
        Command::Down { name } => Ok(Report::Down {
            name: name.clone(),
            changed: backend.down(name)?,
        }),
        Command::Status { name } => {
            let tunnels = match name {
                Some(n) => vec![backend.status_one(n)?],
                None => backend.status_all()?,
            };
            Ok(Report::Status { tunnels })
        }
        Command::Current => Ok(Report::Current {
            active: backend.current()?,
        }),
        Command::Probe {
            name,
            url,
            max_time,
            count,
        } => Ok(Report::Probe {
            results: backend.probe(name.as_deref(), url, *max_time, *count)?,
        }),
        Command::Exec { name, command } => {
            let outcome = backend.exec_through(name, command)?;
            Ok(Report::Exec {
                name: outcome.name,
                activated: outcome.activated,
                exit_code: outcome.exit_code,
                warning: outcome.warning,
            })
        }
        Command::Lint { name } => Ok(Report::Lint {
            results: backend.lint(name.as_deref())?,
        }),
        Command::Add { path, name, force } => {
            let (name, dest, lint) = backend.add(path, name.as_deref(), *force)?;
            Ok(Report::Add {
                name,
                path: dest.display().to_string(),
                lint,
            })
        }
        Command::Split {
            name,
            exclude,
            output,
            keep_dns,
            force,
        } => {
            let (out_name, dest, entries) =
                backend.split(name, exclude, output.as_deref(), *keep_dns, *force)?;
            Ok(Report::Split {
                source: name.clone(),
                name: out_name,
                path: dest.display().to_string(),
                entries,
            })
        }
        Command::Doctor => Ok(Report::Doctor {
            checks: backend.doctor(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::MockRunner;
    use std::fs;
    use tempfile::{tempdir, TempDir};

    const CONF: &str = "[Peer]\nPublicKey = PEERKEY\nAllowedIPs = 0.0.0.0/0, ::/0\n";
    const ALL_DUMP: &str = "utun7\tIFPRIV\tIFPUB\t51820\toff\n\
        utun7\tPEERKEY\t(none)\t203.0.113.1:51820\t0.0.0.0/0,::/0\t1700000000\t1\t2\t25\n";
    const CURL_OK: &str = "0.004,0.012,0.140,0.290,0.291,104.16.132.229,200";

    fn backend_with(runner: MockRunner) -> (Backend<MockRunner>, TempDir) {
        let cfg = tempdir().unwrap();
        fs::write(cfg.path().join("home.conf"), CONF).unwrap();
        let b = Backend::new(runner, cfg.path().to_path_buf(), false);
        (b, cfg)
    }

    #[test]
    fn cli_parses_subcommands_and_globals() {
        let cli = Cli::try_parse_from([
            "vpn",
            "--json",
            "--config-dir",
            "/tmp/cfg",
            "--sudo",
            "up",
            "home",
        ])
        .unwrap();
        assert!(cli.json);
        assert!(cli.sudo);
        assert_eq!(cli.resolved_config_dir(), PathBuf::from("/tmp/cfg"));
        assert!(matches!(cli.command, Command::Up { name } if name == "home"));
    }

    #[test]
    fn cli_parses_probe_with_defaults_and_overrides() {
        let cli = Cli::try_parse_from(["vpn", "probe"]).unwrap();
        match cli.command {
            Command::Probe {
                name,
                url,
                max_time,
                count,
            } => {
                assert_eq!(name, None);
                assert_eq!(url, "https://1.1.1.1/cdn-cgi/trace");
                assert_eq!(max_time, 10);
                assert_eq!(count, 1);
            }
            other => panic!("unexpected: {other:?}"),
        }

        let cli = Cli::try_parse_from([
            "vpn",
            "probe",
            "proton",
            "--url",
            "https://example.org",
            "--max-time",
            "5",
            "--count",
            "5",
        ])
        .unwrap();
        match cli.command {
            Command::Probe {
                name,
                url,
                max_time,
                count,
            } => {
                assert_eq!(name.as_deref(), Some("proton"));
                assert_eq!(url, "https://example.org");
                assert_eq!(max_time, 5);
                assert_eq!(count, 5);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn cli_rejects_zero_count() {
        assert!(Cli::try_parse_from(["vpn", "probe", "--count", "0"]).is_err());
    }

    #[test]
    fn cli_parses_exec_after_separator() {
        let cli = Cli::try_parse_from([
            "vpn",
            "exec",
            "proton",
            "--",
            "curl",
            "-sI",
            "https://x.example",
        ])
        .unwrap();
        match cli.command {
            Command::Exec { name, command } => {
                assert_eq!(name, "proton");
                assert_eq!(command, vec!["curl", "-sI", "https://x.example"]);
            }
            other => panic!("unexpected: {other:?}"),
        }
        // A command is mandatory.
        assert!(Cli::try_parse_from(["vpn", "exec", "proton"]).is_err());
    }

    #[test]
    fn dispatch_exec() {
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // already up
        runner.fail(3, ""); // child exits 3
        let (b, _cfg) = backend_with(runner);
        let report = dispatch(
            &b,
            &Command::Exec {
                name: "home".into(),
                command: vec!["true".into()],
            },
        )
        .unwrap();
        match report {
            Report::Exec {
                name,
                activated,
                exit_code,
                warning,
            } => {
                assert_eq!(name, "home");
                assert!(!activated);
                assert_eq!(exit_code, 3);
                assert!(warning.is_none());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn settings_apply_built_in_defaults() {
        let cli = Cli::try_parse_from(["vpn", "current"]).unwrap();
        let s = cli.settings(&FileConfig::default());
        assert_eq!(s.wg, "wg");
        assert_eq!(s.wg_quick, "wg-quick");
        assert_eq!(s.curl, "curl");
        assert!(!s.sudo);
    }

    #[test]
    fn settings_use_file_when_flags_absent() {
        let cli = Cli::try_parse_from(["vpn", "current"]).unwrap();
        let file = FileConfig {
            sudo: Some(true),
            wg: Some("/abs/wg".into()),
            wg_quick: Some("/abs/wg-quick".into()),
            curl: Some("/abs/curl".into()),
        };
        let s = cli.settings(&file);
        assert!(s.sudo);
        assert_eq!(s.wg, "/abs/wg");
        assert_eq!(s.wg_quick, "/abs/wg-quick");
        assert_eq!(s.curl, "/abs/curl");
    }

    #[test]
    fn flags_override_file() {
        let cli = Cli::try_parse_from(["vpn", "--wg", "/flag/wg", "current"]).unwrap();
        let file = FileConfig {
            sudo: Some(false),
            wg: Some("/file/wg".into()),
            wg_quick: Some("/file/wg-quick".into()),
            curl: None,
        };
        let s = cli.settings(&file);
        // Flag wins for wg; file supplies wg_quick; curl falls to default.
        assert_eq!(s.wg, "/flag/wg");
        assert_eq!(s.wg_quick, "/file/wg-quick");
        assert_eq!(s.curl, "curl");
        assert!(!s.sudo);
    }

    #[test]
    fn sudo_flag_enables_even_if_file_disables() {
        let cli = Cli::try_parse_from(["vpn", "--sudo", "current"]).unwrap();
        let file = FileConfig {
            sudo: Some(false),
            ..FileConfig::default()
        };
        assert!(cli.settings(&file).sudo);
    }

    #[test]
    fn default_config_dir_uses_home() {
        // The test environment always has HOME set.
        let dir = default_config_dir();
        assert!(dir.ends_with("vpn"));
    }

    #[test]
    fn config_dir_for_home_both_branches() {
        assert_eq!(
            config_dir_for_home(Some("/home/me".into())),
            PathBuf::from("/home/me/.config/vpn"),
        );
        assert_eq!(config_dir_for_home(None), PathBuf::from(".config/vpn"),);
    }

    #[test]
    fn dispatch_list() {
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP);
        let (b, _cfg) = backend_with(runner);
        let report = dispatch(&b, &Command::List).unwrap();
        assert!(matches!(report, Report::List { tunnels, .. } if tunnels.len() == 1));
    }

    #[test]
    fn dispatch_up() {
        let runner = MockRunner::new();
        runner.ok(""); // all_dump: down
        runner.ok(""); // wg-quick up
        runner.ok(ALL_DUMP); // status dump
        let (b, _cfg) = backend_with(runner);
        let report = dispatch(
            &b,
            &Command::Up {
                name: "home".into(),
            },
        )
        .unwrap();
        assert!(matches!(report, Report::Up { changed: true, .. }));
    }

    #[test]
    fn dispatch_down() {
        let runner = MockRunner::new();
        runner.ok(""); // all_dump: already down
        let (b, _cfg) = backend_with(runner);
        let report = dispatch(
            &b,
            &Command::Down {
                name: "home".into(),
            },
        )
        .unwrap();
        assert!(matches!(report, Report::Down { changed: false, .. }));
    }

    #[test]
    fn dispatch_status_one_and_all() {
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP);
        let (b, _cfg) = backend_with(runner);
        let one = dispatch(
            &b,
            &Command::Status {
                name: Some("home".into()),
            },
        )
        .unwrap();
        assert!(matches!(one, Report::Status { tunnels } if tunnels.len() == 1));

        let runner = MockRunner::new();
        runner.ok(ALL_DUMP);
        let (b, _cfg) = backend_with(runner);
        let all = dispatch(&b, &Command::Status { name: None }).unwrap();
        assert!(matches!(all, Report::Status { tunnels } if tunnels.len() == 1));
    }

    #[test]
    fn dispatch_current() {
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP);
        let (b, _cfg) = backend_with(runner);
        let report = dispatch(&b, &Command::Current).unwrap();
        assert!(matches!(report, Report::Current { active } if active == vec!["home".to_string()]));
    }

    #[test]
    fn dispatch_probe() {
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // already up
        runner.ok(ALL_DUMP); // info dump
        runner.ok(CURL_OK); // curl
        let (b, _cfg) = backend_with(runner);
        let report = dispatch(
            &b,
            &Command::Probe {
                name: Some("home".into()),
                url: "https://example.org".into(),
                max_time: 10,
                count: 1,
            },
        )
        .unwrap();
        match report {
            Report::Probe { results } => {
                assert_eq!(results.len(), 1);
                assert!(results[0].ok);
                assert_eq!(results[0].samples, 1);
                assert_eq!(results[0].failures, 0);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn dispatch_propagates_errors() {
        let (b, _cfg) = backend_with(MockRunner::new());
        let err = dispatch(
            &b,
            &Command::Up {
                name: "ghost".into(),
            },
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 3);
    }
}
