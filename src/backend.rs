//! Tunnel operations built on top of a [`CommandRunner`].
//!
//! Every operation is idempotent and non-interactive so that agents can call
//! them repeatedly without special-casing "already up"/"already down" states.
//!
//! Live state is observed via a single `wg show all dump` per command; tunnels
//! are matched to interfaces by peer identity (public key + allowed-IPs set),
//! which works without `wg-quick`'s root-only name file on macOS.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use crate::cidr::{self, Cidr4};
use crate::config::{self, Tunnel};
use crate::error::{Error, Result};
use crate::lint;
use crate::probe::{self, ProbeResult};
use crate::runner::{CommandOutput, CommandRunner};
use crate::status::{self, DumpPeer, ListEntry, TunnelStatus};

/// Orchestrates `wg-quick`/`wg`/`curl` for a set of tunnel configs.
pub struct Backend<R: CommandRunner> {
    runner: R,
    config_dir: PathBuf,
    sudo: bool,
    wg: String,
    wg_quick: String,
    curl: String,
}

impl<R: CommandRunner> Backend<R> {
    /// Create a backend for the tunnels in `config_dir`; `sudo` prefixes the
    /// privileged (`wg`/`wg-quick`) commands with `sudo -n`.
    ///
    /// Programs default to bare names (resolved via `PATH`); override them with
    /// [`Backend::with_programs`] when `PATH` is unreliable (e.g. under `sudo`,
    /// which drops Homebrew's `/opt/homebrew/bin`).
    pub fn new(runner: R, config_dir: PathBuf, sudo: bool) -> Self {
        Self {
            runner,
            config_dir,
            sudo,
            wg: "wg".to_string(),
            wg_quick: "wg-quick".to_string(),
            curl: "curl".to_string(),
        }
    }

    /// Override the `wg`, `wg-quick` and `curl` program paths (absolute paths
    /// survive `sudo`'s `PATH` scrubbing).
    #[must_use]
    pub fn with_programs(mut self, wg: String, wg_quick: String, curl: String) -> Self {
        self.wg = wg;
        self.wg_quick = wg_quick;
        self.curl = curl;
        self
    }

    /// The configured tunnel directory.
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Run a privileged backend program, applying the `sudo -n` prefix when
    /// configured (`-n` fails fast instead of prompting for a password).
    fn exec(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        let (program, args) = command_line(self.sudo, program, args);
        self.runner
            .run(&program, &args)
            .map_err(|source| Error::Spawn { program, source })
    }

    /// Snapshot every live WireGuard peer via one `wg show all dump`.
    fn all_dump(&self) -> Result<Vec<DumpPeer>> {
        let out = self.exec(&self.wg, &["show", "all", "dump"])?;
        if !out.success() {
            return Err(backend_error(&self.wg, &out));
        }
        Ok(status::parse_all_dump(&out.stdout))
    }

    /// Find the live peer row serving `tunnel`, if any.
    ///
    /// Candidates must match the config's peer public key. When the config
    /// declares allowed-IPs, the live allowed-IPs set must match exactly —
    /// sibling configs for the same server share a public key and differ only
    /// in routing, so the routing set is the discriminator.
    fn find_live<'d>(&self, tunnel: &Tunnel, dump: &'d [DumpPeer]) -> Result<Option<&'d DumpPeer>> {
        let id = config::peer_identity(&tunnel.path)?;
        let mut candidates = dump.iter().filter(|d| d.peer.public_key == id.public_key);
        if id.allowed_ips.is_empty() {
            return Ok(candidates.next());
        }
        Ok(candidates.find(|d| status::normalize_allowed(&d.peer.allowed_ips) == id.allowed_ips))
    }

    /// Build a [`TunnelStatus`] from a matched dump row (or its absence).
    fn status_from(&self, name: &str, live: Option<&DumpPeer>, dump: &[DumpPeer]) -> TunnelStatus {
        match live {
            None => TunnelStatus::down(name),
            Some(hit) => TunnelStatus {
                name: name.to_string(),
                up: true,
                interface: Some(hit.interface.clone()),
                peers: dump
                    .iter()
                    .filter(|d| d.interface == hit.interface)
                    .map(|d| d.peer.clone())
                    .collect(),
            },
        }
    }

    /// Detailed status for a single tunnel (must exist in the config dir).
    pub fn status_one(&self, name: &str) -> Result<TunnelStatus> {
        let tunnel = config::resolve(&self.config_dir, name)?;
        let dump = self.all_dump()?;
        let live = self.find_live(&tunnel, &dump)?;
        Ok(self.status_from(name, live, &dump))
    }

    /// Detailed status for every discovered tunnel (one `wg` call total).
    pub fn status_all(&self) -> Result<Vec<TunnelStatus>> {
        let tunnels = config::discover(&self.config_dir)?;
        let dump = self.all_dump()?;
        tunnels
            .iter()
            .map(|t| {
                let live = self.find_live(t, &dump)?;
                Ok(self.status_from(&t.name, live, &dump))
            })
            .collect()
    }

    /// Names and up/down state of every discovered tunnel (one `wg` call).
    pub fn list(&self) -> Result<Vec<ListEntry>> {
        let tunnels = config::discover(&self.config_dir)?;
        let dump = self.all_dump()?;
        tunnels
            .iter()
            .map(|t| {
                Ok(ListEntry {
                    name: t.name.clone(),
                    up: self.find_live(t, &dump)?.is_some(),
                })
            })
            .collect()
    }

    /// Names of tunnels that are currently up (one `wg` call).
    pub fn current(&self) -> Result<Vec<String>> {
        let tunnels = config::discover(&self.config_dir)?;
        let dump = self.all_dump()?;
        let mut active = Vec::new();
        for t in &tunnels {
            if self.find_live(t, &dump)?.is_some() {
                active.push(t.name.clone());
            }
        }
        Ok(active)
    }

    /// Bring a tunnel up. Returns `(changed, status)` where `changed` is `false`
    /// if it was already up.
    pub fn up(&self, name: &str) -> Result<(bool, TunnelStatus)> {
        let tunnel = config::resolve(&self.config_dir, name)?;
        let dump = self.all_dump()?;
        if let Some(live) = self.find_live(&tunnel, &dump)? {
            return Ok((false, self.status_from(name, Some(live), &dump)));
        }
        let path = tunnel.path.to_string_lossy().into_owned();
        let out = self.exec(&self.wg_quick, &["up", &path])?;
        if !out.success() {
            return Err(backend_error(&self.wg_quick, &out));
        }
        Ok((true, self.status_one(name)?))
    }

    /// Bring a tunnel down. Returns `changed`, which is `false` if it was
    /// already down.
    pub fn down(&self, name: &str) -> Result<bool> {
        let tunnel = config::resolve(&self.config_dir, name)?;
        let dump = self.all_dump()?;
        if self.find_live(&tunnel, &dump)?.is_none() {
            return Ok(false);
        }
        let path = tunnel.path.to_string_lossy().into_owned();
        let out = self.exec(&self.wg_quick, &["down", &path])?;
        if !out.success() {
            return Err(backend_error(&self.wg_quick, &out));
        }
        Ok(true)
    }

    /// Probe latency through one tunnel, or through every configured tunnel
    /// when `name` is `None` (sequentially — `count` requests per tunnel).
    ///
    /// Results are sorted successes-first by median total time. Per-tunnel
    /// failures (backend refusal, request failure) are embedded in the results
    /// rather than aborting the sweep; only environment-level errors (missing
    /// tunnel, unspawnable `wg`) return `Err`.
    pub fn probe(
        &self,
        name: Option<&str>,
        url: &str,
        max_time: u64,
        count: u32,
    ) -> Result<Vec<ProbeResult>> {
        let tunnels = match name {
            Some(n) => vec![config::resolve(&self.config_dir, n)?],
            None => config::discover(&self.config_dir)?,
        };
        let mut results = Vec::with_capacity(tunnels.len());
        for tunnel in &tunnels {
            results.push(self.probe_one(tunnel, url, max_time, count)?);
        }
        results.sort_by(|a, b| {
            b.ok.cmp(&a.ok)
                .then_with(|| {
                    a.total_ms()
                        .partial_cmp(&b.total_ms())
                        .unwrap_or(Ordering::Equal)
                })
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(results)
    }

    /// Send one timed request through `tunnel`.
    ///
    /// Returns the parsed sample on success, or a failure message. Runs
    /// unprivileged: curl never goes through sudo.
    ///
    /// For trace URLs the small response body is captured (separated from the
    /// write-out metadata by [`probe::OUTPUT_MARKER`]) so the exit IP and
    /// answering PoP can be reported as evidence of where the probe egressed.
    /// Other URLs discard the body — it could be arbitrarily large.
    fn probe_sample(&self, url: &str, timeout: &str) -> std::result::Result<probe::Sample, String> {
        let capture_body = url.contains("cdn-cgi/trace");
        let write_out = format!("\n{}{}", probe::OUTPUT_MARKER, probe::CURL_FORMAT);
        let curl_args: Vec<String> = [
            "-sS",
            "-o",
            if capture_body { "-" } else { "/dev/null" },
            "-w",
            &write_out,
            "--max-time",
            timeout,
            url,
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        match self.runner.run(&self.curl, &curl_args) {
            Err(e) => Err(format!("failed to run '{}': {e}", self.curl)),
            Ok(out) if !out.success() => {
                let msg = out.stderr.trim();
                Err(if msg.is_empty() {
                    format!("{} exited {}", self.curl, out.code.unwrap_or(-1))
                } else {
                    msg.to_string()
                })
            }
            Ok(out) => probe::parse_probe_output(&out.stdout)
                .map_err(|msg| format!("unexpected curl output: {msg}")),
        }
    }

    /// Send `count` timed requests through `tunnel` (bringing it up once if
    /// needed), aggregate the samples, and restore the previous up/down state.
    fn probe_one(
        &self,
        tunnel: &Tunnel,
        url: &str,
        max_time: u64,
        count: u32,
    ) -> Result<ProbeResult> {
        let dump = self.all_dump()?;
        let was_up = self.find_live(tunnel, &dump)?.is_some();
        let mut result = ProbeResult::new(&tunnel.name, url, !was_up);
        let path = tunnel.path.to_string_lossy().into_owned();

        if !was_up {
            let out = self.exec(&self.wg_quick, &["up", &path])?;
            if !out.success() {
                result.error = Some(backend_error(&self.wg_quick, &out).to_string());
                return Ok(result);
            }
        }

        // Interface details for the report (best effort — never fails a probe).
        if let Ok(dump) = self.all_dump() {
            if let Ok(Some(live)) = self.find_live(tunnel, &dump) {
                result.interface = Some(live.interface.clone());
            }
        }

        let timeout = max_time.to_string();
        let count = count.max(1);
        let mut successes: Vec<probe::Sample> = Vec::new();
        let mut first_error: Option<String> = None;
        for _ in 0..count {
            match self.probe_sample(url, &timeout) {
                Ok(sample) => successes.push(sample),
                Err(msg) => {
                    if first_error.is_none() {
                        first_error = Some(msg);
                    }
                }
            }
        }
        result.samples = count;
        result.failures = count - u32::try_from(successes.len()).unwrap_or(0);
        let timings: Vec<probe::Timings> = successes.iter().map(|s| s.timings.clone()).collect();
        if let Some((stats, median_idx)) = probe::compute_stats(&timings) {
            let median = successes.swap_remove(median_idx);
            result.ok = true;
            result.stats = Some(stats);
            result.timings = Some(median.timings);
            result.remote_ip = median.remote_ip;
            result.http_code = median.http_code;
            result.exit = median.trace;
        }
        if result.failures > 0 {
            result.error = first_error;
        }

        if !was_up {
            match self.exec(&self.wg_quick, &["down", &path]) {
                Ok(out) if out.success() => {}
                Ok(out) => {
                    result.warning = Some(format!(
                        "failed to restore tunnel state: {}",
                        backend_error(&self.wg_quick, &out)
                    ));
                }
                Err(e) => {
                    result.warning = Some(format!("failed to restore tunnel state: {e}"));
                }
            }
        }
        Ok(result)
    }
}

impl<R: CommandRunner> Backend<R> {
    /// Lint one named tunnel, or every discovered tunnel. Pure file analysis —
    /// no privileged commands run.
    pub fn lint(&self, name: Option<&str>) -> Result<Vec<lint::LintResult>> {
        let tunnels = match name {
            Some(n) => vec![config::resolve(&self.config_dir, n)?],
            None => config::discover(&self.config_dir)?,
        };
        tunnels
            .iter()
            .map(|t| {
                let summary = config::conf_summary(&t.path)?;
                Ok(lint::lint(&t.name, &summary))
            })
            .collect()
    }

    /// Validate and install a config file as `<name>.conf` (0600) in the
    /// config directory.
    ///
    /// The name defaults to the source file's stem. Lint errors and an
    /// existing destination both refuse unless `force`.
    pub fn add(
        &self,
        source: &Path,
        name: Option<&str>,
        force: bool,
    ) -> Result<(String, PathBuf, lint::LintResult)> {
        let name = match name {
            Some(n) => n.to_string(),
            None => source
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string(),
        };
        if !config::is_valid_name(&name) {
            return Err(Error::InvalidName(name));
        }
        let summary = config::conf_summary(source)?;
        let result = lint::lint(&name, &summary);
        if !result.ok && !force {
            let errors: Vec<&str> = result
                .findings
                .iter()
                .filter(|f| f.severity == lint::Severity::Error)
                .map(|f| f.message.as_str())
                .collect();
            return Err(Error::Refused(format!(
                "refusing to add '{}' — fix these or pass --force: {}",
                source.display(),
                errors.join("; ")
            )));
        }
        let dest = self.config_dir.join(format!("{name}.conf"));
        if dest.exists() && !force {
            return Err(Error::Refused(format!(
                "'{}' already exists — pass --force to overwrite",
                dest.display()
            )));
        }
        let contents =
            std::fs::read_to_string(source).map_err(|source_err| Error::TunnelConfRead {
                path: source.to_path_buf(),
                source: source_err,
            })?;
        write_private(&dest, &contents, &self.config_dir)?;
        Ok((name, dest, result))
    }

    /// Generate a split-tunnel sibling of `name`: `AllowedIPs` covering all of
    /// IPv4 except the `--exclude` CIDRs and — always — the server's own
    /// endpoint `/32` (preventing the routing loop `wg-quick` does not guard
    /// against outside exact default routes). IPv6 stays fully routed (`::/0`).
    /// The `DNS` line is dropped unless `keep_dns`.
    ///
    /// Returns the new tunnel's name, path, and AllowedIPs entry count.
    pub fn split(
        &self,
        name: &str,
        excludes: &[String],
        output: Option<&str>,
        keep_dns: bool,
        force: bool,
    ) -> Result<(String, PathBuf, usize)> {
        let tunnel = config::resolve(&self.config_dir, name)?;
        let summary = config::conf_summary(&tunnel.path)?;
        let endpoint = summary.endpoint.ok_or_else(|| {
            Error::Refused("config has no Endpoint — cannot compute a safe split tunnel".into())
        })?;
        let host = endpoint
            .rsplit_once(':')
            .map_or(endpoint.as_str(), |(host, _)| host);
        let endpoint_ip = cidr::parse_ip4(host).map_err(|_| {
            Error::Refused(format!(
                "Endpoint '{endpoint}' is not an IPv4 address — split requires an IPv4 endpoint"
            ))
        })?;

        let mut holes = vec![Cidr4 {
            base: endpoint_ip,
            prefix: 32,
        }];
        for exclude in excludes {
            holes.push(Cidr4::parse(exclude).map_err(|msg| {
                Error::Refused(format!("--exclude {exclude}: {msg} (IPv4 CIDRs only)"))
            })?);
        }
        let allowed = cidr::exclude_from_full(&holes);
        let allowed_line = allowed
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
            + ", ::/0";
        let entries = allowed.len() + 1;

        let out_name = match output {
            Some(o) => o.to_string(),
            None => format!("{name}-split"),
        };
        if !config::is_valid_name(&out_name) {
            return Err(Error::InvalidName(out_name));
        }
        let dest = self.config_dir.join(format!("{out_name}.conf"));
        if dest.exists() && !force {
            return Err(Error::Refused(format!(
                "'{}' already exists — pass --force to overwrite",
                dest.display()
            )));
        }

        let text =
            std::fs::read_to_string(&tunnel.path).map_err(|source| Error::TunnelConfRead {
                path: tunnel.path.clone(),
                source,
            })?;
        let rewritten = rewrite_split(&text, &allowed_line, keep_dns)
            .ok_or_else(|| Error::Refused("config has no AllowedIPs line to rewrite".into()))?;
        write_private(&dest, &rewritten, &self.config_dir)?;
        Ok((out_name, dest, entries))
    }
}

/// Rewrite a config's first-peer `AllowedIPs` to `allowed_line`, dropping
/// `DNS` lines unless `keep_dns`. Returns `None` if no AllowedIPs line exists.
fn rewrite_split(text: &str, allowed_line: &str, keep_dns: bool) -> Option<String> {
    let mut out = Vec::new();
    let mut in_first_peer = false;
    let mut seen_peer = false;
    let mut replaced = false;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            let is_peer = line.eq_ignore_ascii_case("[peer]");
            in_first_peer = is_peer && !seen_peer;
            seen_peer = seen_peer || is_peer;
            out.push(raw.to_string());
            continue;
        }
        let key = line
            .split_once('=')
            .map(|(k, _)| k.trim().to_ascii_lowercase());
        match key.as_deref() {
            Some("dns") if !keep_dns => continue, // drop DNS override
            Some("allowedips") if in_first_peer => {
                if !replaced {
                    out.push(format!("AllowedIPs = {allowed_line}"));
                    replaced = true;
                }
                // subsequent AllowedIPs lines in the peer are dropped
            }
            _ => out.push(raw.to_string()),
        }
    }
    if !replaced {
        return None;
    }
    let mut result = out.join("\n");
    result.push('\n');
    Some(result)
}

/// Write `contents` to `dest` with owner-only permissions, creating the
/// config directory if needed.
fn write_private(dest: &Path, contents: &str, config_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(config_dir)
        .map_err(|e| Error::ConfigDir(config_dir.to_path_buf(), e))?;
    std::fs::write(dest, contents).map_err(|source| Error::Write {
        path: dest.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o600)).map_err(
            |source| Error::Write {
                path: dest.to_path_buf(),
                source,
            },
        )?;
    }
    Ok(())
}

/// The outcome of running a command through a tunnel via `vpn exec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutcome {
    /// Tunnel name the command ran through.
    pub name: String,
    /// Whether the tunnel was brought up for this run (and torn down after).
    pub activated: bool,
    /// The child's exit code (`1` if it was killed by a signal).
    pub exit_code: i32,
    /// Non-fatal problem (e.g. the tunnel state could not be restored).
    pub warning: Option<String>,
}

impl<R: CommandRunner> Backend<R> {
    /// Run `command` with the tunnel up, streaming its stdio straight through,
    /// then restore the tunnel's previous up/down state.
    ///
    /// The child always runs unprivileged (never under sudo). A tunnel that
    /// cannot be brought up is a hard error; a child that cannot be spawned is
    /// reported as [`Error::Spawn`] *after* the tunnel state is restored.
    pub fn exec_through(&self, name: &str, command: &[String]) -> Result<ExecOutcome> {
        let tunnel = config::resolve(&self.config_dir, name)?;
        let dump = self.all_dump()?;
        let was_up = self.find_live(&tunnel, &dump)?.is_some();
        let path = tunnel.path.to_string_lossy().into_owned();

        if !was_up {
            let out = self.exec(&self.wg_quick, &["up", &path])?;
            if !out.success() {
                return Err(backend_error(&self.wg_quick, &out));
            }
        }

        let (program, args) = command.split_first().expect("clap requires a command");
        let child = self.runner.run_passthrough(program, args);

        let mut warning = None;
        if !was_up {
            match self.exec(&self.wg_quick, &["down", &path]) {
                Ok(out) if out.success() => {}
                Ok(out) => {
                    warning = Some(format!(
                        "failed to restore tunnel state: {}",
                        backend_error(&self.wg_quick, &out)
                    ));
                }
                Err(e) => warning = Some(format!("failed to restore tunnel state: {e}")),
            }
        }

        match child {
            Err(source) => Err(Error::Spawn {
                program: program.clone(),
                source,
            }),
            Ok(code) => Ok(ExecOutcome {
                name: name.to_string(),
                activated: !was_up,
                // Signal-killed children have no code; report a generic failure.
                exit_code: code.unwrap_or(1),
                warning,
            }),
        }
    }
}

/// Build the `(program, args)` to launch, applying the optional `sudo -n`
/// prefix (`-n` = never prompt; fail immediately if a password would be
/// required).
fn command_line(sudo: bool, program: &str, args: &[&str]) -> (String, Vec<String>) {
    if sudo {
        let mut full = Vec::with_capacity(args.len() + 2);
        full.push("-n".to_string());
        full.push(program.to_string());
        full.extend(args.iter().map(|s| (*s).to_string()));
        ("sudo".to_string(), full)
    } else {
        (
            program.to_string(),
            args.iter().map(|s| (*s).to_string()).collect(),
        )
    }
}

/// Turn a failed command's output into a [`Error::Backend`].
fn backend_error(program: &str, out: &CommandOutput) -> Error {
    let detail = if out.stderr.trim().is_empty() {
        out.stdout.trim()
    } else {
        out.stderr.trim()
    };
    Error::Backend {
        program: program.to_string(),
        code: out.code.unwrap_or(-1),
        stderr: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::MockRunner;
    use std::fs;
    use tempfile::{tempdir, TempDir};

    /// Conf whose peer identity matches `ALL_DUMP`'s first interface.
    const CONF: &str = "[Interface]\nPrivateKey = IFPRIV\nAddress = 10.0.0.2/32\n\n\
        [Peer]\nPublicKey = PEERKEY\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.1:51820\n";

    /// Sibling conf: same server key, split-tunnel allowed-IPs.
    const CONF_SPLIT: &str = "[Peer]\nPublicKey = PEERKEY\nAllowedIPs = 0.0.0.0/1, 128.0.0.0/1\n";

    /// Conf for a second, distinct server.
    const CONF_OTHER: &str = "[Peer]\nPublicKey = OTHERKEY\nAllowedIPs = 0.0.0.0/0\n";

    /// `wg show all dump` output with the CONF tunnel live on utun7.
    const ALL_DUMP: &str = "utun7\tIFPRIV\tIFPUB\t51820\toff\n\
        utun7\tPEERKEY\t(none)\t203.0.113.1:51820\t0.0.0.0/0,::/0\t1700000000\t1024\t2048\t25\n";

    const CURL_OK: &str = "0.004000,0.012000,0.140000,0.290000,0.291000,104.16.132.229,200";
    const URL: &str = "https://1.1.1.1/cdn-cgi/trace";

    /// Config dir holding a single `home.conf` matching ALL_DUMP.
    fn fixture() -> TempDir {
        let cfg = tempdir().unwrap();
        fs::write(cfg.path().join("home.conf"), CONF).unwrap();
        cfg
    }

    fn backend(runner: MockRunner, cfg: &TempDir, sudo: bool) -> Backend<MockRunner> {
        Backend::new(runner, cfg.path().to_path_buf(), sudo)
    }

    #[test]
    fn command_line_without_sudo() {
        let (p, a) = command_line(false, "wg", &["show", "all", "dump"]);
        assert_eq!(p, "wg");
        assert_eq!(a, vec!["show", "all", "dump"]);
    }

    #[test]
    fn command_line_with_sudo_uses_non_interactive_flag() {
        let (p, a) = command_line(true, "wg-quick", &["up", "/x.conf"]);
        assert_eq!(p, "sudo");
        assert_eq!(a, vec!["-n", "wg-quick", "up", "/x.conf"]);
    }

    #[test]
    fn backend_error_prefers_stderr_then_stdout() {
        let e = backend_error(
            "wg-quick",
            &CommandOutput {
                code: Some(2),
                stdout: "out".into(),
                stderr: "  boom  ".into(),
            },
        );
        assert!(matches!(e, Error::Backend { code: 2, ref stderr, .. } if stderr == "boom"));

        let e = backend_error(
            "wg-quick",
            &CommandOutput {
                code: None,
                stdout: "fallback".into(),
                stderr: "   ".into(),
            },
        );
        assert!(matches!(e, Error::Backend { code: -1, ref stderr, .. } if stderr == "fallback"));
    }

    #[test]
    fn up_when_down_brings_up() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // all_dump: nothing live
        runner.ok(""); // wg-quick up
        runner.ok(ALL_DUMP); // status_one's all_dump
        let b = backend(runner.clone(), &cfg, false);

        let (changed, status) = b.up("home").unwrap();
        assert!(changed);
        assert!(status.up);
        assert_eq!(status.interface.as_deref(), Some("utun7"));
        assert_eq!(status.peers.len(), 1);
        assert_eq!(
            status.peers[0].endpoint.as_deref(),
            Some("203.0.113.1:51820")
        );

        let calls = runner.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[1].0, "wg-quick");
        assert_eq!(calls[1].1[0], "up");
    }

    #[test]
    fn up_when_already_up_is_noop() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // all_dump: live
        let b = backend(runner.clone(), &cfg, false);

        let (changed, status) = b.up("home").unwrap();
        assert!(!changed);
        assert!(status.up);
        // wg-quick must not have been invoked; one wg call suffices.
        assert_eq!(runner.calls().len(), 1);
        assert_eq!(runner.calls()[0].0, "wg");
    }

    #[test]
    fn up_backend_failure_is_reported() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // all_dump: down
        runner.fail(2, "address already in use"); // wg-quick up fails
        let b = backend(runner, &cfg, false);
        assert_eq!(b.up("home").unwrap_err().exit_code(), 5);
    }

    #[test]
    fn up_missing_tunnel() {
        let cfg = fixture();
        let b = backend(MockRunner::new(), &cfg, false);
        assert_eq!(b.up("ghost").unwrap_err().exit_code(), 3);
    }

    #[test]
    fn up_spawn_failure() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.spawn_err(); // wg cannot be launched
        let b = backend(runner, &cfg, false);
        assert_eq!(b.up("home").unwrap_err().exit_code(), 6);
    }

    #[test]
    fn wg_failure_is_an_error_not_down() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.fail(1, "permission denied");
        let b = backend(runner, &cfg, false);
        assert_eq!(b.status_one("home").unwrap_err().exit_code(), 5);
    }

    #[test]
    fn down_when_up_brings_down() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // live
        runner.ok(""); // wg-quick down
        let b = backend(runner.clone(), &cfg, false);

        assert!(b.down("home").unwrap());
        let calls = runner.calls();
        assert_eq!(calls[1].0, "wg-quick");
        assert_eq!(calls[1].1[0], "down");
    }

    #[test]
    fn down_when_already_down_is_noop() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // nothing live
        let b = backend(runner.clone(), &cfg, false);
        assert!(!b.down("home").unwrap());
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn down_backend_failure() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP);
        runner.fail(1, "permission denied");
        let b = backend(runner, &cfg, false);
        assert_eq!(b.down("home").unwrap_err().exit_code(), 5);
    }

    #[test]
    fn down_missing_tunnel() {
        let cfg = fixture();
        let b = backend(MockRunner::new(), &cfg, false);
        assert_eq!(b.down("ghost").unwrap_err().exit_code(), 3);
    }

    #[test]
    fn status_one_up_and_down() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP);
        runner.ok("");
        let b = backend(runner, &cfg, false);

        let up = b.status_one("home").unwrap();
        assert!(up.up);
        assert_eq!(up.interface.as_deref(), Some("utun7"));
        let down = b.status_one("home").unwrap();
        assert!(!down.up);
    }

    #[test]
    fn sibling_configs_disambiguated_by_allowed_ips() {
        // Same server public key; only the full-tunnel config is live.
        let cfg = fixture();
        fs::write(cfg.path().join("split.conf"), CONF_SPLIT).unwrap();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // one status_all dump
        let b = backend(runner, &cfg, false);

        let all = b.status_all().unwrap();
        assert_eq!(all.len(), 2);
        assert!(all[0].up, "full-tunnel 'home' must be detected as up");
        assert!(!all[1].up, "sibling 'split' must not claim the interface");
    }

    #[test]
    fn pubkey_only_match_when_conf_has_no_allowed_ips() {
        let cfg = tempdir().unwrap();
        fs::write(
            cfg.path().join("bare.conf"),
            "[Peer]\nPublicKey = PEERKEY\n",
        )
        .unwrap();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP);
        let b = backend(runner, &cfg, false);
        assert!(b.status_one("bare").unwrap().up);
    }

    #[test]
    fn conf_without_peer_is_an_error() {
        let cfg = tempdir().unwrap();
        fs::write(cfg.path().join("bad.conf"), "[Interface]\nPrivateKey = X\n").unwrap();
        let runner = MockRunner::new();
        runner.ok("");
        let b = backend(runner, &cfg, false);
        assert_eq!(b.status_one("bad").unwrap_err().exit_code(), 1);
    }

    #[test]
    fn list_and_current_use_one_wg_call() {
        let cfg = fixture();
        fs::write(cfg.path().join("other.conf"), CONF_OTHER).unwrap();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP);
        let b = backend(runner.clone(), &cfg, false);

        let entries = b.list().unwrap();
        assert_eq!(
            entries,
            vec![
                ListEntry {
                    name: "home".into(),
                    up: true
                },
                ListEntry {
                    name: "other".into(),
                    up: false
                },
            ]
        );
        assert_eq!(runner.calls().len(), 1, "list must need only one wg call");

        let runner = MockRunner::new();
        runner.ok(ALL_DUMP);
        let b = backend(runner.clone(), &cfg, false);
        assert_eq!(b.current().unwrap(), vec!["home".to_string()]);
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn sudo_prefixes_privileged_calls() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // all_dump
        runner.ok(""); // wg-quick up
        runner.ok(ALL_DUMP); // status all_dump
        let b = backend(runner.clone(), &cfg, true);

        b.up("home").unwrap();
        for (program, args) in runner.calls() {
            assert_eq!(program, "sudo");
            assert_eq!(args[0], "-n");
        }
    }

    #[test]
    fn probe_activates_probes_and_restores() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // all_dump: down
        runner.ok(""); // wg-quick up
        runner.ok(ALL_DUMP); // info dump
        runner.ok(CURL_OK); // curl
        runner.ok(""); // wg-quick down (restore)
        let b = backend(runner.clone(), &cfg, true);

        let results = b.probe(Some("home"), URL, 10, 1).unwrap();
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert!(r.ok);
        assert!(r.activated);
        assert_eq!(r.interface.as_deref(), Some("utun7"));
        assert_eq!(r.http_code, Some(200));
        assert_eq!(r.remote_ip.as_deref(), Some("104.16.132.229"));
        assert_eq!(r.timings.as_ref().unwrap().total_ms, 291.0);
        assert!(r.error.is_none() && r.warning.is_none());

        // curl must run unprivileged even with sudo configured.
        let calls = runner.calls();
        let programs: Vec<&str> = calls.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(programs, vec!["sudo", "sudo", "sudo", "curl", "sudo"]);
        // And the restore call is a wg-quick down.
        let last = &runner.calls()[4];
        assert_eq!(last.1[1], "wg-quick");
        assert_eq!(last.1[2], "down");
    }

    #[test]
    fn probe_leaves_running_tunnel_up() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // already up
        runner.ok(ALL_DUMP); // info dump
        runner.ok(CURL_OK); // curl
        let b = backend(runner.clone(), &cfg, false);

        let results = b.probe(Some("home"), URL, 10, 1).unwrap();
        assert!(results[0].ok);
        assert!(!results[0].activated);
        // No wg-quick calls at all: state untouched.
        assert!(runner.calls().iter().all(|(p, _)| p != "wg-quick"));
    }

    #[test]
    fn probe_reports_up_failure() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // down
        runner.fail(1, "resolvconf missing"); // wg-quick up fails
        let b = backend(runner.clone(), &cfg, false);

        let results = b.probe(Some("home"), URL, 10, 1).unwrap();
        let r = &results[0];
        assert!(!r.ok);
        assert!(r.error.as_deref().unwrap().contains("resolvconf"));
        assert_eq!(
            runner.calls().len(),
            2,
            "no curl, no restore after failed up"
        );
    }

    #[test]
    fn probe_curl_failure_still_restores() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // down
        runner.ok(""); // up
        runner.ok(ALL_DUMP); // info
        runner.fail(7, "curl: (7) Failed to connect"); // curl fails
        runner.ok(""); // restore down
        let b = backend(runner.clone(), &cfg, false);

        let r = &b.probe(Some("home"), URL, 10, 1).unwrap()[0];
        assert!(!r.ok);
        assert!(r.error.as_deref().unwrap().contains("Failed to connect"));
        assert!(r.warning.is_none());
        let last = runner.calls().last().unwrap().clone();
        assert_eq!(last.0, "wg-quick");
        assert_eq!(last.1[0], "down");
    }

    #[test]
    fn probe_curl_failure_without_stderr_reports_exit() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // already up
        runner.ok(ALL_DUMP); // info
        runner.fail(28, ""); // curl timeout, silent
        let b = backend(runner, &cfg, false);
        let r = &b.probe(Some("home"), URL, 10, 1).unwrap()[0];
        assert!(r.error.as_deref().unwrap().contains("exited 28"));
    }

    #[test]
    fn probe_restore_failure_becomes_warning() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // down
        runner.ok(""); // up
        runner.ok(ALL_DUMP); // info
        runner.ok(CURL_OK); // curl ok
        runner.fail(1, "cannot remove utun"); // restore fails
        let b = backend(runner, &cfg, false);

        let r = &b.probe(Some("home"), URL, 10, 1).unwrap()[0];
        assert!(r.ok, "probe data is still valid");
        assert!(r
            .warning
            .as_deref()
            .unwrap()
            .contains("failed to restore tunnel state"));
    }

    #[test]
    fn probe_curl_spawn_failure_is_embedded_and_restores() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // down
        runner.ok(""); // up
        runner.ok(ALL_DUMP); // info
        runner.spawn_err(); // curl missing
        runner.ok(""); // restore
        let b = backend(runner.clone(), &cfg, false);

        let r = &b.probe(Some("home"), URL, 10, 1).unwrap()[0];
        assert!(!r.ok);
        assert!(r.error.as_deref().unwrap().contains("failed to run"));
        assert_eq!(runner.calls().last().unwrap().1[0], "down");
    }

    #[test]
    fn probe_tolerates_failing_info_dump() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // down
        runner.ok(""); // up
        runner.fail(1, "transient"); // info dump fails: best-effort, ignored
        runner.ok(CURL_OK); // curl
        runner.ok(""); // restore
        let b = backend(runner, &cfg, false);

        let r = &b.probe(Some("home"), URL, 10, 1).unwrap()[0];
        assert!(r.ok, "probe succeeds without interface info");
        assert_eq!(r.interface, None);
    }

    #[test]
    fn probe_restore_spawn_failure_becomes_warning() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // down
        runner.ok(""); // up
        runner.ok(ALL_DUMP); // info
        runner.ok(CURL_OK); // curl ok
        runner.spawn_err(); // restore cannot even launch
        let b = backend(runner, &cfg, false);

        let r = &b.probe(Some("home"), URL, 10, 1).unwrap()[0];
        assert!(r.ok);
        assert!(r
            .warning
            .as_deref()
            .unwrap()
            .contains("failed to restore tunnel state"));
    }

    #[test]
    fn probe_reports_exit_evidence_from_trace_body() {
        const CURL_TRACE: &str = "ip=203.0.113.99\nloc=US\ncolo=EWR\n<<<VPNPROBE>>>0.004,0.012,0.140,0.290,0.291,104.16.132.229,200";
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // already up
        runner.ok(ALL_DUMP); // info
        runner.ok(CURL_TRACE);
        let b = backend(runner.clone(), &cfg, false);

        let r = &b.probe(Some("home"), URL, 10, 1).unwrap()[0];
        assert!(r.ok);
        let exit = r.exit.as_ref().unwrap();
        assert_eq!(exit.ip, "203.0.113.99");
        assert_eq!(exit.loc.as_deref(), Some("US"));
        assert_eq!(exit.colo.as_deref(), Some("EWR"));

        // Trace URL: body is captured to stdout.
        let curl_call = runner
            .calls()
            .into_iter()
            .find(|(p, _)| p == "curl")
            .unwrap();
        let o_pos = curl_call.1.iter().position(|a| a == "-o").unwrap();
        assert_eq!(curl_call.1[o_pos + 1], "-");
    }

    #[test]
    fn probe_discards_body_for_non_trace_urls() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // already up
        runner.ok(ALL_DUMP); // info
        runner.ok(CURL_OK);
        let b = backend(runner.clone(), &cfg, false);

        let r = &b
            .probe(Some("home"), "https://example.org/big", 10, 1)
            .unwrap()[0];
        assert!(r.ok);
        assert!(r.exit.is_none());

        let curl_call = runner
            .calls()
            .into_iter()
            .find(|(p, _)| p == "curl")
            .unwrap();
        let o_pos = curl_call.1.iter().position(|a| a == "-o").unwrap();
        assert_eq!(curl_call.1[o_pos + 1], "/dev/null");
        // The write-out includes the marker so parsing stays uniform.
        assert!(curl_call.1.iter().any(|a| a.contains("<<<VPNPROBE>>>")));
    }

    #[test]
    fn probe_count_aggregates_samples_and_picks_median() {
        const CURL_FAST: &str = "0.001,0.002,0.003,0.100,0.101,1.2.3.4,200";
        const CURL_SLOW: &str = "0.001,0.002,0.003,0.200,0.300,5.6.7.8,200";
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // already up
        runner.ok(ALL_DUMP); // info
        runner.ok(CURL_SLOW); // 300.0 ms
        runner.ok(CURL_FAST); // 101.0 ms
        runner.ok(CURL_OK); // 291.0 ms
        let b = backend(runner, &cfg, false);

        let r = &b.probe(Some("home"), URL, 10, 3).unwrap()[0];
        assert!(r.ok);
        assert_eq!(r.samples, 3);
        assert_eq!(r.failures, 0);
        let s = r.stats.as_ref().unwrap();
        assert_eq!(s.min_total_ms, 101.0);
        assert_eq!(s.median_total_ms, 291.0);
        assert_eq!(s.max_total_ms, 300.0);
        // Reported point-in-time fields come from the median sample.
        assert_eq!(r.timings.as_ref().unwrap().total_ms, 291.0);
        assert_eq!(r.remote_ip.as_deref(), Some("104.16.132.229"));
    }

    #[test]
    fn probe_count_tolerates_partial_failures() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // already up
        runner.ok(ALL_DUMP); // info
        runner.ok(CURL_OK);
        runner.fail(7, "curl: (7) mid-sample blip");
        runner.ok(CURL_OK);
        let b = backend(runner, &cfg, false);

        let r = &b.probe(Some("home"), URL, 10, 3).unwrap()[0];
        assert!(r.ok, "one success is enough");
        assert_eq!(r.samples, 3);
        assert_eq!(r.failures, 1);
        assert!(r.error.as_deref().unwrap().contains("mid-sample blip"));
        assert!(r.stats.is_some());
    }

    #[test]
    fn probe_count_all_failures_is_failed() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // already up
        runner.ok(ALL_DUMP); // info
        runner.fail(7, "first");
        runner.fail(7, "second");
        let b = backend(runner, &cfg, false);

        let r = &b.probe(Some("home"), URL, 10, 2).unwrap()[0];
        assert!(!r.ok);
        assert_eq!(r.failures, 2);
        assert!(r.error.as_deref().unwrap().contains("first"));
        assert!(r.stats.is_none());
    }

    #[test]
    fn probe_bad_curl_output_is_an_error() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // up
        runner.ok(ALL_DUMP); // info
        runner.ok("<html>captive portal</html>"); // nonsense
        let b = backend(runner, &cfg, false);
        let r = &b.probe(Some("home"), URL, 10, 1).unwrap()[0];
        assert!(!r.ok);
        assert!(r
            .error
            .as_deref()
            .unwrap()
            .contains("unexpected curl output"));
    }

    #[test]
    fn probe_all_sorts_successes_first() {
        let cfg = fixture();
        fs::write(cfg.path().join("other.conf"), CONF_OTHER).unwrap();
        let runner = MockRunner::new();
        // 'home' (alphabetically first): full success.
        runner.ok(""); // down
        runner.ok(""); // up
        runner.ok(ALL_DUMP); // info
        runner.ok(CURL_OK); // curl
        runner.ok(""); // restore
                       // 'other': curl fails.
        runner.ok(""); // down
        runner.ok(""); // up
        runner.ok(""); // info (not found)
        runner.fail(7, "curl: (7)"); // curl
        runner.ok(""); // restore
        let b = backend(runner, &cfg, false);

        let results = b.probe(None, URL, 10, 1).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].ok && results[0].name == "home");
        assert!(!results[1].ok && results[1].name == "other");
    }

    #[test]
    fn probe_missing_tunnel_is_a_hard_error() {
        let cfg = fixture();
        let b = backend(MockRunner::new(), &cfg, false);
        assert_eq!(
            b.probe(Some("ghost"), URL, 10, 1).unwrap_err().exit_code(),
            3
        );
    }

    #[test]
    fn probe_passes_url_and_timeout_to_curl() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // up
        runner.ok(ALL_DUMP); // info
        runner.ok(CURL_OK); // curl
        let b = backend(runner.clone(), &cfg, false);
        b.probe(Some("home"), "https://example.org/x", 42, 1)
            .unwrap();

        let curl_call = runner
            .calls()
            .into_iter()
            .find(|(p, _)| p == "curl")
            .unwrap();
        assert!(curl_call.1.contains(&"--max-time".to_string()));
        assert!(curl_call.1.contains(&"42".to_string()));
        assert_eq!(curl_call.1.last().unwrap(), "https://example.org/x");
    }

    fn cmd(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn exec_activates_runs_child_unprivileged_and_restores() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // all_dump: down
        runner.ok(""); // wg-quick up
        runner.fail(42, ""); // child exits 42 (passthrough reads code)
        runner.ok(""); // wg-quick down
        let b = backend(runner.clone(), &cfg, true);

        let outcome = b
            .exec_through("home", &cmd(&["curl", "-sI", "https://x.example"]))
            .unwrap();
        assert!(outcome.activated);
        assert_eq!(outcome.exit_code, 42);
        assert!(outcome.warning.is_none());

        // sudo wraps only the wg calls; the child runs bare.
        let calls = runner.calls();
        let programs: Vec<&str> = calls.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(programs, vec!["sudo", "sudo", "curl", "sudo"]);
        assert_eq!(calls[2].1, vec!["-sI", "https://x.example"]);
        assert_eq!(calls[3].1[1], "wg-quick");
        assert_eq!(calls[3].1[2], "down");
    }

    #[test]
    fn exec_on_running_tunnel_leaves_it_up() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // already up
        runner.ok(""); // child exits 0
        let b = backend(runner.clone(), &cfg, false);

        let outcome = b.exec_through("home", &cmd(&["true"])).unwrap();
        assert!(!outcome.activated);
        assert_eq!(outcome.exit_code, 0);
        assert!(runner.calls().iter().all(|(p, _)| p != "wg-quick"));
    }

    #[test]
    fn exec_up_failure_is_hard_error() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // down
        runner.fail(1, "no permission"); // wg-quick up fails
        let b = backend(runner.clone(), &cfg, false);
        assert_eq!(
            b.exec_through("home", &cmd(&["true"]))
                .unwrap_err()
                .exit_code(),
            5
        );
        assert_eq!(runner.calls().len(), 2, "child never ran");
    }

    #[test]
    fn exec_child_spawn_failure_still_restores() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // down
        runner.ok(""); // up
        runner.spawn_err(); // child missing
        runner.ok(""); // restore
        let b = backend(runner.clone(), &cfg, false);

        let err = b.exec_through("home", &cmd(&["nope"])).unwrap_err();
        assert_eq!(err.exit_code(), 6);
        let last = runner.calls().last().unwrap().clone();
        assert_eq!(last.1[0], "down", "restore ran despite spawn failure");
    }

    #[test]
    fn exec_restore_failure_becomes_warning() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // down
        runner.ok(""); // up
        runner.ok(""); // child ok
        runner.fail(1, "cannot remove"); // restore fails
        let b = backend(runner, &cfg, false);

        let outcome = b.exec_through("home", &cmd(&["true"])).unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome
            .warning
            .as_deref()
            .unwrap()
            .contains("failed to restore tunnel state"));
    }

    #[test]
    fn exec_signal_killed_child_reports_code_1() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // already up
        runner.signal_killed(); // child killed by signal
        let b = backend(runner, &cfg, false);
        assert_eq!(b.exec_through("home", &cmd(&["x"])).unwrap().exit_code, 1);
    }

    #[test]
    fn exec_missing_tunnel() {
        let cfg = fixture();
        let b = backend(MockRunner::new(), &cfg, false);
        assert_eq!(
            b.exec_through("ghost", &cmd(&["true"]))
                .unwrap_err()
                .exit_code(),
            3
        );
    }

    #[test]
    fn lint_checks_one_or_all_configs() {
        let cfg = fixture(); // clean home.conf
        fs::write(
            cfg.path().join("loop.conf"),
            "[Interface]\nPrivateKey = P\n[Peer]\nPublicKey = K\n\
             AllowedIPs = 64.0.0.0/3\nEndpoint = 79.127.160.216:51820\n",
        )
        .unwrap();
        let b = backend(MockRunner::new(), &cfg, false);

        let all = b.lint(None).unwrap();
        assert_eq!(all.len(), 2);
        assert!(all[0].ok, "home is clean");
        assert!(!all[1].ok, "loop.conf has the routing loop");
        assert!(all[1].findings[0].message.contains("routing loop"));

        let one = b.lint(Some("home")).unwrap();
        assert_eq!(one.len(), 1);
        assert!(one[0].ok);

        assert_eq!(b.lint(Some("ghost")).unwrap_err().exit_code(), 3);
    }

    #[test]
    fn add_installs_config_with_private_permissions() {
        let cfg = tempdir().unwrap();
        let src_dir = tempdir().unwrap();
        let src = src_dir.path().join("vpn_cli-JP-77.conf");
        fs::write(&src, CONF).unwrap();
        let b = backend(MockRunner::new(), &cfg, false);

        let (name, dest, lint) = b.add(&src, Some("proton-jp"), false).unwrap();
        assert_eq!(name, "proton-jp");
        assert!(lint.ok);
        assert_eq!(dest, cfg.path().join("proton-jp.conf"));
        assert_eq!(fs::read_to_string(&dest).unwrap(), CONF);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn add_defaults_name_to_stem_and_validates() {
        let cfg = tempdir().unwrap();
        let src_dir = tempdir().unwrap();
        let good = src_dir.path().join("jp.conf");
        fs::write(&good, CONF).unwrap();
        let b = backend(MockRunner::new(), &cfg, false);
        assert_eq!(b.add(&good, None, false).unwrap().0, "jp");

        // A stem that is not a valid tunnel name needs --name.
        let bad = src_dir.path().join("has space.conf");
        fs::write(&bad, CONF).unwrap();
        assert_eq!(b.add(&bad, None, false).unwrap_err().exit_code(), 4);
    }

    #[test]
    fn add_refuses_lint_errors_and_overwrites_without_force() {
        let cfg = tempdir().unwrap();
        let src_dir = tempdir().unwrap();
        let broken = src_dir.path().join("broken.conf");
        fs::write(
            &broken,
            "[Interface]\nPrivateKey = P\n[Peer]\nPublicKey = K\n\
             AllowedIPs = 64.0.0.0/3\nEndpoint = 79.127.160.216:51820\n",
        )
        .unwrap();
        let b = backend(MockRunner::new(), &cfg, false);

        let err = b.add(&broken, None, false).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("routing loop"));
        // --force overrides the lint refusal.
        assert!(b.add(&broken, None, true).is_ok());

        // Existing destination refuses without force.
        let good = src_dir.path().join("broken2.conf");
        fs::write(&good, CONF).unwrap();
        let err = b.add(&good, Some("broken"), false).unwrap_err();
        assert!(err.to_string().contains("already exists"));
        assert!(b.add(&good, Some("broken"), true).is_ok());
    }

    #[test]
    fn add_missing_source_errors() {
        let cfg = tempdir().unwrap();
        let b = backend(MockRunner::new(), &cfg, false);
        let err = b.add(Path::new("/nonexistent/x.conf"), Some("x"), false);
        assert_eq!(err.unwrap_err().exit_code(), 1);
    }

    /// A realistic source conf for split: full tunnel with DNS and comments.
    const SPLIT_SRC: &str = "[Interface]\n# Key for vpn cli\nPrivateKey = IFPRIV\n\
        Address = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\n# US-MA#93\nPublicKey = PEERKEY\n\
        AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 79.127.160.216:51820\n\
        PersistentKeepalive = 25\n";

    #[test]
    fn split_generates_safe_sibling() {
        let cfg = tempdir().unwrap();
        fs::write(cfg.path().join("proton.conf"), SPLIT_SRC).unwrap();
        let b = backend(MockRunner::new(), &cfg, false);

        let (name, dest, entries) = b
            .split("proton", &["100.64.0.0/10".to_string()], None, false, false)
            .unwrap();
        assert_eq!(name, "proton-split");
        // 38 v4 CIDRs (tailscale + endpoint holes) + ::/0.
        assert_eq!(entries, 39);

        let text = fs::read_to_string(&dest).unwrap();
        assert!(!text.to_lowercase().contains("dns ="), "DNS dropped");
        assert!(text.contains("PrivateKey = IFPRIV"), "keys carried over");
        assert!(text.contains("PersistentKeepalive = 25"));
        assert!(text.contains("::/0"));
        assert!(!text.contains("0.0.0.0/0"), "full route replaced");

        // The generated config must lint clean — no routing loop.
        let summary = config::conf_summary(&dest).unwrap();
        let result = lint::lint(&name, &summary);
        assert!(result.ok, "generated split must be safe: {result:?}");
    }

    #[test]
    fn split_keep_dns_and_custom_output() {
        let cfg = tempdir().unwrap();
        fs::write(cfg.path().join("proton.conf"), SPLIT_SRC).unwrap();
        let b = backend(MockRunner::new(), &cfg, false);

        let (name, dest, _) = b.split("proton", &[], Some("p-ts"), true, false).unwrap();
        assert_eq!(name, "p-ts");
        let text = fs::read_to_string(&dest).unwrap();
        assert!(text.contains("DNS = 10.2.0.1"), "--keep-dns preserves DNS");
    }

    #[test]
    fn split_refusals() {
        let cfg = tempdir().unwrap();
        fs::write(cfg.path().join("proton.conf"), SPLIT_SRC).unwrap();
        // No endpoint.
        fs::write(
            cfg.path().join("noend.conf"),
            "[Peer]\nPublicKey = K\nAllowedIPs = 0.0.0.0/0\n",
        )
        .unwrap();
        let b = backend(MockRunner::new(), &cfg, false);

        assert!(b
            .split("noend", &[], None, false, false)
            .unwrap_err()
            .to_string()
            .contains("no Endpoint"));
        // Bad exclude CIDR.
        assert!(b
            .split("proton", &["::/0".to_string()], None, false, false)
            .unwrap_err()
            .to_string()
            .contains("IPv4 CIDRs only"));
        // Default output name too long -> invalid.
        fs::write(cfg.path().join("a-very-long-nm.conf"), SPLIT_SRC).unwrap();
        assert_eq!(
            b.split("a-very-long-nm", &[], None, false, false)
                .unwrap_err()
                .exit_code(),
            4
        );
        // Overwrite protection.
        b.split("proton", &[], None, false, false).unwrap();
        assert!(b
            .split("proton", &[], None, false, false)
            .unwrap_err()
            .to_string()
            .contains("already exists"));
        assert!(b.split("proton", &[], None, false, true).is_ok());
    }

    #[test]
    fn rewrite_split_handles_multiple_allowedips_and_missing() {
        let text =
            "[Peer]\nAllowedIPs = 10.0.0.0/8\nAllowedIPs = 172.16.0.0/12\nEndpoint = 1.2.3.4:1\n";
        let out = rewrite_split(text, "0.0.0.0/1, 128.0.0.0/1", true).unwrap();
        assert_eq!(
            out.matches("AllowedIPs").count(),
            1,
            "collapsed to one line"
        );
        assert!(out.contains("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1"));
        assert!(out.contains("Endpoint = 1.2.3.4:1"));

        assert!(rewrite_split("[Peer]\nPublicKey = K\n", "x", false).is_none());
    }

    #[test]
    fn with_programs_overrides_invoked_binaries() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // all_dump
        runner.ok(""); // wg-quick up
        runner.ok(ALL_DUMP); // status dump
        let b = backend(runner.clone(), &cfg, false).with_programs(
            "/abs/wg".to_string(),
            "/abs/wg-quick".to_string(),
            "/abs/curl".to_string(),
        );

        b.up("home").unwrap();
        let calls = runner.calls();
        assert_eq!(calls[0].0, "/abs/wg");
        assert_eq!(calls[1].0, "/abs/wg-quick");
    }

    #[test]
    fn with_programs_labels_backend_errors() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // all_dump
        runner.fail(2, "boom"); // wg-quick up fails
        let b = backend(runner, &cfg, false).with_programs(
            "/abs/wg".to_string(),
            "/abs/wg-quick".to_string(),
            "curl".to_string(),
        );

        let err = b.up("home").unwrap_err();
        assert!(matches!(err, Error::Backend { program, .. } if program == "/abs/wg-quick"));
    }

    #[test]
    fn config_dir_accessor() {
        let cfg = fixture();
        let b = backend(MockRunner::new(), &cfg, false);
        assert_eq!(b.config_dir(), cfg.path());
    }
}
