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
use crate::diff;
use crate::dns;
use crate::error::{Error, Result};
use crate::lint;
use crate::probe::{self, ProbeResult};
use crate::runner::{CommandOutput, CommandRunner};
use crate::state::{self, Journal, Phase, Reconciliation};
use crate::status::{self, DumpPeer, ListEntry, TunnelStatus};

/// Orchestrates `wg-quick`/`wg`/`curl` for a set of tunnel configs.
pub struct Backend<R: CommandRunner> {
    runner: R,
    config_dir: PathBuf,
    sudo: bool,
    wg: String,
    wg_quick: String,
    curl: String,
    dns_sweeps: Vec<u64>,
    /// Delays (ms) before each `diff` fetch attempt; length = attempt count.
    /// The spacing lets a freshly-activated tunnel finish its handshake before
    /// an in-tunnel DNS lookup, which `probe` sidesteps by hitting an IP.
    diff_retries: Vec<u64>,
    clock: Clock,
}

/// Time source for lease deadlines; swappable so tests are deterministic.
#[derive(Debug, Clone, Copy)]
enum Clock {
    /// Real wall-clock time.
    System,
    /// A fixed Unix timestamp (tests).
    #[cfg_attr(not(test), allow(dead_code))]
    Fixed(u64),
}

impl Clock {
    fn now(&self) -> u64 {
        match self {
            Clock::System => crate::state::now_unix(),
            Clock::Fixed(t) => *t,
        }
    }
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
            dns_sweeps: dns::SWEEP_DELAYS_MS.to_vec(),
            diff_retries: vec![0, 800, 1600],
            clock: Clock::System,
        }
    }

    /// Override the `diff` fetch retry schedule (tests use a single attempt).
    #[cfg(test)]
    #[must_use]
    pub fn with_diff_retries(mut self, delays_ms: Vec<u64>) -> Self {
        self.diff_retries = delays_ms;
        self
    }

    /// Override the DNS-guard sweep schedule (delays in ms before each
    /// verification sweep after a teardown). Tests use all-zero schedules.
    #[must_use]
    pub fn with_dns_sweeps(mut self, sweep_delays_ms: Vec<u64>) -> Self {
        self.dns_sweeps = sweep_delays_ms;
        self
    }

    /// Pin the clock to a fixed Unix timestamp (tests, for lease determinism).
    #[cfg(test)]
    #[must_use]
    pub fn with_fixed_time(mut self, now: u64) -> Self {
        self.clock = Clock::Fixed(now);
        self
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
    /// if it was already up. `lease_secs`, when set, records a deadline after
    /// which reconciliation tears the tunnel down automatically.
    pub fn up(&self, name: &str) -> Result<(bool, TunnelStatus)> {
        self.up_with_lease(name, None)
    }

    /// [`Backend::up`] with an optional lease duration in seconds.
    pub fn up_with_lease(
        &self,
        name: &str,
        lease_secs: Option<u64>,
    ) -> Result<(bool, TunnelStatus)> {
        self.reconcile()?;
        let tunnel = config::resolve(&self.config_dir, name)?;
        let dump = self.all_dump()?;
        if let Some(live) = self.find_live(&tunnel, &dump)? {
            // Already up: adopt it into the journal if untracked, so a later
            // crash still self-heals. No host mutation, no capture.
            if state::read(&self.config_dir, name).is_none() {
                let _ = state::write(
                    &self.config_dir,
                    &self.active_journal(
                        &tunnel,
                        Some(live.interface.clone()),
                        lease_secs,
                        Default::default(),
                    ),
                );
            }
            return Ok((false, self.status_from(name, Some(live), &dump)));
        }
        let status = self.activate(&tunnel, lease_secs)?;
        Ok((true, status))
    }

    /// Bring a tunnel down and restore the host: tear the interface down (if
    /// live), restore each network service's DNS from the journal snapshot
    /// (falling back to clearing the tunnel's pinned resolver to DHCP), and
    /// clear the journal.
    ///
    /// Runs even when the tunnel is already down, so `vpn down` doubles as an
    /// explicit repair for DNS poisoned by an unclean teardown (crash, or
    /// shutdown with the tunnel up).
    pub fn down(&self, name: &str) -> Result<DownOutcome> {
        self.reconcile()?;
        let tunnel = config::resolve(&self.config_dir, name)?;
        let dump = self.all_dump()?;
        let live = self.find_live(&tunnel, &dump)?.is_some();
        let (changed, guard) = self.teardown(&tunnel, live)?;
        Ok(DownOutcome {
            changed,
            dns_cleared: guard.cleared,
            dns_warning: guard.warning,
        })
    }

    /// Build an `Active` journal for `tunnel`, computing the lease deadline
    /// from the injected clock.
    fn active_journal(
        &self,
        tunnel: &Tunnel,
        interface: Option<String>,
        lease_secs: Option<u64>,
        dns_snapshot: std::collections::BTreeMap<String, Vec<String>>,
    ) -> Journal {
        let tunnel_dns = config::conf_summary(&tunnel.path)
            .map(|s| s.dns_servers)
            .unwrap_or_default();
        Journal {
            tunnel: tunnel.name.clone(),
            phase: Phase::Active,
            interface,
            lease_deadline: lease_secs.map(|secs| self.clock.now().saturating_add(secs)),
            dns_snapshot,
            tunnel_dns,
        }
    }

    /// Bring `tunnel` up with the journal as a write-ahead log: snapshot the
    /// pre-tunnel DNS, record `UpPending`, run `wg-quick up`, then record
    /// `Active` with the resolved interface. A crash at any point leaves a
    /// journal that [`Backend::reconcile`] rolls back. Returns the post-up
    /// status (one `wg` dump, as the old `up` did).
    fn activate(&self, tunnel: &Tunnel, lease_secs: Option<u64>) -> Result<TunnelStatus> {
        let dns_snapshot = self.journal_up_pending(tunnel)?;
        let path = tunnel.path.to_string_lossy().into_owned();
        let out = self.exec(&self.wg_quick, &["up", &path])?;
        if !out.success() {
            return Err(backend_error(&self.wg_quick, &out));
        }
        let dump = self.all_dump()?;
        let live = self.find_live(tunnel, &dump)?;
        let interface = live.map(|d| d.interface.clone());
        state::write(
            &self.config_dir,
            &self.active_journal(tunnel, interface, lease_secs, dns_snapshot),
        )?;
        Ok(self.status_from(&tunnel.name, live, &dump))
    }

    /// Snapshot the pre-tunnel DNS (sanitized) and record an `UpPending`
    /// journal, the write-ahead step before `wg-quick up`. Returns the
    /// snapshot for the eventual `Active` record. No system calls when the
    /// config declares no `DNS`.
    fn journal_up_pending(
        &self,
        tunnel: &Tunnel,
    ) -> Result<std::collections::BTreeMap<String, Vec<String>>> {
        let tunnel_dns = config::conf_summary(&tunnel.path)
            .map(|s| s.dns_servers)
            .unwrap_or_default();
        let dns_snapshot = if tunnel_dns.is_empty() {
            Default::default()
        } else {
            dns::capture(&self.runner, &tunnel_dns).unwrap_or_default()
        };
        state::write(
            &self.config_dir,
            &Journal {
                tunnel: tunnel.name.clone(),
                phase: Phase::UpPending,
                interface: None,
                lease_deadline: None,
                dns_snapshot: dns_snapshot.clone(),
                tunnel_dns,
            },
        )?;
        Ok(dns_snapshot)
    }

    /// Tear `tunnel` down and restore the host DNS. `live` says whether an
    /// interface is currently up (the caller already knows: `down` checks,
    /// `probe`/`exec` know they brought it up), so no extra `wg` dump is made.
    /// Returns `(changed, dns)`. Idempotent: with nothing live it still
    /// restores DNS and clears the journal — what makes `down` a repair.
    fn teardown(&self, tunnel: &Tunnel, live: bool) -> Result<(bool, dns::GuardOutcome)> {
        let journal = state::read(&self.config_dir, &tunnel.name);
        if let Some(j) = &journal {
            let mut pending = j.clone();
            pending.phase = Phase::DownPending;
            let _ = state::write(&self.config_dir, &pending);
        }
        let changed = if live {
            let path = tunnel.path.to_string_lossy().into_owned();
            let out = self.exec(&self.wg_quick, &["down", &path])?;
            if !out.success() {
                return Err(backend_error(&self.wg_quick, &out));
            }
            true
        } else {
            false
        };
        let guard = self.restore_dns(tunnel, journal.as_ref());
        state::remove(&self.config_dir, &tunnel.name)?;
        Ok((changed, guard))
    }

    /// Restore DNS after a teardown. Prefers the journal's sanitized snapshot
    /// (which brings back custom static DNS, not just DHCP); falls back to
    /// clearing the config's `DNS` servers wherever they are still pinned.
    ///
    /// Skipped when another configured tunnel is still up — that tunnel
    /// legitimately owns the system DNS. Never fails.
    fn restore_dns(&self, tunnel: &Tunnel, journal: Option<&Journal>) -> dns::GuardOutcome {
        // Nothing DNS-related to do? Return before any system call, so tunnels
        // without a `DNS` line cost nothing here.
        let has_journal_dns = journal.is_some_and(|j| !j.tunnel_dns.is_empty());
        let config_dns = if has_journal_dns {
            Vec::new()
        } else {
            config::conf_summary(&tunnel.path)
                .map(|s| s.dns_servers)
                .unwrap_or_default()
        };
        if !has_journal_dns && config_dns.is_empty() {
            return dns::GuardOutcome::default();
        }
        // A different live tunnel legitimately owns DNS; leave it alone.
        // Conservative on error (unknown liveness → do not touch).
        if self
            .current()
            .map_or(true, |active| active.iter().any(|n| n != &tunnel.name))
        {
            return dns::GuardOutcome::default();
        }
        if let Some(j) = journal {
            if has_journal_dns {
                // Prefer the snapshot: restores custom static DNS, not just DHCP.
                return dns::restore(
                    &self.runner,
                    &j.dns_snapshot,
                    &j.tunnel_dns,
                    &self.dns_sweeps,
                );
            }
        }
        // No journal (e.g. poison predating this version): clear the config's
        // pinned resolver to DHCP.
        dns::guard(&self.runner, &config_dns, &self.dns_sweeps)
    }

    /// Roll back any partial or expired tunnel state recorded in the journals,
    /// returning the host to a working configuration. Runs at the start of
    /// every mutating command. Cheap when idle: with no journals it makes no
    /// system calls at all, so ordinary operation is unaffected.
    pub fn reconcile(&self) -> Result<Vec<Recovered>> {
        let journals = state::read_all(&self.config_dir);
        if journals.is_empty() {
            return Ok(Vec::new());
        }
        let dump = self.all_dump()?;
        let now = self.clock.now();
        let mut recovered = Vec::new();
        for journal in journals {
            let live = self.journal_live(&journal, &dump);
            let Reconciliation::Recover { tear_down, reason } =
                state::reconcile_one(&journal, live, now)
            else {
                continue;
            };
            if tear_down {
                self.tear_down_journal(&journal);
            }
            let guard = self.restore_dns_journal(&journal);
            let _ = state::remove(&self.config_dir, &journal.tunnel);
            recovered.push(Recovered {
                tunnel: journal.tunnel.clone(),
                reason: reason.describe().to_string(),
                dns_cleared: guard.cleared,
                dns_warning: guard.warning,
            });
        }
        Ok(recovered)
    }

    /// Unconditional recovery — the "fix my machine" escape hatch. Needs no
    /// tunnel name and tolerates missing configs: it reconciles every journal,
    /// then tears down any remaining live WireGuard interface (orphans from a
    /// crash or an older version) and clears any config's DNS still pinned
    /// system-wide. Returns everything it changed.
    pub fn recover(&self) -> Result<Vec<Recovered>> {
        let mut recovered = self.reconcile()?;

        // Tear down any WireGuard interface no journal accounts for. Every
        // interface reported by `wg` is a WireGuard interface by definition.
        let dump = self.all_dump()?;
        let claimed: std::collections::BTreeSet<String> = state::read_all(&self.config_dir)
            .into_iter()
            .filter_map(|j| j.interface)
            .collect();
        let mut orphans: Vec<String> = dump
            .iter()
            .map(|d| d.interface.clone())
            .filter(|iface| !claimed.contains(iface))
            .collect();
        orphans.sort();
        orphans.dedup();
        for iface in orphans {
            // `wg-quick down` needs the config *path* on macOS (it rejects a
            // bare interface name), so map the interface back to a config by
            // peer identity. Without a matching config we cannot cleanly tear
            // it down — report it with a manual hint rather than claim success.
            match self.config_for_interface(&iface, &dump) {
                Some(tunnel) => {
                    let path = tunnel.path.to_string_lossy().into_owned();
                    let torn = self
                        .exec(&self.wg_quick, &["down", &path])
                        .map(|o| o.success())
                        .unwrap_or(false);
                    recovered.push(Recovered {
                        tunnel: tunnel.name,
                        reason: if torn {
                            "orphaned interface torn down".to_string()
                        } else {
                            format!("orphaned interface {iface} — teardown failed")
                        },
                        dns_cleared: Vec::new(),
                        dns_warning: None,
                    });
                }
                None => recovered.push(Recovered {
                    tunnel: iface.clone(),
                    reason: format!(
                        "orphaned interface {iface} with no matching config — \
                         remove it manually: wg-quick down <config> (or ifconfig {iface} destroy)"
                    ),
                    dns_cleared: Vec::new(),
                    dns_warning: None,
                }),
            }
        }

        // Mop up any DNS still pinned to a known config's resolver, even for
        // interfaces we never had a journal for.
        let declared = self.declared_dns_servers();
        if !declared.is_empty() && self.current().map(|a| a.is_empty()).unwrap_or(false) {
            let guard = dns::guard(&self.runner, &declared, &self.dns_sweeps);
            if !guard.cleared.is_empty() || guard.warning.is_some() {
                recovered.push(Recovered {
                    tunnel: "(dns)".to_string(),
                    reason: "cleared residual VPN DNS".to_string(),
                    dns_cleared: guard.cleared,
                    dns_warning: guard.warning,
                });
            }
        }
        Ok(recovered)
    }

    /// Every distinct `DNS` server declared across all discovered configs.
    fn declared_dns_servers(&self) -> Vec<String> {
        let mut declared: Vec<String> = Vec::new();
        for tunnel in config::discover(&self.config_dir).unwrap_or_default() {
            if let Ok(summary) = config::conf_summary(&tunnel.path) {
                for server in summary.dns_servers {
                    if !declared.contains(&server) {
                        declared.push(server);
                    }
                }
            }
        }
        declared
    }

    /// Assert the host network is in a consistent state: no WireGuard interface
    /// is live without a matching config (an orphan leaking traffic), no
    /// network service is pinned to a tunnel's DNS while nothing is up, and the
    /// default route is not held by an untracked tunnel. This is the runtime
    /// form of the host invariant — read-only, safe to call anytime.
    pub fn verify(&self) -> Result<HealthReport> {
        let dump = self.all_dump()?;
        let mut issues = Vec::new();

        // Orphaned interfaces: a live WireGuard interface no config accounts for.
        let default_iface = self.default_route_interface();
        let mut wg_ifaces: Vec<String> = dump.iter().map(|d| d.interface.clone()).collect();
        wg_ifaces.sort();
        wg_ifaces.dedup();
        for iface in &wg_ifaces {
            if self.config_for_interface(iface, &dump).is_none() {
                let owns_route = default_iface.as_deref() == Some(iface.as_str());
                issues.push(HealthIssue {
                    kind: "orphan",
                    detail: format!(
                        "WireGuard interface {iface} is live but no config matches it{} \
                         — run `vpn recover`",
                        if owns_route {
                            " and it holds the default route"
                        } else {
                            ""
                        }
                    ),
                });
            }
        }

        // Stale DNS: a service pinned to a known tunnel resolver while nothing
        // is up (name resolution is dead until it is cleared).
        let active = self.current().unwrap_or_default();
        let declared = self.declared_dns_servers();
        if active.is_empty() && !declared.is_empty() {
            if let Some(stale) = dns::stale_services(&self.runner, &declared) {
                if !stale.is_empty() {
                    issues.push(HealthIssue {
                        kind: "dns",
                        detail: format!(
                            "stale VPN DNS pinned on {} — name resolution is broken; \
                             run `vpn recover`",
                            stale.join(", ")
                        ),
                    });
                }
            }
        }

        Ok(HealthReport {
            healthy: issues.is_empty(),
            issues,
        })
    }

    /// The interface backing the current default route (e.g. `en0`), via
    /// `route -n get default`. Unprivileged; `None` if it cannot be read.
    fn default_route_interface(&self) -> Option<String> {
        let out = self.runner.run(ROUTE, &route_default_args()).ok()?;
        if !out.success() {
            return None;
        }
        out.stdout.lines().find_map(|line| {
            line.trim()
                .strip_prefix("interface:")
                .map(|iface| iface.trim().to_string())
        })
    }

    /// The discovered tunnel whose peer identity is live on `iface`, if any.
    /// Used by `recover` to map an orphan interface back to a config path
    /// (which `wg-quick down` requires on macOS).
    fn config_for_interface(&self, iface: &str, dump: &[DumpPeer]) -> Option<Tunnel> {
        for tunnel in config::discover(&self.config_dir).ok()? {
            if let Ok(Some(live)) = self.find_live(&tunnel, dump) {
                if live.interface == iface {
                    return Some(tunnel);
                }
            }
        }
        None
    }

    /// Whether the journal's tunnel is currently live: by recorded interface
    /// name if known, else by peer identity via its config (if it still
    /// exists).
    fn journal_live(&self, journal: &Journal, dump: &[DumpPeer]) -> bool {
        if let Some(iface) = &journal.interface {
            if dump.iter().any(|d| &d.interface == iface) {
                return true;
            }
        }
        config::resolve(&self.config_dir, &journal.tunnel)
            .ok()
            .and_then(|t| self.find_live(&t, dump).ok().flatten())
            .is_some()
    }

    /// Tear down the interface a journal describes, preferring its config path
    /// (so `wg-quick` restores routes correctly) and falling back to the bare
    /// interface name when the config is gone. Best effort.
    fn tear_down_journal(&self, journal: &Journal) {
        let target = config::resolve(&self.config_dir, &journal.tunnel)
            .ok()
            .map(|t| t.path.to_string_lossy().into_owned())
            .or_else(|| journal.interface.clone());
        if let Some(target) = target {
            let _ = self.exec(&self.wg_quick, &["down", &target]);
        }
    }

    /// DNS restore driven purely by a journal (used during reconciliation,
    /// where the config may be absent). Skips when another tunnel is still up.
    fn restore_dns_journal(&self, journal: &Journal) -> dns::GuardOutcome {
        if journal.tunnel_dns.is_empty() {
            return dns::GuardOutcome::default();
        }
        if self
            .current()
            .is_ok_and(|active| active.iter().any(|n| n != &journal.tunnel))
        {
            return dns::GuardOutcome::default();
        }
        dns::restore(
            &self.runner,
            &journal.dns_snapshot,
            &journal.tunnel_dns,
            &self.dns_sweeps,
        )
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
        self.reconcile()?;
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
            // Journal the activation (write-ahead) so a crash mid-probe
            // self-heals on the next run. Journaling is best-effort — a disk
            // hiccup must never fail a probe.
            let snapshot = self.journal_up_pending(tunnel).unwrap_or_default();
            let out = self.exec(&self.wg_quick, &["up", &path])?;
            if !out.success() {
                result.error = Some(backend_error(&self.wg_quick, &out).to_string());
                return Ok(result);
            }
            // A short lease so a killed probe self-heals: if the process dies
            // before the teardown below, reconciliation tears the tunnel down
            // once the lease passes rather than leaving it up indefinitely.
            let lease = max_time
                .saturating_mul(u64::from(count))
                .saturating_add(TRANSIENT_LEASE_BUFFER_SECS);
            let _ = state::write(
                &self.config_dir,
                &self.active_journal(tunnel, None, Some(lease), snapshot),
            );
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
            match self.teardown(tunnel, true) {
                Ok((_, guard)) => result.warning = guard.note(),
                Err(e) => {
                    result.warning = Some(format!("failed to restore tunnel state: {e}"));
                }
            }
        }
        Ok(result)
    }
}

impl<R: CommandRunner> Backend<R> {
    /// Fetch `url` through one tunnel, or through every configured tunnel when
    /// `name` is `None`, and return each location's status + headers for
    /// comparison. Each fetch uses the same activate-run-restore care as
    /// `probe`: a tunnel is brought up only if needed and restored afterwards.
    ///
    /// Per-location failures are embedded in the results; only environment
    /// errors (missing tunnel, unspawnable `wg`) return `Err`.
    pub fn diff(
        &self,
        name: Option<&str>,
        url: &str,
        max_time: u64,
    ) -> Result<Vec<diff::LocationResult>> {
        self.reconcile()?;
        let tunnels = match name {
            Some(n) => vec![config::resolve(&self.config_dir, n)?],
            None => config::discover(&self.config_dir)?,
        };
        let mut results = Vec::with_capacity(tunnels.len());
        for tunnel in &tunnels {
            results.push(self.diff_one(tunnel, url, max_time)?);
        }
        Ok(results)
    }

    /// Fetch `url` once through `tunnel` (bringing it up if needed, restoring
    /// after) and capture the response status and headers.
    fn diff_one(&self, tunnel: &Tunnel, url: &str, max_time: u64) -> Result<diff::LocationResult> {
        let dump = self.all_dump()?;
        let was_up = self.find_live(tunnel, &dump)?.is_some();
        if !was_up {
            // Short lease so a killed diff self-heals (see probe_one).
            let lease = max_time
                .saturating_mul(self.diff_retries.len() as u64)
                .saturating_add(TRANSIENT_LEASE_BUFFER_SECS);
            if let Err(e) = self.activate(tunnel, Some(lease)) {
                return Ok(diff::LocationResult {
                    name: tunnel.name.clone(),
                    ok: false,
                    status: None,
                    headers: Default::default(),
                    exit_ip: None,
                    error: Some(e.to_string()),
                });
            }
        }

        // Retry across the tunnel-settle window: a just-activated tunnel may
        // not have finished its handshake, so the first in-tunnel DNS lookup
        // can fail transiently. A tunnel that was already up gets one attempt.
        let timeout = max_time.to_string();
        let attempts = if was_up { &[0][..] } else { &self.diff_retries };
        let mut fetched = Err("no attempt made".to_string());
        for (i, delay) in attempts.iter().enumerate() {
            if i > 0 && *delay > 0 {
                std::thread::sleep(std::time::Duration::from_millis(*delay));
            }
            fetched = self.diff_fetch(url, &timeout);
            if fetched.is_ok() {
                break;
            }
        }

        if !was_up {
            let _ = self.teardown(tunnel, true);
        }

        Ok(match fetched {
            Ok(head) => diff::LocationResult {
                name: tunnel.name.clone(),
                ok: true,
                status: head.status,
                headers: head.headers,
                exit_ip: None,
                error: None,
            },
            Err(msg) => diff::LocationResult {
                name: tunnel.name.clone(),
                ok: false,
                status: None,
                headers: Default::default(),
                exit_ip: None,
                error: Some(msg),
            },
        })
    }

    /// Run one header-only `curl` and parse the status + headers.
    fn diff_fetch(&self, url: &str, timeout: &str) -> std::result::Result<diff::Head, String> {
        let write_out = format!("\n{}{}", probe::OUTPUT_MARKER, "%{http_code}");
        let args: Vec<String> = [
            "-sS",
            "-m",
            timeout,
            "-D",
            "-",
            "-o",
            "/dev/null",
            "-w",
            &write_out,
            url,
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        match self.runner.run(&self.curl, &args) {
            Err(e) => Err(format!("failed to run '{}': {e}", self.curl)),
            Ok(out) if !out.success() => {
                let msg = out.stderr.trim();
                Err(if msg.is_empty() {
                    format!("{} exited {}", self.curl, out.code.unwrap_or(-1))
                } else {
                    msg.to_string()
                })
            }
            Ok(out) => Ok(diff::parse_head(&out.stdout)),
        }
    }

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
        allow_hooks: bool,
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
        // Security gate: shell hooks run as root and are refused even under
        // --force. Only the explicit --allow-hooks opt-in installs them, so a
        // blanket --force can never smuggle a privilege-escalation vector in.
        if !summary.exec_hooks.is_empty() && !allow_hooks {
            let mut hooks = summary.exec_hooks.clone();
            hooks.dedup();
            return Err(Error::Refused(format!(
                "refusing to add '{}' — it contains shell hook(s) ({}) that wg-quick \
                 runs as root; this is a privilege-escalation risk. Remove them, or pass \
                 --allow-hooks if you fully trust this file (--force will NOT bypass this)",
                source.display(),
                hooks.join(", ")
            )));
        }
        let result = lint::lint(&name, &summary);
        // The --force gate covers ordinary lint errors. Hook errors are
        // excluded here — they are governed solely by the --allow-hooks gate
        // above — so evaluate a hook-free view for this check.
        let force_view = config::ConfSummary {
            exec_hooks: Vec::new(),
            ..summary.clone()
        };
        let force_result = lint::lint(&name, &force_view);
        if !force_result.ok && !force {
            let errors: Vec<&str> = force_result
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

/// The outcome of `vpn down`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownOutcome {
    /// `true` if this call changed state (was up, now down).
    pub changed: bool,
    /// Network services whose stale VPN DNS the guard cleared (reset to DHCP).
    pub dns_cleared: Vec<String>,
    /// Non-fatal DNS-guard problem (stale DNS seen but not cleanly cleared).
    pub dns_warning: Option<String>,
}

/// One tunnel (or interface) that reconciliation or recovery restored.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Recovered {
    /// Tunnel name, or interface name for an orphan with no journal.
    pub tunnel: String,
    /// Why it needed recovery (human-readable).
    pub reason: String,
    /// Network services whose DNS was restored/cleared.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_cleared: Vec<String>,
    /// Non-fatal DNS problem during recovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_warning: Option<String>,
}

/// The `route` binary (unprivileged; `route get` only reads the table).
const ROUTE: &str = "route";

/// Extra seconds added to a transient (probe/diff) activation's lease, so a
/// killed operation's tunnel is reconciled away shortly after it would have
/// finished rather than lingering.
const TRANSIENT_LEASE_BUFFER_SECS: u64 = 60;

/// Arguments to read the default route.
fn route_default_args() -> Vec<String> {
    ["-n", "get", "default"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// The result of `vpn verify`: whether the host network is consistent, and any
/// problems found.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct HealthReport {
    /// `true` when no issues were found.
    pub healthy: bool,
    /// Everything inconsistent about the current host state.
    pub issues: Vec<HealthIssue>,
}

/// One host-health problem.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HealthIssue {
    /// Category slug (`orphan`, `dns`).
    pub kind: &'static str,
    /// Human-readable explanation with a fix hint.
    pub detail: String,
}

/// One environment check performed by `vpn doctor`.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct Check {
    /// What was checked.
    pub name: String,
    /// Whether the check passed.
    pub ok: bool,
    /// Human-readable outcome or fix hint.
    pub detail: String,
}

fn check(name: &str, ok: bool, detail: impl Into<String>) -> Check {
    Check {
        name: name.to_string(),
        ok,
        detail: detail.into(),
    }
}

impl<R: CommandRunner> Backend<R> {
    /// Diagnose the environment: are the backend binaries reachable, does
    /// passwordless sudo work, can WireGuard state be read, and are the
    /// configs valid and private? Failures are embedded in the checks (never
    /// an `Err`) so an agent can read the full picture and fix its own setup.
    pub fn doctor(&self) -> Vec<Check> {
        let mut checks = Vec::new();

        // Binaries reachable (unprivileged).
        checks.push(self.check_version("wg", &self.wg));
        checks.push(match self.runner.run(&self.wg_quick, &[]) {
            // wg-quick with no args prints usage and exits non-zero: found.
            Ok(_) => check("wg-quick", true, format!("found ({})", self.wg_quick)),
            Err(e) => check(
                "wg-quick",
                false,
                format!(
                    "cannot run '{}': {e} — install wireguard-tools",
                    self.wg_quick
                ),
            ),
        });
        checks.push(self.check_version("curl", &self.curl));

        // Passwordless sudo, when configured.
        if self.sudo {
            let args: Vec<String> = ["-n", &self.wg, "--version"]
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            checks.push(match self.runner.run("sudo", &args) {
                Ok(out) if out.success() => check("sudo", true, "passwordless sudo works"),
                Ok(out) => check(
                    "sudo",
                    false,
                    format!(
                        "sudo -n failed: {} — add a NOPASSWD rule for {} and {}",
                        out.stderr.trim(),
                        self.wg_quick,
                        self.wg
                    ),
                ),
                Err(e) => check("sudo", false, format!("cannot run sudo: {e}")),
            });
        }

        // Live WireGuard state readable end-to-end.
        checks.push(match self.all_dump() {
            Ok(dump) => {
                let interfaces: std::collections::BTreeSet<&str> =
                    dump.iter().map(|d| d.interface.as_str()).collect();
                check(
                    "wg state",
                    true,
                    format!("readable ({} live interface(s))", interfaces.len()),
                )
            }
            Err(e) => check("wg state", false, e.to_string()),
        });

        // Configs discoverable, lint-clean, and private.
        match config::discover(&self.config_dir) {
            Err(e) => checks.push(check("config dir", false, e.to_string())),
            Ok(tunnels) => {
                checks.push(check(
                    "config dir",
                    true,
                    format!(
                        "{} tunnel(s) in {}",
                        tunnels.len(),
                        self.config_dir.display()
                    ),
                ));
                for tunnel in &tunnels {
                    checks.push(self.check_tunnel(tunnel));
                }
            }
        }
        if let Some(dns_check) = self.check_dns() {
            checks.push(dns_check);
        }
        checks
    }

    /// Flag network services pinned to any config's `DNS` servers while no
    /// tunnel is up. In that state the pinned resolver is unreachable, so
    /// name resolution is dead machine-wide until the setting is cleared —
    /// the residue of an unclean `wg-quick` teardown.
    ///
    /// `None` when not applicable: no config declares `DNS`, `networksetup`
    /// is unavailable (not macOS), or liveness cannot be determined (the
    /// `wg state` check already reports that failure).
    fn check_dns(&self) -> Option<Check> {
        let tunnels = config::discover(&self.config_dir).unwrap_or_default();
        let mut declared: Vec<String> = Vec::new();
        for tunnel in &tunnels {
            if let Ok(summary) = config::conf_summary(&tunnel.path) {
                for server in summary.dns_servers {
                    if !declared.contains(&server) {
                        declared.push(server);
                    }
                }
            }
        }
        if declared.is_empty() {
            return None;
        }
        match self.current() {
            Err(_) => None,
            Ok(active) if !active.is_empty() => Some(check(
                "dns",
                true,
                format!("VPN DNS active while up (owned by {})", active.join(", ")),
            )),
            Ok(_) => match dns::stale_services(&self.runner, &declared) {
                None => None,
                Some(stale) if stale.is_empty() => Some(check(
                    "dns",
                    true,
                    "no stale VPN DNS on any network service",
                )),
                Some(stale) => Some(check(
                    "dns",
                    false,
                    format!(
                        "stale VPN DNS pinned on {} — name resolution is broken while \
                         tunnels are down; run 'vpn down <name>' to repair, or: \
                         networksetup -setdnsservers '<service>' Empty",
                        stale.join(", ")
                    ),
                )),
            },
        }
    }

    /// Probe a binary via `--version`, unprivileged.
    fn check_version(&self, label: &str, program: &str) -> Check {
        match self.runner.run(program, &["--version".to_string()]) {
            Ok(out) if out.success() => {
                let version = out.stdout.lines().next().unwrap_or("found").trim();
                check(label, true, version)
            }
            Ok(out) => check(
                label,
                false,
                format!("'{program} --version' exited {}", out.code.unwrap_or(-1)),
            ),
            Err(e) => check(label, false, format!("cannot run '{program}': {e}")),
        }
    }

    /// Lint one config and verify its permissions are owner-only.
    fn check_tunnel(&self, tunnel: &Tunnel) -> Check {
        let name = format!("config:{}", tunnel.name);
        let result = match config::conf_summary(&tunnel.path) {
            Ok(summary) => lint::lint(&tunnel.name, &summary),
            Err(e) => return check(&name, false, e.to_string()),
        };
        if !result.ok {
            let errors: Vec<&str> = result
                .findings
                .iter()
                .filter(|f| f.severity == lint::Severity::Error)
                .map(|f| f.message.as_str())
                .collect();
            return check(&name, false, errors.join("; "));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&tunnel.path) {
                let mode = meta.permissions().mode() & 0o077;
                if mode != 0 {
                    return check(
                        &name,
                        false,
                        format!(
                            "private key readable by others (mode {:03o}) — chmod 600 '{}'",
                            meta.permissions().mode() & 0o777,
                            tunnel.path.display()
                        ),
                    );
                }
            }
        }
        let note = if result.findings.is_empty() {
            "ok".to_string()
        } else {
            format!(
                "ok ({})",
                result
                    .findings
                    .iter()
                    .map(|f| f.message.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        };
        check(&name, true, note)
    }
}

/// Rewrite a config's first-peer `AllowedIPs` to `allowed_line`, dropping
/// `DNS` lines unless `keep_dns`. Shell hooks are always dropped: the sibling
/// is written directly (bypassing `add`'s hook gate), so carrying a
/// root-executed hook forward would silently propagate a privilege-escalation
/// vector. Returns `None` if no AllowedIPs line exists.
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
        if let Some((k, _)) = line.split_once('=') {
            if config::exec_hook_name(k.trim()).is_some() {
                continue; // never propagate a root-executed hook
            }
        }
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
        self.reconcile()?;
        let tunnel = config::resolve(&self.config_dir, name)?;
        let dump = self.all_dump()?;
        let was_up = self.find_live(&tunnel, &dump)?.is_some();
        let path = tunnel.path.to_string_lossy().into_owned();

        if !was_up {
            // Journal the activation (write-ahead) so a crash while the child
            // runs still self-heals on the next `vpn` command. No extra `wg`
            // dump: exec does not need the interface name.
            let snapshot = self.journal_up_pending(&tunnel)?;
            let out = self.exec(&self.wg_quick, &["up", &path])?;
            if !out.success() {
                return Err(backend_error(&self.wg_quick, &out));
            }
            let _ = state::write(
                &self.config_dir,
                &self.active_journal(&tunnel, None, None, snapshot),
            );
        }

        let (program, args) = command.split_first().expect("clap requires a command");
        let child = self.runner.run_passthrough(program, args);

        let mut warning = None;
        if !was_up {
            match self.teardown(&tunnel, true) {
                Ok((_, guard)) => warning = guard.note(),
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
            .with_dns_sweeps(vec![0, 0])
            .with_diff_retries(vec![0])
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

        assert!(b.down("home").unwrap().changed);
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
        assert!(!b.down("home").unwrap().changed);
        assert_eq!(runner.calls().len(), 1);
    }

    /// `CONF` plus a `DNS` line, as VPN-provider configs ship it.
    const CONF_DNS: &str = "[Interface]\nPrivateKey = IFPRIV\nAddress = 10.0.0.2/32\n\
        DNS = 10.2.0.1, 2a07:b944::2:1\n\n\
        [Peer]\nPublicKey = PEERKEY\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.1:51820\n";

    const SERVICES: &str = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n";
    const NO_DNS_SET: &str = "There aren't any DNS Servers set on Wi-Fi.";

    #[test]
    fn down_repairs_poisoned_dns() {
        let cfg = fixture();
        fs::write(cfg.path().join("home.conf"), CONF_DNS).unwrap();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // live
        runner.ok(""); // wg-quick down
        runner.ok(""); // guard: current() dump — nothing up
        runner.ok(SERVICES); // sweep 1
        runner.ok("10.2.0.1"); // Wi-Fi still pinned to the tunnel's DNS
        runner.ok(""); // reset to Empty
        runner.ok(SERVICES); // sweep 2
        runner.ok(NO_DNS_SET); // clean
        let b = backend(runner.clone(), &cfg, false);

        let outcome = b.down("home").unwrap();
        assert!(outcome.changed);
        assert_eq!(outcome.dns_cleared, vec!["Wi-Fi".to_string()]);
        assert!(outcome.dns_warning.is_none());
        let reset = &runner.calls()[5];
        assert_eq!(reset.0, "networksetup");
        assert_eq!(reset.1, vec!["-setdnsservers", "Wi-Fi", "Empty"]);
    }

    #[test]
    fn down_when_already_down_still_repairs_dns() {
        // The poisoned state outlives the tunnel (crash, shutdown while up):
        // `vpn down` must repair DNS even with nothing to tear down.
        let cfg = fixture();
        fs::write(cfg.path().join("home.conf"), CONF_DNS).unwrap();
        let runner = MockRunner::new();
        runner.ok(""); // nothing live
        runner.ok(""); // guard: current() dump — nothing up
        runner.ok(SERVICES);
        runner.ok("2a07:b944::2:1"); // pinned via the IPv6 resolver
        runner.ok(""); // reset
        runner.ok(SERVICES);
        runner.ok(NO_DNS_SET);
        let b = backend(runner, &cfg, false);

        let outcome = b.down("home").unwrap();
        assert!(!outcome.changed);
        assert_eq!(outcome.dns_cleared, vec!["Wi-Fi".to_string()]);
    }

    #[test]
    fn down_guard_skipped_while_another_tunnel_is_up() {
        // A live tunnel legitimately owns the system DNS; never touch it.
        let cfg = fixture();
        fs::write(cfg.path().join("home.conf"), CONF_DNS).unwrap();
        fs::write(cfg.path().join("other.conf"), CONF_OTHER).unwrap();
        let other_dump = "utun9\tIFPRIV\tIFPUB\t51820\toff\n\
            utun9\tOTHERKEY\t(none)\t203.0.113.9:51820\t0.0.0.0/0\t1700000000\t1\t2\t25\n";
        let runner = MockRunner::new();
        runner.ok(other_dump); // home not live
        runner.ok(other_dump); // guard: current() — other is up
        let b = backend(runner.clone(), &cfg, false);

        let outcome = b.down("home").unwrap();
        assert!(!outcome.changed);
        assert!(outcome.dns_cleared.is_empty());
        assert!(runner.calls().iter().all(|(p, _)| p != "networksetup"));
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
    fn exec_restore_repairs_stale_dns_and_reports_it() {
        let cfg = fixture();
        fs::write(cfg.path().join("home.conf"), CONF_DNS).unwrap();
        let runner = MockRunner::new();
        runner.ok(""); // all_dump: down (detect)
        runner.ok(SERVICES); // capture: list services
        runner.ok(NO_DNS_SET); // capture: Wi-Fi is on DHCP pre-up
        runner.ok(""); // wg-quick up
        runner.ok(""); // child exits 0
        runner.ok(""); // wg-quick down
        runner.ok(""); // restore_dns: current() dump — nothing up
        runner.ok(""); // restore: set Wi-Fi to snapshot (Empty)
        runner.ok(SERVICES); // guard net sweep 1: list
        runner.ok(NO_DNS_SET); // guard net sweep 1: Wi-Fi clean
        runner.ok(SERVICES); // guard net sweep 2: list
        runner.ok(NO_DNS_SET); // guard net sweep 2: Wi-Fi clean
        let b = backend(runner, &cfg, false);

        let outcome = b.exec_through("home", &cmd(&["true"])).unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(
            outcome.warning.as_deref(),
            Some("cleared stale VPN DNS from Wi-Fi")
        );
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

        let (name, dest, lint) = b.add(&src, Some("proton-jp"), false, false).unwrap();
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
        assert_eq!(b.add(&good, None, false, false).unwrap().0, "jp");

        // A stem that is not a valid tunnel name needs --name.
        let bad = src_dir.path().join("has space.conf");
        fs::write(&bad, CONF).unwrap();
        assert_eq!(b.add(&bad, None, false, false).unwrap_err().exit_code(), 4);
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

        let err = b.add(&broken, None, false, false).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("routing loop"));
        // --force overrides the lint refusal.
        assert!(b.add(&broken, None, true, false).is_ok());

        // Existing destination refuses without force.
        let good = src_dir.path().join("broken2.conf");
        fs::write(&good, CONF).unwrap();
        let err = b.add(&good, Some("broken"), false, false).unwrap_err();
        assert!(err.to_string().contains("already exists"));
        assert!(b.add(&good, Some("broken"), true, false).is_ok());
    }

    /// A config carrying a root-executed shell hook (the escalation vector).
    const CONF_HOOKED: &str = "[Interface]\nPrivateKey = IFPRIV\nAddress = 10.0.0.2/32\n\
        PostUp = /bin/sh -c 'id > /tmp/pwned'\n\n\
        [Peer]\nPublicKey = PEERKEY\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.1:51820\n";

    #[test]
    fn add_refuses_shell_hooks_even_under_force() {
        let cfg = tempdir().unwrap();
        let src_dir = tempdir().unwrap();
        let src = src_dir.path().join("evil.conf");
        fs::write(&src, CONF_HOOKED).unwrap();
        let b = backend(MockRunner::new(), &cfg, false);

        // Default: refused.
        let err = b.add(&src, Some("evil"), false, false).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("PostUp"));
        assert!(err.to_string().contains("root"));
        // --force must NOT bypass the security gate.
        let err = b.add(&src, Some("evil"), true, false).unwrap_err();
        assert!(err.to_string().contains("--allow-hooks"));
        assert!(
            !cfg.path().join("evil.conf").exists(),
            "hooked config must never be installed without --allow-hooks"
        );
        // The explicit opt-in installs it.
        assert!(b.add(&src, Some("evil"), false, true).is_ok());
        assert!(cfg.path().join("evil.conf").exists());
    }

    #[test]
    fn split_strips_shell_hooks_from_the_sibling() {
        let cfg = fixture();
        fs::write(cfg.path().join("hooked.conf"), CONF_HOOKED).unwrap();
        let b = backend(MockRunner::new(), &cfg, false);
        let (_, dest, _) = b
            .split("hooked", &["100.64.0.0/10".to_string()], None, false, false)
            .unwrap();
        let text = fs::read_to_string(&dest).unwrap();
        assert!(
            !text.to_lowercase().contains("postup"),
            "the split sibling must not carry a root-executed hook forward"
        );
        // And the generated sibling passes its own hook gate on re-add.
        assert!(config::conf_summary(&dest).unwrap().exec_hooks.is_empty());
    }

    #[test]
    fn doctor_flags_installed_hooked_config() {
        let cfg = fixture();
        fs::write(cfg.path().join("home.conf"), CONF_HOOKED).unwrap();
        let runner = MockRunner::new();
        runner.ok("wireguard-tools v1.0");
        runner.ok("usage");
        runner.ok("curl 8.0");
        runner.ok(""); // wg state
        let b = backend(runner, &cfg, false);
        let cfg_check = b
            .doctor()
            .into_iter()
            .find(|c| c.name == "config:home")
            .unwrap();
        assert!(!cfg_check.ok);
        assert!(cfg_check.detail.contains("PostUp"));
    }

    #[test]
    fn add_missing_source_errors() {
        let cfg = tempdir().unwrap();
        let b = backend(MockRunner::new(), &cfg, false);
        let err = b.add(Path::new("/nonexistent/x.conf"), Some("x"), false, false);
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
    fn doctor_all_healthy() {
        let cfg = fixture();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                cfg.path().join("home.conf"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let runner = MockRunner::new();
        runner.ok("wireguard-tools v1.0.20260223\n"); // wg --version
        runner.fail(1, "Usage: wg-quick"); // wg-quick (usage exit is fine)
        runner.ok("curl 8.7.1\n"); // curl --version
        runner.ok(ALL_DUMP); // wg show all dump
        let b = backend(runner, &cfg, false);

        let checks = b.doctor();
        assert!(checks.iter().all(|c| c.ok), "all healthy: {checks:?}");
        let names: Vec<&str> = checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "wg",
                "wg-quick",
                "curl",
                "wg state",
                "config dir",
                "config:home"
            ]
        );
        assert!(checks[0].detail.contains("wireguard-tools"));
        assert!(checks[3].detail.contains("1 live interface"));
    }

    #[test]
    fn doctor_flags_stale_dns_when_no_tunnel_up() {
        let cfg = fixture();
        fs::write(cfg.path().join("home.conf"), CONF_DNS).unwrap();
        let runner = MockRunner::new();
        runner.ok("wireguard-tools v1.0"); // wg --version
        runner.ok("usage"); // wg-quick
        runner.ok("curl 8.0"); // curl --version
        runner.ok(""); // wg state dump — nothing up
        runner.ok(""); // check_dns: current() dump
        runner.ok(SERVICES);
        runner.ok("10.2.0.1"); // Wi-Fi pinned, nothing up: broken
        let b = backend(runner, &cfg, false);

        let dns = b.doctor().into_iter().find(|c| c.name == "dns").unwrap();
        assert!(!dns.ok);
        assert!(dns.detail.contains("Wi-Fi"));
        assert!(dns.detail.contains("vpn down"));
    }

    #[test]
    fn doctor_dns_ok_while_a_tunnel_is_up() {
        let cfg = fixture();
        fs::write(cfg.path().join("home.conf"), CONF_DNS).unwrap();
        let runner = MockRunner::new();
        runner.ok("wireguard-tools v1.0");
        runner.ok("usage");
        runner.ok("curl 8.0");
        runner.ok(ALL_DUMP); // wg state dump — home is up
        runner.ok(ALL_DUMP); // check_dns: current() dump
        let b = backend(runner, &cfg, false);

        let dns = b.doctor().into_iter().find(|c| c.name == "dns").unwrap();
        assert!(dns.ok);
        assert!(dns.detail.contains("home"));
    }

    #[test]
    fn doctor_has_no_dns_check_without_dns_configs() {
        let cfg = fixture(); // CONF declares no DNS
        let b = backend(MockRunner::new(), &cfg, false);
        assert!(b.doctor().iter().all(|c| c.name != "dns"));
    }

    #[test]
    fn doctor_reports_missing_binaries_and_sudo() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.spawn_err(); // wg missing
        runner.spawn_err(); // wg-quick missing
        runner.ok("curl 8.7.1\n"); // curl fine
        runner.fail(1, "sudo: a password is required"); // sudo -n fails
        runner.fail(1, "denied"); // all_dump via sudo fails
        let b = backend(runner.clone(), &cfg, true);

        let checks = b.doctor();
        let by_name = |n: &str| checks.iter().find(|c| c.name == n).unwrap();
        assert!(!by_name("wg").ok);
        assert!(!by_name("wg-quick").ok);
        assert!(by_name("wg-quick").detail.contains("wireguard-tools"));
        assert!(by_name("curl").ok);
        assert!(!by_name("sudo").ok);
        assert!(by_name("sudo").detail.contains("NOPASSWD"));
        assert!(!by_name("wg state").ok);
        assert!(by_name("config dir").ok);
        // sudo check went through `sudo -n`.
        assert!(runner
            .calls()
            .iter()
            .any(|(p, a)| p == "sudo" && a[0] == "-n"));
    }

    #[test]
    fn doctor_flags_broken_configs_and_loose_permissions() {
        let cfg = fixture();
        fs::write(
            cfg.path().join("loop.conf"),
            "[Interface]\nPrivateKey = P\n[Peer]\nPublicKey = K\n\
             AllowedIPs = 64.0.0.0/3\nEndpoint = 79.127.160.216:51820\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                cfg.path().join("home.conf"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        let runner = MockRunner::new();
        runner.ok("wg v1\n");
        runner.fail(1, "usage");
        runner.ok("curl 8\n");
        runner.ok(ALL_DUMP);
        let b = backend(runner, &cfg, false);

        let checks = b.doctor();
        let by_name = |n: &str| checks.iter().find(|c| c.name == n).unwrap();
        #[cfg(unix)]
        {
            assert!(!by_name("config:home").ok);
            assert!(by_name("config:home").detail.contains("chmod 600"));
        }
        assert!(!by_name("config:loop").ok);
        assert!(by_name("config:loop").detail.contains("routing loop"));
    }

    #[test]
    fn split_rejects_hostname_endpoint() {
        let cfg = tempdir().unwrap();
        fs::write(
            cfg.path().join("host.conf"),
            "[Interface]\nPrivateKey = P\n[Peer]\nPublicKey = K\n\
             AllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:51820\n",
        )
        .unwrap();
        let b = backend(MockRunner::new(), &cfg, false);
        let err = b.split("host", &[], None, false, false).unwrap_err();
        assert!(err.to_string().contains("not an IPv4 address"));
    }

    #[test]
    fn exec_restore_spawn_failure_becomes_warning() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // down
        runner.ok(""); // up
        runner.ok(""); // child ok
        runner.spawn_err(); // restore cannot launch wg-quick
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
    fn doctor_handles_sudo_spawn_error_and_version_failures() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.fail(127, ""); // wg --version exits non-zero
        runner.fail(1, "usage"); // wg-quick found
        runner.ok("curl 8\n"); // curl fine
        runner.spawn_err(); // sudo itself missing
        runner.ok(ALL_DUMP); // dump
        let b = backend(runner, &cfg, true);

        let checks = b.doctor();
        let by_name = |n: &str| checks.iter().find(|c| c.name == n).unwrap();
        assert!(!by_name("wg").ok);
        assert!(by_name("wg").detail.contains("exited 127"));
        assert!(!by_name("sudo").ok);
        assert!(by_name("sudo").detail.contains("cannot run sudo"));
    }

    #[test]
    fn doctor_reports_unreadable_config_dir() {
        // config_dir whose parent is a regular file cannot be read.
        let dir = tempdir().unwrap();
        let file = dir.path().join("iamafile");
        fs::write(&file, "x").unwrap();
        let runner = MockRunner::new();
        runner.ok("wg v1\n");
        runner.fail(1, "usage");
        runner.ok("curl 8\n");
        runner.ok("");
        let b = Backend::new(runner, file.join("sub"), false);

        let checks = b.doctor();
        let dir_check = checks.iter().find(|c| c.name == "config dir").unwrap();
        assert!(!dir_check.ok);
    }

    #[test]
    #[cfg(unix)]
    fn doctor_reports_unreadable_config_file() {
        use std::os::unix::fs::PermissionsExt;
        let cfg = fixture();
        fs::set_permissions(
            cfg.path().join("home.conf"),
            fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        let runner = MockRunner::new();
        runner.ok("wg v1\n");
        runner.fail(1, "usage");
        runner.ok("curl 8\n");
        runner.ok("");
        let b = backend(runner, &cfg, false);

        let checks = b.doctor();
        let conf = checks.iter().find(|c| c.name == "config:home").unwrap();
        assert!(!conf.ok);
        // Restore perms so TempDir cleanup works everywhere.
        fs::set_permissions(
            cfg.path().join("home.conf"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }

    #[test]
    fn doctor_notes_warnings_on_passing_configs() {
        let cfg = tempdir().unwrap();
        fs::write(
            cfg.path().join("srv.conf"),
            "[Interface]\nPrivateKey = P\n[Peer]\nPublicKey = K\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                cfg.path().join("srv.conf"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let runner = MockRunner::new();
        runner.ok("wg v1\n");
        runner.fail(1, "usage");
        runner.ok("curl 8\n");
        runner.ok("");
        let b = backend(runner, &cfg, false);

        let checks = b.doctor();
        let conf = checks.iter().find(|c| c.name == "config:srv").unwrap();
        assert!(conf.ok, "warnings don't fail doctor");
        assert!(conf.detail.contains("no Endpoint"));
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

    // ---- Journaled state, reconciliation, recovery, and leases ----

    use std::collections::BTreeMap;

    fn dns_journal(tunnel: &str, phase: Phase) -> Journal {
        Journal {
            tunnel: tunnel.to_string(),
            phase,
            interface: Some("utun7".to_string()),
            lease_deadline: None,
            dns_snapshot: BTreeMap::from([("Wi-Fi".to_string(), Vec::new())]),
            tunnel_dns: vec!["10.2.0.1".to_string(), "2a07:b944::2:1".to_string()],
        }
    }

    #[test]
    fn up_records_active_journal_with_lease_deadline() {
        let cfg = fixture(); // home.conf = CONF (no DNS)
        let runner = MockRunner::new();
        runner.ok(""); // all_dump: down (detect)
        runner.ok(""); // wg-quick up
        runner.ok(ALL_DUMP); // post-up dump: resolves utun7
        let b = backend(runner, &cfg, false).with_fixed_time(1000);

        let (changed, _status) = b.up_with_lease("home", Some(1800)).unwrap();
        assert!(changed);
        let journal = state::read(cfg.path(), "home").expect("journal written");
        assert_eq!(journal.phase, Phase::Active);
        assert_eq!(journal.interface.as_deref(), Some("utun7"));
        assert_eq!(journal.lease_deadline, Some(2800));
    }

    #[test]
    fn down_restores_custom_dns_from_journal_snapshot() {
        let cfg = fixture();
        fs::write(cfg.path().join("home.conf"), CONF_DNS).unwrap();
        // Journal says the real pre-tunnel DNS was a custom 9.9.9.9.
        let mut j = dns_journal("home", Phase::Active);
        j.dns_snapshot = BTreeMap::from([("Wi-Fi".to_string(), vec!["9.9.9.9".to_string()])]);
        state::write(cfg.path(), &j).unwrap();

        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // reconcile: all_dump (journal healthy → untouched)
        runner.ok(ALL_DUMP); // down: all_dump (find live)
        runner.ok(""); // wg-quick down
        runner.ok(""); // restore_dns: current() dump — nothing up
        runner.ok(""); // restore: set Wi-Fi to 9.9.9.9
        runner.ok(SERVICES); // guard net sweep 1: list
        runner.ok("9.9.9.9"); // sweep 1: Wi-Fi (custom, not poison → clean)
        runner.ok(SERVICES); // guard net sweep 2: list
        runner.ok("9.9.9.9"); // sweep 2
        let b = backend(runner.clone(), &cfg, false);

        let outcome = b.down("home").unwrap();
        assert!(outcome.changed);
        assert_eq!(outcome.dns_cleared, vec!["Wi-Fi".to_string()]);
        // The restore reapplied the CUSTOM DNS, not Empty.
        let set = runner
            .calls()
            .into_iter()
            .find(|(_, a)| a.first().map(String::as_str) == Some("-setdnsservers"))
            .unwrap();
        assert_eq!(set.1, vec!["-setdnsservers", "Wi-Fi", "9.9.9.9"]);
        assert!(state::read(cfg.path(), "home").is_none(), "journal cleared");
    }

    #[test]
    fn reconcile_is_a_noop_with_no_journals() {
        let cfg = fixture();
        let runner = MockRunner::new();
        let b = backend(runner.clone(), &cfg, false);
        assert!(b.reconcile().unwrap().is_empty());
        assert!(runner.calls().is_empty(), "idle reconcile makes no calls");
    }

    #[test]
    fn reconcile_heals_crashed_up_pending_and_restores_dns() {
        let cfg = fixture();
        fs::write(cfg.path().join("home.conf"), CONF_DNS).unwrap();
        // Crash during `up`: interface never came live.
        let mut j = dns_journal("home", Phase::UpPending);
        j.interface = None;
        state::write(cfg.path(), &j).unwrap();

        let runner = MockRunner::new();
        runner.ok(""); // reconcile: all_dump — nothing live
        runner.ok(""); // restore_dns: current() dump — nothing up
        runner.ok(""); // restore: set Wi-Fi (snapshot Empty)
        runner.ok(SERVICES); // guard sweep 1 list
        runner.ok(NO_DNS_SET); // sweep 1 clean
        runner.ok(SERVICES); // guard sweep 2 list
        runner.ok(NO_DNS_SET); // sweep 2 clean
        let b = backend(runner, &cfg, false);

        let recovered = b.reconcile().unwrap();
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].reason.contains("bringing the tunnel up"));
        assert_eq!(recovered[0].dns_cleared, vec!["Wi-Fi".to_string()]);
        assert!(state::read(cfg.path(), "home").is_none());
    }

    #[test]
    fn reconcile_tears_down_expired_lease() {
        let cfg = fixture(); // CONF, no DNS
        let mut j = Journal {
            tunnel: "home".to_string(),
            phase: Phase::Active,
            interface: Some("utun7".to_string()),
            lease_deadline: Some(500),
            dns_snapshot: BTreeMap::new(),
            tunnel_dns: Vec::new(),
        };
        j.lease_deadline = Some(500);
        state::write(cfg.path(), &j).unwrap();

        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // reconcile: all_dump — utun7 live
        runner.ok(""); // wg-quick down (lease expired)
        let b = backend(runner.clone(), &cfg, false).with_fixed_time(1000);

        let recovered = b.reconcile().unwrap();
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].reason.contains("lease expired"));
        let downs: Vec<_> = runner
            .calls()
            .into_iter()
            .filter(|(_, a)| a.first().map(String::as_str) == Some("down"))
            .collect();
        assert_eq!(downs.len(), 1, "expired tunnel torn down");
        assert!(state::read(cfg.path(), "home").is_none());
    }

    #[test]
    fn reconcile_leaves_healthy_active_tunnel_untouched() {
        let cfg = fixture();
        let j = Journal {
            tunnel: "home".to_string(),
            phase: Phase::Active,
            interface: Some("utun7".to_string()),
            lease_deadline: Some(9999),
            dns_snapshot: BTreeMap::new(),
            tunnel_dns: Vec::new(),
        };
        state::write(cfg.path(), &j).unwrap();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // reconcile: all_dump — utun7 live, within lease
        let b = backend(runner.clone(), &cfg, false).with_fixed_time(1000);

        assert!(b.reconcile().unwrap().is_empty());
        assert!(state::read(cfg.path(), "home").is_some(), "journal kept");
        assert!(runner
            .calls()
            .iter()
            .all(|(_, a)| a.first().map(String::as_str) != Some("down")));
    }

    #[test]
    fn recover_tears_down_orphan_via_config_path() {
        let cfg = fixture(); // home.conf = CONF matches ALL_DUMP's utun7
        let runner = MockRunner::new();
        // recover -> reconcile (no journals, no calls) -> its own all_dump.
        runner.ok(ALL_DUMP); // recover: all_dump — utun7 live, unclaimed
        runner.ok(""); // wg-quick down <home.conf path>
        let b = backend(runner.clone(), &cfg, false);

        let recovered = b.recover().unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(
            recovered[0].tunnel, "home",
            "mapped orphan iface to its config"
        );
        assert!(recovered[0].reason.contains("torn down"));
        // Torn down by the config PATH (wg-quick rejects a bare interface on macOS).
        let down = runner
            .calls()
            .into_iter()
            .find(|(_, a)| a.first().map(String::as_str) == Some("down"))
            .unwrap();
        assert!(
            down.1[1].ends_with("home.conf"),
            "used config path: {:?}",
            down.1
        );
    }

    #[test]
    fn recover_reports_orphan_with_no_matching_config() {
        let cfg = tempdir().unwrap(); // no configs at all
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // recover: all_dump — utun7 live, no config matches
        let b = backend(runner.clone(), &cfg, false);

        let recovered = b.recover().unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].tunnel, "utun7");
        assert!(recovered[0].reason.contains("no matching config"));
        // Nothing was torn down (we cannot safely).
        assert!(runner
            .calls()
            .iter()
            .all(|(_, a)| a.first().map(String::as_str) != Some("down")));
    }

    #[test]
    fn recover_is_clean_when_nothing_is_wrong() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(""); // recover: all_dump — nothing live
        let b = backend(runner, &cfg, false);
        assert!(b.recover().unwrap().is_empty());
    }

    // ---- vpn verify (host-health assertion) ----

    const ROUTE_HOME: &str = "   route to: default\ngateway: 172.20.0.1\n  interface: en0\n";
    // A live WireGuard interface whose peer no config matches → an orphan.
    const ORPHAN_DUMP: &str = "utun9\tIF\tIFP\t51820\toff\n\
        utun9\tORPHANKEY\t(none)\t203.0.113.9:51820\t0.0.0.0/0\t1700000000\t1\t2\t25\n";

    #[test]
    fn verify_healthy_on_clean_host() {
        let cfg = fixture(); // home.conf = CONF (no DNS)
        let runner = MockRunner::new();
        runner.ok(""); // verify: all_dump — nothing live
        runner.ok(ROUTE_HOME); // route -n get default
        runner.ok(""); // current(): all_dump — nothing up
        let b = backend(runner, &cfg, false);
        let health = b.verify().unwrap();
        assert!(health.healthy);
        assert!(health.issues.is_empty());
    }

    #[test]
    fn verify_flags_orphan_interface_holding_the_route() {
        let cfg = fixture(); // only home.conf (PEERKEY); utun9/ORPHANKEY matches nothing
        let runner = MockRunner::new();
        runner.ok(ORPHAN_DUMP); // verify: all_dump — utun9 live, unmatched
        runner.ok("  interface: utun9\n"); // default route is via the orphan
        runner.ok(ORPHAN_DUMP); // current(): all_dump (no config matches → empty)
        let b = backend(runner, &cfg, false);
        let health = b.verify().unwrap();
        assert!(!health.healthy);
        assert_eq!(health.issues.len(), 1);
        assert_eq!(health.issues[0].kind, "orphan");
        assert!(health.issues[0].detail.contains("utun9"));
        assert!(health.issues[0].detail.contains("default route"));
    }

    #[test]
    fn verify_flags_stale_dns_with_nothing_up() {
        let cfg = fixture();
        fs::write(cfg.path().join("home.conf"), CONF_DNS).unwrap();
        let runner = MockRunner::new();
        runner.ok(""); // verify: all_dump — nothing live
        runner.ok(ROUTE_HOME); // route home (fine)
        runner.ok(""); // current(): all_dump — nothing up
        runner.ok(SERVICES); // stale_services: list
        runner.ok("10.2.0.1"); // Wi-Fi pinned to the tunnel resolver
        let b = backend(runner, &cfg, false);
        let health = b.verify().unwrap();
        assert!(!health.healthy);
        assert_eq!(health.issues[0].kind, "dns");
        assert!(health.issues[0].detail.contains("Wi-Fi"));
    }

    // ---- vpn diff (cross-location response comparison) ----

    #[test]
    fn diff_one_fetches_headers_and_restores() {
        let cfg = fixture(); // home.conf = CONF (no DNS)
        let header_out = format!(
            "HTTP/2 200 \ncf-cache-status: HIT\ncontent-type: text/html\n\n{}200",
            probe::OUTPUT_MARKER
        );
        let runner = MockRunner::new();
        runner.ok(""); // diff_one: all_dump (detect, down)
        runner.ok(""); // activate: wg-quick up
        runner.ok(ALL_DUMP); // activate: all_dump (interface)
        runner.ok(&header_out); // diff_fetch: curl headers
        runner.ok(""); // teardown: wg-quick down
        let b = backend(runner.clone(), &cfg, false);

        let results = b.diff(Some("home"), "https://x.example", 10).unwrap();
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert!(r.ok);
        assert_eq!(r.status, Some(200));
        assert_eq!(r.headers.get("cf-cache-status").unwrap(), "HIT");
        // Tunnel state was restored (a wg-quick down ran).
        assert!(runner
            .calls()
            .iter()
            .any(|(_, a)| a.first().map(String::as_str) == Some("down")));
        // curl fetched headers only (no body), through the tunnel.
        let curl = runner
            .calls()
            .into_iter()
            .find(|(p, _)| p == "curl")
            .unwrap();
        assert!(curl.1.contains(&"-D".to_string()) && curl.1.contains(&"-".to_string()));
        assert_eq!(curl.1.last().unwrap(), "https://x.example");
    }

    #[test]
    fn diff_records_fetch_failure_per_location() {
        let cfg = fixture();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // diff_one: all_dump — already up (no activate/teardown)
        runner.fail(28, "curl: (28) timeout"); // curl fails
        let b = backend(runner, &cfg, false);
        let results = b.diff(Some("home"), "https://x.example", 5).unwrap();
        assert!(!results[0].ok);
        assert!(results[0].error.as_deref().unwrap().contains("timeout"));
    }

    #[test]
    fn verify_healthy_when_a_tunnel_is_legitimately_up() {
        let cfg = fixture();
        fs::write(cfg.path().join("home.conf"), CONF_DNS).unwrap();
        let runner = MockRunner::new();
        runner.ok(ALL_DUMP); // verify: all_dump — home live on utun7
        runner.ok(ROUTE_HOME); // route (irrelevant; tunnel owns DNS)
        runner.ok(ALL_DUMP); // current(): home is up → active non-empty
        let b = backend(runner, &cfg, false);
        // utun7 matches home's config, and a tunnel is up, so DNS is owned.
        let health = b.verify().unwrap();
        assert!(health.healthy, "issues: {:?}", health.issues);
    }

    #[test]
    fn up_reconciles_a_crashed_tunnel_before_activating() {
        let cfg = fixture(); // home.conf = CONF (no DNS)
                             // A different tunnel crashed mid-up and left a stale journal.
        let mut stale = dns_journal("ghost", Phase::UpPending);
        stale.interface = None;
        stale.tunnel_dns = Vec::new(); // no DNS work during its recovery
        stale.dns_snapshot = BTreeMap::new();
        state::write(cfg.path(), &stale).unwrap();

        let runner = MockRunner::new();
        runner.ok(""); // reconcile: all_dump — nothing live (ghost gone)
        runner.ok(""); // up: all_dump (detect home down)
        runner.ok(""); // wg-quick up home
        runner.ok(ALL_DUMP); // post-up dump
        let b = backend(runner, &cfg, false);

        let (changed, _) = b.up("home").unwrap();
        assert!(changed);
        // The stale journal was reconciled away.
        assert!(state::read(cfg.path(), "ghost").is_none());
        assert!(state::read(cfg.path(), "home").is_some());
    }
}
