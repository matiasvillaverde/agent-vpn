//! Self-healing for stale VPN DNS left behind by `wg-quick` on macOS.
//!
//! On macOS, `wg-quick up` stamps the tunnel's `DNS` servers onto every
//! network service with `networksetup`, remembering the previous values only
//! in the memory of a backgrounded monitor process. If that process dies
//! without restoring them (system shutdown, SIGKILL, crash) — or if another
//! tunnel comes up before the asynchronous restore fires — the tunnel's
//! VPN-internal resolver stays pinned as the system DNS. With no tunnel up
//! that resolver is unreachable, so every lookup fails and the machine looks
//! offline. Worse, the next `up` snapshots the stale value as the "original",
//! so `wg-quick`'s own restore perpetuates the damage forever.
//!
//! [`guard`] runs after a tunnel goes down: any network service whose static
//! DNS still contains one of the tunnel's own `DNS` servers is reset to
//! `Empty` (back to DHCP). Because `wg-quick`'s restore is asynchronous, the
//! guard sweeps several times, trusting the result only after two consecutive
//! clean sweeps. On systems without `networksetup` (anything but macOS) the
//! guard is a no-op.

use std::collections::BTreeSet;

use crate::runner::CommandRunner;

/// The `networksetup` binary; resolved via `PATH` (it lives in
/// `/usr/sbin`, which is always on the default path). Runs unprivileged —
/// admin users may change DNS settings without sudo.
const NETWORKSETUP: &str = "networksetup";

/// Delays (ms) before each verification sweep after a teardown. The spacing
/// exists to outlast `wg-quick`'s monitor daemon, which restores its (possibly
/// poisoned) DNS snapshot asynchronously after the interface disappears.
pub const SWEEP_DELAYS_MS: &[u64] = &[0, 400, 1200, 2500];

/// What the DNS guard did. Both fields empty means nothing was wrong.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuardOutcome {
    /// Network services whose stale VPN DNS was cleared (reset to DHCP).
    pub cleared: Vec<String>,
    /// Non-fatal problem: stale DNS was seen but could not be cleared, or
    /// kept reappearing past the final sweep.
    pub warning: Option<String>,
}

impl GuardOutcome {
    /// A one-line human note about what happened, if anything did.
    #[must_use]
    pub fn note(&self) -> Option<String> {
        let mut parts = Vec::new();
        if !self.cleared.is_empty() {
            parts.push(format!(
                "cleared stale VPN DNS from {}",
                self.cleared.join(", ")
            ));
        }
        if let Some(warning) = &self.warning {
            parts.push(warning.clone());
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("; "))
        }
    }
}

/// The list of configurable network services, in `networksetup` order.
/// `None` when `networksetup` cannot run (not macOS).
fn list_services<R: CommandRunner>(runner: &R) -> Option<Vec<String>> {
    let list = runner
        .run(NETWORKSETUP, &["-listallnetworkservices".to_string()])
        .ok()?;
    if !list.success() {
        return None;
    }
    // The first line is a legend ("An asterisk (*) denotes ..."); a leading
    // '*' marks a disabled service, which still carries DNS settings.
    Some(
        list.stdout
            .lines()
            .skip(1)
            .map(|raw| raw.trim().trim_start_matches('*').trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

/// The static DNS servers currently set on `service` (empty = DHCP).
/// `None` when the query itself could not run.
fn service_dns<R: CommandRunner>(runner: &R, service: &str) -> Option<Vec<String>> {
    let out = runner
        .run(
            NETWORKSETUP,
            &["-getdnsservers".to_string(), service.to_string()],
        )
        .ok()?;
    // Output is one server per line, or a sentence ("There aren't any DNS
    // Servers set on ...") — server lines carry no whitespace.
    Some(
        out.stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.contains(char::is_whitespace))
            .map(str::to_string)
            .collect(),
    )
}

/// Network services whose static DNS currently contains one of `tunnel_dns`.
///
/// Returns `None` when `networksetup` cannot run (not macOS) — the caller
/// should treat the check as not applicable.
pub fn stale_services<R: CommandRunner>(runner: &R, tunnel_dns: &[String]) -> Option<Vec<String>> {
    let services = list_services(runner)?;
    let mut stale = Vec::new();
    for service in services {
        let servers = service_dns(runner, &service)?;
        if servers.iter().any(|s| tunnel_dns.contains(s)) {
            stale.push(service);
        }
    }
    Some(stale)
}

/// Snapshot each service's current DNS, **sanitized**: any server equal to a
/// `tunnel_dns` entry is dropped. Taking the snapshot from an already-poisoned
/// system therefore still yields a clean baseline (an empty list = DHCP), so
/// restoring it can never re-pin the tunnel's resolver.
///
/// `None` when `networksetup` is unavailable.
pub fn capture<R: CommandRunner>(
    runner: &R,
    tunnel_dns: &[String],
) -> Option<std::collections::BTreeMap<String, Vec<String>>> {
    let services = list_services(runner)?;
    let mut snapshot = std::collections::BTreeMap::new();
    for service in services {
        let servers = service_dns(runner, &service)?;
        let clean: Vec<String> = servers
            .into_iter()
            .filter(|s| !tunnel_dns.contains(s))
            .collect();
        snapshot.insert(service, clean);
    }
    Some(snapshot)
}

/// Restore each service in `snapshot` to its recorded DNS (an empty list resets
/// it to DHCP), then run [`guard`] to verify no tunnel resolver lingers — this
/// mops up asynchronous re-stamps by `wg-quick`'s monitor and any service
/// outside the snapshot. Returns the combined outcome.
pub fn restore<R: CommandRunner>(
    runner: &R,
    snapshot: &std::collections::BTreeMap<String, Vec<String>>,
    tunnel_dns: &[String],
    sweep_delays_ms: &[u64],
) -> GuardOutcome {
    let mut restored: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut warning = None;
    for (service, servers) in snapshot {
        let mut args = vec!["-setdnsservers".to_string(), service.clone()];
        if servers.is_empty() {
            args.push("Empty".to_string());
        } else {
            args.extend(servers.iter().cloned());
        }
        let ok = runner
            .run(NETWORKSETUP, &args)
            .map(|out| out.success())
            .unwrap_or(false);
        if ok {
            restored.insert(service.clone());
        } else {
            warning = Some(format!(
                "could not restore DNS on '{service}' — run: networksetup -setdnsservers '{service}' {}",
                if servers.is_empty() { "Empty".to_string() } else { servers.join(" ") }
            ));
        }
    }
    // Safety net: clear any residual poison the snapshot pass did not cover.
    let mut outcome = guard(runner, tunnel_dns, sweep_delays_ms);
    for service in restored {
        if !outcome.cleared.contains(&service) {
            outcome.cleared.push(service);
        }
    }
    outcome.cleared.sort();
    outcome.cleared.dedup();
    if outcome.warning.is_none() {
        outcome.warning = warning;
    }
    outcome
}

/// Reset any service still pinned to `tunnel_dns` back to DHCP, sweeping on
/// the given delay schedule until two consecutive sweeps come back clean.
///
/// Never fails: problems are embedded in the outcome so teardown paths can
/// report them without aborting.
pub fn guard<R: CommandRunner>(
    runner: &R,
    tunnel_dns: &[String],
    sweep_delays_ms: &[u64],
) -> GuardOutcome {
    let mut outcome = GuardOutcome::default();
    if tunnel_dns.is_empty() {
        return outcome;
    }
    let mut cleared: BTreeSet<String> = BTreeSet::new();
    let mut previous_clean = false;
    let mut dirty = false;
    for delay in sweep_delays_ms {
        if *delay > 0 {
            std::thread::sleep(std::time::Duration::from_millis(*delay));
        }
        let Some(stale) = stale_services(runner, tunnel_dns) else {
            return outcome; // no networksetup — nothing to guard
        };
        dirty = !stale.is_empty();
        if !dirty {
            if previous_clean {
                break; // verified: two consecutive clean sweeps
            }
            previous_clean = true;
            continue;
        }
        previous_clean = false;
        for service in stale {
            let reset = runner
                .run(
                    NETWORKSETUP,
                    &[
                        "-setdnsservers".to_string(),
                        service.clone(),
                        "Empty".to_string(),
                    ],
                )
                .map(|out| out.success())
                .unwrap_or(false);
            if reset {
                cleared.insert(service);
            } else {
                outcome.warning = Some(format!(
                    "could not reset DNS on '{service}' — run: networksetup -setdnsservers '{service}' Empty"
                ));
            }
        }
    }
    if dirty && outcome.warning.is_none() {
        outcome.warning = Some(
            "stale VPN DNS kept reappearing after the final sweep — \
             a lingering wg-quick monitor may still be restoring it; \
             re-run `vpn down` to repair"
                .to_string(),
        );
    }
    outcome.cleared = cleared.into_iter().collect();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::MockRunner;

    const LEGEND: &str = "An asterisk (*) denotes that a network service is disabled.";

    fn dns() -> Vec<String> {
        vec!["10.2.0.1".to_string(), "2a07:b944::2:1".to_string()]
    }

    #[test]
    fn stale_services_matches_only_pinned_services() {
        let mock = MockRunner::new();
        mock.ok(&format!(
            "{LEGEND}\nWi-Fi\n*Thunderbolt Bridge\niPhone USB\n"
        ));
        mock.ok("10.2.0.1\n2a07:b944::2:1"); // Wi-Fi: pinned
        mock.ok("There aren't any DNS Servers set on Thunderbolt Bridge."); // clean
        mock.ok("1.1.1.1"); // custom, unrelated DNS: untouched
        let stale = stale_services(&mock, &dns()).unwrap();
        assert_eq!(stale, vec!["Wi-Fi".to_string()]);
    }

    #[test]
    fn stale_services_none_without_networksetup() {
        let mock = MockRunner::new();
        mock.spawn_err();
        assert_eq!(stale_services(&mock, &dns()), None);
        mock.fail(1, "unknown command");
        assert_eq!(stale_services(&mock, &dns()), None);
    }

    #[test]
    fn guard_clears_stale_and_verifies_clean() {
        let mock = MockRunner::new();
        // Sweep 1: Wi-Fi pinned -> cleared.
        mock.ok(&format!("{LEGEND}\nWi-Fi\n"));
        mock.ok("10.2.0.1");
        mock.ok(""); // setdnsservers Empty
                     // Sweeps 2 and 3: clean twice -> verified, stop early.
        mock.ok(&format!("{LEGEND}\nWi-Fi\n"));
        mock.ok("There aren't any DNS Servers set on Wi-Fi.");
        mock.ok(&format!("{LEGEND}\nWi-Fi\n"));
        mock.ok("There aren't any DNS Servers set on Wi-Fi.");
        let outcome = guard(&mock, &dns(), &[0, 0, 0, 0]);
        assert_eq!(outcome.cleared, vec!["Wi-Fi".to_string()]);
        assert!(outcome.warning.is_none());
        // Early exit: the 4th sweep never ran.
        assert_eq!(mock.calls().len(), 7);
        assert_eq!(outcome.note().unwrap(), "cleared stale VPN DNS from Wi-Fi");
    }

    #[test]
    fn guard_reclears_when_daemon_restamps_between_sweeps() {
        let mock = MockRunner::new();
        // Sweep 1: clean (daemon has not restored yet).
        mock.ok(&format!("{LEGEND}\nWi-Fi\n"));
        mock.ok("There aren't any DNS Servers set on Wi-Fi.");
        // Sweep 2: daemon restored the poisoned snapshot -> clear it.
        mock.ok(&format!("{LEGEND}\nWi-Fi\n"));
        mock.ok("10.2.0.1");
        mock.ok("");
        // Sweeps 3 and 4: clean twice.
        mock.ok(&format!("{LEGEND}\nWi-Fi\n"));
        mock.ok("There aren't any DNS Servers set on Wi-Fi.");
        mock.ok(&format!("{LEGEND}\nWi-Fi\n"));
        mock.ok("There aren't any DNS Servers set on Wi-Fi.");
        let outcome = guard(&mock, &dns(), &[0, 0, 0, 0]);
        assert_eq!(outcome.cleared, vec!["Wi-Fi".to_string()]);
        assert!(outcome.warning.is_none());
    }

    #[test]
    fn guard_warns_when_still_dirty_after_final_sweep() {
        let mock = MockRunner::new();
        for _ in 0..2 {
            mock.ok(&format!("{LEGEND}\nWi-Fi\n"));
            mock.ok("10.2.0.1");
            mock.ok(""); // reset succeeds but poison returns
        }
        let outcome = guard(&mock, &dns(), &[0, 0]);
        assert_eq!(outcome.cleared, vec!["Wi-Fi".to_string()]);
        assert!(outcome.warning.unwrap().contains("kept reappearing"));
    }

    #[test]
    fn guard_warns_when_reset_fails() {
        let mock = MockRunner::new();
        mock.ok(&format!("{LEGEND}\nWi-Fi\n"));
        mock.ok("10.2.0.1");
        mock.fail(1, "not an admin user");
        let outcome = guard(&mock, &dns(), &[0]);
        assert!(outcome.cleared.is_empty());
        let note = outcome.note().unwrap();
        assert!(note.contains("could not reset DNS on 'Wi-Fi'"));
    }

    #[test]
    fn capture_sanitizes_poison_and_keeps_custom_dns() {
        let mock = MockRunner::new();
        mock.ok(&format!("{LEGEND}\nWi-Fi\nEthernet\nStale\n"));
        mock.ok("9.9.9.9\n149.112.112.112"); // Wi-Fi: real custom DNS, kept
        mock.ok("There aren't any DNS Servers set on Ethernet."); // DHCP
        mock.ok("10.2.0.1\n9.9.9.9"); // Stale: poison stripped, custom kept
        let snap = capture(&mock, &dns()).unwrap();
        assert_eq!(snap["Wi-Fi"], vec!["9.9.9.9", "149.112.112.112"]);
        assert!(snap["Ethernet"].is_empty());
        assert_eq!(snap["Stale"], vec!["9.9.9.9"], "tunnel DNS filtered out");
    }

    #[test]
    fn capture_none_without_networksetup() {
        let mock = MockRunner::new();
        mock.spawn_err();
        assert!(capture(&mock, &dns()).is_none());
    }

    #[test]
    fn restore_reapplies_snapshot_and_verifies_clean() {
        use std::collections::BTreeMap;
        let snapshot = BTreeMap::from([
            ("Wi-Fi".to_string(), vec!["9.9.9.9".to_string()]),
            ("Ethernet".to_string(), Vec::new()),
        ]);
        let mock = MockRunner::new();
        mock.ok(""); // set Wi-Fi 9.9.9.9
        mock.ok(""); // set Ethernet Empty
                     // guard() safety net: one clean sweep pair.
        mock.ok(&format!("{LEGEND}\nWi-Fi\nEthernet\n"));
        mock.ok("9.9.9.9");
        mock.ok("There aren't any DNS Servers set on Ethernet.");
        mock.ok(&format!("{LEGEND}\nWi-Fi\nEthernet\n"));
        mock.ok("9.9.9.9");
        mock.ok("There aren't any DNS Servers set on Ethernet.");
        let outcome = restore(&mock, &snapshot, &dns(), &[0, 0, 0]);
        assert!(outcome.warning.is_none());
        assert_eq!(
            outcome.cleared,
            vec!["Ethernet".to_string(), "Wi-Fi".to_string()]
        );
        // Wi-Fi was set to its custom value, not Empty.
        let set_wifi = mock
            .calls()
            .into_iter()
            .find(|(_, a)| {
                a.first().map(String::as_str) == Some("-setdnsservers") && a[1] == "Wi-Fi"
            })
            .unwrap();
        assert_eq!(set_wifi.1, vec!["-setdnsservers", "Wi-Fi", "9.9.9.9"]);
    }

    #[test]
    fn restore_warns_when_reapply_fails() {
        use std::collections::BTreeMap;
        let snapshot = BTreeMap::from([("Wi-Fi".to_string(), vec!["9.9.9.9".to_string()])]);
        let mock = MockRunner::new();
        mock.fail(1, "not admin"); // set Wi-Fi fails
                                   // guard net: clean immediately (nothing poisoned to clear).
        mock.ok(&format!("{LEGEND}\nWi-Fi\n"));
        mock.ok("There aren't any DNS Servers set on Wi-Fi.");
        mock.ok(&format!("{LEGEND}\nWi-Fi\n"));
        mock.ok("There aren't any DNS Servers set on Wi-Fi.");
        let outcome = restore(&mock, &snapshot, &dns(), &[0, 0, 0]);
        assert!(outcome
            .warning
            .unwrap()
            .contains("could not restore DNS on 'Wi-Fi'"));
    }

    #[test]
    fn guard_noop_without_dns_or_networksetup() {
        let mock = MockRunner::new();
        assert_eq!(guard(&mock, &[], &[0]), GuardOutcome::default());
        assert!(mock.calls().is_empty());
        mock.spawn_err();
        let outcome = guard(&mock, &dns(), &[0]);
        assert_eq!(outcome, GuardOutcome::default());
        assert!(outcome.note().is_none());
    }
}
