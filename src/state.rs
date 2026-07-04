//! Crash-safe host-state journal.
//!
//! An agent driving `vpn` is killed mid-operation as a matter of course
//! (context limits, timeouts, Ctrl-C, a closing lid). WireGuard's own teardown
//! on macOS trusts a backgrounded process's memory to undo host mutations, so a
//! `SIGKILL` at the wrong instant strands the machine — most visibly with the
//! tunnel's DNS resolver left pinned system-wide (see [`crate::dns`]).
//!
//! This module records enough on disk, *before* each mutation, to reconstruct
//! the pre-tunnel host state from a cold start. Every mutating command begins
//! by reconciling these journals against the live system, so a partial
//! operation is always rolled forward or back the next time `vpn` runs — even
//! after `kill -9` or a reboot. The recovery data lives on disk, never in a
//! process that can die with it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Sub-directory of the config dir holding one `<tunnel>.json` journal per
/// in-flight or active tunnel. Not scanned by tunnel discovery (that only
/// looks at `*.conf`).
pub const STATE_DIR: &str = "state";

/// Where a mutating operation is in its lifecycle. The journal is written
/// *before* the corresponding host mutation, so a crash leaves a record that
/// [`reconcile_one`] can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// `wg-quick up` is about to run or is running: the interface and DNS may
    /// be half-applied.
    UpPending,
    /// The tunnel is fully up and owns the host DNS.
    Active,
    /// `wg-quick down` is about to run or is running: finish the teardown and
    /// restore the host on recovery.
    DownPending,
}

/// The on-disk record for one tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    /// Tunnel (config) name this journal belongs to.
    pub tunnel: String,
    /// Lifecycle phase at the last write.
    pub phase: Phase,
    /// Kernel interface backing the tunnel once known (e.g. `utun4`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Absolute Unix deadline (seconds) after which the tunnel must be torn
    /// down automatically; `None` means no lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_deadline: Option<u64>,
    /// Per-network-service DNS to restore on teardown, sanitized so it never
    /// contains the tunnel's own resolver. An empty vector means "back to
    /// DHCP" for that service.
    #[serde(default)]
    pub dns_snapshot: BTreeMap<String, Vec<String>>,
    /// The tunnel's own `DNS =` servers, kept so recovery can recognize and
    /// clear the pinned resolver even without the config file.
    #[serde(default)]
    pub tunnel_dns: Vec<String>,
}

impl Journal {
    /// Whether this journal's lease (if any) has expired at `now`.
    #[must_use]
    pub fn lease_expired(&self, now: u64) -> bool {
        self.lease_deadline.is_some_and(|deadline| now >= deadline)
    }
}

/// Current Unix time in whole seconds (production clock).
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The state directory inside `config_dir`.
#[must_use]
pub fn dir(config_dir: &Path) -> PathBuf {
    config_dir.join(STATE_DIR)
}

/// Path to one tunnel's journal file.
#[must_use]
pub fn path(config_dir: &Path, tunnel: &str) -> PathBuf {
    dir(config_dir).join(format!("{tunnel}.json"))
}

/// Atomically write `journal` (temp file + rename), creating the state
/// directory `0700` and the file `0600`.
pub fn write(config_dir: &Path, journal: &Journal) -> Result<()> {
    let state_dir = dir(config_dir);
    fs::create_dir_all(&state_dir).map_err(|e| Error::ConfigDir(state_dir.clone(), e))?;
    restrict_dir(&state_dir);
    let dest = path(config_dir, &journal.tunnel);
    let tmp = state_dir.join(format!(".{}.json.tmp", journal.tunnel));
    let body = serde_json::to_vec_pretty(journal).expect("Journal is always serializable");
    fs::write(&tmp, &body).map_err(|source| Error::Write {
        path: tmp.clone(),
        source,
    })?;
    restrict_file(&tmp);
    fs::rename(&tmp, &dest).map_err(|source| Error::Write { path: dest, source })
}

/// Read one tunnel's journal, or `None` if it is absent or unreadable/corrupt
/// (a corrupt journal must never wedge the tool — reconciliation treats it as
/// "no record").
#[must_use]
pub fn read(config_dir: &Path, tunnel: &str) -> Option<Journal> {
    let text = fs::read_to_string(path(config_dir, tunnel)).ok()?;
    serde_json::from_str(&text).ok()
}

/// All readable journals in the state directory, sorted by tunnel name.
#[must_use]
pub fn read_all(config_dir: &Path) -> Vec<Journal> {
    let mut journals = Vec::new();
    let Ok(entries) = fs::read_dir(dir(config_dir)) else {
        return journals;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Some(journal) = fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str::<Journal>(&t).ok())
        {
            journals.push(journal);
        }
    }
    journals.sort_by(|a, b| a.tunnel.cmp(&b.tunnel));
    journals
}

/// Delete one tunnel's journal. Missing is success (idempotent teardown).
pub fn remove(config_dir: &Path, tunnel: &str) -> Result<()> {
    match fs::remove_file(path(config_dir, tunnel)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::Write {
            path: path(config_dir, tunnel),
            source,
        }),
    }
}

/// What reconciliation decided for a single journal, given the live system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciliation {
    /// Journal matches reality (active, within lease) — leave it untouched.
    Healthy,
    /// The tunnel must be brought back to a clean host state. `tear_down` is
    /// `true` when a live interface still needs `wg-quick down` first; either
    /// way the DNS snapshot is restored and the journal cleared afterwards.
    Recover {
        /// Whether a live interface still needs tearing down.
        tear_down: bool,
        /// Why recovery is happening (for reporting).
        reason: RecoverReason,
    },
}

/// Why a journal needs recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverReason {
    /// `Active` but the interface vanished (crash/reboot killed the tunnel).
    InterfaceGone,
    /// Crash during `up` — interface and DNS may be half-applied.
    InterruptedUp,
    /// Crash during `down` — finish the teardown.
    InterruptedDown,
    /// Lease deadline passed; tear the tunnel down.
    LeaseExpired,
}

impl RecoverReason {
    /// A short human explanation for reports.
    #[must_use]
    pub fn describe(&self) -> &'static str {
        match self {
            RecoverReason::InterfaceGone => "tunnel interface vanished (crash or reboot)",
            RecoverReason::InterruptedUp => "interrupted while bringing the tunnel up",
            RecoverReason::InterruptedDown => "interrupted while bringing the tunnel down",
            RecoverReason::LeaseExpired => "lease expired",
        }
    }
}

/// Decide what to do with one journal given whether its interface is live and
/// the current time. Pure and total — the whole reconcile policy in one place.
#[must_use]
pub fn reconcile_one(journal: &Journal, live: bool, now: u64) -> Reconciliation {
    match journal.phase {
        Phase::Active => {
            if !live {
                Reconciliation::Recover {
                    tear_down: false,
                    reason: RecoverReason::InterfaceGone,
                }
            } else if journal.lease_expired(now) {
                Reconciliation::Recover {
                    tear_down: true,
                    reason: RecoverReason::LeaseExpired,
                }
            } else {
                Reconciliation::Healthy
            }
        }
        Phase::UpPending => Reconciliation::Recover {
            tear_down: live,
            reason: RecoverReason::InterruptedUp,
        },
        Phase::DownPending => Reconciliation::Recover {
            tear_down: live,
            reason: RecoverReason::InterruptedDown,
        },
    }
}

#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) {}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn journal(phase: Phase) -> Journal {
        Journal {
            tunnel: "proton".to_string(),
            phase,
            interface: Some("utun4".to_string()),
            lease_deadline: None,
            dns_snapshot: BTreeMap::from([("Wi-Fi".to_string(), vec!["10.19.16.1".to_string()])]),
            tunnel_dns: vec!["10.2.0.1".to_string()],
        }
    }

    #[test]
    fn write_read_roundtrip_and_remove() {
        let dir = tempdir().unwrap();
        let j = journal(Phase::Active);
        write(dir.path(), &j).unwrap();
        assert_eq!(read(dir.path(), "proton").as_ref(), Some(&j));
        assert_eq!(read_all(dir.path()), vec![j]);
        remove(dir.path(), "proton").unwrap();
        assert!(read(dir.path(), "proton").is_none());
        // Removing an absent journal is success.
        remove(dir.path(), "proton").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn write_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        write(dir.path(), &journal(Phase::Active)).unwrap();
        let file_mode = fs::metadata(path(dir.path(), "proton"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        let dir_mode = fs::metadata(super::dir(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn corrupt_journal_reads_as_none_and_is_skipped() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(super::dir(dir.path())).unwrap();
        fs::write(path(dir.path(), "broken"), "{ not json").unwrap();
        assert!(read(dir.path(), "broken").is_none());
        assert!(read_all(dir.path()).is_empty());
    }

    #[test]
    fn read_all_ignores_non_json_and_sorts() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            &Journal {
                tunnel: "zeta".to_string(),
                ..journal(Phase::Active)
            },
        )
        .unwrap();
        write(
            dir.path(),
            &Journal {
                tunnel: "alpha".to_string(),
                ..journal(Phase::Active)
            },
        )
        .unwrap();
        fs::write(super::dir(dir.path()).join("note.txt"), "ignore me").unwrap();
        let names: Vec<String> = read_all(dir.path()).into_iter().map(|j| j.tunnel).collect();
        assert_eq!(names, vec!["alpha", "zeta"]);
    }

    #[test]
    fn reconcile_active_and_live_within_lease_is_healthy() {
        let mut j = journal(Phase::Active);
        j.lease_deadline = Some(1000);
        assert_eq!(reconcile_one(&j, true, 999), Reconciliation::Healthy);
    }

    #[test]
    fn reconcile_active_but_dead_interface_recovers_without_teardown() {
        let j = journal(Phase::Active);
        assert_eq!(
            reconcile_one(&j, false, 0),
            Reconciliation::Recover {
                tear_down: false,
                reason: RecoverReason::InterfaceGone,
            }
        );
    }

    #[test]
    fn reconcile_expired_lease_tears_down() {
        let mut j = journal(Phase::Active);
        j.lease_deadline = Some(1000);
        assert_eq!(
            reconcile_one(&j, true, 1000),
            Reconciliation::Recover {
                tear_down: true,
                reason: RecoverReason::LeaseExpired,
            }
        );
    }

    #[test]
    fn reconcile_interrupted_up_tears_down_only_if_live() {
        let j = journal(Phase::UpPending);
        assert!(matches!(
            reconcile_one(&j, true, 0),
            Reconciliation::Recover {
                tear_down: true,
                reason: RecoverReason::InterruptedUp
            }
        ));
        assert!(matches!(
            reconcile_one(&j, false, 0),
            Reconciliation::Recover {
                tear_down: false,
                ..
            }
        ));
    }

    #[test]
    fn reconcile_interrupted_down_finishes_teardown() {
        let j = journal(Phase::DownPending);
        assert!(matches!(
            reconcile_one(&j, true, 0),
            Reconciliation::Recover {
                tear_down: true,
                reason: RecoverReason::InterruptedDown
            }
        ));
    }

    #[test]
    fn reconcile_invariants_hold_across_the_whole_input_space() {
        // Exhaustively enumerate every (phase, live, lease, now) combination and
        // assert the two safety invariants of the reconcile decision:
        //   1. Healthy IFF the tunnel is Active, live, and within its lease.
        //   2. We never tear down an interface that is not live.
        // This is the crash-recovery core: if it is sound, no interrupted
        // sequence can leave the host in a state reconcile won't fix.
        let phases = [Phase::UpPending, Phase::Active, Phase::DownPending];
        let leases = [None, Some(500u64)];
        let nows = [0u64, 499, 500, 501, 1_000];
        for phase in phases {
            for &live in &[true, false] {
                for lease in leases {
                    for now in nows {
                        let j = Journal {
                            tunnel: "t".to_string(),
                            phase,
                            interface: Some("utun0".to_string()),
                            lease_deadline: lease,
                            dns_snapshot: BTreeMap::new(),
                            tunnel_dns: Vec::new(),
                        };
                        let decision = reconcile_one(&j, live, now);
                        let expired = lease.is_some_and(|d| now >= d);
                        let expect_healthy = phase == Phase::Active && live && !expired;
                        assert_eq!(
                            matches!(decision, Reconciliation::Healthy),
                            expect_healthy,
                            "phase={phase:?} live={live} lease={lease:?} now={now}"
                        );
                        if let Reconciliation::Recover { tear_down, .. } = decision {
                            assert!(
                                !tear_down || live,
                                "never tear down a dead interface: \
                                 phase={phase:?} live={live} lease={lease:?} now={now}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn lease_expired_boundary() {
        let mut j = journal(Phase::Active);
        assert!(!j.lease_expired(5));
        j.lease_deadline = Some(10);
        assert!(!j.lease_expired(9));
        assert!(j.lease_expired(10));
        assert!(j.lease_expired(11));
    }
}
