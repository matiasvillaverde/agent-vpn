//! Cross-process serialization of state-mutating commands.
//!
//! Two agents driving `vpn` concurrently could interleave `up`/`down`/`probe`
//! and tear down each other's tunnels mid-measurement. An advisory `flock` on
//! `<config_dir>/.vpn.lock` serializes the mutating commands; read-only
//! commands (`list`, `status`, `current`, `lint`, `doctor`) stay lock-free.

use std::fs::{self, File};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use crate::error::{Error, Result};

/// Name of the lock file inside the config directory (no `.conf` suffix, so
/// tunnel discovery never sees it).
pub const LOCK_FILE: &str = ".vpn.lock";

/// An exclusive advisory lock over the config directory's tunnels, released
/// on drop.
#[derive(Debug)]
pub struct Lock {
    file: File,
}

impl Lock {
    /// Acquire the lock, blocking until any concurrent `vpn` invocation
    /// releases it. Creates the config directory and lock file as needed.
    pub fn acquire(config_dir: &Path) -> Result<Lock> {
        Self::flock_on(config_dir, libc::LOCK_EX)
            .map(|lock| lock.expect("blocking lock always acquires"))
    }

    /// Try to acquire without blocking; `None` when another process holds it.
    pub fn try_acquire(config_dir: &Path) -> Result<Option<Lock>> {
        Self::flock_on(config_dir, libc::LOCK_EX | libc::LOCK_NB)
    }

    fn flock_on(config_dir: &Path, operation: libc::c_int) -> Result<Option<Lock>> {
        fs::create_dir_all(config_dir)
            .map_err(|e| Error::ConfigDir(config_dir.to_path_buf(), e))?;
        let path = config_dir.join(LOCK_FILE);
        let file = File::create(&path).map_err(|source| Error::Write {
            path: path.clone(),
            source,
        })?;
        // flock locks follow the open file description, so two handles within
        // one process conflict too — exactly what concurrent invocations need.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(Some(Lock { file }));
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        Err(Error::Write { path, source: err })
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // Unlock explicitly; closing the fd would release it anyway.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn lock_is_exclusive_until_dropped() {
        let dir = tempdir().unwrap();
        let held = Lock::acquire(dir.path()).unwrap();
        assert!(
            Lock::try_acquire(dir.path()).unwrap().is_none(),
            "second acquisition must be refused while held"
        );
        drop(held);
        assert!(Lock::try_acquire(dir.path()).unwrap().is_some());
    }

    #[test]
    fn acquire_blocks_until_release() {
        let dir = tempdir().unwrap();
        let held = Lock::acquire(dir.path()).unwrap();

        let (tx, rx) = mpsc::channel();
        let path = dir.path().to_path_buf();
        let waiter = thread::spawn(move || {
            let _lock = Lock::acquire(&path).unwrap();
            tx.send(()).unwrap();
        });

        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "waiter must block while the lock is held"
        );
        drop(held);
        assert!(
            rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "waiter must proceed once released"
        );
        waiter.join().unwrap();
    }

    #[test]
    fn acquire_creates_missing_config_dir() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("not").join("yet");
        let _lock = Lock::acquire(&nested).unwrap();
        assert!(nested.join(LOCK_FILE).exists());
    }

    #[test]
    fn lock_file_is_not_discovered_as_a_tunnel() {
        let dir = tempdir().unwrap();
        let _lock = Lock::acquire(dir.path()).unwrap();
        assert!(crate::config::discover(dir.path()).unwrap().is_empty());
    }
}
