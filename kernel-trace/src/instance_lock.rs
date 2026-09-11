//! Cross-process resource guard for one active tracer on this device.
//!
//! The file is intentionally retained after shutdown: unlinking a locked file
//! would let a new process lock a different inode while the old owner runs.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const LOCK_FILENAME: &str = "rustfrida-kernel-trace.lock";

/// Closing the owned descriptor releases the lock, including on process exit.
/// Keep this guard alive until all tracer resources have stopped.
#[derive(Debug)]
pub(crate) struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    pub(crate) fn acquire() -> io::Result<Self> {
        Self::acquire_at(&lock_path())
    }

    fn acquire_at(path: &Path) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            // NONBLOCK also prevents an unexpected FIFO from hanging startup
            // before the regular-file check below. It has no effect on a file.
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "kernel-trace lock must be a regular file",
            ));
        }

        loop {
            // SAFETY: file owns a valid descriptor throughout this call.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == io::ErrorKind::WouldBlock {
                let owner = holder_pid(&file)
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "unknown".into());
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("kernel-trace is already running (holder PID: {owner})"),
                ));
            }
            return Err(error);
        }

        // Only the lock owner may replace the diagnostic PID. A failed contender
        // must leave it untouched. The flock, not this possibly stale PID, is
        // authoritative; a crash requires no stale-file cleanup.
        file.set_len(0)?;
        writeln!(file, "{}", std::process::id())?;
        Ok(Self { _file: file })
    }
}

fn lock_path() -> PathBuf {
    #[cfg(target_os = "android")]
    {
        Path::new("/data/local/tmp").join(LOCK_FILENAME)
    }
    #[cfg(not(target_os = "android"))]
    {
        std::env::temp_dir().join(LOCK_FILENAME)
    }
}

fn holder_pid(file: &File) -> Option<u32> {
    // Never expose arbitrary file contents in an error. The only supported
    // metadata is a decimal PID. A newly acquired lock may briefly have no PID.
    let mut bytes = [0u8; 32];
    let len = file.read_at(&mut bytes, 0).ok()?;
    let pid = std::str::from_utf8(&bytes[..len]).ok()?.trim().parse().ok()?;
    (pid != 0).then_some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::fs::{symlink, MetadataExt};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);
    const CHILD_PATH_ENV: &str = "KTRACE_INSTANCE_LOCK_TEST_PATH";
    const CHILD_READY: &str = "KTRACE_INSTANCE_LOCK_READY";

    struct TestPath(PathBuf);

    impl TestPath {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ktrace-lock-test-{}-{}",
                std::process::id(),
                NEXT_PATH.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir.join("instance.lock"))
        }
    }

    impl Drop for TestPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
        }
    }

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn rejects_duplicate_without_overwriting_owner() {
        let path = TestPath::new();
        let _first = InstanceLock::acquire_at(&path.0).unwrap();
        let expected_pid = format!("{}\n", std::process::id());
        let error = InstanceLock::acquire_at(&path.0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(error
            .to_string()
            .contains(&format!("holder PID: {}", std::process::id())));
        assert_eq!(std::fs::read_to_string(&path.0).unwrap(), expected_pid);
    }

    #[test]
    fn releases_on_drop_without_removing_the_file() {
        let path = TestPath::new();
        let first = InstanceLock::acquire_at(&path.0).unwrap();
        let inode = std::fs::metadata(&path.0).unwrap().ino();
        drop(first);
        assert!(path.0.is_file());
        let _second = InstanceLock::acquire_at(&path.0).unwrap();
        assert_eq!(std::fs::metadata(&path.0).unwrap().ino(), inode);
    }

    #[test]
    fn rejects_symlinks_without_modifying_the_destination() {
        let path = TestPath::new();
        let destination = path.0.with_file_name("untouched");
        std::fs::write(&destination, "existing data").unwrap();
        symlink(&destination, &path.0).unwrap();
        assert!(InstanceLock::acquire_at(&path.0).is_err());
        assert_eq!(std::fs::read_to_string(destination).unwrap(), "existing data");
    }

    #[test]
    fn process_exit_releases_lock() {
        let path = TestPath::new();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--nocapture", "instance_lock_child_probe"])
            .env(CHILD_PATH_ENV, &path.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut child = ChildGuard(child);
        let stdout = child.0.stdout.take().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if line.as_deref().is_ok_and(|line| line.contains(CHILD_READY)) {
                    let _ = ready_tx.send(());
                    break;
                }
            }
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let error = InstanceLock::acquire_at(&path.0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(error.to_string().contains(&format!("holder PID: {}", child.0.id())));
        // Abrupt exit skips Rust Drop, so this verifies kernel-owned cleanup.
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let _next = InstanceLock::acquire_at(&path.0).unwrap();
    }

    #[test]
    #[ignore = "subprocess helper invoked by process_exit_releases_lock"]
    fn instance_lock_child_probe() {
        let Some(path) = std::env::var_os(CHILD_PATH_ENV) else {
            return;
        };
        let _lock = InstanceLock::acquire_at(Path::new(&path)).unwrap();
        println!("{CHILD_READY}");
        std::io::stdout().flush().unwrap();
        // The parent retains this pipe while checking the lock, then terminates
        // this process. EOF also lets the helper exit if the parent disappears.
        let _ = std::io::stdin().read_exact(&mut [0u8]);
    }
}
