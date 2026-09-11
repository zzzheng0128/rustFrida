//! Short-lived process metadata shared by report workers.
//!
//! Reads happen outside the cache lock. Concurrent misses may perform duplicate
//! reads, but a slow /proc read never blocks cache hits for unrelated processes.
//! The TTL limits stale data after exit; it is not an exact PID-reuse detector.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const SUCCESS_TTL: Duration = Duration::from_millis(250);
const FAILURE_TTL: Duration = Duration::from_millis(100);
const MAX_CACHED_PIDS: usize = 256;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProcInfo {
    pub ns_pid: Option<u32>,
    pub uid: Option<u32>,
}

struct Entry {
    info: ProcInfo,
    expires_at: Instant,
}

#[derive(Default)]
struct Cache {
    entries: HashMap<u32, Entry>,
}

static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();

pub(crate) fn get(pid: u32) -> ProcInfo {
    get_cached(
        CACHE.get_or_init(|| Mutex::new(Cache::default())),
        pid,
        Instant::now,
        |pid| std::fs::read_to_string(format!("/proc/{pid}/status")).ok(),
    )
}

fn lock(cache: &Mutex<Cache>) -> MutexGuard<'_, Cache> {
    cache.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn get_cached(
    cache: &Mutex<Cache>,
    pid: u32,
    now: impl Fn() -> Instant,
    read: impl FnOnce(u32) -> Option<String>,
) -> ProcInfo {
    let lookup_at = now();
    {
        let cache = lock(cache);
        if let Some(entry) = cache.entries.get(&pid) {
            if lookup_at < entry.expires_at {
                return entry.info;
            }
        }
    }

    // Both I/O and parsing remain outside the shared lock. Start the TTL after
    // the read completes so a delayed read does not expire before it is cached.
    let content = read(pid);
    let (info, ttl) = match content {
        Some(content) => (parse(&content), SUCCESS_TTL),
        None => (ProcInfo::default(), FAILURE_TTL),
    };
    let loaded_at = now();
    let mut cache = lock(cache);
    if cache.entries.len() >= MAX_CACHED_PIDS && !cache.entries.contains_key(&pid) {
        cache.entries.retain(|_, entry| loaded_at < entry.expires_at);
        if cache.entries.len() >= MAX_CACHED_PIDS {
            // At most 256 entries: a linear scan avoids another index and
            // favors keeping metadata whose refresh is furthest in the future.
            let victim = cache
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(&pid, _)| pid);
            if let Some(victim) = victim {
                cache.entries.remove(&victim);
            }
        }
    }
    cache.entries.insert(
        pid,
        Entry {
            info,
            expires_at: loaded_at + ttl,
        },
    );
    info
}

fn parse(status: &str) -> ProcInfo {
    let mut info = ProcInfo::default();
    let mut uid_seen = false;
    for line in status.lines() {
        if info.ns_pid.is_none() {
            if let Some(value) = line.strip_prefix("NSpid:") {
                // Preserve the existing namespace translation: use the last
                // successfully parsed PID, i.e. the innermost namespace.
                info.ns_pid = value
                    .split_whitespace()
                    .filter_map(|part| part.parse::<u32>().ok())
                    .last();
            }
        }
        if !uid_seen {
            if let Some(value) = line.strip_prefix("Uid:") {
                // The first field is the real UID, not the effective UID.
                info.uid = value.split_whitespace().next().and_then(|uid| uid.parse().ok());
                uid_seen = true;
            }
        }
        if info.ns_pid.is_some() && uid_seen {
            break;
        }
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn status(ns_pid: u32, uid: u32) -> String {
        format!("Name:\ttest\nNSpid:\t123\t{ns_pid}\nUid:\t{uid}\t2000\t3000\t4000\n")
    }

    #[test]
    fn parser_uses_innermost_namespace_and_real_uid() {
        assert_eq!(
            parse("Name:\ttest\nUid:\t1000 2000 3000 4000\nNSpid:\t900 80 7\n"),
            ProcInfo {
                ns_pid: Some(7),
                uid: Some(1000),
            }
        );
        assert_eq!(parse("NSpid:\t123\nUid:\t0\n").ns_pid, Some(123));
        assert_eq!(parse("NSpid:\t123\nUid:\t0\n").uid, Some(0));
    }

    #[test]
    fn parser_handles_missing_and_malformed_fields() {
        assert_eq!(parse("Name:\ttest\n"), ProcInfo::default());
        assert_eq!(parse("NSpid:\nUid:\n"), ProcInfo::default());
        assert_eq!(
            parse("NSpid:\t100 invalid 9 invalid\nUid:\tinvalid 1000\n"),
            ProcInfo {
                ns_pid: Some(9),
                uid: None,
            }
        );
        assert_eq!(parse("NSpid:\t4294967296\nUid:\t-1\n"), ProcInfo::default());
        assert_eq!(parse("NSpid:\t8\n").uid, None);
        assert_eq!(parse("Uid:\t1000\n").ns_pid, None);
    }

    #[test]
    fn successful_reads_are_shared_until_the_ttl_boundary() {
        let cache = Mutex::new(Cache::default());
        let start = Instant::now();
        let now = Cell::new(start);
        let reads = Cell::new(0);
        let fetch = || {
            get_cached(
                &cache,
                1,
                || now.get(),
                |_| {
                    reads.set(reads.get() + 1);
                    Some(status(reads.get(), 1000 + reads.get()))
                },
            )
        };
        assert_eq!(fetch().ns_pid, Some(1));
        now.set(start + SUCCESS_TTL - Duration::from_nanos(1));
        assert_eq!(fetch().uid, Some(1001));
        assert_eq!(reads.get(), 1);
        now.set(start + SUCCESS_TTL);
        assert_eq!(fetch().ns_pid, Some(2));
        assert_eq!(fetch().uid, Some(1002));
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn failed_reads_are_cached_briefly_and_recover() {
        let cache = Mutex::new(Cache::default());
        let start = Instant::now();
        let now = Cell::new(start);
        let reads = Cell::new(0);
        let fetch = || {
            get_cached(
                &cache,
                1,
                || now.get(),
                |_| {
                    reads.set(reads.get() + 1);
                    (reads.get() > 1).then(|| status(7, 1000))
                },
            )
        };
        assert_eq!(fetch(), ProcInfo::default());
        now.set(start + FAILURE_TTL - Duration::from_nanos(1));
        assert_eq!(fetch(), ProcInfo::default());
        assert_eq!(reads.get(), 1);
        now.set(start + FAILURE_TTL);
        assert_eq!(fetch().ns_pid, Some(7));
        assert_eq!(reads.get(), 2);
        now.set(start + FAILURE_TTL + SUCCESS_TTL - Duration::from_nanos(1));
        assert_eq!(fetch().uid, Some(1000));
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn filesystem_read_does_not_hold_the_cache_lock() {
        let cache = Mutex::new(Cache::default());
        let info = get_cached(&cache, 1, Instant::now, |_| {
            assert!(cache.try_lock().is_ok());
            Some(status(7, 1000))
        });
        assert_eq!(info.ns_pid, Some(7));
    }

    #[test]
    fn capacity_is_bounded_and_oldest_expiration_is_evicted() {
        let cache = Mutex::new(Cache::default());
        let start = Instant::now();
        let reads = Cell::new(0);
        for pid in 0..=MAX_CACHED_PIDS as u32 {
            get_cached(
                &cache,
                pid,
                || start + Duration::from_nanos(pid as u64),
                |pid| {
                    reads.set(reads.get() + 1);
                    Some(status(pid, 1000))
                },
            );
            assert!(lock(&cache).entries.len() <= MAX_CACHED_PIDS);
        }
        assert_eq!(reads.get(), MAX_CACHED_PIDS + 1);
        let cache = lock(&cache);
        assert_eq!(cache.entries.len(), MAX_CACHED_PIDS);
        assert!(!cache.entries.contains_key(&0));
        assert!(cache.entries.contains_key(&(MAX_CACHED_PIDS as u32)));
    }

    #[test]
    fn a_full_cache_clears_expired_entries_before_evicting_live_entries() {
        let cache = Mutex::new(Cache::default());
        let start = Instant::now();
        for pid in 0..MAX_CACHED_PIDS as u32 {
            get_cached(&cache, pid, || start, |pid| Some(status(pid, 1000)));
        }
        get_cached(
            &cache,
            MAX_CACHED_PIDS as u32,
            || start + SUCCESS_TTL,
            |pid| Some(status(pid, 1001)),
        );
        assert_eq!(lock(&cache).entries.len(), 1);
    }

    #[test]
    fn ttl_starts_after_a_slow_read_completes() {
        let cache = Mutex::new(Cache::default());
        let start = Instant::now();
        let now = Cell::new(start);
        get_cached(
            &cache,
            1,
            || now.get(),
            |_| {
                now.set(start + Duration::from_secs(1));
                Some(status(7, 1000))
            },
        );
        now.set(start + Duration::from_secs(1) + SUCCESS_TTL - Duration::from_nanos(1));
        let info = get_cached(&cache, 1, || now.get(), |_| panic!("unexpected reread"));
        assert_eq!(info.ns_pid, Some(7));
    }
}
