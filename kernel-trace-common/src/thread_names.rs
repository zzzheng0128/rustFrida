//! Default exclusions use the kernel's comm, at most 15 visible bytes plus NUL.

use crate::TASK_COMM_LEN;

/// Exact visible-name comparison: a shorter entry never acts as a prefix.
#[inline(always)]
fn comm_matches_name(comm: &[u8; TASK_COMM_LEN], name: &[u8]) -> bool {
    if name.len() >= TASK_COMM_LEN {
        return false;
    }
    let mut i = 0;
    while i < name.len() {
        if comm[i] != name[i] {
            return false;
        }
        i += 1;
    }
    comm[i] == 0
}

/// Edit this function to change the default kernel-tracing thread blacklist.
/// Entries must use the visible comm name, including truncation to 15 bytes.
#[allow(non_snake_case)]
#[inline(always)]
pub fn DefaultThreadBlacklist(comm: &[u8; TASK_COMM_LEN]) -> bool {
    comm_matches_name(comm, b"Profile Saver")
        || comm_matches_name(comm, b"Runtime worker")
        || comm_matches_name(comm, b"ReferenceQueueD")
        || comm_matches_name(comm, b"FinalizerDaemon")
        || comm_matches_name(comm, b"FinalizerWatchd")
        || comm_matches_name(comm, b"HeapTaskDaemon")
        || comm_matches_name(comm, b"perfetto_hprof_")
        || comm_matches_name(comm, b"RenderThread")
        || comm_matches_name(comm, b"RxCachedThreadS")
        || comm_matches_name(comm, b"mali-cmar-backe")
        || comm_matches_name(comm, b"mali-utility-wo")
        || comm_matches_name(comm, b"mali-mem-purge")
        || comm_matches_name(comm, b"mali-hist-dump")
        || comm_matches_name(comm, b"mali-event-hand")
        || comm_matches_name(comm, b"hwuiTask0")
        || comm_matches_name(comm, b"hwuiTask1")
        || comm_matches_name(comm, b"NDK MediaCodec_")
}

/// `full_tname` bypasses only the default name exclusions, not other filters.
#[inline(always)]
pub fn should_filter_thread(comm: &[u8; TASK_COMM_LEN], full_tname: bool) -> bool {
    !full_tname && DefaultThreadBlacklist(comm)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_NAMES: [&str; 17] = [
        "Profile Saver",
        "Runtime worker",
        "ReferenceQueueD",
        "FinalizerDaemon",
        "FinalizerWatchd",
        "HeapTaskDaemon",
        "perfetto_hprof_",
        "RenderThread",
        "RxCachedThreadS",
        "mali-cmar-backe",
        "mali-utility-wo",
        "mali-mem-purge",
        "mali-hist-dump",
        "mali-event-hand",
        "hwuiTask0",
        "hwuiTask1",
        "NDK MediaCodec_",
    ];

    fn comm(name: &str) -> [u8; TASK_COMM_LEN] {
        let mut result = [0; TASK_COMM_LEN];
        let len = name.len().min(TASK_COMM_LEN - 1);
        result[..len].copy_from_slice(&name.as_bytes()[..len]);
        result
    }

    #[test]
    fn all_default_names_are_unique_exact_exclusions() {
        for (index, name) in DEFAULT_NAMES.iter().enumerate() {
            assert!(name.len() < TASK_COMM_LEN, "{name}");
            assert!(!DEFAULT_NAMES[..index].contains(name), "duplicate: {name}");
            assert!(should_filter_thread(&comm(name), false), "{name}");
        }
    }

    #[test]
    fn shorter_names_do_not_match_extensions_or_other_threads() {
        for name in DEFAULT_NAMES {
            if name.len() < TASK_COMM_LEN - 1 {
                let mut extended = comm(name);
                extended[name.len()] = b'X';
                assert!(!should_filter_thread(&extended, false), "{name}");
            }
        }
        for name in ["", "main", "renderthread", "Render", "hwuiTask2", "myRenderThread"] {
            assert!(!should_filter_thread(&comm(name), false), "{name}");
        }
    }

    #[test]
    fn fifteen_byte_names_match_kernel_truncation() {
        assert!(should_filter_thread(&comm("ReferenceQueueDaemon"), false));
        assert!(should_filter_thread(&comm("FinalizerDaemon-worker"), false));
        let mut no_nul = comm("ReferenceQueueD");
        no_nul[TASK_COMM_LEN - 1] = b'X';
        assert!(!should_filter_thread(&no_nul, false));
    }

    #[test]
    fn comparison_ignores_bytes_after_terminating_nul() {
        let mut value = comm("hwuiTask0");
        value[12] = b'X';
        assert!(should_filter_thread(&value, false));
    }

    #[test]
    fn full_tname_bypasses_default_name_exclusions() {
        for name in DEFAULT_NAMES {
            assert!(!should_filter_thread(&comm(name), true), "{name}");
        }
        assert!(!should_filter_thread(&comm("main"), true));
    }
}
