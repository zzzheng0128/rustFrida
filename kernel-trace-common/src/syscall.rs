//! ARM64 Linux syscall 名↔nr 解析。
//!
//! 数据源:stackplz_dev/user/config/config_syscall_aarch64.json(306 个 syscall)
//! 自动生成的 const slice 见 `syscall_table_aarch64.rs`。
//!
//! 提供:
//! - `nr_to_name(nr) -> Option<&'static str>`
//! - `name_to_nr(name) -> Option<i64>`
//! - `parse_syscall_list("openat,connect,sendto") -> Vec<i64>`(支持数字直通)
//! - `expand_syscall_groups("%file,%net") -> Vec<i64>`(支持 stackplz 风格的 %分组)
//!
//! 分组来源:stackplz_dev/user/module/syscall.go::Parse_SyscallNames + 常用 Android 习惯。

use crate::syscall_table_aarch64::AARCH64_SYSCALL_TABLE;

/// `nr → name`,二分查找(数据按 nr 升序)。
pub fn nr_to_name(nr: i64) -> Option<&'static str> {
    match AARCH64_SYSCALL_TABLE.binary_search_by_key(&nr, |(k, _)| *k) {
        Ok(idx) => Some(AARCH64_SYSCALL_TABLE[idx].1),
        Err(_) => None,
    }
}

/// `name → nr`,线性扫描(306 项,简单可靠;若要快可以建 hashmap)。
pub fn name_to_nr(name: &str) -> Option<i64> {
    for (k, v) in AARCH64_SYSCALL_TABLE {
        if *v == name {
            return Some(*k);
        }
    }
    None
}

/// 解析逗号分隔的 syscall 列表,每一项可以是:
/// - 数字(如 "56")→ 原样返回
/// - 名(如 "openat")→ 查表得 nr
/// - %分组(如 "%file")→ 展开为该分组所有 syscall 的 nr
///
/// 出错时返回 `Err(String)`,错误信息包含未识别的 token。
pub fn parse_syscall_list(spec: &str) -> Result<Vec<i64>, String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for token in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(rest) = token.strip_prefix('%') {
            // %分组展开
            let members = expand_group(rest).ok_or_else(|| {
                format!("unknown syscall group: %{rest}; available: %file %net %read %write %attr %exec %process %signal %kill %exit %dup %epoll %stat %recv %send %clone %all")
            })?;
            for m in &members {
                if seen.insert(*m) {
                    out.push(*m);
                }
            }
        } else if let Ok(n) = token.parse::<i64>() {
            if seen.insert(n) {
                out.push(n);
            }
        } else {
            let nr = name_to_nr(token).ok_or_else(|| {
                format!("unknown syscall name: {token} (not a number and not in aarch64 syscall table)")
            })?;
            if seen.insert(nr) {
                out.push(nr);
            }
        }
    }
    Ok(out)
}

/// Stackplz 风格的 syscall 分组定义。
///
/// 返回值是 syscall **编号**列表(已查表),不是名字。
fn expand_group(name: &str) -> Option<Vec<i64>> {
    // 注意:name_to_nr 可能会返回 None(如果某个名字在 306 个 aarch64 syscall 里不存在);
    // 我们对此采取"该名字跳过不报错"的策略,毕竟不同内核版本 syscall 表略有差异。
    fn names_to_nrs(names: &[&str]) -> Vec<i64> {
        names.iter().filter_map(|n| name_to_nr(n)).collect()
    }
    Some(match name {
        // 文件/IO
        "file" => names_to_nrs(&[
            "openat",
            "open",
            "openat2",
            "creat",
            "unlink",
            "unlinkat",
            "mkdir",
            "mkdirat",
            "rmdir",
            "rename",
            "renameat",
            "renameat2",
            "link",
            "linkat",
            "symlink",
            "symlinkat",
            "readlink",
            "readlinkat",
            "truncate",
            "ftruncate",
            "faccessat",
            "faccessat2",
            "chmod",
            "fchmod",
            "fchmodat",
            "chown",
            "fchown",
            "fchownat",
            "lchown",
            "stat",
            "lstat",
            "fstat",
            "fstatat",
            "statx",
            "statfs",
            "fstatfs",
            "newfstatat",
            "umask",
            "chdir",
            "fchdir",
            "getcwd",
            "fcntl",
            "ioctl",
            "close",
            "close_range",
            "dup",
            "dup2",
            "dup3",
            "pipe",
            "pipe2",
            "pread64",
            "pwrite64",
            "readv",
            "writev",
            "preadv",
            "pwritev",
            "preadv2",
            "pwritev2",
            "read",
            "write",
            "lseek",
            "llseek",
            "getdents",
            "getdents64",
            "fsync",
            "fdatasync",
            "sync",
            "syncfs",
            "fallocate",
            "fadvise64",
            "readahead",
            "sendfile",
            "splice",
            "tee",
            "vmsplice",
            "copy_file_range",
            "mknod",
            "mknodat",
            "utime",
            "utimes",
            "utimensat",
            "futimesat",
            "inotify_init",
            "inotify_init1",
            "inotify_add_watch",
            "inotify_rm_watch",
            "fanotify_init",
            "fanotify_mark",
            "flock",
            "fsopen",
            "fsmount",
            "fsconfig",
            "fspick",
            "mount",
            "umount2",
            "chroot",
            "pivot_root",
        ]),
        "net" => names_to_nrs(&[
            "socket",
            "socketpair",
            "connect",
            "bind",
            "listen",
            "accept",
            "accept4",
            "getsockname",
            "getpeername",
            "getsockopt",
            "setsockopt",
            "shutdown",
            "sendto",
            "recvfrom",
            "sendmsg",
            "recvmsg",
            "sendmmsg",
            "recvmmsg",
            "send",
            "recv",
        ]),
        "send" => names_to_nrs(&["sendto", "sendmsg", "sendmmsg", "send"]),
        "recv" => names_to_nrs(&["recvfrom", "recvmsg", "recvmmsg", "recv"]),
        "read" => names_to_nrs(&[
            "read", "pread64", "readv", "preadv", "preadv2", "recvfrom", "recvmsg", "recvmmsg", "recv",
        ]),
        "write" => names_to_nrs(&[
            "write", "pwrite64", "writev", "pwritev", "pwritev2", "sendto", "sendmsg", "sendmmsg", "send",
        ]),
        "attr" => names_to_nrs(&[
            "faccessat",
            "faccessat2",
            "chmod",
            "fchmod",
            "fchmodat",
            "chown",
            "fchown",
            "fchownat",
            "lchown",
            "umask",
            "utime",
            "utimes",
            "utimensat",
            "statx",
            "newfstatat",
            "listxattr",
            "llistxattr",
            "flistxattr",
            "setxattr",
            "lsetxattr",
            "fsetxattr",
            "getxattr",
            "lgetxattr",
            "fgetxattr",
            "removexattr",
            "lremovexattr",
            "fremovexattr",
        ]),
        "exec" => names_to_nrs(&[
            "execve",
            "execveat",
            "fexecve",
            "prctl",
            "seccomp",
            "personality",
            "arch_prctl",
        ]),
        "process" => names_to_nrs(&[
            "clone",
            "clone3",
            "fork",
            "vfork",
            "execve",
            "execveat",
            "exit",
            "exit_group",
            "wait4",
            "waitid",
            "getpid",
            "gettid",
            "getppid",
            "getuid",
            "geteuid",
            "getgid",
            "getegid",
            "setsid",
            "getsid",
            "setpgid",
            "getpgid",
            "getpgrp",
            "setpgrp",
            "kill",
            "tkill",
            "tgkill",
            "ptrace",
        ]),
        "clone" => names_to_nrs(&["clone", "clone3", "fork", "vfork"]),
        "signal" => names_to_nrs(&[
            "rt_sigaction",
            "rt_sigprocmask",
            "rt_sigpending",
            "rt_sigtimedwait",
            "rt_sigtimedwait_time64",
            "rt_sigqueueinfo",
            "rt_sigreturn",
            "kill",
            "tkill",
            "tgkill",
            "sigaltstack",
            "pause",
        ]),
        "kill" => names_to_nrs(&["kill", "tkill", "tgkill"]),
        "exit" => names_to_nrs(&["exit", "exit_group"]),
        "dup" => names_to_nrs(&["dup", "dup2", "dup3", "close", "close_range", "fcntl"]),
        "epoll" => names_to_nrs(&[
            "epoll_create",
            "epoll_create1",
            "epoll_ctl",
            "epoll_wait",
            "epoll_pwait",
            "epoll_pwait2",
            "eventfd",
            "eventfd2",
            "signalfd",
            "signalfd4",
        ]),
        "stat" => names_to_nrs(&[
            "stat",
            "lstat",
            "fstat",
            "fstatat",
            "newfstatat",
            "statx",
            "statfs",
            "fstatfs",
            "ustat",
        ]),
        "all" => {
            // %all 展开为全部 syscall
            return Some(AARCH64_SYSCALL_TABLE.iter().map(|(k, _)| *k).collect());
        }
        _ => return None,
    })
}

/// 把一个 Vec<i64> 内的 nr 排序去重(传 Filter map 前)。
pub fn dedup_sorted(mut v: Vec<i64>) -> Vec<i64> {
    v.sort_unstable();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nr_name_roundtrip() {
        assert_eq!(nr_to_name(56), Some("openat"));
        assert_eq!(name_to_nr("openat"), Some(56));
        assert_eq!(name_to_nr("connect"), Some(203));
        assert_eq!(nr_to_name(999999), None);
        assert_eq!(name_to_nr("notexist"), None);
    }

    #[test]
    fn parse_mixed_list() {
        let v = parse_syscall_list("openat,connect,56,sendto").unwrap();
        assert_eq!(v, vec![56, 203, 206]);
    }

    #[test]
    fn parse_group() {
        let v = parse_syscall_list("%file").unwrap();
        assert!(v.len() > 20);
        assert!(v.contains(&56)); // openat
    }

    #[test]
    fn parse_unknown_name() {
        assert!(parse_syscall_list("zzz_notexist").is_err());
    }
}
