//! syscall 参数语义解析（全量版，覆盖 arm64 全部 ~306 个 syscall）。
//!
//! 类型体系：
//! - Int / UInt / Hex / Octal：标量格式化
//! - Dirfd / Signal / ClockId：专用枚举
//! - Flags / Enum：位标志、精确匹配解码（flags 表）
//! - Str：char* → /proc/<pid>/mem 读 C 字符串
//! - Buf(n)：void* + 长度取第 n 个参数 → 最多 32B 预览，可选附加最多 4KB hexdump
//! - SockAddr / Stat / CloneArgs / SigAction / TimeSpec / SeccompFprog / IoctlReq：结构体解码
//!
//! 注意：sys_enter 时刻"输出型"结构体（statbuf 等）尚未被内核填充，
//! 此类参数会标注 (out)，其内容仅作参考快照。

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::File;
use std::os::unix::fs::FileExt;

#[derive(Clone, Copy, Debug)]
pub enum ArgType {
    /// 十进制有符号
    Int,
    /// 十六进制（指针/地址）
    Hex,
    /// 八进制权限位 0o755
    Octal,
    /// dirfd：-100 → AT_FDCWD
    Dirfd,
    /// 信号编号 → SIG 名
    Signal,
    /// 位标志解码
    Flags(&'static [(u64, &'static str)]),
    /// 精确值解码
    Enum(&'static [(i64, &'static str)]),
    /// char* → 字符串
    Str,
    /// void* + 长度来自第 N 个参数（0-based）→ 预览，可选 hexdump（最多 4KB）
    Buf(usize),
    /// sockaddr* → 族/IP:port/路径
    SockAddr,
    /// struct stat*（输出型，标注 (out)）
    Stat,
    /// struct clone_args*（clone3）
    CloneArgs,
    /// 内核 struct sigaction*
    SigAction,
    /// struct timespec*
    TimeSpec,
    /// seccomp SET_MODE_FILTER 的 sock_fprog*
    SeccompFprog,
    /// ioctl request 字段拆解（dir/type/nr/size）
    IoctlReq,
}

pub struct ArgSpec {
    pub name: &'static str,
    pub ty: ArgType,
}

const fn int(name: &'static str) -> ArgSpec {
    ArgSpec { name, ty: ArgType::Int }
}
const fn hex(name: &'static str) -> ArgSpec {
    ArgSpec { name, ty: ArgType::Hex }
}
const fn oct(name: &'static str) -> ArgSpec {
    ArgSpec {
        name,
        ty: ArgType::Octal,
    }
}
const fn dirfd(name: &'static str) -> ArgSpec {
    ArgSpec {
        name,
        ty: ArgType::Dirfd,
    }
}
const fn sig(name: &'static str) -> ArgSpec {
    ArgSpec {
        name,
        ty: ArgType::Signal,
    }
}
const fn strp(name: &'static str) -> ArgSpec {
    ArgSpec { name, ty: ArgType::Str }
}
const fn buf(name: &'static str, len_arg: usize) -> ArgSpec {
    ArgSpec {
        name,
        ty: ArgType::Buf(len_arg),
    }
}
const fn flg(name: &'static str, t: &'static [(u64, &'static str)]) -> ArgSpec {
    ArgSpec {
        name,
        ty: ArgType::Flags(t),
    }
}
const fn enm(name: &'static str, t: &'static [(i64, &'static str)]) -> ArgSpec {
    ArgSpec {
        name,
        ty: ArgType::Enum(t),
    }
}
const fn sockaddr(name: &'static str) -> ArgSpec {
    ArgSpec {
        name,
        ty: ArgType::SockAddr,
    }
}
const fn statp(name: &'static str) -> ArgSpec {
    ArgSpec {
        name,
        ty: ArgType::Stat,
    }
}
const fn timespec(name: &'static str) -> ArgSpec {
    ArgSpec {
        name,
        ty: ArgType::TimeSpec,
    }
}

// =====================================================================
// 标志/枚举表
// =====================================================================

const SIGNALS: &[(i64, &str)] = &[
    (1, "SIGHUP"),
    (2, "SIGINT"),
    (3, "SIGQUIT"),
    (4, "SIGILL"),
    (5, "SIGTRAP"),
    (6, "SIGABRT"),
    (7, "SIGBUS"),
    (8, "SIGFPE"),
    (9, "SIGKILL"),
    (10, "SIGUSR1"),
    (11, "SIGSEGV"),
    (12, "SIGUSR2"),
    (13, "SIGPIPE"),
    (14, "SIGALRM"),
    (15, "SIGTERM"),
    (16, "SIGSTKFLT"),
    (17, "SIGCHLD"),
    (18, "SIGCONT"),
    (19, "SIGSTOP"),
    (20, "SIGTSTP"),
    (21, "SIGTTIN"),
    (22, "SIGTTOU"),
    (23, "SIGURG"),
    (24, "SIGXCPU"),
    (25, "SIGXFSZ"),
    (26, "SIGVTALRM"),
    (27, "SIGPROF"),
    (28, "SIGWINCH"),
    (29, "SIGIO"),
    (30, "SIGPWR"),
    (31, "SIGSYS"),
];

const OPEN_FLAGS: &[(u64, &str)] = &[
    (0o100, "O_CREAT"),
    (0o200, "O_EXCL"),
    (0o400, "O_NOCTTY"),
    (0o1000, "O_TRUNC"),
    (0o2000, "O_APPEND"),
    (0o4000, "O_NONBLOCK"),
    (0o10000, "O_DSYNC"),
    (0o40000, "O_DIRECT"),
    (0o100000, "O_LARGEFILE"),
    (0o200000, "O_DIRECTORY"),
    (0o400000, "O_NOFOLLOW"),
    (0o1000000, "O_NOATIME"),
    (0o2000000, "O_CLOEXEC"),
    (0o4010000, "O_SYNC"),
    (0o10000000, "O_PATH"),
    (0o20000000, "O_TMPFILE"),
];

const PIPE_FLAGS: &[(u64, &str)] = &[(0o4000, "O_NONBLOCK"), (0o2000000, "O_CLOEXEC")];

const AT_FLAGS: &[(u64, &str)] = &[
    (0x100, "AT_SYMLINK_NOFOLLOW"),
    (0x200, "AT_REMOVEDIR"),
    (0x400, "AT_SYMLINK_FOLLOW"),
    (0x800, "AT_NO_AUTOMOUNT"),
    (0x1000, "AT_EMPTY_PATH"),
    (0x200, "AT_EACCESS"),
    (0x6000, "AT_STATX_SYNC_TYPE"),
];

const ACCESS_MODE: &[(u64, &str)] = &[(4, "R_OK"), (2, "W_OK"), (1, "X_OK")];

const PROT_FLAGS: &[(u64, &str)] = &[
    (1, "PROT_READ"),
    (2, "PROT_WRITE"),
    (4, "PROT_EXEC"),
    (0x01000000, "PROT_BTI"),
    (0x02000000, "PROT_MTE"),
];

const MAP_FLAGS: &[(u64, &str)] = &[
    (0x01, "MAP_SHARED"),
    (0x02, "MAP_PRIVATE"),
    (0x10, "MAP_FIXED"),
    (0x20, "MAP_ANONYMOUS"),
    (0x8000, "MAP_POPULATE"),
    (0x10000, "MAP_NORESERVE"),
    (0x20000, "MAP_STACK"),
    (0x40000, "MAP_HUGETLB"),
    (0x80000, "MAP_SYNC"),
    (0x100000, "MAP_FIXED_NOREPLACE"),
];

const CLONE_FLAGS: &[(u64, &str)] = &[
    (0x100, "CLONE_VM"),
    (0x200, "CLONE_FS"),
    (0x400, "CLONE_FILES"),
    (0x800, "CLONE_SIGHAND"),
    (0x1000, "CLONE_PIDFD"),
    (0x2000, "CLONE_PTRACE"),
    (0x4000, "CLONE_VFORK"),
    (0x8000, "CLONE_PARENT"),
    (0x10000, "CLONE_THREAD"),
    (0x20000, "CLONE_NEWNS"),
    (0x40000, "CLONE_SYSVSEM"),
    (0x80000, "CLONE_SETTLS"),
    (0x100000, "CLONE_PARENT_SETTID"),
    (0x200000, "CLONE_CHILD_CLEARTID"),
    (0x400000, "CLONE_DETACHED"),
    (0x800000, "CLONE_UNTRACED"),
    (0x1000000, "CLONE_CHILD_SETTID"),
    (0x2000000, "CLONE_NEWCGROUP"),
    (0x4000000, "CLONE_NEWUTS"),
    (0x8000000, "CLONE_NEWIPC"),
    (0x10000000, "CLONE_NEWUSER"),
    (0x20000000, "CLONE_NEWPID"),
    (0x40000000, "CLONE_NEWNET"),
    (0x80000000, "CLONE_IO"),
];

const WAIT_OPTS: &[(u64, &str)] = &[
    (1, "WNOHANG"),
    (2, "WUNTRACED"),
    (4, "WEXITED"),
    (8, "WCONTINUED"),
    (0x1000000, "WNOWAIT"),
    (0x20000000, "__WNOTHREAD"),
    (0x40000000, "__WALL"),
    (0x80000000, "__WCLONE"),
];

const MEMFD_FLAGS: &[(u64, &str)] = &[(1, "MFD_CLOEXEC"), (2, "MFD_ALLOW_SEALING"), (4, "MFD_HUGETLB")];

const SOCK_FDS_FLAGS: &[(u64, &str)] = &[(0o4000, "SOCK_NONBLOCK"), (0o2000000, "SOCK_CLOEXEC")];

const SOCK_DOMAINS: &[(i64, &str)] = &[
    (0, "AF_UNSPEC"),
    (1, "AF_UNIX"),
    (2, "AF_INET"),
    (4, "AF_DECnet"),
    (5, "AF_APPLETALK"),
    (9, "AF_X25"),
    (10, "AF_INET6"),
    (12, "AF_DECnet"),
    (16, "AF_NETLINK"),
    (17, "AF_PACKET"),
    (21, "AF_RDS"),
    (26, "AF_LLC"),
    (28, "AF_CAN"),
    (31, "AF_BLUETOOTH"),
    (33, "AF_MCTP"),
    (35, "AF_PHONET"),
    (38, "AF_ALG"),
    (40, "AF_VSOCK"),
    (42, "AF_QIPCRTR"),
];

const PRCTL_OPTS: &[(i64, &str)] = &[
    (1, "PR_SET_PDEATHSIG"),
    (2, "PR_GET_PDEATHSIG"),
    (3, "PR_GET_DUMPABLE"),
    (4, "PR_SET_DUMPABLE"),
    (5, "PR_GET_KEEPCAPS"),
    (6, "PR_SET_KEEPCAPS"),
    (7, "PR_GET_FPEMU"),
    (9, "PR_GET_FPEXC"),
    (10, "PR_SET_TIMING"),
    (11, "PR_GET_TIMING"),
    (12, "PR_SET_NAME"),
    (13, "PR_GET_ENDIAN"),
    (15, "PR_SET_NAME"),
    (16, "PR_GET_NAME"),
    (19, "PR_GET_UNALIGN"),
    (21, "PR_GET_SECCOMP"),
    (22, "PR_SET_SECCOMP"),
    (23, "PR_CAPBSET_READ"),
    (24, "PR_CAPBSET_DROP"),
    (25, "PR_GET_TSC"),
    (26, "PR_SET_TSC"),
    (27, "PR_GET_SECUREBITS"),
    (28, "PR_SET_SECUREBITS"),
    (29, "PR_SET_TIMERSLACK"),
    (30, "PR_GET_TIMERSLACK"),
    (31, "PR_TASK_PERF_EVENTS_DISABLE"),
    (32, "PR_TASK_PERF_EVENTS_ENABLE"),
    (33, "PR_MCE_KILL"),
    (34, "PR_MCE_KILL_GET"),
    (35, "PR_SET_MM"),
    (36, "PR_SET_CHILD_SUBREAPER"),
    (37, "PR_GET_CHILD_SUBREAPER"),
    (38, "PR_SET_NO_NEW_PRIVS"),
    (39, "PR_GET_NO_NEW_PRIVS"),
    (40, "PR_GET_TID_ADDRESS"),
    (41, "PR_SET_THP_DISABLE"),
    (42, "PR_GET_THP_DISABLE"),
    (43, "PR_MPX_ENABLE_MANAGEMENT"),
    (45, "PR_SET_FP_MODE"),
    (46, "PR_GET_FP_MODE"),
    (47, "PR_CAP_AMBIENT"),
    (50, "PR_SVE_SET_VL"),
    (51, "PR_SVE_GET_VL"),
    (52, "PR_GET_SPECULATION_CTRL"),
    (53, "PR_SET_SPECULATION_CTRL"),
    (55, "PR_SET_TAGGED_ADDR_CTRL"),
    (56, "PR_GET_TAGGED_ADDR_CTRL"),
    (57, "PR_SET_IO_FLUSHER"),
    (58, "PR_GET_IO_FLUSHER"),
    (59, "PR_SET_SYSCALL_USER_DISPATCH"),
    (60, "PR_PAC_SET_ENABLED_KEYS"),
    (61, "PR_PAC_GET_ENABLED_KEYS"),
    (0x59616d61, "PR_SET_PTRACER"),
];

const FUTEX_OPS: &[(i64, &str)] = &[
    (0, "FUTEX_WAIT"),
    (1, "FUTEX_WAKE"),
    (2, "FUTEX_FD"),
    (3, "FUTEX_REQUEUE"),
    (4, "FUTEX_CMP_REQUEUE"),
    (5, "FUTEX_WAKE_OP"),
    (6, "FUTEX_LOCK_PI"),
    (7, "FUTEX_UNLOCK_PI"),
    (8, "FUTEX_TRYLOCK_PI"),
    (9, "FUTEX_WAIT_BITSET"),
    (10, "FUTEX_WAKE_BITSET"),
    (11, "FUTEX_WAIT_REQUEUE_PI"),
    (12, "FUTEX_CMP_REQUEUE_PI"),
];

const SIGPROCMASK_HOW: &[(i64, &str)] = &[(0, "SIG_BLOCK"), (1, "SIG_UNBLOCK"), (2, "SIG_SETMASK")];

const MADV_OPTS: &[(i64, &str)] = &[
    (0, "MADV_NORMAL"),
    (1, "MADV_RANDOM"),
    (2, "MADV_SEQUENTIAL"),
    (3, "MADV_WILLNEED"),
    (4, "MADV_DONTNEED"),
    (8, "MADV_FREE"),
    (9, "MADV_REMOVE"),
    (10, "MADV_DONTFORK"),
    (11, "MADV_DOFORK"),
    (12, "MADV_MERGEABLE"),
    (13, "MADV_UNMERGEABLE"),
    (14, "MADV_HUGEPAGE"),
    (15, "MADV_NOHUGEPAGE"),
    (16, "MADV_DONTDUMP"),
    (17, "MADV_DODUMP"),
    (18, "MADV_WIPEONFORK"),
    (19, "MADV_KEEPONFORK"),
    (20, "MADV_COLD"),
    (21, "MADV_PAGEOUT"),
    (22, "MADV_POPULATE_READ"),
    (23, "MADV_POPULATE_WRITE"),
    (24, "MADV_DONTNEED_LOCKED"),
];

const FCNTL_CMDS: &[(i64, &str)] = &[
    (0, "F_DUPFD"),
    (1, "F_GETFD"),
    (2, "F_SETFD"),
    (3, "F_GETFL"),
    (4, "F_SETFL"),
    (5, "F_GETLK"),
    (6, "F_SETLK"),
    (7, "F_SETLKW"),
    (8, "F_SETOWN"),
    (9, "F_GETOWN"),
    (10, "F_SETSIG"),
    (11, "F_GETSIG"),
    (12, "F_GETLK64"),
    (13, "F_SETLK64"),
    (14, "F_SETLKW64"),
    (15, "F_SETOWN_EX"),
    (16, "F_GETOWN_EX"),
    (17, "F_OFD_GETLK"),
    (18, "F_OFD_SETLK"),
    (19, "F_OFD_SETLKW"),
    (1024, "F_SETLEASE"),
    (1025, "F_GETLEASE"),
    (1026, "F_NOTIFY"),
    (1029, "F_CANCELLK"),
    (1030, "F_DUPFD_CLOEXEC"),
    (1031, "F_SETPIPE_SZ"),
    (1032, "F_GETPIPE_SZ"),
    (1033, "F_ADD_SEALS"),
    (1034, "F_GET_SEALS"),
    (1036, "F_GET_RW_HINT"),
    (1037, "F_SET_RW_HINT"),
    (1038, "F_GET_FILE_RW_HINT"),
    (1039, "F_SET_FILE_RW_HINT"),
];

const WHENCE: &[(i64, &str)] = &[
    (0, "SEEK_SET"),
    (1, "SEEK_CUR"),
    (2, "SEEK_END"),
    (3, "SEEK_DATA"),
    (4, "SEEK_HOLE"),
];

const SHUT_HOW: &[(i64, &str)] = &[(0, "SHUT_RD"), (1, "SHUT_WR"), (2, "SHUT_RDWR")];

const SECCOMP_OPS: &[(i64, &str)] = &[
    (0, "SECCOMP_SET_MODE_STRICT"),
    (1, "SECCOMP_SET_MODE_FILTER"),
    (2, "SECCOMP_GET_ACTION_AVAIL"),
    (3, "SECCOMP_GET_NOTIF_SIZES"),
];

const BPF_CMDS: &[(i64, &str)] = &[
    (0, "BPF_MAP_CREATE"),
    (1, "BPF_MAP_LOOKUP_ELEM"),
    (2, "BPF_MAP_UPDATE_ELEM"),
    (3, "BPF_MAP_DELETE_ELEM"),
    (4, "BPF_MAP_GET_NEXT_KEY"),
    (5, "BPF_PROG_LOAD"),
    (6, "BPF_OBJ_PIN"),
    (7, "BPF_OBJ_GET"),
    (8, "BPF_PROG_ATTACH"),
    (9, "BPF_PROG_DETACH"),
    (10, "BPF_PROG_TEST_RUN"),
    (11, "BPF_PROG_GET_NEXT_ID"),
    (12, "BPF_MAP_GET_NEXT_ID"),
    (13, "BPF_PROG_GET_FD_BY_ID"),
    (14, "BPF_MAP_GET_FD_BY_ID"),
    (15, "BPF_OBJ_GET_INFO_BY_FD"),
    (16, "BPF_PROG_QUERY"),
    (17, "BPF_RAW_TRACEPOINT_OPEN"),
    (18, "BPF_BTF_LOAD"),
    (19, "BPF_BTF_GET_FD_BY_ID"),
    (20, "BPF_TASK_FD_QUERY"),
    (21, "BPF_MAP_LOOKUP_AND_DELETE_ELEM"),
    (22, "BPF_MAP_FREEZE"),
    (23, "BPF_BTF_GET_NEXT_ID"),
    (24, "BPF_MAP_LOOKUP_BATCH"),
    (25, "BPF_MAP_LOOKUP_AND_DELETE_BATCH"),
    (26, "BPF_MAP_UPDATE_BATCH"),
    (27, "BPF_MAP_DELETE_BATCH"),
    (28, "BPF_LINK_CREATE"),
    (29, "BPF_LINK_UPDATE"),
    (30, "BPF_LINK_GET_FD_BY_ID"),
    (31, "BPF_LINK_GET_NEXT_ID"),
    (32, "BPF_ENABLE_STATS"),
    (33, "BPF_ITER_CREATE"),
    (34, "BPF_LINK_DETACH"),
    (35, "BPF_PROG_BIND_MAP"),
];

const MSG_FLAGS: &[(u64, &str)] = &[
    (1, "MSG_OOB"),
    (2, "MSG_PEEK"),
    (4, "MSG_DONTROUTE"),
    (8, "MSG_CTRUNC"),
    (0x10, "MSG_PROXY"),
    (0x20, "MSG_TRUNC"),
    (0x40, "MSG_DONTWAIT"),
    (0x80, "MSG_EOR"),
    (0x100, "MSG_WAITALL"),
    (0x200, "MSG_FIN"),
    (0x400, "MSG_SYN"),
    (0x800, "MSG_CONFIRM"),
    (0x1000, "MSG_RST"),
    (0x2000, "MSG_ERRQUEUE"),
    (0x4000, "MSG_NOSIGNAL"),
    (0x8000, "MSG_MORE"),
    (0x10000, "MSG_WAITFORONE"),
    (0x20000, "MSG_BATCH"),
    (0x80000, "MSG_ZEROCOPY"),
    (0x4000000, "MSG_SPLICE_PAGES"),
    (0x40000000, "MSG_CMSG_CLOEXEC"),
];

const CLOCKS: &[(i64, &str)] = &[
    (0, "CLOCK_REALTIME"),
    (1, "CLOCK_MONOTONIC"),
    (2, "CLOCK_PROCESS_CPUTIME_ID"),
    (3, "CLOCK_THREAD_CPUTIME_ID"),
    (4, "CLOCK_MONOTONIC_RAW"),
    (5, "CLOCK_REALTIME_COARSE"),
    (6, "CLOCK_MONOTONIC_COARSE"),
    (7, "CLOCK_BOOTTIME"),
    (8, "CLOCK_REALTIME_ALARM"),
    (9, "CLOCK_BOOTTIME_ALARM"),
    (10, "CLOCK_SGI_CYCLE"),
    (11, "CLOCK_TAI"),
];

const RLIMIT_RES: &[(i64, &str)] = &[
    (0, "RLIMIT_CPU"),
    (1, "RLIMIT_FSIZE"),
    (2, "RLIMIT_DATA"),
    (3, "RLIMIT_STACK"),
    (4, "RLIMIT_CORE"),
    (5, "RLIMIT_RSS"),
    (6, "RLIMIT_NPROC"),
    (7, "RLIMIT_NOFILE"),
    (8, "RLIMIT_MEMLOCK"),
    (9, "RLIMIT_AS"),
    (10, "RLIMIT_LOCKS"),
    (11, "RLIMIT_SIGPENDING"),
    (12, "RLIMIT_MSGQUEUE"),
    (13, "RLIMIT_NICE"),
    (14, "RLIMIT_RTPRIO"),
    (15, "RLIMIT_RTTIME"),
];

const SCHED_POLICIES: &[(i64, &str)] = &[
    (0, "SCHED_NORMAL"),
    (1, "SCHED_FIFO"),
    (2, "SCHED_RR"),
    (3, "SCHED_BATCH"),
    (5, "SCHED_IDLE"),
    (6, "SCHED_DEADLINE"),
];

const PTRACE_REQS: &[(i64, &str)] = &[
    (0, "PTRACE_TRACEME"),
    (1, "PTRACE_PEEKTEXT"),
    (2, "PTRACE_PEEKDATA"),
    (3, "PTRACE_PEEKUSR"),
    (4, "PTRACE_POKETEXT"),
    (5, "PTRACE_POKEDATA"),
    (6, "PTRACE_POKEUSR"),
    (7, "PTRACE_CONT"),
    (8, "PTRACE_KILL"),
    (9, "PTRACE_SINGLESTEP"),
    (12, "PTRACE_GETREGS"),
    (13, "PTRACE_SETREGS"),
    (14, "PTRACE_GETFPREGS"),
    (15, "PTRACE_SETFPREGS"),
    (16, "PTRACE_ATTACH"),
    (17, "PTRACE_DETACH"),
    (24, "PTRACE_SYSCALL"),
    (31, "PTRACE_SETOPTIONS"),
    (0x4200, "PTRACE_SET_SYSCALL"),
    (0x4201, "PTRACE_GET_THREAD_AREA"),
    (0x4203, "PTRACE_GETVFPREGS"),
    (0x4204, "PTRACE_GETREGSET"),
    (0x4205, "PTRACE_SETREGSET"),
    (0x4206, "PTRACE_SEIZE"),
    (0x4207, "PTRACE_INTERRUPT"),
    (0x4208, "PTRACE_LISTEN"),
    (0x4209, "PTRACE_PEEKSIGINFO"),
    (0x420a, "PTRACE_GETSIGMASK"),
    (0x420b, "PTRACE_SETSIGMASK"),
    (0x420c, "PTRACE_SECCOMP_GET_FILTER"),
    (0x420d, "PTRACE_SECCOMP_GET_METADATA"),
    (0x420e, "PTRACE_GET_SYSCALL_INFO"),
];

const EPOLL_OPS: &[(i64, &str)] = &[(1, "EPOLL_CTL_ADD"), (2, "EPOLL_CTL_DEL"), (3, "EPOLL_CTL_MOD")];

const ITIMERS: &[(i64, &str)] = &[(0, "ITIMER_REAL"), (1, "ITIMER_VIRTUAL"), (2, "ITIMER_PROF")];

const PRIO_WHICH: &[(i64, &str)] = &[(0, "PRIO_PROCESS"), (1, "PRIO_PGRP"), (2, "PRIO_USER")];

const RUSAGE_WHO: &[(i64, &str)] = &[(0, "RUSAGE_SELF"), (-1, "RUSAGE_CHILDREN"), (1, "RUSAGE_THREAD")];

const FLOCK_OPS: &[(u64, &str)] = &[(1, "LOCK_SH"), (2, "LOCK_EX"), (4, "LOCK_NB"), (8, "LOCK_UN")];

const MSYNC_FLAGS: &[(u64, &str)] = &[(1, "MS_ASYNC"), (2, "MS_INVALIDATE"), (4, "MS_SYNC")];

const MLOCKALL_FLAGS: &[(u64, &str)] = &[(1, "MCL_CURRENT"), (2, "MCL_FUTURE"), (4, "MCL_ONFAULT")];

const UMOUNT_FLAGS: &[(u64, &str)] = &[
    (1, "MNT_FORCE"),
    (2, "MNT_DETACH"),
    (4, "MNT_EXPIRE"),
    (8, "UMOUNT_NOFOLLOW"),
];

const RENAME_FLAGS: &[(u64, &str)] = &[(1, "RENAME_NOREPLACE"), (2, "RENAME_EXCHANGE"), (4, "RENAME_WHITEOUT")];

const GETRANDOM_FLAGS: &[(u64, &str)] = &[(1, "GRND_NONBLOCK"), (2, "GRND_RANDOM"), (4, "GRND_INSECURE")];

const SPLICE_FLAGS: &[(u64, &str)] = &[
    (1, "SPLICE_F_MOVE"),
    (2, "SPLICE_F_NONBLOCK"),
    (4, "SPLICE_F_MORE"),
    (8, "SPLICE_F_GIFT"),
];

const SYNC_FILE_RANGE_FLAGS: &[(u64, &str)] = &[
    (1, "SYNC_FILE_RANGE_WAIT_BEFORE"),
    (2, "SYNC_FILE_RANGE_WRITE"),
    (4, "SYNC_FILE_RANGE_WAIT_AFTER"),
];

const EVENTFD_FLAGS: &[(u64, &str)] = &[
    (1, "EFD_SEMAPHORE"),
    (0o4000, "EFD_NONBLOCK"),
    (0o2000000, "EFD_CLOEXEC"),
];

const EPOLL_CREATE1_FLAGS: &[(u64, &str)] = &[(0o2000000, "EPOLL_CLOEXEC")];

const INOTIFY_INIT_FLAGS: &[(u64, &str)] = &[(0o4000, "IN_NONBLOCK"), (0o2000000, "IN_CLOEXEC")];

const INOTIFY_MASK: &[(u64, &str)] = &[
    (1, "IN_ACCESS"),
    (2, "IN_MODIFY"),
    (4, "IN_ATTRIB"),
    (8, "IN_CLOSE_WRITE"),
    (0x10, "IN_CLOSE_NOWRITE"),
    (0x20, "IN_OPEN"),
    (0x40, "IN_MOVED_FROM"),
    (0x80, "IN_MOVED_TO"),
    (0x100, "IN_CREATE"),
    (0x200, "IN_DELETE"),
    (0x400, "IN_DELETE_SELF"),
    (0x800, "IN_MOVE_SELF"),
    (0x2000, "IN_UNMOUNT"),
    (0x4000, "IN_Q_OVERFLOW"),
    (0x8000, "IN_IGNORED"),
    (0x10000, "IN_ONLYDIR"),
    (0x20000, "IN_DONT_FOLLOW"),
    (0x200000, "IN_EXCL_UNLINK"),
    (0x1000000, "IN_ISDIR"),
    (0x2000000, "IN_ONESHOT"),
];

const TIMERFD_FLAGS: &[(u64, &str)] = &[(0o4000, "TFD_NONBLOCK"), (0o2000000, "TFD_CLOEXEC")];

const TIMERFD_SETTIME_FLAGS: &[(u64, &str)] = &[(1, "TFD_TIMER_ABSTIME"), (2, "TFD_TIMER_CANCEL_ON_SET")];

const SIGNALFD_FLAGS: &[(u64, &str)] = &[(0o4000, "SFD_NONBLOCK"), (0o2000000, "SFD_CLOEXEC")];

const MREMAP_FLAGS: &[(u64, &str)] = &[(1, "MREMAP_MAYMOVE"), (2, "MREMAP_FIXED"), (4, "MREMAP_DONTUNMAP")];

const STATX_MASK: &[(u64, &str)] = &[
    (0x1, "STATX_TYPE"),
    (0x2, "STATX_MODE"),
    (0x4, "STATX_NLINK"),
    (0x8, "STATX_UID"),
    (0x10, "STATX_GID"),
    (0x20, "STATX_ATIME"),
    (0x40, "STATX_MTIME"),
    (0x80, "STATX_CTIME"),
    (0x100, "STATX_INO"),
    (0x200, "STATX_SIZE"),
    (0x400, "STATX_BLOCKS"),
    (0x800, "STATX_BTIME"),
    (0x1000, "STATX_MNT_ID"),
    (0x2000, "STATX_DIOALIGN"),
];

const STATX_ATFLAGS: &[(u64, &str)] = &[
    (0x100, "AT_SYMLINK_NOFOLLOW"),
    (0x800, "AT_NO_AUTOMOUNT"),
    (0x1000, "AT_EMPTY_PATH"),
    (0x2000, "AT_STATX_SYNC_AS_STAT"),
    (0x4000, "AT_STATX_FORCE_SYNC"),
    (0x6000, "AT_STATX_DONT_SYNC"),
];

const PREADV2_FLAGS: &[(u64, &str)] = &[
    (1, "RWF_HIPRI"),
    (2, "RWF_DSYNC"),
    (4, "RWF_SYNC"),
    (8, "RWF_NOWAIT"),
    (0x10, "RWF_APPEND"),
];

const MEMBARRIER_CMDS: &[(i64, &str)] = &[
    (0, "MEMBARRIER_CMD_QUERY"),
    (1, "MEMBARRIER_CMD_GLOBAL"),
    (2, "MEMBARRIER_CMD_GLOBAL_EXPEDITED"),
    (3, "MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED"),
    (4, "MEMBARRIER_CMD_PRIVATE_EXPEDITED"),
    (5, "MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED"),
    (6, "MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE"),
    (7, "MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE"),
    (8, "MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ"),
    (9, "MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ"),
    (10, "MEMBARRIER_CMD_SHARED"),
    (32, "MEMBARRIER_CMD_GLOBAL"),
    (16, "MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE"),
];

const KCMP_TYPES: &[(i64, &str)] = &[
    (0, "KCMP_FILE"),
    (1, "KCMP_VM"),
    (2, "KCMP_FILES"),
    (3, "KCMP_FS"),
    (4, "KCMP_SIGHAND"),
    (5, "KCMP_IO"),
    (6, "KCMP_SYSVSEM"),
    (7, "KCMP_EPOLL_TFD"),
];

const UNSHARE_FLAGS: &[(u64, &str)] = &[
    (0x100, "CLONE_VM"),
    (0x200, "CLONE_FS"),
    (0x400, "CLONE_FILES"),
    (0x800, "CLONE_SIGHAND"),
    (0x10000, "CLONE_THREAD"),
    (0x20000, "CLONE_NEWNS"),
    (0x40000, "CLONE_SYSVSEM"),
    (0x2000000, "CLONE_NEWCGROUP"),
    (0x4000000, "CLONE_NEWUTS"),
    (0x8000000, "CLONE_NEWIPC"),
    (0x10000000, "CLONE_NEWUSER"),
    (0x20000000, "CLONE_NEWPID"),
    (0x40000000, "CLONE_NEWNET"),
    (0x80000000, "CLONE_IO"),
    (0x20000, "CLONE_NEWNS"),
    (0x8000000, "CLONE_NEWIPC"),
    (0x40000, "CLONE_SYSVSEM"),
    (0x1000, "CLONE_PIDFD"),
];

const SETNS_FLAGS: &[(i64, &str)] = &[
    (0, "0(any)"),
    (0x20000, "CLONE_NEWNS"),
    (0x2000000, "CLONE_NEWCGROUP"),
    (0x4000000, "CLONE_NEWUTS"),
    (0x8000000, "CLONE_NEWIPC"),
    (0x10000000, "CLONE_NEWUSER"),
    (0x20000000, "CLONE_NEWPID"),
    (0x40000000, "CLONE_NEWNET"),
    (0x80, "CLONE_NEWTIME"),
];

const PERSONALITY_FLAGS: &[(u64, &str)] = &[
    (0x0001, "UNAME26"),
    (0x0002, "ADDR_NO_RANDOMIZE"),
    (0x0004, "FDPIC_FUNCPTRS"),
    (0x0008, "MMAP_PAGE_ZERO"),
    (0x0010, "ADDR_COMPAT_LAYOUT"),
    (0x0020, "READ_IMPLIES_EXEC"),
    (0x0040, "ADDR_LIMIT_32BIT"),
    (0x0080, "SHORT_INODE"),
    (0x0100, "WHOLE_SECONDS"),
    (0x0200, "STICKY_TIMEOUTS"),
    (0x0400, "ADDR_LIMIT_3GB"),
];

const CLOSE_RANGE_FLAGS: &[(u64, &str)] = &[(1, "CLOSE_RANGE_UNSHARE"), (2, "CLOSE_RANGE_CLOEXEC")];

const UFFD_FLAGS: &[(u64, &str)] = &[
    (0o2000000, "O_CLOEXEC"),
    (0o4000, "O_NONBLOCK"),
    (1, "UFFD_USER_MODE_ONLY"),
];

const IOURING_SETUP_FLAGS: &[(u64, &str)] = &[
    (1, "IORING_SETUP_IOPOLL"),
    (2, "IORING_SETUP_SQPOLL"),
    (4, "IORING_SETUP_SQ_AFF"),
    (8, "IORING_SETUP_CQSIZE"),
    (0x10, "IORING_SETUP_CLAMP"),
    (0x20, "IORING_SETUP_ATTACH_WQ"),
    (0x40, "IORING_SETUP_R_DISABLED"),
    (0x80, "IORING_SETUP_SUBMIT_ALL"),
    (0x100, "IORING_SETUP_COOP_TASKRUN"),
    (0x200, "IORING_SETUP_TASKRUN_FLAG"),
    (0x400, "IORING_SETUP_SQE128"),
    (0x800, "IORING_SETUP_CQE32"),
    (0x1000, "IORING_SETUP_SINGLE_ISSUER"),
    (0x2000, "IORING_SETUP_DEFER_TASKRUN"),
    (0x4000, "IORING_SETUP_NO_MMAP"),
    (0x8000, "IORING_SETUP_REGISTERED_FD_ONLY"),
];

const IOURING_ENTER_FLAGS: &[(u64, &str)] = &[
    (1, "IORING_ENTER_GETEVENTS"),
    (2, "IORING_ENTER_SQ_WAKEUP"),
    (4, "IORING_ENTER_SQ_WAIT"),
    (8, "IORING_ENTER_EXT_ARG"),
    (0x10, "IORING_ENTER_REGISTERED_RING"),
];

const SIGACTION_FLAGS: &[(u64, &str)] = &[
    (1, "SA_NOCLDSTOP"),
    (2, "SA_NOCLDWAIT"),
    (4, "SA_SIGINFO"),
    (0x4000000, "SA_RESTORER"),
    (0x8000000, "SA_ONSTACK"),
    (0x10000000, "SA_RESTART"),
    (0x40000000, "SA_NODEFER"),
    (0x80000000, "SA_RESETHAND"),
];

// =====================================================================
// 每个 syscall 的参数签名（nr 0..450 全覆盖）
// =====================================================================

macro_rules! spec {
    ($name:ident, $($e:expr),* $(,)?) => {
        const $name: &[ArgSpec] = &[$($e),*];
    };
}

spec!(S_NONE,);
spec!(S_IO_SETUP, int("nr_events"), hex("ctx_idp"));
spec!(S_IO_DESTROY, hex("ctx_id"));
spec!(S_IO_SUBMIT, hex("ctx_id"), int("nr"), hex("iocbpp"));
spec!(S_IO_CANCEL, hex("ctx_id"), hex("iocb"), hex("result"));
spec!(
    S_IO_GETEVENTS,
    hex("ctx_id"),
    int("min_nr"),
    int("nr"),
    hex("events"),
    timespec("timeout")
);
spec!(S_XATTR_PATH, strp("path"), strp("name"), hex("value"), int("size"));
spec!(S_XATTR_FD, int("fd"), strp("name"), hex("value"), int("size"));
spec!(
    S_SETXATTR_PATH,
    strp("path"),
    strp("name"),
    hex("value"),
    int("size"),
    int("flags")
);
spec!(
    S_SETXATTR_FD,
    int("fd"),
    strp("name"),
    hex("value"),
    int("size"),
    int("flags")
);
spec!(S_LISTXATTR_PATH, strp("path"), hex("list"), int("size"));
spec!(S_LISTXATTR_FD, int("fd"), hex("list"), int("size"));
spec!(S_REMOVEXATTR_PATH, strp("path"), strp("name"));
spec!(S_REMOVEXATTR_FD, int("fd"), strp("name"));
spec!(S_GETCWD, hex("buf"), int("size"));
spec!(S_LOOKUP_DCOOKIE, hex("cookie"), hex("buf"), int("len"));
spec!(S_EVENTFD2, int("initval"), flg("flags", EVENTFD_FLAGS));
spec!(S_EPOLL_CREATE1, flg("flags", EPOLL_CREATE1_FLAGS));
spec!(S_EPOLL_CTL, int("epfd"), enm("op", EPOLL_OPS), int("fd"), hex("event"));
spec!(
    S_EPOLL_PWAIT,
    int("epfd"),
    hex("events"),
    int("maxevents"),
    int("timeout"),
    hex("sigmask"),
    int("sigsetsize")
);
spec!(S_DUP, int("fd"));
spec!(S_DUP3, int("oldfd"), int("newfd"), flg("flags", PIPE_FLAGS));
spec!(S_FCNTL, int("fd"), enm("cmd", FCNTL_CMDS), hex("arg"));
spec!(S_INOTIFY_INIT1, flg("flags", INOTIFY_INIT_FLAGS));
spec!(
    S_INOTIFY_ADD_WATCH,
    int("fd"),
    strp("pathname"),
    flg("mask", INOTIFY_MASK)
);
spec!(S_INOTIFY_RM_WATCH, int("fd"), int("wd"));
spec!(
    S_IOCTL,
    int("fd"),
    ArgSpec {
        name: "request",
        ty: ArgType::IoctlReq
    },
    hex("arg")
);
spec!(S_IOPRIO_SET, enm("which", PRIO_WHICH), int("who"), int("ioprio"));
spec!(S_IOPRIO_GET, enm("which", PRIO_WHICH), int("who"));
spec!(S_FLOCK, int("fd"), flg("operation", FLOCK_OPS));
spec!(S_MKNODAT, dirfd("dirfd"), strp("pathname"), oct("mode"), hex("dev"));
spec!(S_MKDIRAT, dirfd("dirfd"), strp("pathname"), oct("mode"));
spec!(S_UNLINKAT, dirfd("dirfd"), strp("pathname"), flg("flags", AT_FLAGS));
spec!(S_SYMLINKAT, strp("target"), dirfd("newdirfd"), strp("linkpath"));
spec!(
    S_LINKAT,
    dirfd("olddirfd"),
    strp("oldpath"),
    dirfd("newdirfd"),
    strp("newpath"),
    flg("flags", AT_FLAGS)
);
spec!(
    S_RENAMEAT,
    dirfd("olddirfd"),
    strp("oldpath"),
    dirfd("newdirfd"),
    strp("newpath")
);
spec!(
    S_RENAMEAT2,
    dirfd("olddirfd"),
    strp("oldpath"),
    dirfd("newdirfd"),
    strp("newpath"),
    flg("flags", RENAME_FLAGS)
);
spec!(S_UMOUNT2, strp("target"), flg("flags", UMOUNT_FLAGS));
spec!(
    S_MOUNT,
    strp("source"),
    strp("target"),
    strp("fstype"),
    hex("flags"),
    hex("data")
);
spec!(S_PIVOT_ROOT, strp("new_root"), strp("put_old"));
spec!(S_STATFS, strp("path"), hex("buf"));
spec!(S_FSTATFS, int("fd"), hex("buf"));
spec!(S_TRUNCATE, strp("path"), int("length"));
spec!(S_FTRUNCATE, int("fd"), int("length"));
spec!(S_FALLOCATE, int("fd"), int("mode"), int("offset"), int("len"));
spec!(S_FACCESSAT, dirfd("dirfd"), strp("pathname"), flg("mode", ACCESS_MODE));
spec!(
    S_FACCESSAT2,
    dirfd("dirfd"),
    strp("pathname"),
    flg("mode", ACCESS_MODE),
    flg("flags", AT_FLAGS)
);
spec!(S_CHDIR, strp("path"));
spec!(S_FCHDIR, int("fd"));
spec!(S_CHROOT, strp("path"));
spec!(S_FCHMOD, int("fd"), oct("mode"));
spec!(
    S_FCHMODAT,
    dirfd("dirfd"),
    strp("pathname"),
    oct("mode"),
    flg("flags", AT_FLAGS)
);
spec!(
    S_FCHOWNAT,
    dirfd("dirfd"),
    strp("pathname"),
    int("uid"),
    int("gid"),
    flg("flags", AT_FLAGS)
);
spec!(S_FCHOWN, int("fd"), int("uid"), int("gid"));
spec!(
    S_OPENAT,
    dirfd("dirfd"),
    strp("pathname"),
    flg("flags", OPEN_FLAGS),
    oct("mode")
);
spec!(S_CLOSE, int("fd"));
spec!(S_PIPE2, hex("pipefd"), flg("flags", PIPE_FLAGS));
spec!(S_QUOTACTL, hex("cmd"), strp("special"), int("id"), hex("addr"));
spec!(S_GETDENTS64, int("fd"), hex("dirp"), int("count"));
spec!(S_LSEEK, int("fd"), int("offset"), enm("whence", WHENCE));
spec!(S_READ, int("fd"), buf("buf", 2), int("count"));
spec!(S_WRITE, int("fd"), buf("buf", 2), int("count"));
spec!(S_IOV, int("fd"), hex("iov"), int("iovcnt"));
spec!(S_PREAD64, int("fd"), buf("buf", 2), int("count"), int("pos"));
spec!(S_PWRITE64, int("fd"), buf("buf", 2), int("count"), int("pos"));
spec!(
    S_PREADV,
    int("fd"),
    hex("iov"),
    int("iovcnt"),
    int("pos_l"),
    int("pos_h")
);
spec!(
    S_PREADV2,
    int("fd"),
    hex("iov"),
    int("iovcnt"),
    int("pos_l"),
    int("pos_h"),
    flg("flags", PREADV2_FLAGS)
);
spec!(S_SENDFILE, int("out_fd"), int("in_fd"), hex("offset"), int("count"));
spec!(
    S_PSELECT6,
    int("nfds"),
    hex("readfds"),
    hex("writefds"),
    hex("exceptfds"),
    timespec("timeout"),
    hex("sigmask")
);
spec!(
    S_PPOLL,
    hex("fds"),
    int("nfds"),
    timespec("tmo"),
    hex("sigmask"),
    int("sigsetsize")
);
spec!(
    S_SIGNALFD4,
    int("fd"),
    hex("mask"),
    int("sizemask"),
    flg("flags", SIGNALFD_FLAGS)
);
spec!(
    S_VMSPLICE,
    int("fd"),
    hex("iov"),
    int("nr_segs"),
    flg("flags", SPLICE_FLAGS)
);
spec!(
    S_SPLICE,
    int("fd_in"),
    hex("off_in"),
    int("fd_out"),
    hex("off_out"),
    int("len"),
    flg("flags", SPLICE_FLAGS)
);
spec!(S_TEE, int("fdin"), int("fdout"), int("len"), flg("flags", SPLICE_FLAGS));
spec!(
    S_READLINKAT,
    dirfd("dirfd"),
    strp("pathname"),
    hex("buf"),
    int("bufsiz")
);
spec!(
    S_NEWFSTATAT,
    dirfd("dirfd"),
    strp("pathname"),
    statp("statbuf"),
    flg("flags", AT_FLAGS)
);
spec!(S_FSTAT, int("fd"), statp("statbuf"));
spec!(
    S_SYNC_FILE_RANGE,
    int("fd"),
    int("offset"),
    int("nbytes"),
    flg("flags", SYNC_FILE_RANGE_FLAGS)
);
spec!(S_TIMERFD_CREATE, enm("clockid", CLOCKS), flg("flags", TIMERFD_FLAGS));
spec!(
    S_TIMERFD_SETTIME,
    int("fd"),
    flg("flags", TIMERFD_SETTIME_FLAGS),
    hex("new_value"),
    hex("old_value")
);
spec!(S_TIMERFD_GETTIME, int("fd"), hex("curr_value"));
spec!(
    S_UTIMENSAT,
    dirfd("dirfd"),
    strp("pathname"),
    hex("times"),
    flg("flags", AT_FLAGS)
);
spec!(S_ACCT, strp("name"));
spec!(S_CAPGET, hex("header"), hex("dataptr"));
spec!(S_PERSONALITY, flg("persona", PERSONALITY_FLAGS));
spec!(S_EXIT, int("error_code"));
spec!(
    S_WAITID,
    enm("which", PRIO_WHICH),
    int("upid"),
    hex("infop"),
    flg("options", WAIT_OPTS),
    hex("ru")
);
spec!(S_SET_TID_ADDRESS, hex("tidptr"));
spec!(S_UNSHARE, flg("flags", UNSHARE_FLAGS));
spec!(
    S_FUTEX,
    hex("uaddr"),
    ArgSpec {
        name: "op",
        ty: ArgType::Enum(FUTEX_OPS)
    },
    int("val"),
    timespec("timeout"),
    hex("uaddr2"),
    hex("val3")
);
spec!(S_SET_ROBUST_LIST, hex("head"), int("len"));
spec!(S_GET_ROBUST_LIST, int("pid"), hex("head_ptr"), hex("len_ptr"));
spec!(S_NANOSLEEP, timespec("req"), timespec("rem"));
spec!(S_GETITIMER, enm("which", ITIMERS), hex("value"));
spec!(S_SETITIMER, enm("which", ITIMERS), hex("new_value"), hex("old_value"));
spec!(
    S_KEXEC_LOAD,
    hex("entry"),
    int("nr_segments"),
    hex("segments"),
    hex("flags")
);
spec!(S_INIT_MODULE, hex("module_image"), int("len"), strp("param_values"));
spec!(S_DELETE_MODULE, strp("name"), flg("flags", OPEN_FLAGS));
spec!(S_TIMER_CREATE, enm("clockid", CLOCKS), hex("sevp"), hex("timerid"));
spec!(S_TIMER_GETTIME, hex("timerid"), hex("curr_value"));
spec!(S_TIMER_GETOVERRUN, hex("timerid"));
spec!(
    S_TIMER_SETTIME,
    hex("timerid"),
    flg("flags", TIMERFD_SETTIME_FLAGS),
    hex("new_value"),
    hex("old_value")
);
spec!(S_TIMER_DELETE, hex("timerid"));
spec!(S_CLOCK_SETTIME, enm("clockid", CLOCKS), timespec("tp"));
spec!(S_CLOCK_GETTIME, enm("clockid", CLOCKS), timespec("tp"));
spec!(S_CLOCK_GETRES, enm("clockid", CLOCKS), timespec("res"));
spec!(
    S_CLOCK_NANOSLEEP,
    enm("clockid", CLOCKS),
    flg("flags", TIMERFD_SETTIME_FLAGS),
    timespec("req"),
    timespec("rem")
);
spec!(S_SYSLOG, int("type"), hex("buf"), int("len"));
spec!(
    S_PTRACE,
    enm("request", PTRACE_REQS),
    int("pid"),
    hex("addr"),
    hex("data")
);
spec!(S_SCHED_SETPARAM, int("pid"), hex("param"));
spec!(
    S_SCHED_SETSCHEDULER,
    int("pid"),
    enm("policy", SCHED_POLICIES),
    hex("param")
);
spec!(S_SCHED_GETSCHEDULER, int("pid"));
spec!(S_SCHED_GETPARAM, int("pid"), hex("param"));
spec!(S_SCHED_SETAFFINITY, int("pid"), int("cpusetsize"), hex("mask"));
spec!(S_SCHED_GETAFFINITY, int("pid"), int("cpusetsize"), hex("mask"));
spec!(S_SCHED_GET_PRIORITY_MAX, enm("policy", SCHED_POLICIES));
spec!(S_SCHED_RR_GET_INTERVAL, int("pid"), timespec("interval"));
spec!(S_KILL, int("pid"), sig("sig"));
spec!(S_TKILL, int("tid"), sig("sig"));
spec!(S_TGKILL, int("tgid"), int("tid"), sig("sig"));
spec!(S_SIGALTSTACK, hex("ss"), hex("old_ss"));
spec!(S_RT_SIGSUSPEND, hex("mask"), int("sigsetsize"));
spec!(
    S_RT_SIGACTION,
    sig("sig"),
    ArgSpec {
        name: "act",
        ty: ArgType::SigAction
    },
    hex("oldact"),
    int("sigsetsize")
);
spec!(
    S_RT_SIGPROCMASK,
    enm("how", SIGPROCMASK_HOW),
    hex("set"),
    hex("oldset"),
    int("sigsetsize")
);
spec!(S_RT_SIGPENDING, hex("set"), int("sigsetsize"));
spec!(
    S_RT_SIGTIMEDWAIT,
    hex("set"),
    hex("info"),
    timespec("timeout"),
    int("sigsetsize")
);
spec!(S_RT_SIGQUEUEINFO, int("tgid"), sig("sig"), hex("info"));
spec!(S_RT_SIGRETURN,);
spec!(S_SETPRIORITY, enm("which", PRIO_WHICH), int("who"), int("niceval"));
spec!(S_GETPRIORITY, enm("which", PRIO_WHICH), int("who"));
spec!(S_REBOOT, hex("magic1"), hex("magic2"), hex("cmd"), hex("arg"));
spec!(S_SETGID, int("gid"));
spec!(S_SETUID, int("uid"));
spec!(S_SETREGID, int("rgid"), int("egid"));
spec!(S_SETREUID, int("ruid"), int("euid"));
spec!(S_SETRESUID, int("ruid"), int("euid"), int("suid"));
spec!(S_GETRESUID, hex("ruid"), hex("euid"), hex("suid"));
spec!(S_SETFSUID, int("fsuid"));
spec!(S_TIMES, hex("tms"));
spec!(S_SETPGID, int("pid"), int("pgid"));
spec!(S_GETPGID, int("pid"));
spec!(S_GETSID, int("pid"));
spec!(S_GETGROUPS, int("size"), hex("list"));
spec!(S_SETGROUPS, int("size"), hex("list"));
spec!(S_UNAME, hex("buf"));
spec!(S_SETHOSTNAME, strp("name"), int("len"));
spec!(S_SETDOMAINNAME, strp("name"), int("len"));
spec!(S_GETRLIMIT, enm("resource", RLIMIT_RES), hex("rlim"));
spec!(S_SETRLIMIT, enm("resource", RLIMIT_RES), hex("rlim"));
spec!(S_GETRUSAGE, enm("who", RUSAGE_WHO), hex("ru"));
spec!(S_UMASK, oct("mask"));
spec!(
    S_PRCTL,
    enm("option", PRCTL_OPTS),
    hex("arg2"),
    hex("arg3"),
    hex("arg4"),
    hex("arg5")
);
spec!(S_GETCPU, hex("cpu"), hex("node"), hex("tcache"));
spec!(S_GETTIMEOFDAY, hex("tv"), hex("tz"));
spec!(S_SETTIMEOFDAY, hex("tv"), hex("tz"));
spec!(S_ADJTIMEX, hex("buf"));
spec!(S_SYSINFO, hex("info"));
spec!(
    S_MQ_OPEN,
    strp("name"),
    flg("oflag", OPEN_FLAGS),
    oct("mode"),
    hex("attr")
);
spec!(S_MQ_UNLINK, strp("name"));
spec!(
    S_MQ_TIMEDSEND,
    hex("mqdes"),
    hex("msg_ptr"),
    int("msg_len"),
    int("msg_prio"),
    timespec("abs_timeout")
);
spec!(
    S_MQ_TIMEDRECEIVE,
    hex("mqdes"),
    hex("msg_ptr"),
    int("msg_len"),
    hex("msg_prio"),
    timespec("abs_timeout")
);
spec!(S_MQ_NOTIFY, hex("mqdes"), hex("sevp"));
spec!(S_MQ_GETSETATTR, hex("mqdes"), hex("newattr"), hex("oldattr"));
spec!(S_MSGGET, hex("key"), flg("msgflg", OPEN_FLAGS));
spec!(S_MSGCTL, int("msqid"), int("cmd"), hex("buf"));
spec!(
    S_MSGRCV,
    int("msqid"),
    hex("msgp"),
    int("msgsz"),
    int("msgtyp"),
    flg("msgflg", OPEN_FLAGS)
);
spec!(
    S_MSGSND,
    int("msqid"),
    hex("msgp"),
    int("msgsz"),
    flg("msgflg", OPEN_FLAGS)
);
spec!(S_SEMGET, hex("key"), int("nsems"), flg("semflg", OPEN_FLAGS));
spec!(S_SEMCTL, int("semid"), int("semnum"), int("cmd"), hex("arg"));
spec!(
    S_SEMTIMEDOP,
    int("semid"),
    hex("sops"),
    int("nsops"),
    timespec("timeout")
);
spec!(S_SEMOP, int("semid"), hex("sops"), int("nsops"));
spec!(S_SHMGET, hex("key"), int("size"), flg("shmflg", OPEN_FLAGS));
spec!(S_SHMCTL, int("shmid"), int("cmd"), hex("buf"));
spec!(S_SHMAT, int("shmid"), hex("shmaddr"), flg("shmflg", OPEN_FLAGS));
spec!(S_SHMDT, hex("shmaddr"));
spec!(
    S_SOCKET,
    enm("domain", SOCK_DOMAINS),
    ArgSpec {
        name: "type",
        ty: ArgType::Int
    },
    int("protocol")
);
spec!(
    S_SOCKETPAIR,
    enm("domain", SOCK_DOMAINS),
    int("type"),
    int("protocol"),
    hex("sv")
);
spec!(S_BIND, int("fd"), sockaddr("addr"), int("addrlen"));
spec!(S_LISTEN, int("fd"), int("backlog"));
spec!(S_ACCEPT, int("fd"), sockaddr("addr"), hex("addrlen"));
spec!(
    S_ACCEPT4,
    int("fd"),
    sockaddr("addr"),
    hex("addrlen"),
    flg("flags", SOCK_FDS_FLAGS)
);
spec!(S_CONNECT, int("fd"), sockaddr("addr"), int("addrlen"));
spec!(S_GETSOCKNAME, int("fd"), sockaddr("addr"), hex("addrlen"));
spec!(S_GETPEERNAME, int("fd"), sockaddr("addr"), hex("addrlen"));
spec!(
    S_SENDTO,
    int("fd"),
    buf("buf", 2),
    int("len"),
    flg("flags", MSG_FLAGS),
    sockaddr("addr"),
    int("addrlen")
);
spec!(
    S_RECVFROM,
    int("fd"),
    buf("buf", 2),
    int("len"),
    flg("flags", MSG_FLAGS),
    sockaddr("addr"),
    hex("addrlen")
);
spec!(
    S_SETSOCKOPT,
    int("fd"),
    int("level"),
    int("optname"),
    hex("optval"),
    int("optlen")
);
spec!(
    S_GETSOCKOPT,
    int("fd"),
    int("level"),
    int("optname"),
    hex("optval"),
    hex("optlen")
);
spec!(S_SHUTDOWN, int("fd"), enm("how", SHUT_HOW));
spec!(S_SENDMSG, int("fd"), hex("msg"), flg("flags", MSG_FLAGS));
spec!(S_RECVMSG, int("fd"), hex("msg"), flg("flags", MSG_FLAGS));
spec!(S_READAHEAD, int("fd"), int("offset"), int("count"));
spec!(S_BRK, hex("brk"));
spec!(S_MUNMAP, hex("addr"), int("length"));
spec!(
    S_MREMAP,
    hex("old_address"),
    int("old_size"),
    int("new_size"),
    flg("flags", MREMAP_FLAGS),
    hex("new_address")
);
spec!(
    S_ADD_KEY,
    strp("type"),
    strp("description"),
    hex("payload"),
    int("plen"),
    hex("keyring")
);
spec!(
    S_REQUEST_KEY,
    strp("type"),
    strp("description"),
    strp("callout_info"),
    hex("dest_keyring")
);
spec!(
    S_KEYCTL,
    int("option"),
    hex("arg2"),
    hex("arg3"),
    hex("arg4"),
    hex("arg5")
);
spec!(
    S_CLONE,
    flg("flags", CLONE_FLAGS),
    hex("stack"),
    hex("parent_tid"),
    hex("child_tid"),
    hex("tls")
);
spec!(S_EXECVE, strp("filename"), hex("argv"), hex("envp"));
spec!(
    S_EXECVEAT,
    dirfd("dirfd"),
    strp("pathname"),
    hex("argv"),
    hex("envp"),
    flg("flags", AT_FLAGS)
);
spec!(
    S_MMAP,
    hex("addr"),
    int("length"),
    flg("prot", PROT_FLAGS),
    flg("flags", MAP_FLAGS),
    int("fd"),
    hex("offset")
);
spec!(S_FADVISE64, int("fd"), int("offset"), int("len"), int("advice"));
spec!(S_SWAPON, strp("path"), hex("swapflags"));
spec!(S_SWAPOFF, strp("path"));
spec!(S_MPROTECT, hex("start"), int("len"), flg("prot", PROT_FLAGS));
spec!(S_MSYNC, hex("start"), int("len"), flg("flags", MSYNC_FLAGS));
spec!(S_MLOCK, hex("start"), int("len"));
spec!(S_MUNLOCK, hex("start"), int("len"));
spec!(S_MLOCKALL, flg("flags", MLOCKALL_FLAGS));
spec!(S_MINCORE, hex("start"), int("len"), hex("vec"));
spec!(S_MADVISE, hex("addr"), int("len"), enm("advice", MADV_OPTS));
spec!(
    S_REMAP_FILE_PAGES,
    hex("start"),
    int("size"),
    int("prot"),
    int("pgoff"),
    int("flags")
);
spec!(
    S_MBIND,
    hex("start"),
    int("len"),
    int("mode"),
    hex("nmask"),
    int("maxnode"),
    flg("flags", OPEN_FLAGS)
);
spec!(
    S_GET_MEMPOLICY,
    hex("policy"),
    hex("nmask"),
    int("maxnode"),
    hex("addr"),
    hex("flags")
);
spec!(S_SET_MEMPOLICY, int("mode"), hex("nmask"), int("maxnode"));
spec!(
    S_MIGRATE_PAGES,
    int("pid"),
    int("maxnode"),
    hex("old_nodes"),
    hex("new_nodes")
);
spec!(
    S_MOVE_PAGES,
    int("pid"),
    int("nr_pages"),
    hex("pages"),
    hex("nodes"),
    hex("status"),
    int("flags")
);
spec!(S_RT_TGSIGQUEUEINFO, int("tgid"), int("tid"), sig("sig"), hex("info"));
spec!(
    S_PERF_EVENT_OPEN,
    hex("attr"),
    int("pid"),
    int("cpu"),
    int("group_fd"),
    hex("flags")
);
spec!(
    S_RECVMMSG,
    int("fd"),
    hex("mmsg"),
    int("vlen"),
    flg("flags", MSG_FLAGS),
    timespec("timeout")
);
spec!(
    S_WAIT4,
    int("pid"),
    hex("wstatus"),
    flg("options", WAIT_OPTS),
    hex("rusage")
);
spec!(
    S_PRLIMIT64,
    int("pid"),
    enm("resource", RLIMIT_RES),
    hex("new_rlim"),
    hex("old_rlim")
);
spec!(
    S_FANOTIFY_INIT,
    flg("flags", OPEN_FLAGS),
    flg("event_f_flags", OPEN_FLAGS)
);
spec!(
    S_FANOTIFY_MARK,
    int("fd"),
    flg("flags", OPEN_FLAGS),
    hex("mask"),
    dirfd("dirfd"),
    strp("pathname")
);
spec!(
    S_NAME_TO_HANDLE_AT,
    dirfd("dirfd"),
    strp("pathname"),
    hex("handle"),
    hex("mnt_id"),
    flg("flags", AT_FLAGS)
);
spec!(
    S_OPEN_BY_HANDLE_AT,
    int("mount_fd"),
    hex("handle"),
    flg("flags", OPEN_FLAGS)
);
spec!(S_CLOCK_ADJTIME, enm("clockid", CLOCKS), hex("buf"));
spec!(S_SYNCFS, int("fd"));
spec!(S_SETNS, int("fd"), enm("nstype", SETNS_FLAGS));
spec!(S_SENDMMSG, int("fd"), hex("mmsg"), int("vlen"), flg("flags", MSG_FLAGS));
spec!(
    S_PROCESS_VM_READV,
    int("pid"),
    hex("lvec"),
    int("liovcnt"),
    hex("rvec"),
    int("riovcnt"),
    hex("flags")
);
spec!(
    S_KCMP,
    int("pid1"),
    int("pid2"),
    enm("type", KCMP_TYPES),
    hex("idx1"),
    hex("idx2")
);
spec!(
    S_FINIT_MODULE,
    int("fd"),
    strp("param_values"),
    flg("flags", OPEN_FLAGS)
);
spec!(S_SCHED_SETATTR, int("pid"), hex("attr"), hex("flags"));
spec!(S_SCHED_GETATTR, int("pid"), hex("attr"), int("size"), hex("flags"));
spec!(
    S_SECCOMP,
    enm("operation", SECCOMP_OPS),
    hex("flags"),
    ArgSpec {
        name: "args",
        ty: ArgType::SeccompFprog
    }
);
spec!(S_GETRANDOM, buf("buf", 1), int("count"), flg("flags", GETRANDOM_FLAGS));
spec!(S_MEMFD_CREATE, strp("name"), flg("flags", MEMFD_FLAGS));
spec!(S_BPF, enm("cmd", BPF_CMDS), hex("attr"), int("size"));
spec!(S_USERFAULTFD, flg("flags", UFFD_FLAGS));
spec!(
    S_MEMBARRIER,
    enm("cmd", MEMBARRIER_CMDS),
    flg("flags", OPEN_FLAGS),
    int("cpu_id")
);
spec!(S_MLOCK2, hex("start"), int("len"), flg("flags", MLOCKALL_FLAGS));
spec!(
    S_COPY_FILE_RANGE,
    int("fd_in"),
    hex("off_in"),
    int("fd_out"),
    hex("off_out"),
    int("len"),
    flg("flags", OPEN_FLAGS)
);
spec!(
    S_PKEY_MPROTECT,
    hex("start"),
    int("len"),
    flg("prot", PROT_FLAGS),
    int("pkey")
);
spec!(S_PKEY_ALLOC, flg("flags", OPEN_FLAGS), hex("access_rights"));
spec!(S_PKEY_FREE, int("pkey"));
spec!(
    S_STATX,
    dirfd("dirfd"),
    strp("pathname"),
    flg("flags", STATX_ATFLAGS),
    flg("mask", STATX_MASK),
    hex("statxbuf")
);
spec!(
    S_IO_PGETEVENTS,
    hex("ctx_id"),
    int("min_nr"),
    int("nr"),
    hex("events"),
    timespec("timeout"),
    hex("usig")
);
spec!(
    S_RSEQ,
    hex("rseq"),
    int("rseq_len"),
    flg("flags", OPEN_FLAGS),
    hex("sig")
);
spec!(
    S_KEXEC_FILE_LOAD,
    int("kernel_fd"),
    int("initrd_fd"),
    int("cmdline_len"),
    hex("cmdline"),
    hex("flags")
);
spec!(S_PIDFD_SEND_SIGNAL, int("pidfd"), sig("sig"), hex("info"), hex("flags"));
spec!(S_IO_URING_SETUP, int("entries"), hex("params"));
spec!(
    S_IO_URING_ENTER,
    int("fd"),
    int("to_submit"),
    int("min_complete"),
    flg("flags", IOURING_ENTER_FLAGS),
    hex("sig"),
    int("sigsz")
);
spec!(
    S_IO_URING_REGISTER,
    int("fd"),
    int("opcode"),
    hex("arg"),
    int("nr_args")
);
spec!(S_OPEN_TREE, dirfd("dirfd"), strp("pathname"), flg("flags", AT_FLAGS));
spec!(
    S_MOVE_MOUNT,
    dirfd("from_dirfd"),
    strp("from_pathname"),
    dirfd("to_dirfd"),
    strp("to_pathname"),
    flg("flags", OPEN_FLAGS)
);
spec!(S_FSOPEN, strp("fs_name"), flg("flags", OPEN_FLAGS));
spec!(S_FSCONFIG, int("fd"), int("cmd"), strp("key"), hex("value"), int("aux"));
spec!(
    S_FSMOUNT,
    int("fd"),
    flg("flags", OPEN_FLAGS),
    flg("attr_flags", OPEN_FLAGS)
);
spec!(S_FSPICK, dirfd("dirfd"), strp("pathname"), flg("flags", AT_FLAGS));
spec!(S_PIDFD_OPEN, int("pid"), hex("flags"));
spec!(
    S_CLONE3,
    ArgSpec {
        name: "cl_args",
        ty: ArgType::CloneArgs
    },
    int("size")
);
spec!(
    S_CLOSE_RANGE,
    int("first"),
    int("last"),
    flg("flags", CLOSE_RANGE_FLAGS)
);
spec!(S_OPENAT2, dirfd("dirfd"), strp("pathname"), hex("how"), int("usize"));
spec!(S_PIDFD_GETFD, int("pidfd"), int("fd"), hex("flags"));
spec!(
    S_PROCESS_MADVISE,
    int("pidfd"),
    hex("iov"),
    int("n"),
    enm("advice", MADV_OPTS),
    hex("flags")
);
spec!(
    S_EPOLL_PWAIT2,
    int("epfd"),
    hex("events"),
    int("maxevents"),
    timespec("timeout"),
    hex("sigmask"),
    int("sigsetsize")
);
spec!(
    S_MOUNT_SETATTR,
    dirfd("dirfd"),
    strp("pathname"),
    flg("flags", AT_FLAGS),
    hex("uattr"),
    int("usize")
);
spec!(S_QUOTACTL_FD, int("fd"), hex("cmd"), int("id"), hex("addr"));
spec!(
    S_LANDLOCK_CREATE_RULESET,
    hex("attr"),
    int("size"),
    flg("flags", OPEN_FLAGS)
);
spec!(
    S_LANDLOCK_ADD_RULE,
    int("ruleset_fd"),
    int("rule_type"),
    hex("rule_attr"),
    flg("flags", OPEN_FLAGS)
);
spec!(S_LANDLOCK_RESTRICT_SELF, int("ruleset_fd"), flg("flags", OPEN_FLAGS));
spec!(S_MEMFD_SECRET, flg("flags", OPEN_FLAGS));
spec!(S_PROCESS_MRELEASE, int("pidfd"), hex("flags"));
spec!(
    S_FUTEX_WAITV,
    hex("waiters"),
    int("nr_futexes"),
    flg("flags", OPEN_FLAGS),
    timespec("timeout"),
    enm("clockid", CLOCKS)
);
spec!(
    S_SET_MEMPOLICY_HOME_NODE,
    hex("start"),
    int("len"),
    int("home_node"),
    hex("flags")
);
// 兜底:未在表中的 syscall 也给出 x0-x5
spec!(
    S_FALLBACK,
    hex("x0"),
    hex("x1"),
    hex("x2"),
    hex("x3"),
    hex("x4"),
    hex("x5")
);

pub fn syscall_argspec(nr: i64) -> Option<&'static [ArgSpec]> {
    Some(match nr {
        0 => S_IO_SETUP,
        1 => S_IO_DESTROY,
        2 => S_IO_SUBMIT,
        3 => S_IO_CANCEL,
        4 => S_IO_GETEVENTS,
        5 => S_SETXATTR_PATH,
        6 => S_SETXATTR_PATH,
        7 => S_SETXATTR_FD,
        8 => S_XATTR_PATH,
        9 => S_XATTR_PATH,
        10 => S_XATTR_FD,
        11 => S_LISTXATTR_PATH,
        12 => S_LISTXATTR_PATH,
        13 => S_LISTXATTR_FD,
        14 => S_REMOVEXATTR_PATH,
        15 => S_REMOVEXATTR_PATH,
        16 => S_REMOVEXATTR_FD,
        17 => S_GETCWD,
        18 => S_LOOKUP_DCOOKIE,
        19 => S_EVENTFD2,
        20 => S_EPOLL_CREATE1,
        21 => S_EPOLL_CTL,
        22 => S_EPOLL_PWAIT,
        23 => S_DUP,
        24 => S_DUP3,
        25 => S_FCNTL,
        26 => S_INOTIFY_INIT1,
        27 => S_INOTIFY_ADD_WATCH,
        28 => S_INOTIFY_RM_WATCH,
        29 => S_IOCTL,
        30 => S_IOPRIO_SET,
        31 => S_IOPRIO_GET,
        32 => S_FLOCK,
        33 => S_MKNODAT,
        34 => S_MKDIRAT,
        35 => S_UNLINKAT,
        36 => S_SYMLINKAT,
        37 => S_LINKAT,
        38 => S_RENAMEAT,
        39 => S_UMOUNT2,
        40 => S_MOUNT,
        41 => S_PIVOT_ROOT,
        42 => S_NONE,
        43 => S_STATFS,
        44 => S_FSTATFS,
        45 => S_TRUNCATE,
        46 => S_FTRUNCATE,
        47 => S_FALLOCATE,
        48 => S_FACCESSAT,
        49 => S_CHDIR,
        50 => S_FCHDIR,
        51 => S_CHROOT,
        52 => S_FCHMOD,
        53 => S_FCHMODAT,
        54 => S_FCHOWNAT,
        55 => S_FCHOWN,
        56 => S_OPENAT,
        57 => S_CLOSE,
        58 => S_NONE,
        59 => S_PIPE2,
        60 => S_QUOTACTL,
        61 => S_GETDENTS64,
        62 => S_LSEEK,
        63 => S_READ,
        64 => S_WRITE,
        65 => S_IOV,
        66 => S_IOV,
        67 => S_PREAD64,
        68 => S_PWRITE64,
        69 => S_PREADV,
        70 => S_PREADV,
        71 => S_SENDFILE,
        72 => S_PSELECT6,
        73 => S_PPOLL,
        74 => S_SIGNALFD4,
        75 => S_VMSPLICE,
        76 => S_SPLICE,
        77 => S_TEE,
        78 => S_READLINKAT,
        79 => S_NEWFSTATAT,
        80 => S_FSTAT,
        81 => S_NONE,
        82 => S_CLOSE,
        83 => S_CLOSE,
        84 => S_SYNC_FILE_RANGE,
        85 => S_TIMERFD_CREATE,
        86 => S_TIMERFD_SETTIME,
        87 => S_TIMERFD_GETTIME,
        88 => S_UTIMENSAT,
        89 => S_ACCT,
        90 => S_CAPGET,
        91 => S_CAPGET,
        92 => S_PERSONALITY,
        93 => S_EXIT,
        94 => S_EXIT,
        95 => S_WAITID,
        96 => S_SET_TID_ADDRESS,
        97 => S_UNSHARE,
        98 => S_FUTEX,
        99 => S_SET_ROBUST_LIST,
        100 => S_GET_ROBUST_LIST,
        101 => S_NANOSLEEP,
        102 => S_GETITIMER,
        103 => S_SETITIMER,
        104 => S_KEXEC_LOAD,
        105 => S_INIT_MODULE,
        106 => S_DELETE_MODULE,
        107 => S_TIMER_CREATE,
        108 => S_TIMER_GETTIME,
        109 => S_TIMER_GETOVERRUN,
        110 => S_TIMER_SETTIME,
        111 => S_TIMER_DELETE,
        112 => S_CLOCK_SETTIME,
        113 => S_CLOCK_GETTIME,
        114 => S_CLOCK_GETRES,
        115 => S_CLOCK_NANOSLEEP,
        116 => S_SYSLOG,
        117 => S_PTRACE,
        118 => S_SCHED_SETPARAM,
        119 => S_SCHED_SETSCHEDULER,
        120 => S_SCHED_GETSCHEDULER,
        121 => S_SCHED_GETPARAM,
        122 => S_SCHED_SETAFFINITY,
        123 => S_SCHED_GETAFFINITY,
        124 => S_NONE,
        125 => S_SCHED_GET_PRIORITY_MAX,
        126 => S_SCHED_GET_PRIORITY_MAX,
        127 => S_SCHED_RR_GET_INTERVAL,
        128 => S_NONE,
        129 => S_KILL,
        130 => S_TKILL,
        131 => S_TGKILL,
        132 => S_SIGALTSTACK,
        133 => S_RT_SIGSUSPEND,
        134 => S_RT_SIGACTION,
        135 => S_RT_SIGPROCMASK,
        136 => S_RT_SIGPENDING,
        137 => S_RT_SIGTIMEDWAIT,
        138 => S_RT_SIGQUEUEINFO,
        139 => S_RT_SIGRETURN,
        140 => S_SETPRIORITY,
        141 => S_GETPRIORITY,
        142 => S_REBOOT,
        143 => S_SETREGID,
        144 => S_SETGID,
        145 => S_SETREUID,
        146 => S_SETUID,
        147 => S_SETRESUID,
        148 => S_GETRESUID,
        149 => S_SETRESUID,
        150 => S_GETRESUID,
        151 => S_SETFSUID,
        152 => S_SETFSUID,
        153 => S_TIMES,
        154 => S_SETPGID,
        155 => S_GETPGID,
        156 => S_GETSID,
        157 => S_NONE,
        158 => S_GETGROUPS,
        159 => S_SETGROUPS,
        160 => S_UNAME,
        161 => S_SETHOSTNAME,
        162 => S_SETDOMAINNAME,
        163 => S_GETRLIMIT,
        164 => S_SETRLIMIT,
        165 => S_GETRUSAGE,
        166 => S_UMASK,
        167 => S_PRCTL,
        168 => S_GETCPU,
        169 => S_GETTIMEOFDAY,
        170 => S_SETTIMEOFDAY,
        171 => S_ADJTIMEX,
        172 => S_NONE,
        173 => S_NONE,
        174 => S_NONE,
        175 => S_NONE,
        176 => S_NONE,
        177 => S_NONE,
        178 => S_NONE,
        179 => S_SYSINFO,
        180 => S_MQ_OPEN,
        181 => S_MQ_UNLINK,
        182 => S_MQ_TIMEDSEND,
        183 => S_MQ_TIMEDRECEIVE,
        184 => S_MQ_NOTIFY,
        185 => S_MQ_GETSETATTR,
        186 => S_MSGGET,
        187 => S_MSGCTL,
        188 => S_MSGRCV,
        189 => S_MSGSND,
        190 => S_SEMGET,
        191 => S_SEMCTL,
        192 => S_SEMTIMEDOP,
        193 => S_SEMOP,
        194 => S_SHMGET,
        195 => S_SHMCTL,
        196 => S_SHMAT,
        197 => S_SHMDT,
        198 => S_SOCKET,
        199 => S_SOCKETPAIR,
        200 => S_BIND,
        201 => S_LISTEN,
        202 => S_ACCEPT,
        203 => S_CONNECT,
        204 => S_GETSOCKNAME,
        205 => S_GETPEERNAME,
        206 => S_SENDTO,
        207 => S_RECVFROM,
        208 => S_SETSOCKOPT,
        209 => S_GETSOCKOPT,
        210 => S_SHUTDOWN,
        211 => S_SENDMSG,
        212 => S_RECVMSG,
        213 => S_READAHEAD,
        214 => S_BRK,
        215 => S_MUNMAP,
        216 => S_MREMAP,
        217 => S_ADD_KEY,
        218 => S_REQUEST_KEY,
        219 => S_KEYCTL,
        220 => S_CLONE,
        221 => S_EXECVE,
        222 => S_MMAP,
        223 => S_FADVISE64,
        224 => S_SWAPON,
        225 => S_SWAPOFF,
        226 => S_MPROTECT,
        227 => S_MSYNC,
        228 => S_MLOCK,
        229 => S_MUNLOCK,
        230 => S_MLOCKALL,
        231 => S_NONE,
        232 => S_MINCORE,
        233 => S_MADVISE,
        234 => S_REMAP_FILE_PAGES,
        235 => S_MBIND,
        236 => S_GET_MEMPOLICY,
        237 => S_SET_MEMPOLICY,
        238 => S_MIGRATE_PAGES,
        239 => S_MOVE_PAGES,
        240 => S_RT_TGSIGQUEUEINFO,
        241 => S_PERF_EVENT_OPEN,
        242 => S_ACCEPT4,
        243 => S_RECVMMSG,
        260 => S_WAIT4,
        261 => S_PRLIMIT64,
        262 => S_FANOTIFY_INIT,
        263 => S_FANOTIFY_MARK,
        264 => S_NAME_TO_HANDLE_AT,
        265 => S_OPEN_BY_HANDLE_AT,
        266 => S_CLOCK_ADJTIME,
        267 => S_SYNCFS,
        268 => S_SETNS,
        269 => S_SENDMMSG,
        270 => S_PROCESS_VM_READV,
        271 => S_PROCESS_VM_READV,
        272 => S_KCMP,
        273 => S_FINIT_MODULE,
        274 => S_SCHED_SETATTR,
        275 => S_SCHED_GETATTR,
        276 => S_RENAMEAT2,
        277 => S_SECCOMP,
        278 => S_GETRANDOM,
        279 => S_MEMFD_CREATE,
        280 => S_BPF,
        281 => S_EXECVEAT,
        282 => S_USERFAULTFD,
        283 => S_MEMBARRIER,
        284 => S_MLOCK2,
        285 => S_COPY_FILE_RANGE,
        286 => S_PREADV2,
        287 => S_PREADV2,
        288 => S_PKEY_MPROTECT,
        289 => S_PKEY_ALLOC,
        290 => S_PKEY_FREE,
        291 => S_STATX,
        292 => S_IO_PGETEVENTS,
        293 => S_RSEQ,
        294 => S_KEXEC_FILE_LOAD,
        424 => S_PIDFD_SEND_SIGNAL,
        425 => S_IO_URING_SETUP,
        426 => S_IO_URING_ENTER,
        427 => S_IO_URING_REGISTER,
        428 => S_OPEN_TREE,
        429 => S_MOVE_MOUNT,
        430 => S_FSOPEN,
        431 => S_FSCONFIG,
        432 => S_FSMOUNT,
        433 => S_FSPICK,
        434 => S_PIDFD_OPEN,
        435 => S_CLONE3,
        436 => S_CLOSE_RANGE,
        437 => S_OPENAT2,
        438 => S_PIDFD_GETFD,
        439 => S_FACCESSAT2,
        440 => S_PROCESS_MADVISE,
        441 => S_EPOLL_PWAIT2,
        442 => S_MOUNT_SETATTR,
        443 => S_QUOTACTL_FD,
        444 => S_LANDLOCK_CREATE_RULESET,
        445 => S_LANDLOCK_ADD_RULE,
        446 => S_LANDLOCK_RESTRICT_SELF,
        447 => S_MEMFD_SECRET,
        448 => S_PROCESS_MRELEASE,
        449 => S_FUTEX_WAITV,
        450 => S_SET_MEMPOLICY_HOME_NODE,
        _ => return None,
    })
}

// =====================================================================
// 目标进程内存读取（/proc/<pid>/mem）
// =====================================================================

thread_local! {
    static MEM_FILES: RefCell<HashMap<u32, File>> = RefCell::new(HashMap::new());
}

fn with_mem_file<R>(pid: u32, f: impl FnOnce(&File) -> std::io::Result<R>) -> Option<R> {
    MEM_FILES.with(|m| {
        let mut m = m.borrow_mut();
        if !m.contains_key(&pid) {
            match File::open(format!("/proc/{}/mem", pid)) {
                Ok(file) => {
                    m.insert(pid, file);
                }
                Err(_) => return None,
            }
        }
        let file = m.get(&pid)?;
        match f(file) {
            Ok(v) => Some(v),
            Err(_) => {
                m.remove(&pid);
                None
            }
        }
    })
}

fn read_mem(pid: u32, addr: u64, len: usize) -> Option<Vec<u8>> {
    read_mem_pub(pid, addr, len)
}

/// 供 stackwalk 等模块复用的目标进程内存读取
pub fn read_mem_pub(pid: u32, addr: u64, len: usize) -> Option<Vec<u8>> {
    if addr == 0 || addr >= 0x0000_8000_0000_0000 || len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    let n = with_mem_file(pid, |f| f.read_at(&mut buf, addr))?;
    buf.truncate(n);
    if buf.is_empty() {
        return None;
    }
    Some(buf)
}

/// 读 C 字符串（最多 max_len，遇 \0 截断，不可打印字符转义）
pub fn read_c_string(pid: u32, addr: u64, max_len: usize) -> Option<String> {
    let buf = read_mem(pid, addr, max_len)?;
    Some(format_c_string(&buf))
}

fn format_c_string(mut buf: &[u8]) -> String {
    if let Some(pos) = buf.iter().position(|&b| b == 0) {
        buf = &buf[..pos];
    }
    let mut out = String::with_capacity(buf.len());
    for &b in buf {
        match b {
            0x20..=0x7e => out.push(b as char),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            _ => {
                out.push_str("\\x");
                push_hex_byte(&mut out, b);
            }
        }
    }
    out
}

fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn rd_i32(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn rd_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}
fn rd_i64(b: &[u8], off: usize) -> i64 {
    rd_u64(b, off) as i64
}

// =====================================================================
// 标量/标志渲染
// =====================================================================

fn render_enum(table: &[(i64, &'static str)], v: u64) -> String {
    let iv = v as i64;
    for (k, name) in table {
        if *k == iv {
            return name.to_string();
        }
    }
    // futex op 带 PRIVATE/SHARED 标志位
    format!("0x{:x}", v)
}

fn render_futex_op(v: u64) -> String {
    let op = (v & 0x7f) as i64;
    let mut s = render_enum(FUTEX_OPS, op as u64);
    if s.starts_with("0x") {
        s = format!("op={}", op);
    }
    let mut extra = Vec::new();
    if v & 128 != 0 {
        extra.push("FUTEX_PRIVATE_FLAG");
    }
    if v & 256 != 0 {
        extra.push("FUTEX_CLOCK_REALTIME");
    }
    if extra.is_empty() {
        s
    } else {
        format!("{}|{}", s, extra.join("|"))
    }
}

fn render_flags(table: &[(u64, &'static str)], v: u64) -> String {
    if v == 0 {
        return "0".to_string();
    }
    let mut names: Vec<&str> = Vec::new();
    let mut rest = v;
    for (bit, name) in table {
        if *bit != 0 && v & bit == *bit {
            names.push(name);
            rest &= !bit;
        }
    }
    let mut s = names.join("|");
    if rest != 0 {
        if !s.is_empty() {
            s.push('|');
        }
        s.push_str(&format!("0x{:x}", rest));
    }
    if s.is_empty() {
        format!("0x{:x}", v)
    } else {
        s
    }
}

fn render_open_flags(v: u64) -> String {
    let accmode = v & 0o3;
    let acc = match accmode {
        0 => "O_RDONLY",
        1 => "O_WRONLY",
        2 => "O_RDWR",
        _ => "O_ACCMODE?",
    };
    let rest = render_flags(OPEN_FLAGS, v & !0o3);
    if rest == "0" {
        acc.to_string()
    } else {
        format!("{}|{}", acc, rest)
    }
}

fn render_signal(v: u64) -> String {
    let iv = v as i64;
    if iv > 31 && iv <= 64 {
        return format!("SIGRT{}", iv - 32);
    }
    render_enum(SIGNALS, v)
}

fn render_dirfd(v: u64) -> String {
    // 应用常以 w0 传参,高 32 位为 0:-100 表现为 0xFFFFFF9C,需按 32 位解释
    if v as i64 == -100 || (v as u32) as i32 == -100 {
        "AT_FDCWD".to_string()
    } else {
        format!("{}", v as i64)
    }
}

fn render_ioctl_req(v: u64) -> String {
    let nr = v & 0xff;
    let ty = ((v >> 8) & 0xff) as u8;
    let size = (v >> 16) & 0x3fff;
    let dir = (v >> 30) & 0x3;
    let dir_s = match dir {
        0 => "N",
        1 => "W",
        2 => "R",
        _ => "RW",
    };
    let ty_c = if ty.is_ascii_graphic() { ty as char } else { '?' };
    format!("0x{:x}(dir={} type='{}' nr={} size={})", v, dir_s, ty_c, nr, size)
}

// =====================================================================
// 结构体渲染
// =====================================================================

fn render_sockaddr(pid: u32, addr: u64) -> String {
    read_mem(pid, addr, 128)
        .and_then(|b| format_sockaddr(&b, addr))
        .unwrap_or_else(|| format!("0x{:x}", addr))
}

fn format_sockaddr(b: &[u8], addr: u64) -> Option<String> {
    if b.len() < 2 {
        return None;
    }
    let family = rd_u16(b, 0);
    // /proc/<pid>/mem 允许短读；每个族必须包含下面实际访问的所有字段。
    let required = match family {
        2 | 17 | 31 => 8,
        10 => 24,
        16 | 40 => 12,
        _ => 2,
    };
    if b.len() < required {
        return None;
    }
    Some(match family {
        1 => {
            // AF_UNIX
            let path = format_c_string(&b[2..b.len().min(109)]);
            if path.is_empty() {
                "AF_UNIX(unnamed)".to_string()
            } else {
                format!("AF_UNIX \"{}\"", path)
            }
        }
        2 => {
            // AF_INET
            let port = u16::from_be_bytes([b[2], b[3]]);
            let ip = format!("{}.{}.{}.{}", b[4], b[5], b[6], b[7]);
            format!("AF_INET {}:{}", ip, port)
        }
        10 => {
            // AF_INET6
            let port = u16::from_be_bytes([b[2], b[3]]);
            let mut seg = String::new();
            for i in 0..8 {
                if i > 0 {
                    seg.push(':');
                }
                let _ = write!(seg, "{:x}", u16::from_be_bytes([b[8 + i * 2], b[8 + i * 2 + 1]]));
            }
            format!("AF_INET6 [{}]:{}", seg, port)
        }
        16 => {
            // AF_NETLINK
            let pid_v = rd_u32(b, 4);
            let groups = rd_u32(b, 8);
            format!("AF_NETLINK pid={} groups=0x{:x}", pid_v, groups)
        }
        17 => {
            // AF_PACKET
            let proto = u16::from_be_bytes([b[2], b[3]]);
            let ifindex = rd_i32(b, 4);
            format!("AF_PACKET proto=0x{:x} ifindex={}", proto, ifindex)
        }
        40 => {
            // AF_VSOCK
            let port = rd_u32(b, 4);
            let cid = rd_u32(b, 8);
            format!("AF_VSOCK cid={} port={}", cid, port)
        }
        31 => {
            // AF_BLUETOOTH
            let mac = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                b[7], b[6], b[5], b[4], b[3], b[2]
            );
            format!("AF_BLUETOOTH {}", mac)
        }
        _ => format!("sa_family={} 0x{:x}", family, addr),
    })
}

fn render_stat(pid: u32, addr: u64) -> String {
    let Some(b) = read_mem(pid, addr, 112) else {
        return format!("0x{:x}(out)", addr);
    };
    if b.len() < 104 {
        return format!("0x{:x}(out)", addr);
    }
    let mode = rd_u32(&b, 16);
    let uid = rd_u32(&b, 24);
    let gid = rd_u32(&b, 28);
    let size = rd_i64(&b, 48);
    let mtime = rd_i64(&b, 88);
    let mode_ty = match mode & 0o170000 {
        0o100000 => "reg",
        0o040000 => "dir",
        0o120000 => "lnk",
        0o140000 => "sock",
        0o060000 => "blk",
        0o020000 => "chr",
        0o010000 => "fifo",
        _ => "?",
    };
    format!(
        "0x{:x}(out){{{} mode=0o{:o} uid={} gid={} size={} mtime={}}}",
        addr,
        mode_ty,
        mode & 0o7777,
        uid,
        gid,
        size,
        mtime
    )
}

fn render_clone_args(pid: u32, addr: u64) -> String {
    read_mem(pid, addr, 88)
        .and_then(|b| format_clone_args(&b))
        .unwrap_or_else(|| format!("0x{:x}", addr))
}

/// Format captured clone_args bytes without reading process memory.
fn format_clone_args(b: &[u8]) -> Option<String> {
    if b.len() < 64 {
        return None;
    }
    let flags = rd_u64(b, 0);
    let parent_tid = rd_u64(b, 24);
    let exit_signal = rd_u64(b, 32);
    let stack = rd_u64(b, 40);
    let stack_size = rd_u64(b, 48);
    let tls = rd_u64(b, 56);
    // clone3 has a separate exit_signal field; even the low flags byte belongs
    // to flags (for example CLONE_NEWTIME), not the legacy clone exit signal.
    let flags_s = render_flags(CLONE_FLAGS, flags);
    let sig_s = render_signal(exit_signal);
    Some(format!(
        "{{flags={} exit_sig={} stack=0x{:x} stack_size=0x{:x} tls=0x{:x} parent_tid=0x{:x}}}",
        flags_s, sig_s, stack, stack_size, tls, parent_tid
    ))
}

fn render_sigaction(pid: u32, addr: u64) -> String {
    if addr == 0 {
        return "NULL".to_string();
    }
    let Some(b) = read_mem(pid, addr, 32) else {
        return format!("0x{:x}", addr);
    };
    if b.len() < 32 {
        return format!("0x{:x}", addr);
    }
    let handler = rd_u64(&b, 0);
    let flags = rd_u64(&b, 8);
    let handler_s = match handler {
        0 => "SIG_DFL".to_string(),
        1 => "SIG_IGN".to_string(),
        h => format!("0x{:x}", h),
    };
    format!(
        "{{handler={} flags={}}}",
        handler_s,
        render_flags(SIGACTION_FLAGS, flags)
    )
}

fn render_timespec(pid: u32, addr: u64) -> String {
    if addr == 0 {
        return "NULL".to_string();
    }
    let Some(b) = read_mem(pid, addr, 16) else {
        return format!("0x{:x}", addr);
    };
    if b.len() < 16 {
        return format!("0x{:x}", addr);
    }
    let sec = rd_i64(&b, 0);
    let nsec = rd_i64(&b, 8);
    format!("{}.{:09}s", sec, nsec)
}

fn render_seccomp_fprog(pid: u32, addr: u64) -> String {
    if addr == 0 {
        return "NULL".to_string();
    }
    let Some(b) = read_mem(pid, addr, 16) else {
        return format!("0x{:x}", addr);
    };
    if b.len() < 16 {
        return format!("0x{:x}", addr);
    }
    let len = rd_u16(&b, 0);
    let filter = rd_u64(&b, 8);
    // 读前 min(len,16) 条 sock_filter(每条 8B: code u16, jt u8, jf u8, k u32)
    let show = (len as usize).min(16);
    let mut rules = String::new();
    if let Some(fb) = read_mem(pid, filter, show * 8) {
        for i in 0..(fb.len() / 8) {
            let code = rd_u16(&fb, i * 8);
            let jt = fb[i * 8 + 2];
            let jf = fb[i * 8 + 3];
            let k = rd_u32(&fb, i * 8 + 4);
            if i > 0 {
                rules.push_str(", ");
            }
            rules.push_str(&format!("[{}]c=0x{:02x} jt={} jf={} k=0x{:08x}", i, code, jt, jf, k));
        }
    }
    format!(
        "sock_fprog{{len={} filter=0x{:x} rules={}{}{}}}",
        len,
        filter,
        "[",
        rules,
        if len as usize > show { "]...(truncated)" } else { "]" }
    )
}

// =====================================================================
// hexdump（xxd 风格）
// =====================================================================

const BUFFER_DUMP_LIMIT: usize = 4096;
const BUFFER_PREVIEW_LIMIT: usize = 32;

fn push_hex_byte(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
}

/// 生成 xxd 风格 hexdump 块（16B/行，带偏移和 ASCII），最多 4KB。
pub fn hexdump_block(pid: u32, addr: u64, len: usize, label: &str) -> Option<String> {
    let data = read_mem(pid, addr, len.min(BUFFER_DUMP_LIMIT))?;
    Some(format_hexdump(&data, addr, len, label))
}

fn format_hexdump(data: &[u8], addr: u64, len: usize, label: &str) -> String {
    let mut out = String::with_capacity(data.len() * 5 + label.len() + 96);
    if len > data.len() {
        let _ = writeln!(
            out,
            "  {} @ 0x{:x} ({} bytes, 截断自 {}):",
            label,
            addr,
            data.len(),
            len
        );
    } else {
        let _ = writeln!(out, "  {} @ 0x{:x} ({} bytes):", label, addr, data.len());
    }
    for (row, chunk) in data.chunks(16).enumerate() {
        let _ = write!(out, "  {:08x}  ", row * 16);
        for (i, b) in chunk.iter().enumerate() {
            push_hex_byte(&mut out, *b);
            out.push(' ');
            if i == 7 {
                out.push(' ');
            }
        }
        // 补齐空格
        for i in chunk.len()..16 {
            out.push_str("   ");
            if i == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        for b in chunk {
            out.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        out.push_str("|\n");
    }
    out
}

fn format_buffer_preview(data: &[u8], addr: u64) -> String {
    let preview = &data[..data.len().min(BUFFER_PREVIEW_LIMIT)];
    let mut out = String::with_capacity(48 + preview.len() * 2);
    let _ = write!(out, "0x{:x} len={}", addr, data.len());
    if !preview.is_empty() {
        out.push_str(" hex=");
        for &byte in preview {
            push_hex_byte(&mut out, byte);
        }
    }
    out
}

// =====================================================================
// 解码入口
// =====================================================================

/// 按签名解码 6 个参数（regs[0..6]）。
/// 返回 (args 列表, hexdump 块列表)。内存读失败时退化为 hex。
/// 保留既有 API 行为：Buf 参数读取最多 4KB 并生成 hexdump。
pub fn decode_args(nr: i64, pid: u32, regs: &[u64; 31]) -> Option<(Vec<String>, Vec<String>)> {
    decode_args_with_options(nr, pid, regs, true)
}

/// 按签名解码，可控制 Buf 参数是否生成完整 hexdump。
/// 关闭时最多读取 32B 预览；开启时最多读取 4KB，预览复用同一次读取。
/// 两种模式均不超过调用请求的长度，预览 len 表示实际捕获的字节数。
pub fn decode_args_with_options(
    nr: i64,
    pid: u32,
    regs: &[u64; 31],
    dumphex: bool,
) -> Option<(Vec<String>, Vec<String>)> {
    decode_args_with_buffer_reader(nr, pid, regs, dumphex, read_mem)
}

/// Only Buf reads are injected; scalar dispatch and buffer rendering are shared
/// with production. Host tests can verify read limits without opening /proc.
fn decode_args_with_buffer_reader(
    nr: i64,
    pid: u32,
    regs: &[u64; 31],
    dumphex: bool,
    mut read_buffer: impl FnMut(u32, u64, usize) -> Option<Vec<u8>>,
) -> Option<(Vec<String>, Vec<String>)> {
    let specs = syscall_argspec(nr).unwrap_or(S_FALLBACK);
    let mut out = Vec::with_capacity(specs.len());
    let mut dumps: Vec<String> = Vec::new();
    for (i, spec) in specs.iter().enumerate() {
        if i >= 6 {
            break;
        }
        let v = regs[i];
        let rendered = match spec.ty {
            ArgType::Int => format!("{}", v as i64),
            ArgType::Hex => format!("0x{:x}", v),
            ArgType::Octal => format!("0o{:o}", v),
            ArgType::Dirfd => render_dirfd(v),
            ArgType::Signal => render_signal(v),
            ArgType::Enum(t) => {
                if t as *const _ == FUTEX_OPS as *const _ {
                    render_futex_op(v)
                } else {
                    render_enum(t, v)
                }
            }
            ArgType::Flags(t) => {
                if t as *const _ == OPEN_FLAGS as *const _ {
                    render_open_flags(v)
                } else {
                    render_flags(t, v)
                }
            }
            ArgType::Str => match read_c_string(pid, v, 255) {
                Some(s) => format!("\"{}\"", s),
                None => format!("0x{:x}", v),
            },
            ArgType::Buf(len_idx) => {
                let want = if len_idx < 6 { regs[len_idx] as usize } else { 0 };
                let limit = if dumphex {
                    BUFFER_DUMP_LIMIT
                } else {
                    BUFFER_PREVIEW_LIMIT
                };
                match read_buffer(pid, v, want.min(limit)) {
                    Some(data) => {
                        if dumphex {
                            let label = format!("{}(nr={})", spec.name, nr);
                            dumps.push(format_hexdump(&data, v, want, &label));
                        }
                        // 与 hexdump 共用同一次读取，预览不会越过请求长度或短读边界。
                        format_buffer_preview(&data, v)
                    }
                    None => format!("0x{:x}", v),
                }
            }
            ArgType::SockAddr => render_sockaddr(pid, v),
            ArgType::Stat => render_stat(pid, v),
            ArgType::CloneArgs => render_clone_args(pid, v),
            ArgType::SigAction => render_sigaction(pid, v),
            ArgType::TimeSpec => render_timespec(pid, v),
            ArgType::SeccompFprog => render_seccomp_fprog(pid, v),
            ArgType::IoctlReq => render_ioctl_req(v),
        };
        out.push(format!("{}={}", spec.name, rendered));
    }
    Some((out, dumps))
}

// =====================================================================
// 库映射范围（判断 lr 是否落在某个 .so 内，如 libmetasec_ml.so）
// =====================================================================

const EMPTY_LIB_RANGES_RETRY: std::time::Duration = std::time::Duration::from_millis(100);
const NONEMPTY_LIB_RANGES_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

struct CachedLibraryRanges {
    ranges: Vec<(u64, u64)>,
    retry_at: std::time::Instant,
}

#[derive(Default)]
struct LibraryRangesCache {
    // 分层索引允许热路径直接用 &str 查询,不必每条事件分配模式 String。
    entries: HashMap<u32, HashMap<String, CachedLibraryRanges>>,
}

impl LibraryRangesCache {
    fn get(&self, pid: u32, needle: &str) -> Option<&[(u64, u64)]> {
        Some(&self.entries.get(&pid)?.get(needle)?.ranges)
    }

    fn get_or_read(
        &mut self,
        pid: u32,
        needle: &str,
        mut now: impl FnMut() -> std::time::Instant,
        read: impl FnOnce() -> Vec<(u64, u64)>,
    ) -> &[(u64, u64)] {
        let patterns = self.entries.entry(pid).or_default();
        let refresh = match patterns.get(needle) {
            Some(entry) => now() >= entry.retry_at,
            None => true,
        };
        if refresh {
            let fresh = read();
            // 从读取结束开始限频,慢 maps 读取也不会导致下一条事件立即重试。
            let read_finished = now();
            let entry = patterns
                .entry(needle.to_owned())
                .or_insert_with(|| CachedLibraryRanges {
                    ranges: Vec::new(),
                    retry_at: read_finished,
                });
            // 后加载库加入历史集合;匿名化或本次读取失败都不擦掉已知区间。
            entry.ranges.extend(fresh);
            entry.ranges.sort_unstable();
            entry.ranges.dedup();
            entry.retry_at = read_finished
                + if entry.ranges.is_empty() {
                    EMPTY_LIB_RANGES_RETRY
                } else {
                    NONEMPTY_LIB_RANGES_RETRY
                };
        }
        &patterns.get(needle).expect("library ranges populated above").ranges
    }
}

thread_local! {
    /// 按 PID + 匹配模式隔离缓存。空结果每 100ms 最多重读一次;
    /// 非空结果每 1s 合并新范围,并保留映射随后匿名化前的历史区间。
    /// 与内核刷新器独立,新库仍可能在本地刷新前的有限窗口内未命中。
    static LIB_RANGES: RefCell<LibraryRangesCache> = RefCell::new(LibraryRangesCache::default());
}

/// 目标库路径匹配规则(逗号分隔多模式):
/// - 系统库目录始终排除,包括显式指定库名的情况
/// - "all" 或 "*":仅 Android 应用目录中的 .so,不包含 /data/local/tmp
/// - 以 ".so" 结尾(如 "libmetasec_ml.so"):路径子串匹配(单库)
/// - 其他(如 "com.ss.android.ugc.aweme"):路径含该串且以 .so 结尾——
///   即"该包名下的所有 .so",覆盖 app 全部原生库
pub fn lib_path_matches(path: &str, needle: &str) -> bool {
    if ["/system/", "/system_ext/", "/vendor/", "/product/", "/odm/", "/apex/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return false;
    }
    let app_directory = ["/data/app/", "/data/data/", "/data/user/", "/data/user_de/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
        || path
            .strip_prefix("/mnt/expand/")
            .and_then(|relative| relative.split_once('/'))
            .is_some_and(|(volume, relative)| {
                !matches!(volume, "" | "." | "..")
                    && ["app/", "user/", "user_de/"]
                        .iter()
                        .any(|prefix| relative.starts_with(prefix))
            });
    needle.split(',').any(|pat| {
        let pat = pat.trim();
        if pat.is_empty() {
            return false;
        }
        if pat == "all" || pat == "*" {
            return app_directory && path.ends_with(".so");
        }
        if pat.ends_with(".so") {
            path.contains(pat)
        } else {
            path.contains(pat) && path.ends_with(".so")
        }
    })
}

/// 读 pid 进程 maps 中目标库的可执行(r-x)映射区间列表,带库全路径。
/// LIB_FILTER 刷新器用它把"名字"喂给 stackwalk 历史命名缓存——
/// 库被匿名化前名字窗口期可能极短,赶上就要存下来。
pub fn read_lib_ranges_named(pid: u32, needle: &str) -> Vec<(u64, u64, String)> {
    let mut out = Vec::new();
    if let Ok(maps) = std::fs::read_to_string(format!("/proc/{}/maps", pid)) {
        for line in maps.lines() {
            if let Some(range) = parse_lib_range_line(line, needle) {
                out.push(range);
            }
        }
    }
    out
}

/// Parse fixed maps fields before inspecting the complete, possibly spaced pathname.
fn parse_lib_range_line(line: &str, needle: &str) -> Option<(u64, u64, String)> {
    fn hex(field: &str) -> Option<u64> {
        if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(field, 16).ok()
    }

    let mut remaining = line.trim_start();
    let mut fields = [""; 5];
    for field in &mut fields {
        let end = remaining.find(char::is_whitespace)?;
        *field = &remaining[..end];
        remaining = remaining[end..].trim_start();
    }
    let (lo, hi) = fields[0].split_once('-')?;
    let (lo, hi) = (hex(lo)?, hex(hi)?);
    if lo >= hi || !matches!(fields[1], "r-xp" | "r-xs") {
        return None;
    }
    hex(fields[2])?;
    let (major, minor) = fields[3].split_once(':')?;
    hex(major)?;
    hex(minor)?;
    if fields[4].is_empty() || !fields[4].bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    fields[4].parse::<u64>().ok()?;
    let path = remaining.strip_suffix(" (deleted)").unwrap_or(remaining);
    if !path.starts_with('/') || !lib_path_matches(path, needle) {
        return None;
    }
    Some((lo, hi, path.to_owned()))
}

/// 读 pid 进程 maps 中目标库的可执行(r-x)映射区间列表。
/// 公开给 LIB_FILTER 的用户态刷新器(kernel-trace/src/lib.rs)。
/// needle 支持逗号分隔多模式(见 lib_path_matches)。
pub fn read_lib_ranges(pid: u32, needle: &str) -> Vec<(u64, u64)> {
    read_lib_ranges_named(pid, needle)
        .into_iter()
        .map(|(lo, hi, _)| (lo, hi))
        .collect()
}

/// lr 命中历史区间时返回 "needle+0x偏移"（代码段匿名化后的归属提示）
pub fn hist_offset(pid: u32, lr: u64, needle: &str) -> Option<String> {
    LIB_RANGES.with(|c| {
        let c = c.borrow();
        let ranges = c.get(pid, needle)?;
        for &(lo, hi) in ranges {
            if lr >= lo && lr < hi {
                return Some(format!("{}+0x{:x}(hist)", needle, lr - lo));
            }
        }
        None
    })
}

/// lr 是否落在 pid 进程内名字含 needle 的可执行映射中
pub fn lr_in_lib(pid: u32, lr: u64, needle: &str) -> bool {
    LIB_RANGES.with(|c| {
        let mut c = c.borrow_mut();
        c.get_or_read(pid, needle, std::time::Instant::now, || read_lib_ranges(pid, needle))
            .iter()
            .any(|&(lo, hi)| lr >= lo && lr < hi)
    })
}

#[cfg(test)]
mod library_ranges_cache_tests {
    use super::*;
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    #[test]
    fn frequent_empty_queries_do_not_repeat_reads_before_deadline() {
        let mut cache = LibraryRangesCache::default();
        let start = Instant::now();
        let reads = Cell::new(0);
        for query in 0..10_000 {
            let now = start + Duration::from_micros(query);
            assert!(cache
                .get_or_read(
                    7,
                    "one.so",
                    || now,
                    || {
                        reads.set(reads.get() + 1);
                        Vec::new()
                    }
                )
                .is_empty());
        }
        assert_eq!(reads.get(), 1);
        assert_eq!(
            cache.get_or_read(
                7,
                "one.so",
                || start + EMPTY_LIB_RANGES_RETRY,
                || {
                    reads.set(reads.get() + 1);
                    vec![(10, 20)]
                }
            ),
            [(10, 20)]
        );
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn pid_and_pattern_keys_do_not_share_ranges_or_retry_deadlines() {
        let mut cache = LibraryRangesCache::default();
        let now = Instant::now();
        assert!(cache.get_or_read(7, "one.so", || now, Vec::new).is_empty());
        assert_eq!(cache.get_or_read(7, "two.so", || now, || vec![(20, 30)]), [(20, 30)]);
        assert_eq!(cache.get_or_read(8, "one.so", || now, || vec![(40, 50)]), [(40, 50)]);
        assert_eq!(cache.get(7, "one.so"), Some([].as_slice()));
        assert_eq!(cache.get(7, "two.so"), Some([(20, 30)].as_slice()));
        assert_eq!(cache.get(8, "one.so"), Some([(40, 50)].as_slice()));
        assert!(cache.get(8, "two.so").is_none());
        assert!(cache
            .get_or_read(7, "one.so", || now, || panic!("retry too early"))
            .is_empty());
    }

    #[test]
    fn empty_retry_deadline_starts_after_slow_read_completes() {
        let mut cache = LibraryRangesCache::default();
        let start = Instant::now();
        let now = Cell::new(start);
        assert!(cache
            .get_or_read(
                7,
                "one.so",
                || now.get(),
                || {
                    now.set(start + Duration::from_millis(500));
                    Vec::new()
                }
            )
            .is_empty());
        now.set(start + Duration::from_millis(599));
        assert!(cache
            .get_or_read(7, "one.so", || now.get(), || panic!("retry too early"))
            .is_empty());
        now.set(start + Duration::from_millis(600));
        assert_eq!(cache.get_or_read(7, "one.so", || now.get(), || vec![(1, 2)]), [(1, 2)]);
    }

    #[test]
    fn frequent_nonempty_queries_do_not_repeat_reads_before_deadline() {
        let mut cache = LibraryRangesCache::default();
        let start = Instant::now();
        let reads = Cell::new(0);
        for query in 0..10_000 {
            let now = start + Duration::from_micros(query * 99);
            assert_eq!(
                cache.get_or_read(
                    7,
                    "one.so",
                    || now,
                    || {
                        reads.set(reads.get() + 1);
                        vec![(10, 20)]
                    }
                ),
                [(10, 20)]
            );
        }
        assert_eq!(reads.get(), 1);
    }

    #[test]
    fn independent_workers_merge_late_library_without_losing_history() {
        // Each instance represents one worker's TLS cache, initialized at a
        // different time. Neither worker may remain frozen at library A.
        let mut workers = [LibraryRangesCache::default(), LibraryRangesCache::default()];
        let start = Instant::now();
        let a = (0x1000, 0x2000);
        let b = (0x3000, 0x4000);
        for (index, cache) in workers.iter_mut().enumerate() {
            let started = start + Duration::from_millis(index as u64 * 250);
            assert_eq!(cache.get_or_read(7, "all", || started, || vec![a, a]), [a]);
            // B has loaded, but the bounded local refresh window has not ended.
            let before = started + NONEMPTY_LIB_RANGES_RETRY - Duration::from_nanos(1);
            let ranges = cache.get_or_read(7, "all", || before, || panic!("refresh too early"));
            assert!(!ranges.iter().any(|&(lo, hi)| lo <= 0x3040 && 0x3040 < hi));
            let refresh = started + NONEMPTY_LIB_RANGES_RETRY;
            let ranges = cache.get_or_read(7, "all", || refresh, || vec![b, a, b]);
            assert_eq!(ranges, [a, b]);
            assert!(ranges.iter().any(|&(lo, hi)| lo <= 0x3040 && 0x3040 < hi));
            // A subsequent empty scan must retain both historical libraries.
            let empty_at = refresh + NONEMPTY_LIB_RANGES_RETRY;
            assert_eq!(cache.get_or_read(7, "all", || empty_at, Vec::new), [a, b]);
            assert_eq!(
                cache.get_or_read(
                    7,
                    "all",
                    || empty_at + EMPTY_LIB_RANGES_RETRY,
                    || panic!("history should keep the nonempty retry interval")
                ),
                [a, b]
            );
            assert_eq!(
                cache.get_or_read(7, "all", || empty_at + NONEMPTY_LIB_RANGES_RETRY, || vec![b]),
                [a, b]
            );
        }
    }

    #[test]
    fn nonempty_retry_deadline_starts_after_slow_refresh_completes() {
        let mut cache = LibraryRangesCache::default();
        let start = Instant::now();
        let now = Cell::new(start);
        cache.get_or_read(7, "all", || now.get(), || vec![(10, 20)]);
        now.set(start + NONEMPTY_LIB_RANGES_RETRY);
        assert_eq!(
            cache.get_or_read(
                7,
                "all",
                || now.get(),
                || {
                    now.set(start + Duration::from_millis(1500));
                    vec![(30, 40)]
                }
            ),
            [(10, 20), (30, 40)]
        );
        now.set(start + Duration::from_millis(2499));
        assert_eq!(
            cache.get_or_read(7, "all", || now.get(), || panic!("retry too early")),
            [(10, 20), (30, 40)]
        );
        now.set(start + Duration::from_millis(2500));
        assert_eq!(
            cache.get_or_read(7, "all", || now.get(), || vec![(50, 60)]),
            [(10, 20), (30, 40), (50, 60)]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_parser_preserves_spaced_paths_before_library_filtering() {
        let app = "/data/app/org.example.sample/with space/libsample.so";
        let app_line = format!("1000-2000 r-xp 00000000 08:01 123    {app}");
        assert_eq!(
            parse_lib_range_line(&app_line, "all"),
            Some((0x1000, 0x2000, app.into()))
        );
        assert!(parse_lib_range_line(&app_line, "libsample.so").is_some());
        for root in ["system", "system_ext", "vendor", "product", "odm", "apex"] {
            let line = format!("1000-2000 r-xp 00000000 08:01 123 /{root}/with space/libsample.so");
            for pattern in ["all", "libsample.so"] {
                assert!(parse_lib_range_line(&line, pattern).is_none(), "{pattern}: {line}");
            }
        }
    }

    #[test]
    fn maps_parser_removes_only_the_standard_deleted_suffix() {
        let path = "/data/user/0/org.example/with space/libsample.so";
        let line = format!("1000-2000\tr-xs\t00001000\t00:00\t0\t{path} (deleted)");
        assert_eq!(parse_lib_range_line(&line, "all"), Some((0x1000, 0x2000, path.into())));
        assert!(parse_lib_range_line(
            "1000-2000 r-xp 0 08:01 1 /system/with space/libsample.so (deleted)",
            "libsample.so"
        )
        .is_none());
        let literal = "/data/app/pkg/dir (deleted)/libsample.so";
        let line = format!("1000-2000 r-xp 0 08:01 1 {literal}");
        assert_eq!(
            parse_lib_range_line(&line, "all"),
            Some((0x1000, 0x2000, literal.into()))
        );
    }

    #[test]
    fn maps_parser_rejects_anonymous_malformed_and_nonexecutable_rows() {
        for line in [
            "",
            "1000-2000 r-xp",
            "1000-2000 r-xp 0 00:00 0",
            "1000-2000 r-xp 0 00:00 0   ",
            "1000-2000 r-xp 0 00:00 0 [anon:libsample.so]",
            "1000-2000 r-xp 0 00:00 0 libsample.so",
            "2000-1000 r-xp 0 08:01 1 /data/app/pkg/libsample.so",
            "1000-1000 r-xp 0 08:01 1 /data/app/pkg/libsample.so",
            "bad-range r-xp 0 08:01 1 /data/app/pkg/libsample.so",
            "1000-2000 rw-p 0 08:01 1 /data/app/pkg/libsample.so",
            "1000-2000 r-xz 0 08:01 1 /data/app/pkg/libsample.so",
            "1000-2000 r-xp offset 08:01 1 /data/app/pkg/libsample.so",
            "1000-2000 r-xp 0 invalid 1 /data/app/pkg/libsample.so",
            "1000-2000 r-xp 0 08:01 inode /data/app/pkg/libsample.so",
        ] {
            assert!(parse_lib_range_line(line, "libsample.so").is_none(), "{line}");
        }
    }

    #[test]
    fn all_library_patterns_include_android_app_directories() {
        for path in [
            "/data/app/~~token/org.example.sample/lib/arm64/libc.so",
            "/data/data/org.example.sample/files/libsample.so",
            "/data/user/0/org.example.sample/files/libsample.so",
            "/data/user_de/0/org.example.sample/files/libsample.so",
            "/mnt/expand/volume-123/app/org.example.sample/lib/arm64/libsample.so",
            "/mnt/expand/volume-123/user/0/org.example.sample/files/libsample.so",
            "/mnt/expand/volume-123/user_de/0/org.example.sample/files/libsample.so",
        ] {
            for pattern in ["all", "*", " , missing.so, all , "] {
                assert!(lib_path_matches(path, pattern), "{pattern}: {path}");
            }
        }
        assert!(lib_path_matches(
            "/data/app/org.example.sample/lib/arm64/libc.so",
            "libc.so"
        ));
    }

    #[test]
    fn system_library_directories_are_excluded_even_when_explicit() {
        for prefix in ["/system/", "/system_ext/", "/vendor/", "/product/", "/odm/", "/apex/"] {
            let path = format!("{prefix}org.example.sample/lib64/libc.so");
            for pattern in ["all", "*", "libc.so", "org.example.sample", "missing.so, libc.so"] {
                assert!(!lib_path_matches(&path, pattern), "{pattern}: {path}");
            }
            assert!(!lib_path_matches(&path, &path), "{path}");
        }
    }

    #[test]
    fn explicit_owned_samples_still_match_without_wildcard_inclusion() {
        let path = "/data/local/tmp/self_trace/libself_trace_a.so";
        for pattern in ["all", "*"] {
            assert!(!lib_path_matches(path, pattern));
        }
        for pattern in ["libself_trace_a.so", path, "self_trace", "all, libself_trace_a.so"] {
            assert!(lib_path_matches(path, pattern), "{pattern}");
        }
        assert!(lib_path_matches("/data/local/tmp/libsample.so.1", "libsample.so"));
    }

    #[test]
    fn wildcard_app_directories_require_complete_path_components() {
        for path in [
            "/data/application/pkg/libsample.so",
            "/data/app-lib/pkg/libsample.so",
            "/data/database/pkg/libsample.so",
            "/data/users/0/pkg/libsample.so",
            "/data/user_de_backup/0/pkg/libsample.so",
            "/mnt/expander/volume/app/pkg/libsample.so",
            "/mnt/expand/volume/application/pkg/libsample.so",
            "/mnt/expand/volume/users/0/pkg/libsample.so",
            "/mnt/expand/volume/user_de_backup/0/pkg/libsample.so",
            "/mnt/expand//app/pkg/libsample.so",
            "/mnt/expand/../app/pkg/libsample.so",
            "/data/app/pkg/not-a-library.txt",
        ] {
            for pattern in ["all", "*"] {
                assert!(!lib_path_matches(path, pattern), "{pattern}: {path}");
            }
        }
    }

    #[test]
    fn library_patterns_preserve_package_matching_and_comma_alternatives() {
        let path = "/data/app/~~token/org.example.sample/lib/arm64/libsample.so";
        assert!(lib_path_matches(path, "missing.so, org.example.sample"));
        assert!(lib_path_matches(path, " , libsample.so , "));
        for pattern in ["", " , ", "org.other.sample", "missing.so"] {
            assert!(!lib_path_matches(path, pattern), "{pattern}");
        }
        assert!(!lib_path_matches(
            "/data/app/org.example.sample/file.txt",
            "org.example.sample"
        ));
    }

    #[test]
    fn xattr_setters_include_flags_and_keep_fd_arguments_scalar() {
        for nr in [5, 6] {
            let spec = syscall_argspec(nr).unwrap();
            assert_eq!(
                spec.iter().map(|arg| arg.name).collect::<Vec<_>>(),
                ["path", "name", "value", "size", "flags"]
            );
            assert!(matches!(spec[0].ty, ArgType::Str));
            assert!(matches!(spec[4].ty, ArgType::Int));
        }
        let fd_spec = syscall_argspec(7).unwrap();
        assert_eq!(
            fd_spec.iter().map(|arg| arg.name).collect::<Vec<_>>(),
            ["fd", "name", "value", "size", "flags"]
        );
        assert!(matches!(fd_spec[0].ty, ArgType::Int));
        assert!(matches!(fd_spec[1].ty, ArgType::Str));
        assert!(matches!(fd_spec[4].ty, ArgType::Int));
        // getxattr/lgetxattr/fgetxattr still take four arguments, without flags.
        for nr in [8, 9, 10] {
            let spec = syscall_argspec(nr).unwrap();
            assert_eq!(spec.len(), 4);
            assert_eq!(spec[3].name, "size");
        }
        assert!(matches!(syscall_argspec(10).unwrap()[0].ty, ArgType::Int));
    }

    #[test]
    fn setreid_signatures_decode_real_and_effective_ids() {
        let mut regs = [0u64; 31];
        regs[0] = 1001;
        regs[1] = 1002;
        // These signatures contain only scalars; no process memory is read.
        for (nr, expected) in [
            (143, vec!["rgid=1001", "egid=1002"]),
            (145, vec!["ruid=1001", "euid=1002"]),
            (144, vec!["gid=1001"]),
            (146, vec!["uid=1001"]),
        ] {
            let (args, dumps) = decode_args(nr, 0, &regs).unwrap();
            assert_eq!(args, expected);
            assert!(dumps.is_empty());
        }
    }

    #[test]
    fn clone3_uses_its_exit_signal_field_and_preserves_low_flags() {
        let mut bytes = [0u8; 88];
        for (offset, value) in [
            (0, 0x180u64), // CLONE_VM plus the low CLONE_NEWTIME flag.
            (24, 0x1234),
            (32, 17), // SIGCHLD is independent from flags.
            (40, 0x2000),
            (48, 0x3000),
            (56, 0x4000),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        for length in [64, 80, 88] {
            assert_eq!(
                format_clone_args(&bytes[..length]).as_deref(),
                Some("{flags=CLONE_VM|0x80 exit_sig=SIGCHLD stack=0x2000 stack_size=0x3000 tls=0x4000 parent_tid=0x1234}")
            );
        }
        bytes[0..8].copy_from_slice(&0u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&15u64.to_le_bytes());
        assert!(format_clone_args(&bytes)
            .unwrap()
            .starts_with("{flags=0 exit_sig=SIGTERM "));
    }

    #[test]
    fn clone3_rejects_every_short_header_before_reading_fields() {
        let bytes = [0u8; 64];
        for length in 0..64 {
            assert!(format_clone_args(&bytes[..length]).is_none(), "length={length}");
        }
        assert!(format_clone_args(&bytes).is_some());
    }

    #[test]
    fn hexdump_preserves_full_row_layout() {
        assert_eq!(
            format_hexdump(b"0123456789abcdef", 0x1234, 16, "buf"),
            concat!(
                "  buf @ 0x1234 (16 bytes):\n",
                "  00000000  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|\n"
            )
        );
    }

    #[test]
    fn hexdump_short_read_reports_actual_length_and_pads_ascii_column() {
        let dump = format_hexdump(b"\0\x7f A", 0x1234, 8, "buf");
        assert!(dump.starts_with("  buf @ 0x1234 (4 bytes, 截断自 8):\n"));
        let row = dump.lines().nth(1).unwrap();
        assert_eq!(row.find('|'), Some(62));
        assert!(row.ends_with("|.. A|"));
    }

    #[test]
    fn buffer_preview_uses_captured_length_and_at_most_32_bytes() {
        assert_eq!(format_buffer_preview(&[0xab], 0x1234), "0x1234 len=1 hex=ab");
        assert_eq!(format_buffer_preview(&[], 0x1234), "0x1234 len=0");

        let data = vec![0xab; BUFFER_DUMP_LIMIT];
        assert_eq!(
            format_buffer_preview(&data, 0x1234),
            format!("0x1234 len=4096 hex={}", "ab".repeat(32))
        );
        assert!(format_hexdump(&data, 0x1234, 8192, "buf").starts_with("  buf @ 0x1234 (4096 bytes, 截断自 8192):\n"));
    }

    #[test]
    fn preview_only_caps_reads_for_every_buffer_signature_without_dumps() {
        for (nr, buffer_arg, length_arg) in [
            (63, 1, 2),
            (64, 1, 2),
            (67, 1, 2),
            (68, 1, 2),
            (206, 1, 2),
            (207, 1, 2),
            (278, 0, 1),
        ] {
            let mut regs = [0; 31];
            regs[buffer_arg] = 0x1234;
            regs[length_arg] = 8192;
            let mut reads = 0;
            let (args, dumps) = decode_args_with_buffer_reader(nr, 0, &regs, false, |pid, addr, len| {
                reads += 1;
                assert_eq!((pid, addr, len), (0, 0x1234, 32), "nr={nr}");
                Some(vec![0xab; len])
            })
            .unwrap();
            // Other pointer parameters (sendto/recvfrom sockaddr) are NULL;
            // no test path opens /proc or accesses a real process.
            assert_eq!(reads, 1, "nr={nr}");
            assert_eq!(args[buffer_arg], format!("buf=0x1234 len=32 hex={}", "ab".repeat(32)));
            assert!(dumps.is_empty(), "nr={nr}");
        }
    }

    #[test]
    fn dump_enabled_preserves_the_existing_row_and_preview_format() {
        let mut regs = [0; 31];
        regs[1] = 0x1234;
        regs[2] = 16;
        let mut reads = 0;
        let (args, dumps) = decode_args_with_buffer_reader(64, 0, &regs, true, |_, addr, len| {
            reads += 1;
            assert_eq!((addr, len), (0x1234, 16));
            Some(b"0123456789abcdef".to_vec())
        })
        .unwrap();
        assert_eq!(reads, 1, "hexdump and preview must share one read");
        assert_eq!(args[1], "buf=0x1234 len=16 hex=30313233343536373839616263646566");
        assert_eq!(
            dumps,
            [concat!(
                "  buf(nr=64) @ 0x1234 (16 bytes):\n",
                "  00000000  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|\n"
            )]
        );
    }

    #[test]
    fn dump_enabled_reads_at_most_4096_bytes_and_marks_truncation() {
        let mut regs = [0; 31];
        regs[1] = 0x1234;
        regs[2] = 8192;
        let mut reads = 0;
        let (args, dumps) = decode_args_with_buffer_reader(64, 0, &regs, true, |_, _, len| {
            reads += 1;
            assert_eq!(len, 4096);
            Some(vec![0xab; len])
        })
        .unwrap();
        assert_eq!(reads, 1);
        assert_eq!(args[1], format!("buf=0x1234 len=4096 hex={}", "ab".repeat(32)));
        assert_eq!(dumps.len(), 1);
        assert!(dumps[0].starts_with("  buf(nr=64) @ 0x1234 (4096 bytes, 截断自 8192):\n"));
        assert_eq!(dumps[0].lines().count(), 257);
        assert!(dumps[0].lines().last().unwrap().starts_with("  00000ff0  "));
    }

    #[test]
    fn buffer_modes_respect_requested_lengths_and_short_reads() {
        for dumphex in [false, true] {
            for want in [0usize, 1, 7, 31, 32, 33, 8192] {
                let mut regs = [0; 31];
                regs[1] = 0x1234;
                regs[2] = want as u64;
                let captured = want.min(3);
                let mut reads = 0;
                let (args, dumps) = decode_args_with_buffer_reader(64, 0, &regs, dumphex, |_, _, len| {
                    reads += 1;
                    assert_eq!(len, want.min(if dumphex { 4096 } else { 32 }));
                    // The real reader returns None for a zero-length request.
                    (len != 0).then(|| vec![0xab; captured])
                })
                .unwrap();
                assert_eq!(reads, 1);
                if want == 0 {
                    assert_eq!(args[1], "buf=0x1234");
                    assert!(dumps.is_empty());
                    continue;
                }
                assert_eq!(
                    args[1],
                    format!("buf=0x1234 len={captured} hex={}", "ab".repeat(captured))
                );
                assert_eq!(dumps.len(), usize::from(dumphex));
                if dumphex {
                    let suffix = if captured < want {
                        format!(", 截断自 {want}")
                    } else {
                        String::new()
                    };
                    assert!(dumps[0].starts_with(&format!("  buf(nr=64) @ 0x1234 ({captured} bytes{suffix}):\n")));
                }
            }
        }
    }

    #[test]
    fn buffer_read_failure_falls_back_to_address_in_both_modes() {
        for dumphex in [false, true] {
            let mut regs = [0; 31];
            regs[1] = 0x1234;
            regs[2] = 8192;
            let (args, dumps) = decode_args_with_buffer_reader(64, 0, &regs, dumphex, |_, _, _| None).unwrap();
            assert_eq!(args[1], "buf=0x1234");
            assert!(dumps.is_empty());
        }
    }

    #[test]
    fn sockaddr_rejects_every_short_prefix_before_accessing_fields() {
        for (family, minimum) in [(2u16, 8), (10, 24), (16, 12), (17, 8), (40, 12), (31, 8)] {
            let mut data = vec![0u8; minimum];
            data[..2].copy_from_slice(&family.to_le_bytes());
            for length in 0..minimum {
                assert!(
                    format_sockaddr(&data[..length], 0x1234).is_none(),
                    "family={family}, length={length}"
                );
            }
            assert!(format_sockaddr(&data, 0x1234).is_some(), "family={family}");
        }
    }

    #[test]
    fn sockaddr_preserves_network_byte_order_and_unknown_family_address() {
        assert_eq!(
            format_sockaddr(&[2, 0, 0x1f, 0x90, 127, 0, 0, 1], 0x1234).as_deref(),
            Some("AF_INET 127.0.0.1:8080")
        );
        let mut ipv6 = [0u8; 24];
        ipv6[0] = 10;
        ipv6[3] = 80;
        ipv6[23] = 1;
        assert_eq!(
            format_sockaddr(&ipv6, 0x1234).as_deref(),
            Some("AF_INET6 [0:0:0:0:0:0:0:1]:80")
        );
        assert_eq!(
            format_sockaddr(&[255, 0], 0x1234).as_deref(),
            Some("sa_family=255 0x1234")
        );
    }

    #[test]
    fn unix_sockaddr_uses_captured_path_with_existing_length_limit() {
        assert_eq!(format_sockaddr(&[1, 0], 0x1234).as_deref(), Some("AF_UNIX(unnamed)"));
        assert_eq!(
            format_sockaddr(b"\x01\0/tmp/a\n\xff\0ignored", 0x1234).as_deref(),
            Some("AF_UNIX \"/tmp/a\\n\\xff\"")
        );
        let mut data = [b'a'; 128];
        data[..2].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            format_sockaddr(&data, 0x1234),
            Some(format!("AF_UNIX \"{}\"", "a".repeat(107)))
        );
    }
}
