#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::{map, perf_event, raw_tracepoint, uprobe},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{PerfEventContext, ProbeContext, RawTracePointContext},
    EbpfContext,
};
use kernel_trace_common::{
    thread_names::should_filter_thread, trace_stats, Filter, HwBpEvent, LibRanges, SyscallEnterEvent, UprobeEvent,
    MAX_LIB_RANGES, MAX_TID_BLACKLIST_COUNT,
};

// =====================================================================
// 共享过滤器（uid / pid / nr / tid_blacklist / lib_only）
// 字段语义与 stackplz StackFilter / SyscallFilter 一致
// =====================================================================

#[map]
static FILTER: HashMap<u32, Filter> = HashMap::with_max_entries(1, 0);

// =====================================================================
// LIB_RANGES: pid(tgid) -> 目标库可执行区间集合
// 用户态周期扫 /proc/<pid>/maps 填充。lib_only 过滤开启时,
// sys_enter 里 lr(x30) 不在任区间内 → 直接丢弃,不进 ring。
// 这是治 perf buffer Lost 的根本手段:ring 流量从"全 app syscall"
// 降到"只有目标库发起的 syscall",通常降 1~2 个数量级。
// =====================================================================

// 1024 进程 × (4 + 64*16)B ≈ 1MB 预分配。
// 区间上限 64:包名模式下一个进程几十个 .so 的可执行段都放得下。
#[map]
static LIB_RANGES: HashMap<u32, LibRanges> = HashMap::with_max_entries(1024, 0);

/// lr 是否落在该进程的目标库区间内。
/// fail-closed:进程还没有区间记录(库未加载/用户态还没扫到)→ 丢弃。
/// 语义上正确:库没加载就不可能有来自它的 svc;加载后最坏丢 1s(刷新周期)。
#[inline(always)]
fn lr_in_lib_ranges(pid: u32, lr: u64) -> bool {
    // 注意:LibRanges 有 1KB(64 段),绝不能 *r 整体拷贝(BPF 栈只 512B)。
    // 通过 map value 指针逐字段读,编译为直接内存访问。
    let rs = match unsafe { LIB_RANGES.get(&pid) } {
        Some(r) => r,
        None => return false,
    };
    // 固定上限循环(verifier 友好),count 越界时截断
    let mut i = 0usize;
    while i < MAX_LIB_RANGES {
        if (i as u32) >= rs.count {
            break;
        }
        let lo = rs.ranges[i][0];
        let hi = rs.ranges[i][1];
        if lr >= lo && lr < hi {
            return true;
        }
        i += 1;
    }
    false
}

// =====================================================================
// 进程树跟踪(stackplz 风格)
// child_parent_map: key = child_ns_pid, value = parent_ns_pid
// - sys_enter 里:当前 PID 在 map 中 → 视为"被跟踪进程的后代",放行
// - sys_exit(clone/clone3):父进程在 map 中 → 把 ret(子进程 pid)加进 map
// - 这样"指定 --trace-pid 抖音主进程"即可自动跟踪整个进程树
// =====================================================================

#[map]
static CHILD_PARENT_MAP: HashMap<u32, u32> = HashMap::with_max_entries(4096, 0);

/// 判断 pid 是否是被跟踪进程的后代(查 child_parent_map)。
/// 单次 map lookup,O(1),不递归(父进程 fork 时已经把子进程加进 map 了)。
#[inline(always)]
fn is_tracked_descendant(pid: u32) -> bool {
    unsafe { CHILD_PARENT_MAP.get(&pid).is_some() }
}

/// 当 pid 命中主 filter 时,把它自己加进 child_parent_map,作为后续 fork 跟踪的根。
/// 后续它 fork 的子进程会被 sched_process_fork 监听到并自动加入。
#[inline(always)]
fn mark_tracked_root(pid: u32) {
    let _ = CHILD_PARENT_MAP.insert(&pid, &pid, 0);
}

/// 读 FILTER map(单次 lookup,调用方复用结果)。
/// 没装过滤器 → Filter::any()(保留默认线程名排除)。
#[inline(always)]
fn load_filter() -> Filter {
    let key = 0u32;
    match unsafe { FILTER.get(&key) } {
        Some(f) => *f,
        None => Filter::any(),
    }
}

#[inline(always)]
fn passes_filter(f: &Filter, uid: u32, pid: u32, tid: u32, nr: i64) -> bool {
    if f.uid != 0 && f.uid != uid {
        return false;
    }
    // PID 过滤:严格相等 OR 是被跟踪进程的后代
    if f.pid != 0 {
        if f.pid == pid {
            // 命中主 filter,标记为跟踪根(后续 fork 自动跟踪)
            mark_tracked_root(pid);
        } else if is_tracked_descendant(pid) {
            // 是被跟踪进程的后代,放行
        } else {
            return false;
        }
    }
    if f.nr >= 0 && (nr as i32) != f.nr {
        return false;
    }

    // tid_blacklist：位图 + 5 槽
    let mask = f.tid_blacklist_mask;
    if mask != 0 {
        let mut i = 0;
        while i < MAX_TID_BLACKLIST_COUNT {
            if (mask & (1u32 << i)) != 0 {
                if f.tid_blacklist[i] == tid {
                    return false;
                }
            } else {
                break;
            }
            i += 1;
        }
    }
    true
}

// =====================================================================
// fork 子进程自动跟踪:raw_tracepoint/sys_exit 方案
//
// 为什么不走 sched_process_fork:
//   sched_process_fork 的 args[1] 是 child task_struct*,要拿 child_pid
//   必须按 task_struct.pid 偏移读 —— 偏移随内核版本/配置漂移,需要 BTF/CO-RE,
//   aya 没有 libbpf 那样的重定位能力,硬编码偏移不可靠。
//
// sys_exit 方案零偏移、跨内核稳定:
//   父进程 fork/clone 返回时,sys_exit 的 ret 就是子进程 PID,
//   且触发上下文是父进程 —— 不需要读任何 task_struct 字段。
//   bpf_raw_tracepoint_args layout(sys_exit):
//     args[0] = struct pt_regs*
//     args[1] = long ret
//
// arm64 注意:没有独立的 fork/vfork syscall,libc 都走 clone(220)/clone3(435)。
// =====================================================================

const NR_CLONE: i32 = 220;
const NR_CLONE3: i32 = 435;

#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn raw_sys_sys_exit(ctx: RawTracePointContext) -> u32 {
    let _ = try_raw_sys_sys_exit(&ctx);
    0
}

fn try_raw_sys_sys_exit(ctx: &RawTracePointContext) -> Result<(), u32> {
    let args_ptr = ctx.as_ptr() as *const u64;
    let regs_ptr = unsafe { bpf_probe_read_kernel(args_ptr) }.map_err(|_| 20u32)? as *const PtRegs;
    let ret = unsafe { bpf_probe_read_kernel(unsafe { args_ptr.add(1) }) }.map_err(|_| 21u32)? as i64;

    // 只关心 clone/clone3
    let syscallno = unsafe { bpf_probe_read_kernel(&(*regs_ptr).syscallno) }.map_err(|_| 22u32)?;
    if syscallno != NR_CLONE && syscallno != NR_CLONE3 {
        return Ok(());
    }
    // ret <= 0: 出错(<0)或子进程返回路径(=0)。父进程 ret 才是 child pid。
    if ret <= 0 || ret > 0x7fff_ffff {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    // Helper 返回 (gid << 32) | uid，低 32 位才是 UID。
    let uid = bpf_get_current_uid_gid() as u32;

    let key = 0u32;
    let f = match unsafe { FILTER.get(&key) } {
        Some(f) => *f,
        None => Filter::any(),
    };

    // 父进程是否被跟踪:
    // - pid 模式:主 filter pid 本身,或已被跟踪的后代
    // - uid 模式:同 uid 即被跟踪(uid 过滤天然覆盖子进程)
    let is_root = f.pid != 0 && f.pid == pid;
    let tracked = if f.pid != 0 {
        is_root || is_tracked_descendant(pid)
    } else {
        f.uid == 0 || f.uid == uid
    };
    if !tracked {
        return Ok(());
    }
    if is_root {
        mark_tracked_root(pid);
    }

    let child = ret as u32;
    let _ = CHILD_PARENT_MAP.insert(&child, &pid, 0);

    // lib_only:fork 子进程继承父进程 mm,把目标库区间直接复制给子进程。
    // 关键场景:metasec fork 出短命子进程做 process_vm_readv/ptrace 反调试,
    // 子进程活不过用户态 1s 刷新周期,没有这一步它的 svc 会被 fail-closed 丢掉。
    // (exec 后地址空间变了,陈旧区间不匹配任何 lr,自然失效,无副作用)
    if f.lib_only != 0 {
        if let Some(rs) = unsafe { LIB_RANGES.get(&pid) } {
            let _ = LIB_RANGES.insert(&child, rs, 0);
        }
    }
    Ok(())
}

// =====================================================================
// ARM64 小端 pt_regs 前缀(arch/arm64/include/asm/ptrace.h)
// struct pt_regs {
//     u64 regs[31];     // x0-x30
//     u64 sp;
//     u64 pc;
//     u64 pstate;
//     u64 orig_x0;
//     s32 syscallno;
//     u32 unused2;
//     ...
// }
// syscallno 位于偏移 280,只读其 4 字节,不能把后面的 padding 当作编号高位。
// 该前缀共 288 字节,不依赖后续内核字段。
// =====================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtRegs {
    pub regs: [u64; 31], // x0..x30
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub orig_x0: u64,
    pub syscallno: i32,
    pub unused2: u32,
}

// =====================================================================
// 探针 1：raw_tracepoint/sys_enter
// bpf_raw_tracepoint_args layout:
//   u64 args[0] = struct pt_regs*
//   u64 args[1] = long id (syscall 编号)
// =====================================================================

// RingBuf(内核 5.8+):全 CPU 共享单环,可开大容量抗爆发。
// 之前 PerfEventArray 每 CPU 仅 8 页(~300 事件),metasec 反调试
// 爆发(getppid/clone 风暴)瞬间灌满 → 大量 Lost;且 aya 显式 page_count
// 在 P6/6.1 上会导致全 Lost 不可用。RingBuf 4MB ≈ 1.3 万事件缓冲。
#[map]
static SYSCALL_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 22, 0);

// 事件统计(内核侧),用户态周期读取对账,保证"该抓的全抓到"可验证:
// [0]=svc drop(ring 满)  [1]=uprobe drop
// [2]=svc pass(写入 ring 成功)  [3]=uprobe pass
// [4]=svc 默认线程名排除  [5]=uprobe 默认线程名排除，不计入 ring drop。
// [6]=hwbp drop(ring 满)  [7]=hwbp pass
// 每个 CPU 单独计数,避免共享计数器的读改写丢失增量;用户态读取时汇总所有 CPU。
// pass 只包含写入成功的事件,不包含 ring drop。上报尝试数 = pass + drop。
// [8]=hwbp BPF 入口（UID/PID 过滤前，不代表未进入 BPF 的硬件异常数）。
// [9]=hwbp UID 拒绝  [10]=hwbp PID 拒绝（UID 优先，每次最多记一种拒绝）。
// HWBP 排空后应满足：入口 = UID 拒绝 + PID 拒绝 + pass + drop。
// 停止生产并排空 ring 后,pass 应等于用户态从 ring 读取的事件数。
// 运行中读取各 CPU / 用户态计数不是同一时刻的快照,允许存在暂时差值。
#[map]
static TRACE_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(trace_stats::COUNT, 0);

#[inline(always)]
fn bump_stat(idx: u32) {
    if let Some(p) = TRACE_STATS.get_ptr_mut(idx) {
        unsafe {
            *p = (*p).wrapping_add(1);
        }
    }
}

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn raw_sys_sys_enter(ctx: RawTracePointContext) -> u32 {
    match try_raw_sys_sys_enter(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_raw_sys_sys_enter(ctx: &RawTracePointContext) -> Result<u32, u32> {
    // bpf_raw_tracepoint_args: args[0] = struct pt_regs*
    // 必须通过 bpf_probe_read_kernel 读,不能直接解引用(verifier 拒绝)
    let args_ptr = ctx.as_ptr() as *const u64;
    let regs_ptr = unsafe { bpf_probe_read_kernel(args_ptr) }.map_err(|_| 1u32)? as *const PtRegs;

    // raw sys_enter 直接传入 long id,不依赖 pt_regs.syscallno 的字段布局。
    let nr = unsafe { bpf_probe_read_kernel(args_ptr.add(1)) }.map_err(|_| 2u32)? as i64;

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    // Helper 返回 (gid << 32) | uid，低 32 位才是 UID。
    let uid = bpf_get_current_uid_gid() as u32;

    let f = load_filter();
    if !passes_filter(&f, uid, pid, tid, nr) {
        return Ok(0);
    }

    // lib_only:lr(x30) 必须落在目标库代码段内,否则直接丢弃。
    // 全程 fail-closed(不再等 armed):库未加载时 LIB_RANGES 无记录 → 全丢。
    // 语义上零损失——库没加载就不可能有 lr 落在它里面;
    // 库加载后用户态 100ms 内把区间刷进来,最坏丢 100ms 目标事件。
    // (旧版未 armed 时 fail-open,启动窗口 15s 灌进 236 万事件,
    //  ring/队列丢失率 74%,正是"process_vm_readv 抓不到"的根因)
    if f.lib_only != 0 {
        let lr = unsafe { bpf_probe_read_kernel(&(*regs_ptr).regs[30]) }.map_err(|_| 7u32)?;
        if !lr_in_lib_ranges(pid, lr) {
            return Ok(0);
        }
    }

    // 通过显式条件和库区间后再计名称排除，避免统计无关线程。
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    if should_filter_thread(&comm, f.full_tname != 0) {
        bump_stat(trace_stats::SVC_THREAD_FILTERED);
        return Ok(0);
    }

    // 直接填 ring 预留区，不在 BPF 栈上创建 312 字节的事件。
    // 栈限制按整条调用链计算；局部 event + 过滤器 spills + memset 曾达到 544B。
    let mut event = match SYSCALL_EVENTS.reserve::<SyscallEnterEvent>(0) {
        Some(event) => event,
        None => {
            bump_stat(trace_stats::SVC_RING_DROPPED);
            return Ok(0);
        }
    };
    let dst = event.as_mut_ptr();
    // 预留区尚未初始化，只通过原始指针逐字段写，不创建 &mut SyscallEnterEvent。
    // 读取失败的 ? 仅离开闭包，统一 discard 后才从探针返回。
    let filled = (|| -> Result<(), u32> {
        unsafe {
            core::ptr::addr_of_mut!((*dst).pid).write(pid);
            core::ptr::addr_of_mut!((*dst).tid).write(tid);
            core::ptr::addr_of_mut!((*dst).timestamp_ns).write(bpf_ktime_get_ns());
            core::ptr::addr_of_mut!((*dst).comm).write(comm);
            core::ptr::addr_of_mut!((*dst).nr).write(nr);
            let mut i = 0;
            while i < 31 {
                let value = bpf_probe_read_kernel(&(*regs_ptr).regs[i]).map_err(|_| 3u32)?;
                core::ptr::addr_of_mut!((*dst).regs[i]).write(value);
                i += 1;
            }
            core::ptr::addr_of_mut!((*dst).sp).write(bpf_probe_read_kernel(&(*regs_ptr).sp).map_err(|_| 4u32)?);
            core::ptr::addr_of_mut!((*dst).pc).write(bpf_probe_read_kernel(&(*regs_ptr).pc).map_err(|_| 5u32)?);
            core::ptr::addr_of_mut!((*dst).pstate).write(bpf_probe_read_kernel(&(*regs_ptr).pstate).map_err(|_| 6u32)?);
        }
        Ok(())
    })();
    if let Err(error) = filled {
        event.discard(0);
        return Err(error);
    }
    event.submit(0);
    bump_stat(trace_stats::SVC_SUBMITTED);
    Ok(0)
}

// =====================================================================
// 探针 2：uprobe(attach 时由用户态指定 lib+offset)
// uprobe 的 ctx 本来就是 struct pt_regs*,直接 cast 拿 33 GPR
// =====================================================================

#[map]
static UPROBE_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[uprobe]
pub fn generic_uprobe(ctx: ProbeContext) -> u32 {
    match try_generic_uprobe(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_generic_uprobe(ctx: &ProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    // Helper 返回 (gid << 32) | uid，低 32 位才是 UID。
    let uid = bpf_get_current_uid_gid() as u32;

    // uprobe 没有 syscall nr 概念，传 -1 → nr filter 自动失效
    let f = load_filter();
    if !passes_filter(&f, uid, pid, tid, -1) {
        return Ok(0);
    }

    // uprobe 的 ctx 本来就是 struct pt_regs*,通过 bpf_probe_read_kernel 读
    let regs_ptr = ctx.as_ptr() as *const PtRegs;

    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    if should_filter_thread(&comm, f.full_tname != 0) {
        bump_stat(trace_stats::UPROBE_THREAD_FILTERED);
        return Ok(0);
    }

    // 与 svc 相同，事件直接写 ring；保留原有 ABI 和每个寄存器的读取语义。
    let mut event = match UPROBE_EVENTS.reserve::<UprobeEvent>(0) {
        Some(event) => event,
        None => {
            bump_stat(trace_stats::UPROBE_RING_DROPPED);
            return Ok(0);
        }
    };
    let dst = event.as_mut_ptr();
    let filled = (|| -> Result<(), u32> {
        unsafe {
            core::ptr::addr_of_mut!((*dst).pid).write(pid);
            core::ptr::addr_of_mut!((*dst).tid).write(tid);
            core::ptr::addr_of_mut!((*dst).timestamp_ns).write(bpf_ktime_get_ns());
            core::ptr::addr_of_mut!((*dst).comm).write(comm);
            let mut i = 0;
            while i < 31 {
                let value = bpf_probe_read_kernel(&(*regs_ptr).regs[i]).map_err(|_| 10u32)?;
                core::ptr::addr_of_mut!((*dst).regs[i]).write(value);
                i += 1;
            }
            core::ptr::addr_of_mut!((*dst).sp).write(bpf_probe_read_kernel(&(*regs_ptr).sp).map_err(|_| 11u32)?);
            core::ptr::addr_of_mut!((*dst).pc).write(bpf_probe_read_kernel(&(*regs_ptr).pc).map_err(|_| 12u32)?);
            core::ptr::addr_of_mut!((*dst).pstate)
                .write(bpf_probe_read_kernel(&(*regs_ptr).pstate).map_err(|_| 13u32)?);
        }
        Ok(())
    })();
    if let Err(error) = filled {
        event.discard(0);
        return Err(error);
    }
    event.submit(0);
    bump_stat(trace_stats::UPROBE_SUBMITTED);
    Ok(0)
}

// =====================================================================
// 探针 3：perf_event 硬件断点/观察点（stackplz 同机制）
//
// 用户态通过 perf_event_open(PERF_TYPE_BREAKPOINT) 申请 ARM64 硬件调试
// 寄存器（DBGBCR/DBGWVR），PERF_EVENT_IOC_SET_BPF 挂本程序。
// 命中时内核 hw_breakpoint 框架在 debug exception 上下文里跑本程序：
// ctx 是 bpf_perf_event_data = { regs: user_pt_regs, sample_period, addr }。
// addr = 观察点命中的访问地址(far)，执行断点时无意义（用 pc 匹配）。
// 只做内核态过滤 + 寄存器快照上报，不 patch 任何代码，目标进程无感知。
// =====================================================================

#[map]
static HWBP_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

/// arm64 user_pt_regs（bpf_user_pt_regs_t）：只有 33 GPR 前缀，无 orig_x0/syscallno。
#[repr(C)]
pub struct UserRegs {
    pub regs: [u64; 31], // x0..x30
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// bpf_perf_event_data 的布局前缀（aya-ebpf 未 re-export，这里按 uapi 自建）。
/// 注意 regs 是 user_pt_regs(288B)，sample_period 紧跟其后，不能用含
/// orig_x0/syscallno 的 PtRegs（304B），否则 sample_period/addr 全部错位。
#[repr(C)]
pub struct PerfEventData {
    pub regs: UserRegs,
    pub sample_period: u64,
    pub addr: u64,
}

#[perf_event]
pub fn hw_breakpoint(ctx: PerfEventContext) -> u32 {
    match try_hw_breakpoint(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_hw_breakpoint(ctx: &PerfEventContext) -> Result<u32, u32> {
    bump_stat(trace_stats::HWBP_ENTERED);
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    // Helper 返回 (gid << 32) | uid，低 32 位才是 UID。
    let uid = bpf_get_current_uid_gid() as u32;

    // 显式地址断点不做线程名排除（用户点名监控的地址，线程名过滤会丢数据）。
    // 只做 uid / pid（含 fork 后代）过滤，与 svc/uprobe 语义一致。
    let f = load_filter();
    if f.uid != 0 && f.uid != uid {
        bump_stat(trace_stats::HWBP_UID_FILTERED);
        return Ok(0);
    }
    if f.pid != 0 && f.pid != pid && !is_tracked_descendant(pid) {
        bump_stat(trace_stats::HWBP_PID_FILTERED);
        return Ok(0);
    }

    // 关键：必须直接解引用 ctx 字段（编译成 ldx，verifier 按 perf_event ctx
    // 做 convert_ctx_access 转换）。内核侧 raw ctx 实际是
    // bpf_perf_event_data_kern = { *regs, sample_period, addr }，
    // 用 bpf_probe_read_kernel 裸读会拿到指针/垃圾值。
    let data = unsafe { &*ctx.ctx };
    let addr = data.addr;
    let regs = &data.regs;

    let mut event = match HWBP_EVENTS.reserve::<HwBpEvent>(0) {
        Some(event) => event,
        None => {
            bump_stat(trace_stats::HWBP_RING_DROPPED);
            return Ok(0);
        }
    };
    let dst = event.as_mut_ptr();
    let filled = (|| -> Result<(), u32> {
        unsafe {
            core::ptr::addr_of_mut!((*dst).pid).write(pid);
            core::ptr::addr_of_mut!((*dst).tid).write(tid);
            core::ptr::addr_of_mut!((*dst).timestamp_ns).write(bpf_ktime_get_ns());
            core::ptr::addr_of_mut!((*dst).comm).write(bpf_get_current_comm().unwrap_or([0u8; 16]));
            core::ptr::addr_of_mut!((*dst).addr).write(addr);
            let mut i = 0;
            while i < 31 {
                core::ptr::addr_of_mut!((*dst).regs[i]).write(regs.regs[i]);
                i += 1;
            }
            core::ptr::addr_of_mut!((*dst).sp).write(regs.sp);
            core::ptr::addr_of_mut!((*dst).pc).write(regs.pc);
            core::ptr::addr_of_mut!((*dst).pstate).write(regs.pstate);
        }
        Ok(())
    })();
    if let Err(error) = filled {
        event.discard(0);
        return Err(error);
    }
    event.submit(0);
    bump_stat(trace_stats::HWBP_SUBMITTED);
    Ok(0)
}

// =====================================================================
// panic + license（eBPF 程序标配）
// =====================================================================

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
