//! Shared callback utilities for hook and java hook callbacks
//!
//! Contains: JS engine lock acquisition, JS exception handling,
//! and registry initialization helpers.

use crate::ffi;
use crate::jsapi::console::output_message;
use crate::jsapi::ptr::get_native_pointer_addr;
use crate::jsapi::util::JSCFn;
use crate::value::JSValue;
use crate::JSEngine;
use std::cell::UnsafeCell;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

const JS_MAX_SAFE_INTEGER: u64 = 1u64 << 53;

// ──────────────────────────────────────────────────────────────────────────
// 热路径 atom 缓存
//
// 每次 hook callback 原本要为 x0..x30 + sp/pc/lr/returnAddress/trampoline/
// __hookCtxPtr/__hookTrampoline 共 ~37 个属性名反复 CString::new + JS_NewAtom +
// JS_FreeAtom，在高频 hook 下制造大量 Rust 堆 / QuickJS atom 表抖动。
//
// 这里在 JSEngine 构造时一次性 `JS_NewAtom` 全部热点名字，跨线程以 JS_ENGINE
// Mutex 为串行点 (hot path 永远在持锁期间读取)。JSRuntime 销毁前 (JSEngine::drop)
// 显式 JS_FreeAtom 归还引用。
//
// 字段布局固定，callback 直接按下标取，无哈希/查表开销。
// ──────────────────────────────────────────────────────────────────────────

#[repr(C)]
pub(crate) struct HotAtoms {
    // ─── native hook (replace + attach) ──────────────────────────
    pub x: [ffi::JSAtom; 31],
    pub sp: ffi::JSAtom,
    pub pc: ffi::JSAtom,
    pub lr: ffi::JSAtom,
    pub return_address: ffi::JSAtom,
    pub trampoline: ffi::JSAtom,
    pub hook_ctx_ptr: ffi::JSAtom,
    pub hook_trampoline: ffi::JSAtom,
    // ─── java hook ───────────────────────────────────────────────
    pub this_obj: ffi::JSAtom,
    pub env: ffi::JSAtom,
    pub hook_art_method: ffi::JSAtom,
    pub args: ffi::JSAtom,
    pub orig_jobject: ffi::JSAtom,
    pub jptr: ffi::JSAtom,
}

impl HotAtoms {
    const fn zeros() -> Self {
        Self {
            x: [0; 31],
            sp: 0,
            pc: 0,
            lr: 0,
            return_address: 0,
            trampoline: 0,
            hook_ctx_ptr: 0,
            hook_trampoline: 0,
            this_obj: 0,
            env: 0,
            hook_art_method: 0,
            args: 0,
            orig_jobject: 0,
            jptr: 0,
        }
    }
}

pub(crate) struct HotAtomsCell(UnsafeCell<HotAtoms>);
// Safety: 变更只发生在 init_hot_atoms / free_hot_atoms（都在 JS_ENGINE 锁下调用）,
// hot path 读取也必然在 JS_ENGINE 锁下。
unsafe impl Sync for HotAtomsCell {}

pub(crate) static HOT_ATOMS: HotAtomsCell = HotAtomsCell(UnsafeCell::new(HotAtoms::zeros()));
pub(crate) static HOT_ATOMS_READY: AtomicBool = AtomicBool::new(false);

unsafe fn new_atom_cstr(ctx: *mut ffi::JSContext, name: &str) -> ffi::JSAtom {
    let c = CString::new(name).unwrap();
    ffi::JS_NewAtom(ctx, c.as_ptr())
}

/// 初始化热路径 atom 缓存。调用方必须持有 JS_ENGINE 锁并提供合法 ctx。
/// 幂等：已初始化时直接返回。
pub(crate) unsafe fn init_hot_atoms(ctx: *mut ffi::JSContext) {
    if HOT_ATOMS_READY.load(Ordering::Acquire) {
        return;
    }
    let atoms = &mut *HOT_ATOMS.0.get();
    for i in 0..31 {
        atoms.x[i] = new_atom_cstr(ctx, &format!("x{}", i));
    }
    atoms.sp = new_atom_cstr(ctx, "sp");
    atoms.pc = new_atom_cstr(ctx, "pc");
    atoms.lr = new_atom_cstr(ctx, "lr");
    atoms.return_address = new_atom_cstr(ctx, "returnAddress");
    atoms.trampoline = new_atom_cstr(ctx, "trampoline");
    atoms.hook_ctx_ptr = new_atom_cstr(ctx, "__hookCtxPtr");
    atoms.hook_trampoline = new_atom_cstr(ctx, "__hookTrampoline");
    atoms.this_obj = new_atom_cstr(ctx, "thisObj");
    atoms.env = new_atom_cstr(ctx, "env");
    atoms.hook_art_method = new_atom_cstr(ctx, "__hookArtMethod");
    atoms.args = new_atom_cstr(ctx, "args");
    atoms.orig_jobject = new_atom_cstr(ctx, "__origJobject");
    atoms.jptr = new_atom_cstr(ctx, "__jptr");
    HOT_ATOMS_READY.store(true, Ordering::Release);
}

/// 释放热路径 atom。必须在 JSContext 仍有效时调用 (JSEngine::drop 里, context 字段 drop 之前)。
/// 幂等。
pub(crate) unsafe fn free_hot_atoms(ctx: *mut ffi::JSContext) {
    if !HOT_ATOMS_READY.swap(false, Ordering::AcqRel) {
        return;
    }
    let atoms = &mut *HOT_ATOMS.0.get();
    for i in 0..31 {
        if atoms.x[i] != 0 {
            ffi::JS_FreeAtom(ctx, atoms.x[i]);
            atoms.x[i] = 0;
        }
    }
    macro_rules! free_field {
        ($($f:ident),+ $(,)?) => {
            $(
                if atoms.$f != 0 {
                    ffi::JS_FreeAtom(ctx, atoms.$f);
                    atoms.$f = 0;
                }
            )+
        };
    }
    free_field!(
        sp,
        pc,
        lr,
        return_address,
        trampoline,
        hook_ctx_ptr,
        hook_trampoline,
        this_obj,
        env,
        hook_art_method,
        args,
        orig_jobject,
        jptr,
    );
}

/// 读取热路径 atom 缓存。调用方必须持有 JS_ENGINE 锁。
#[inline]
pub(crate) unsafe fn hot_atoms() -> &'static HotAtoms {
    debug_assert!(HOT_ATOMS_READY.load(Ordering::Relaxed), "hot atoms not initialized");
    &*HOT_ATOMS.0.get()
}

/// 回调入口的访问凭证：locked 对应本层取得的锁，否则依赖外层所有者。
/// 真正的 MutexGuard 保存在 TLS 中；凭证必须在进入线程上销毁。
pub(crate) struct JsEngineCallbackGuard {
    locked: bool,
    #[cfg(feature = "engine-depth-diagnostics")]
    entry: CallbackEntrySnapshot,
    _thread_bound: std::marker::PhantomData<*mut ()>,
}

impl JsEngineCallbackGuard {
    fn new(locked: bool, _target_id: u64) -> Self {
        Self {
            locked,
            #[cfg(feature = "engine-depth-diagnostics")]
            entry: CallbackEntrySnapshot::capture(_target_id),
            _thread_bound: std::marker::PhantomData,
        }
    }
}

impl Drop for JsEngineCallbackGuard {
    fn drop(&mut self) {
        let site = if self.locked { "cb-locked" } else { "cb-reentrant" };
        // 快照保存在调用栈上的 guard 中，不依赖可能已变化的 TLS 寻找入口记录。
        #[cfg(feature = "engine-depth-diagnostics")]
        self.entry.report_if_changed(site);
        note_js_engine_exit(site);
        if self.locked {
            crate::clear_js_engine_owner_current_thread();
            // 弹出本线程持有的引擎锁 guard 并 drop（真正解锁）。
            // 与 acquire/deposit 配对；若期间发生过 yield/reacquire，
            // 弹出的是 reacquire 时重新存入的 guard，锁计数依然平衡。
            drop(take_js_engine_guard());
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// 引擎锁 TLS 托管 + 协作式让出
//
// 背景（真机 ANR 实锤）：gate hook（Instrumentation.callApplicationOnCreate）
// 在主线程触发后，整个 Application.onCreate 都跑在 $orig 里，而 JS 回调分发
// 全程持有 JS_ENGINE 锁。此时其它线程 loadLibrary → dlopen hook → 等引擎锁，
// 同时它持有 Runtime.loadLibrary monitor；主线程 onCreate 深处又在等由这些
// 线程持有的 Java monitor → ABBA 死锁 → "failed to complete startup" ANR。
//
// 当前实现：已接入的外部调用路径在调用前尝试让锁，返回后重新拿锁。
// MutexGuard 借线程局部栈托管，yield 时取出并释放，reacquire 时重新存回。
// 这不表示所有外部调用入口都已接入，也不等于完整的执行作用域管理。
thread_local! {
    static JS_ENGINE_TLS_GUARDS: std::cell::RefCell<Vec<MutexGuard<'static, Option<JSEngine>>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

// 让锁时保存的挂起执行状态（每线程一条 LIFO 栈，与 yield/reacquire 严格配对）。
//
// 除帧链头外还携带：
//   - generation：引擎代次，恢复时比对，识别"引擎已销毁重建、Runtime 地址复用"；
//   - rt：JSRuntime 指针，恢复时与锁内当前引擎的 Runtime 二次比对；
//   - stack_top/stack_limit：让锁前的栈检查基准，恢复时原样还原，
//     不用当前（更深的）栈指针重建，防止挂起恢复不断抬深基准、重发栈预算。
//
// Bellard quickjs 的 JSStackFrame 分配在执行线程的 C 栈上，rt->current_stack_frame
// 是全局链头。线程让锁期间若不摘链：其它线程进 JS 会在本线程的帧上继续压链
// （异常 backtrace 串栈）；若本线程在让出期间被销毁，链头残留指向已释放
// C 栈的悬垂指针，下次任何线程构建 backtrace 直接踩死。
pub(crate) struct SuspendedJsState {
    generation: u64,
    rt: usize,
    frame: *mut std::ffi::c_void,
    stack_top: u64,
    stack_limit: u64,
}

thread_local! {
    static JS_SUSPENDED_FRAMES: std::cell::RefCell<Vec<SuspendedJsState>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

// JS 引擎执行域进入深度（每线程）。只有最外层进入（depth 0→1）才建立
// 栈检查基准（qjs_update_stack_top）；同线程嵌套沿用外层基准——否则
// JS → native → JS 每深一层都重发一份栈预算，已消耗的 C 栈被豁免检查。
thread_local! {
    static JS_ENGINE_ENTRY_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(feature = "engine-depth-diagnostics")]
#[derive(Debug, PartialEq, Eq)]
struct CallbackEntrySnapshot {
    target: u64,
    ktid: i64,
    tpidr: u64,
    depth_cell: usize,
    guards_cell: usize,
    depth: usize,
    guards: usize,
    suspended: usize,
    generation: u64,
    owner: u64,
}

#[cfg(feature = "engine-depth-diagnostics")]
impl CallbackEntrySnapshot {
    fn capture(target: u64) -> Self {
        let (depth_cell, depth) = JS_ENGINE_ENTRY_DEPTH.with(|d| (d as *const _ as usize, d.get()));
        let (guards_cell, guards) = JS_ENGINE_TLS_GUARDS.with(|s| (s as *const _ as usize, s.borrow().len()));
        Self {
            target,
            ktid: unsafe { libc::gettid() } as i64,
            tpidr: crate::current_thread_id_u64(),
            depth_cell,
            guards_cell,
            depth,
            guards,
            suspended: JS_SUSPENDED_FRAMES.with(|s| s.borrow().len()),
            generation: crate::js_engine_generation(),
            owner: crate::JS_ENGINE_OWNER_THREAD.load(Ordering::Acquire),
        }
    }

    fn report_if_changed(&self, site: &str) {
        let exit = Self::capture(self.target);
        if self != &exit {
            output_message(&format!(
                "[rustfrida INTERNAL] callback scope mismatch site={} target={:#x}\n\
                 [rustfrida INTERNAL] entry: {:x?}\n\
                 [rustfrida INTERNAL] exit:  {:x?}\n",
                site, self.target, self, exit,
            ));
        }
    }
}

// 站点计数（每线程、按入口/出口站点分别累计，进入 +1、退出 -1）。
// 只用于 underflow 诊断：真机出现过 ~1/246k 的深度下溢，静态审查无法定位，
// 下溢时 dump 各站点净值可直接指出"哪个出口多跑 / 哪个入口少跑"。
// 仅在 engine-depth-diagnostics feature 开启时记录，默认热路径不计数。
thread_local! {
    static JS_ENGINE_DEPTH_SITES: std::cell::RefCell<Vec<(&'static str, i64)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn bump_depth_site(site: &'static str, delta: i64) {
    if !cfg!(feature = "engine-depth-diagnostics") {
        return;
    }
    JS_ENGINE_DEPTH_SITES.with(|s| {
        let mut v = s.borrow_mut();
        for (k, n) in v.iter_mut() {
            if *k == site {
                *n += delta;
                return;
            }
        }
        v.push((site, delta));
    });
}

fn dump_depth_sites() -> String {
    if !cfg!(feature = "engine-depth-diagnostics") {
        return "disabled (enable engine-depth-diagnostics)".to_string();
    }
    JS_ENGINE_DEPTH_SITES.with(|s| {
        let v = s.borrow();
        let mut out = String::new();
        for (k, n) in v.iter() {
            if !out.is_empty() {
                out.push_str(", ");
            }
            out.push_str(&format!("{}:{}", k, n));
        }
        out
    })
}

// ── 深度事件全局环形缓冲（纯诊断）────────────────────────────────────
// 真机 underflow 数据显示：出口线程 TLS 全空（depth=0/sites={}/guards=0）
// 但全局 owner 恰等于该线程 TPIDR——单线程稳定 TLS 模型下不可能。
// 需要跨线程事件序列区分三种可能：TPIDR 复用（旧线程残留 owner）、
// 进程内静态双副本（hide-so 遮蔽 maps 无法确认）、TLS 被外部重置。
// 内核 tid（gettid）唯一且不快速复用，与 TPIDR 一起记录即可分辨。
struct EngineDepthEvent {
    ktid: i64,
    tpidr: u64,
    site: &'static str,
    is_entry: bool,
    depth: i64,
}

static ENGINE_DEPTH_EVENTS: Mutex<std::collections::VecDeque<EngineDepthEvent>> =
    Mutex::new(std::collections::VecDeque::new());

fn record_depth_event(site: &'static str, is_entry: bool, depth: i64) {
    if !cfg!(feature = "engine-depth-diagnostics") {
        return;
    }
    // 热路径：try_lock，竞争时丢事件也不阻塞回调。
    if let Ok(mut q) = ENGINE_DEPTH_EVENTS.try_lock() {
        if q.len() >= 512 {
            q.pop_front();
        }
        q.push_back(EngineDepthEvent {
            ktid: unsafe { libc::gettid() } as i64,
            tpidr: crate::current_thread_id_u64(),
            site,
            is_entry,
            depth,
        });
    }
}

fn dump_depth_events(max: usize) -> String {
    if !cfg!(feature = "engine-depth-diagnostics") {
        return "disabled (enable engine-depth-diagnostics)".to_string();
    }
    let q = match ENGINE_DEPTH_EVENTS.lock() {
        Ok(q) => q,
        Err(e) => e.into_inner(),
    };
    let skip = q.len().saturating_sub(max);
    let mut out = String::new();
    for ev in q.iter().skip(skip) {
        if !out.is_empty() {
            out.push_str(" | ");
        }
        out.push_str(&format!(
            "{}{} k{} t{:#x} d{}",
            if ev.is_entry { "E" } else { "X" },
            ev.site,
            ev.ktid,
            ev.tpidr,
            ev.depth
        ));
    }
    out
}

/// 进入一层 JS 引擎执行域。
///
/// 栈检查基准的建立分三种情况：
///   1. 本线程有外层调用正让锁挂起（TLS 挂起记录非空）：Runtime 里当前的
///      栈基准可能属于让锁窗口内跑过 JS 的其它线程——恢复本线程挂起时
///      保存的基准。只恢复栈检查状态，不接回帧链（帧链由外层 reacquire
///      恢复）。挂起记录里的地址在本线程 C 栈上，本线程存活期间始终有效。
///   2. 最外层进入（depth 0）：以当前栈指针建立新基准。
///   3. 同线程持锁嵌套（无挂起记录、depth>0）：沿用外层基准——锁在本线程
///      手里，期间没有其它线程能进 JS，基准必然还是自己的。
pub(crate) unsafe fn note_js_engine_entry(ctx: *mut ffi::JSContext, site: &'static str) {
    let suspended = JS_SUSPENDED_FRAMES.with(|s| s.borrow().last().map(|st| (st.stack_top, st.stack_limit)));
    if let Some((stack_top, stack_limit)) = suspended {
        ffi::qjs_restore_stack_check_state(ctx, stack_top, stack_limit);
    } else {
        let depth = JS_ENGINE_ENTRY_DEPTH.with(|d| d.get());
        if depth == 0 {
            ffi::qjs_update_stack_top(ctx);
        }
    }
    bump_depth_site(site, 1);
    let new_depth = JS_ENGINE_ENTRY_DEPTH.with(|d| {
        let v = d.get() + 1;
        d.set(v);
        v
    });
    record_depth_event(site, true, new_depth as i64);
}

/// 与 note_js_engine_entry 配对退出一层。计数下溢属于内部状态错误，响亮报告，
/// 并 dump 本线程各入口/出口站点净值与挂起记录数，定位是哪条路径不配平。
pub(crate) fn note_js_engine_exit(site: &'static str) {
    bump_depth_site(site, -1);
    let underflow = JS_ENGINE_ENTRY_DEPTH.with(|d| {
        let v = d.get();
        if v == 0 {
            true
        } else {
            d.set(v - 1);
            false
        }
    });
    if underflow {
        record_depth_event(site, false, -1);
        let suspended = JS_SUSPENDED_FRAMES.with(|s| s.borrow().len());
        let tls_guards = JS_ENGINE_TLS_GUARDS.with(|s| s.borrow().len());
        let owner = crate::JS_ENGINE_OWNER_THREAD.load(Ordering::Relaxed);
        // 只探测互斥量状态，不读取引擎或尝试恢复丢失的 guard。
        let lock_state = match crate::JS_ENGINE.try_lock() {
            Ok(_) => "available",
            Err(std::sync::TryLockError::WouldBlock) => "locked",
            Err(std::sync::TryLockError::Poisoned(_)) => "poisoned",
        };
        let depth_addr = JS_ENGINE_ENTRY_DEPTH.with(|d| d as *const std::cell::Cell<usize> as u64);
        let engine_addr = &crate::JS_ENGINE as *const _ as u64;
        output_message(&format!(
            "[rustfrida INTERNAL] js engine entry depth underflow site={} ktid={} tpidr={:#x} pthread={:#x} owner={} suspended={} tls_guards={} engine_lock={} sites={{{}}} depth_cell={:#x} engine_static={:#x}\n[rustfrida INTERNAL] recent: {}\n",
            site,
            unsafe { libc::gettid() } as i64,
            crate::current_thread_id_u64(),
            unsafe { libc::pthread_self() } as u64,
            owner,
            suspended,
            tls_guards,
            lock_state,
            dump_depth_sites(),
            depth_addr,
            engine_addr,
            dump_depth_events(48)
        ));
    } else {
        let depth = JS_ENGINE_ENTRY_DEPTH.with(|d| d.get());
        record_depth_event(site, false, depth as i64);
    }
}

/// RAII 执行域：进入时 note_js_engine_entry，退出（含提前 return）时
/// note_js_engine_exit。供直接使用 JSContext 独立执行 JS 的调用方
/// （Context::eval / eval_module、java_boot 注入等）接入统一的栈基准管理，
/// 不得绕过它直接调 qjs_update_stack_top。
pub(crate) struct JsEngineExecutionScope;

impl JsEngineExecutionScope {
    pub(crate) unsafe fn enter(ctx: *mut ffi::JSContext) -> Self {
        note_js_engine_entry(ctx, "exec-scope");
        Self
    }
}

impl Drop for JsEngineExecutionScope {
    fn drop(&mut self) {
        note_js_engine_exit("exec-scope");
    }
}

fn deposit_js_engine_guard(g: MutexGuard<'static, Option<JSEngine>>) {
    JS_ENGINE_TLS_GUARDS.with(|s| s.borrow_mut().push(g));
}

fn take_js_engine_guard() -> Option<MutexGuard<'static, Option<JSEngine>>> {
    JS_ENGINE_TLS_GUARDS.with(|s| s.borrow_mut().pop())
}

/// 顶层脚本 / RPC 宿主执行把引擎 guard 托管进 TLS：让锁在全部 JS 入口
/// （回调、顶层脚本、RPC）行为一致，避免同一段 NativeFunction 调用仅因
/// 调用入口不同就从可协作执行变为持续持锁。
pub(crate) fn host_js_engine_guard_in_tls(g: MutexGuard<'static, Option<JSEngine>>) {
    deposit_js_engine_guard(g);
}

/// 与 host_js_engine_guard_in_tls 配对：宿主执行结束取回 guard 并释放锁。
/// TLS 中没有 guard 属于内部状态错误（让锁/reacquire 配对被破坏），响亮报告。
pub(crate) fn unhost_js_engine_guard_from_tls() {
    if take_js_engine_guard().is_none() {
        crate::jsapi::console::output_message(
            "[rustfrida INTERNAL] top-level execution ended but no engine guard in TLS\n",
        );
    }
    // 取出的 guard 在此 drop → 真正解锁
}

/// 让出 JS 引擎锁，供当前线程执行外部代码（JNI 原方法 / trampoline / NativeFunction）。
///
/// 仅当当前线程是引擎 owner 且锁已托管进 TLS（callback 路径，或顶层脚本/RPC
/// 的宿主执行）才真正让出；否则返回 false，原有持锁行为及其等待风险仍然存在。
/// 让出期间本线程不得触碰 QuickJS；外部代码里若触发其它 hook，
/// 其它线程（或本线程的嵌套回调）可以正常拿锁执行 JS。
pub(crate) unsafe fn yield_js_engine_for_external_call() -> bool {
    let current = crate::current_thread_id_u64();
    if crate::JS_ENGINE_OWNER_THREAD.load(Ordering::Acquire) != current {
        return false;
    }
    let guard = match take_js_engine_guard() {
        Some(g) => g,
        None => return false, // 锁未托管进 TLS（不应发生，见 host_js_engine_guard_in_tls），无法让出
    };
    let Some(engine) = guard.as_ref() else {
        // 引擎不存在时不存在可保存的执行状态：放回 guard，按未让锁处理。
        deposit_js_engine_guard(guard);
        return false;
    };
    // 摘下帧链头，并同时记录引擎代次、Runtime 归属与栈检查基准。
    // 此处只保存上述列出的状态，不隔离其它 Runtime 状态，也不延长
    // Context、活动调用或外部资源的生命期。
    let ctx = engine.context().as_ptr();
    let mut stack_top: u64 = 0;
    let mut stack_limit: u64 = 0;
    ffi::qjs_save_stack_check_state(ctx, &mut stack_top, &mut stack_limit);
    let state = SuspendedJsState {
        generation: crate::js_engine_generation(),
        rt: ffi::qjs_get_runtime(ctx) as usize,
        frame: ffi::qjs_save_current_stack_frame(ctx),
        stack_top,
        stack_limit,
    };
    JS_SUSPENDED_FRAMES.with(|s| s.borrow_mut().push(state));
    crate::clear_js_engine_owner_current_thread();
    drop(guard); // 真正解锁
    true
}

/// 与 yield_js_engine_for_external_call 配对：外部代码返回后重新拿锁。
///
/// yielded=false 表示"本次没有让锁"，直接返回。
/// yielded=true 时的校验顺序（与静态审查对齐）：
///   1. 确认锁内引擎仍存在（否则传入的 ctx 可能是悬垂指针，不得访问）；
///   2. 确认挂起记录存在、且代次与 Runtime 都与锁内当前引擎一致；
///   3. 以上全部通过才访问 ctx，接回帧链并还原栈检查基准。
/// 任何一步失败都是不可恢复的内部状态错误（继续执行等于在损坏的
/// 执行状态上运行 JS），响亮报告后终止进程，不伪装恢复成功。
pub(crate) unsafe fn reacquire_js_engine_after_external_call(ctx: *mut ffi::JSContext, yielded: bool) {
    if !yielded {
        return;
    }
    let g = match crate::JS_ENGINE.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let Some(engine) = g.as_ref() else {
        output_message(
            "[rustfrida INTERNAL] engine destroyed while external call suspended; cannot resume, aborting\n",
        );
        std::process::abort();
    };
    let saved = JS_SUSPENDED_FRAMES.with(|s| s.borrow_mut().pop());
    let Some(saved) = saved else {
        output_message("[rustfrida INTERNAL] engine reacquired after yield but no suspended state in TLS, aborting\n");
        std::process::abort();
    };
    let cur_generation = crate::js_engine_generation();
    let cur_rt = ffi::qjs_get_runtime(engine.context().as_ptr()) as usize;
    if cur_generation != saved.generation || cur_rt != saved.rt {
        output_message(&format!(
            "[rustfrida INTERNAL] suspended state stale: generation saved={} current={}, \
             rt saved={:#x} current={:#x}; aborting\n",
            saved.generation, cur_generation, saved.rt, cur_rt
        ));
        std::process::abort();
    }
    // 身份确认完毕，可以安全访问 ctx：接回帧链，并还原让锁前的栈检查基准
    // （不做 qjs_update_stack_top，避免挂起恢复抬深基准、重发栈预算）。
    ffi::qjs_restore_current_stack_frame(ctx, saved.frame);
    ffi::qjs_restore_stack_check_state(ctx, saved.stack_top, saved.stack_limit);
    crate::mark_js_engine_owner_current_thread();
    deposit_js_engine_guard(g);
}

/// 回调进入共享引擎：同线程重入复用外层访问权，其他线程阻塞等待 Mutex。
/// 返回前更新栈检查基准。此函数不验证外部调用的等待关系，也不提供等待超时。
pub(crate) unsafe fn acquire_js_engine_for_callback(
    ctx: *mut ffi::JSContext,
    _context_name: &str,
    target_id: u64,
) -> Option<JsEngineCallbackGuard> {
    let current_thread = crate::current_thread_id_u64();

    if crate::JS_ENGINE_OWNER_THREAD.load(std::sync::atomic::Ordering::Acquire) == current_thread {
        // 同线程重入：只加深计数，沿用外层已建立的栈检查基准，不重置。
        note_js_engine_entry(ctx, "cb-reentrant");
        return Some(JsEngineCallbackGuard::new(false, target_id));
    }

    let g = match crate::JS_ENGINE.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    crate::mark_js_engine_owner_current_thread();
    note_js_engine_entry(ctx, "cb-locked"); // 新持锁线程：建基准；若本线程有挂起记录则还原其基准
    deposit_js_engine_guard(g);
    Some(JsEngineCallbackGuard::new(true, target_id))
}

/// Check for JS exception, extract message + stack, and output error.
///
/// Returns true if an exception was found (caller should do cleanup and return).
/// 输出格式: `[{ctx} error] {message}\n{stack}` — stack 含 QuickJS 行号/函数名, 便于定位。
/// Handles secondary exceptions from toString gracefully.
pub(crate) unsafe fn handle_js_exception(ctx: *mut ffi::JSContext, result: ffi::JSValue, context_name: &str) -> bool {
    if ffi::qjs_is_exception(result) == 0 {
        return false;
    }
    let exc = ffi::JS_GetException(ctx);
    let exc_val = JSValue(exc);

    // message: Error.prototype.message 或 fallback 到 exception 本身 toString
    let msg_prop = exc_val.get_property(ctx, "message");
    let msg = if let Some(s) = msg_prop.to_string(ctx) {
        msg_prop.free(ctx);
        s
    } else {
        msg_prop.free(ctx);
        let fallback = exc_val
            .to_string(ctx)
            .unwrap_or_else(|| "[unknown exception]".to_string());
        // 吞掉 toString 可能抛出的二级异常
        let secondary = ffi::JS_GetException(ctx);
        let secondary_val = JSValue(secondary);
        if !secondary_val.is_null() && !secondary_val.is_undefined() {
            secondary_val.free(ctx);
        }
        fallback
    };

    // stack: QuickJS 在 Error 对象上自动生成, 含 "<anonymous>@<file>:<line>" 每一帧
    let stack_prop = exc_val.get_property(ctx, "stack");
    let stack = stack_prop.to_string(ctx).filter(|s| !s.is_empty());
    stack_prop.free(ctx);

    match stack {
        Some(s) => output_message(&format!("[{} error] {}\n{}", context_name, msg, s.trim_end())),
        None => output_message(&format!("[{} error] {}", context_name, msg)),
    }
    exc_val.free(ctx);
    true
}

/// Initialize a Mutex<Option<HashMap>> registry if not already initialized (idempotent).
pub(crate) fn ensure_registry_initialized<K: std::hash::Hash + Eq, V>(
    registry: &std::sync::Mutex<Option<std::collections::HashMap<K, V>>>,
) {
    let mut guard = registry.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(std::collections::HashMap::new());
    }
}

/// Acquire registry lock and call f with immutable reference to the HashMap.
/// Returns None if the registry is not initialized.
pub(crate) fn with_registry<K, V, R>(
    registry: &std::sync::Mutex<Option<std::collections::HashMap<K, V>>>,
    f: impl FnOnce(&std::collections::HashMap<K, V>) -> R,
) -> Option<R>
where
    K: std::hash::Hash + Eq,
{
    let guard = registry.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().map(f)
}

/// Acquire registry lock and call f with mutable reference to the HashMap.
/// Returns None if the registry is not initialized.
pub(crate) fn with_registry_mut<K, V, R>(
    registry: &std::sync::Mutex<Option<std::collections::HashMap<K, V>>>,
    f: impl FnOnce(&mut std::collections::HashMap<K, V>) -> R,
) -> Option<R>
where
    K: std::hash::Hash + Eq,
{
    let mut guard = registry.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_mut().map(f)
}

/// Bidirectional map backed by two Mutex<Option<HashMap<u64, u64>>>.
/// Provides synchronized forward and reverse lookups.
pub(crate) struct BiMap {
    forward: std::sync::Mutex<Option<std::collections::HashMap<u64, u64>>>,
    reverse: std::sync::Mutex<Option<std::collections::HashMap<u64, u64>>>,
}

impl BiMap {
    pub(crate) const fn new() -> Self {
        Self {
            forward: std::sync::Mutex::new(None),
            reverse: std::sync::Mutex::new(None),
        }
    }

    /// 初始化双向映射（幂等）
    pub(crate) fn init(&self) {
        ensure_registry_initialized(&self.forward);
        ensure_registry_initialized(&self.reverse);
    }

    /// 插入 forward(left → right) + reverse(right → left)
    pub(crate) fn insert(&self, left: u64, right: u64) {
        with_registry_mut(&self.forward, |map| {
            map.insert(left, right);
        });
        with_registry_mut(&self.reverse, |map| {
            map.insert(right, left);
        });
    }

    /// 通过 forward key 查找 value
    pub(crate) fn get_forward(&self, left: u64) -> Option<u64> {
        with_registry(&self.forward, |map| map.get(&left).copied()).flatten()
    }

    /// 通过 reverse key 查找是否存在
    pub(crate) fn contains_reverse(&self, right: u64) -> bool {
        with_registry(&self.reverse, |map| map.contains_key(&right)).unwrap_or(false)
    }

    /// 删除 forward(left) 及对应的 reverse 条目，返回被删除的 right 值
    pub(crate) fn remove_by_forward(&self, left: u64) -> Option<u64> {
        let right = with_registry_mut(&self.forward, |map| map.remove(&left)).flatten();
        if let Some(r) = right {
            with_registry_mut(&self.reverse, |map| {
                map.remove(&r);
            });
        }
        right
    }
}

/// Extract a u64 address from a JSValue that is either a NativePointer or a numeric value.
///
/// Returns Ok(addr) on success, Err(js_exception) on failure (exception already thrown).
pub(crate) unsafe fn extract_pointer_address(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
    func_name: &str,
) -> Result<u64, ffi::JSValue> {
    if let Some(a) = get_native_pointer_addr(ctx, arg) {
        return Ok(a);
    }
    if let Some(a) = arg.to_u64(ctx) {
        return Ok(a);
    }
    let msg = std::ffi::CString::new(format!("{}() argument must be a pointer", func_name)).unwrap_or_default();
    Err(ffi::JS_ThrowTypeError(ctx, msg.as_ptr()))
}

/// Extract a string argument from JSValue.
pub(crate) unsafe fn extract_string_arg(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
    error_msg: &[u8],
) -> Result<String, ffi::JSValue> {
    arg.to_string(ctx)
        .ok_or_else(|| ffi::JS_ThrowTypeError(ctx, error_msg.as_ptr() as *const _))
}

/// Ensure a JSValue is a function.
pub(crate) unsafe fn ensure_function_arg(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
    error_msg: &[u8],
) -> Result<(), ffi::JSValue> {
    if arg.is_function(ctx) {
        Ok(())
    } else {
        Err(ffi::JS_ThrowTypeError(ctx, error_msg.as_ptr() as *const _))
    }
}

/// Throw a type error from a static byte string.
pub(crate) unsafe fn throw_type_error(ctx: *mut ffi::JSContext, error_msg: &[u8]) -> ffi::JSValue {
    // error_msg 是 &[u8] 常量短字符串（不超 256 字节），继续用内置路径
    ffi::JS_ThrowTypeError(ctx, error_msg.as_ptr() as *const _)
}

/// Throw an internal error from an owned Rust string.
///
/// 绕开 QuickJS `JS_ThrowInternalError` 内部 `char buf[256]` + vsnprintf 的双重坑:
///   1. 256 字节硬截断 (Java 异常 + cause 链容易超过)
///   2. 消息被当 printf 格式字符串 (含 % 会被误解析/崩溃)
///
/// 使用 `qjs_throw_error_with_message` 直接 `new InternalError(msg)` 走 JS 构造器路径，
/// 消息长度无限制，`%` 原样保留。
pub(crate) unsafe fn throw_internal_error(ctx: *mut ffi::JSContext, message: impl AsRef<str>) -> ffi::JSValue {
    let msg = message.as_ref();
    let bytes = msg.as_bytes();
    let class_name = b"InternalError\0";
    ffi::qjs_throw_error_with_message(
        ctx,
        class_name.as_ptr() as *const std::os::raw::c_char,
        bytes.as_ptr() as *const std::os::raw::c_char,
        bytes.len(),
    )
}

/// Set a u64 property on a JS object. Uses Number for values ≤ 2^53, BigUint64 otherwise.
///
/// 封装 CString → JS_NewAtom → (Number | BigUint64) → qjs_set_property → JS_FreeAtom。
/// 热路径应直接用 `set_js_u64_property_atom` 跳过 CString / atom 分配。
pub(crate) unsafe fn set_js_u64_property(ctx: *mut ffi::JSContext, obj: ffi::JSValue, name: &str, value: u64) {
    let cname = std::ffi::CString::new(name).unwrap();
    let atom = ffi::JS_NewAtom(ctx, cname.as_ptr());
    let val = js_u64_to_js_number_or_bigint(ctx, value);
    ffi::qjs_set_property(ctx, obj, atom, val);
    ffi::JS_FreeAtom(ctx, atom);
}

/// Atom 版 u64 属性写入：直接用预缓存 atom，不做 CString/atom 分配，值走 Number-or-BigInt。
#[inline]
pub(crate) unsafe fn set_js_u64_property_atom(
    ctx: *mut ffi::JSContext,
    obj: ffi::JSValue,
    atom: ffi::JSAtom,
    value: u64,
) {
    let val = js_u64_to_js_number_or_bigint(ctx, value);
    ffi::qjs_set_property(ctx, obj, atom, val);
}

/// Atom 版通用属性写入：调用方已构造好 value，跳过 CString/atom 分配。
///
/// qjs_set_property 接管 value 的引用计数（成功时消耗，失败时也会 free），
/// 语义与 JSValue::set_property 一致。
#[inline]
pub(crate) unsafe fn set_js_value_property_atom(
    ctx: *mut ffi::JSContext,
    obj: ffi::JSValue,
    atom: ffi::JSAtom,
    value: ffi::JSValue,
) {
    ffi::qjs_set_property(ctx, obj, atom, value);
}

/// Set a CFunction property on a JS object.
pub(crate) unsafe fn set_js_cfunction_property(
    ctx: *mut ffi::JSContext,
    obj: ffi::JSValue,
    name: &str,
    func: JSCFn,
    argc: i32,
) {
    let cname = CString::new(name).unwrap();
    let func_val = ffi::qjs_new_cfunction(ctx, Some(func), cname.as_ptr(), argc);
    JSValue(obj).set_property(ctx, name, JSValue(func_val));
}

/// Read a u64-like property from a JS object. Non-numeric values fall back to 0.
pub(crate) unsafe fn get_js_u64_property(ctx: *mut ffi::JSContext, obj: ffi::JSValue, name: &str) -> u64 {
    let prop = JSValue(obj).get_property(ctx, name);
    let value = prop.to_u64(ctx).unwrap_or(0);
    prop.free(ctx);
    value
}

/// Atom 版 u64 属性读取：绕开 CString / atom 临时分配。
#[inline]
pub(crate) unsafe fn get_js_u64_property_atom(ctx: *mut ffi::JSContext, obj: ffi::JSValue, atom: ffi::JSAtom) -> u64 {
    let prop = ffi::qjs_get_property(ctx, obj, atom);
    let jv = JSValue(prop);
    let value = jv.to_u64(ctx).unwrap_or(0);
    jv.free(ctx);
    value
}

/// Convert a JS numeric/BigInt value to u64, defaulting to 0 on conversion failure.
pub(crate) unsafe fn js_value_to_u64_or_zero(ctx: *mut ffi::JSContext, value: JSValue) -> u64 {
    get_native_pointer_addr(ctx, value)
        .or_else(|| value.to_u64(ctx))
        .unwrap_or(0)
}

/// Encode a u64 as Number when it fits JS safe integer range, otherwise BigUint64.
pub(crate) unsafe fn js_u64_to_js_number_or_bigint(ctx: *mut ffi::JSContext, value: u64) -> ffi::JSValue {
    if value <= JS_MAX_SAFE_INTEGER {
        ffi::qjs_new_int64(ctx, value as i64)
    } else {
        ffi::JS_NewBigUint64(ctx, value)
    }
}

/// Encode an i64 as Number when it fits JS safe integer range, otherwise BigInt64.
pub(crate) unsafe fn js_i64_to_js_number_or_bigint(ctx: *mut ffi::JSContext, value: i64) -> ffi::JSValue {
    if value.unsigned_abs() <= JS_MAX_SAFE_INTEGER {
        ffi::qjs_new_int64(ctx, value)
    } else {
        ffi::JS_NewBigInt64(ctx, value)
    }
}

/// Duplicate a JS callback value and return its raw bytes for Send/Sync-safe storage.
///
/// The caller is responsible for eventually freeing the duplicated value via qjs_free_value.
pub(crate) unsafe fn dup_callback_to_bytes(ctx: *mut ffi::JSContext, callback: ffi::JSValue) -> [u8; 16] {
    let callback_dup = ffi::qjs_dup_value(ctx, callback);
    let mut bytes = [0u8; 16];
    std::ptr::copy_nonoverlapping(
        &callback_dup as *const ffi::JSValue as *const u8,
        bytes.as_mut_ptr(),
        16,
    );
    bytes
}

/// 统一的 hook 回调骨架：获取 JS 锁 → 提取 callback → 构建上下文对象 → JS_Call → 异常处理 → 清理。
///
/// 将 native hook 和 Java hook 回调的公共流程提取为一个函数。
/// 调用方负责：锁 registry 复制数据、设置/清除 atomics。
///
/// - `ctx_raw`: QuickJS context 指针（usize）
/// - `callback_bytes`: 16 字节 JS callback value（由 dup_callback_to_bytes 生成）
/// - `context_name`: 日志标识（"hook" / "java hook"）
/// - `target_id`: 目标地址（用于日志）
/// - `build_context`: 闭包，构建传给 JS 回调的上下文对象（返回 JSValue）
/// - `handle_result`: 闭包，处理 JS 回调返回值（仅无异常时调用）；
///   参数为 (ctx, js_ctx_obj, call_result)，可同时访问上下文对象和调用结果
/// - `on_js_exception`: 闭包，JS 抛异常时在 **JS_ENGINE 锁仍持有、QuickJS stack_top
///   仍有效** 的上下文里调用。用于需要"与 ctx.orig() 同等 ART 可见状态"的 fallback。
///   传 `|| {}` 跳过。
///
/// 返回值: `true` 表示 JS 回调抛异常（handle_result 未被调用），`false` 表示正常执行。
/// JS 执行期间 ART suspend 检查点。
///
/// QuickJS interrupt handler 周期性调用 ExceptionCheck，通过 JNI 调用触发
/// kNative→kRunnable→kNative 转换，让 ART 处理 pending suspend/checkpoint 请求。
/// 解决 JS_Call 长时间 kNative → SuspendThreadByPeer 超时 → SIGABRT。
///
/// JNIEnv 按线程现取（JavaVM.GetEnv），不用全局保存：
/// 旧实现 ART_CHECKPOINT_ENV 是全局 swap/restore，协作式让锁允许回调跨线程
/// 交错后嵌套顺序不再隐含正确（恢复线程可能拿到其它线程的 JNIEnv）；且让锁
/// 线程若在让出期间死亡，全局会残留死线程的 JNIEnv。GetEnv 在 handler 触发
/// 的当前线程上解析，天然线程正确；未 attach ART 的线程 GetEnv 失败即跳过。
static CHECKPOINT_JAVA_VM: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// JNIEnv 函数表索引（NDK jni.h 实测；与 jni_core.rs 常量同源）。
const JNI_FN_GET_JAVA_VM: usize = 219;
/// JavaVM 函数表索引。
const JNI_VM_GET_ENV: usize = 6;
/// JNIEnv 函数表 ExceptionCheck 索引（与 jni_core::JNI_EXCEPTION_CHECK 一致）。
const JNI_FN_EXCEPTION_CHECK: usize = 228;
const JNI_VERSION_1_6: i32 = 0x00010006;

/// 首次拿到合法 JNIEnv 时捕获 JavaVM*（幂等；GetJavaVM 是纯查表，无副作用）。
unsafe fn capture_java_vm_from_env(env: *mut std::ffi::c_void) {
    if env.is_null() || CHECKPOINT_JAVA_VM.load(std::sync::atomic::Ordering::Acquire) != 0 {
        return;
    }
    let vtable = *(env as *const *const usize);
    type GetJavaVmFn = unsafe extern "C" fn(*mut std::ffi::c_void, *mut *mut std::ffi::c_void) -> i32;
    let get_vm: GetJavaVmFn = std::mem::transmute(*(vtable.add(JNI_FN_GET_JAVA_VM)));
    let mut vm: *mut std::ffi::c_void = std::ptr::null_mut();
    if get_vm(env, &mut vm) == 0 && !vm.is_null() {
        CHECKPOINT_JAVA_VM.store(vm as usize, std::sync::atomic::Ordering::Release);
    }
}

/// QuickJS interrupt handler — 注册到 JS_SetInterruptHandler。
/// QuickJS 每执行一定数量的操作码后调用一次（默认 ~255 条指令）。
pub(crate) unsafe extern "C" fn art_interrupt_handler(_rt: *mut ffi::JSRuntime, _opaque: *mut std::ffi::c_void) -> i32 {
    let vm = CHECKPOINT_JAVA_VM.load(std::sync::atomic::Ordering::Acquire);
    if vm != 0 {
        let vm_ptr = vm as *mut std::ffi::c_void;
        let vm_vtable = *(vm_ptr as *const *const usize);
        type GetEnvFn = unsafe extern "C" fn(*mut std::ffi::c_void, *mut *mut std::ffi::c_void, i32) -> i32;
        let get_env: GetEnvFn = std::mem::transmute(*(vm_vtable.add(JNI_VM_GET_ENV)));
        let mut env: *mut std::ffi::c_void = std::ptr::null_mut();
        // JNI_OK=0：当前线程已 attach ART，拿到的是本线程的 JNIEnv。
        if get_env(vm_ptr, &mut env, JNI_VERSION_1_6) == 0 && !env.is_null() {
            let env_vtable = *(env as *const *const usize);
            type ExcCheckFn = unsafe extern "C" fn(*mut std::ffi::c_void) -> u8;
            let exc_check: ExcCheckFn = std::mem::transmute(*(env_vtable.add(JNI_FN_EXCEPTION_CHECK)));
            exc_check(env);
        }
    }
    if crate::js_execution_deadline_expired() {
        1
    } else {
        0
    }
}

pub(crate) unsafe fn invoke_hook_callback_common(
    ctx_raw: usize,
    callback_bytes: &[u8; 16],
    context_name: &str,
    target_id: u64,
    build_context: impl FnOnce(*mut ffi::JSContext) -> ffi::JSValue,
    handle_result: impl FnOnce(*mut ffi::JSContext, ffi::JSValue, ffi::JSValue),
    on_js_exception: impl FnOnce(*mut ffi::JSContext, ffi::JSValue),
) -> bool {
    invoke_hook_callback_common_with_env(
        ctx_raw,
        callback_bytes,
        context_name,
        target_id,
        std::ptr::null_mut(),
        build_context,
        handle_result,
        on_js_exception,
    )
}

pub(crate) unsafe fn invoke_hook_callback_common_with_env(
    ctx_raw: usize,
    callback_bytes: &[u8; 16],
    context_name: &str,
    target_id: u64,
    jni_env: *mut std::ffi::c_void,
    build_context: impl FnOnce(*mut ffi::JSContext) -> ffi::JSValue,
    handle_result: impl FnOnce(*mut ffi::JSContext, ffi::JSValue, ffi::JSValue),
    on_js_exception: impl FnOnce(*mut ffi::JSContext, ffi::JSValue),
) -> bool {
    let ctx = ctx_raw as *mut ffi::JSContext;

    // 同线程重入复用外层访问权；其他线程在这里阻塞等待，不是 try_lock。
    let _js_guard = match acquire_js_engine_for_callback(ctx, context_name, target_id) {
        Some(g) => g,
        None => return false,
    };

    let callback: ffi::JSValue = std::ptr::read(callback_bytes.as_ptr() as *const ffi::JSValue);
    let callback_dup = ffi::qjs_dup_value(ctx, callback);

    let js_ctx = build_context(ctx);

    // ART suspend 兼容: 捕获 JavaVM（幂等）。interrupt handler 在 JS 执行线程上
    // 现取 JNIEnv 做 ExceptionCheck 检查点，无需全局 swap/restore。
    capture_java_vm_from_env(jni_env);

    let global = ffi::JS_GetGlobalObject(ctx);
    let result = ffi::JS_Call(ctx, callback_dup, global, 1, &js_ctx as *const _ as *mut _);

    // 先固定本次回调的同步结果与异常归属：读取并清算异常槽、完成结果写回，
    // 再进入任务处理阶段。任务自身可能抛异常并覆盖异常槽，若先 drain，
    // 本次回调的原始错误和堆栈会被任务异常冲掉。
    let had_exception = handle_js_exception(ctx, result, context_name);
    if had_exception {
        on_js_exception(ctx, js_ctx);
    } else {
        handle_result(ctx, js_ctx, result);
    }

    // 任务边界（对齐 frida gumjs 离开 scope 时 drain）：回调内 queueMicrotask /
    // Promise.then 排队的 job 在此立即执行，不拖到下次脚本加载/RPC。
    // 空队列时 JS_ExecutePendingJob 立即返回 0，开销可忽略。
    crate::context::drain_pending_jobs_reporting(ctx);

    ffi::qjs_free_value(ctx, js_ctx);
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, global);
    ffi::qjs_free_value(ctx, callback_dup);

    had_exception
}
