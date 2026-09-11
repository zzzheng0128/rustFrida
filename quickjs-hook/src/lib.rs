//! quickjs-hook：连接 QuickJS 引擎、宿主脚本入口和扩展 API 的 Rust 封装层。
//!
//! 阅读主线：JSEngine::new 创建 Runtime/Context 并注册 API；
//! load_script_with_filename 负责共享引擎的加锁、脚本执行和后续任务处理。
//! 解释器本体在 quickjs-src；本文件负责宿主生命周期，不负责 JS 字节码解释。
//!
//! This crate provides:
//! - QuickJS JavaScript engine bindings
//! - ARM64 inline hook engine
//! - Frida-style JavaScript API for hooking
//!
//! # Example
//!
//! ```rust,ignore
//! use quickjs_hook::{JSEngine, init_hook_engine};
//!
//! // Initialize hook engine with executable memory
//! init_hook_engine(exec_mem, size).unwrap();
//!
//! // Create JS engine and run script
//! let engine = JSEngine::new().unwrap();
//! engine.eval(r#"
//!     console.log("Hello from QuickJS!");
//!     hook(ptr("0x12345678"), function(ctx) {
//!         console.log("Hooked! x0=" + ctx.x0);
//!     });
//! "#).unwrap();
//! ```

#![allow(clippy::missing_safety_doc)]

mod completion;
pub mod context;
mod execution_state;
pub mod fast_hook;
pub mod ffi;
pub mod jsapi;
mod raw_thread;
pub mod recomp;
pub mod runtime;
pub mod value;

pub use completion::complete_script;
pub use context::JSContext;
pub use jsapi::console::{set_console_callback, set_verbose};
pub use jsapi::deferred_java_init;
pub use jsapi::hook_api::cleanup_hooks;
#[cfg(feature = "qbdi")]
pub use jsapi::hook_api::preload_qbdi_helper;
#[cfg(feature = "qbdi")]
pub use jsapi::hook_api::shutdown_qbdi_helper;
pub use jsapi::hook_api::{cut_native_hooks, free_native_hooks};
pub use jsapi::java::abort_raw_clone_java_executor_for_unload;
pub use jsapi::java::art_controller::{
    cut_art_controller_hooks, cut_art_controller_routing_hooks, cut_art_controller_walkstack_guards,
    free_art_controller_state, set_art_controller_reload_paused,
};
pub use jsapi::java::cleanup_java_hooks;
pub use jsapi::java::detach_current_jni_thread;
pub use jsapi::java::finish_java_worker_thread_from_native;
pub use jsapi::java::java_subsystem_active_for_cleanup;
pub use jsapi::java::raw_clone_java_executor_hook_active;
pub use jsapi::java::start_java_worker_thread;
pub use jsapi::java::{cut_java_hooks, drain_thunk_in_flight, free_java_hooks};
pub use jsapi::memory::cleanup_wxshadow_patches;
pub use raw_thread::set_thread_exit_callback;
pub use runtime::JSRuntime;
pub use value::JSValue;

pub(crate) use execution_state::js_execution_deadline_expired;
use execution_state::{EngineLifecycle, JsExecutionDeadlineGuard};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const JS_TOP_LEVEL_EXECUTION_TIMEOUT_MS: u64 = 6_500;

static QBDI_OUTPUT_DIR: OnceLock<String> = OnceLock::new();
static QBDI_HELPER_BLOB: Mutex<Option<Vec<u8>>> = Mutex::new(None);

pub fn set_qbdi_output_dir(output_dir: impl Into<String>) {
    let _ = QBDI_OUTPUT_DIR.set(output_dir.into());
}

pub fn set_qbdi_helper_blob(blob: Vec<u8>) {
    *QBDI_HELPER_BLOB.lock().unwrap_or_else(|e| e.into_inner()) = Some(blob);
}

pub(crate) fn qbdi_output_dir() -> Option<&'static str> {
    QBDI_OUTPUT_DIR.get().map(|s| s.as_str())
}

pub(crate) fn qbdi_helper_blob() -> Option<Vec<u8>> {
    QBDI_HELPER_BLOB.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// 宿主入口共享的引擎；Mutex 用于串行化访问，不能据此推断外部调用不会死锁。
/// 回调模块也访问此锁。让锁期间的活动调用状态和对象生命期由调用路径另行维护。
pub(crate) static JS_ENGINE: Mutex<Option<JSEngine>> = Mutex::new(None);
/// 当前执行线程的辅助标记，用于区分同线程重入和其他线程争用。
/// 此原子值不替代 Mutex，也不拥有 Runtime 或 Context 的生命周期。
pub(crate) static JS_ENGINE_OWNER_THREAD: AtomicU64 = AtomicU64::new(0);

/// 查闸门与登记在途执行共用同一把锁。锁序为 ENGINE → LIFECYCLE；
/// 清理时关闭入口并等待归零，释放生命周期锁后才取得 ENGINE 销毁引擎。
static ENGINE_LIFECYCLE: EngineLifecycle = EngineLifecycle::new();
/// 引擎代次：cleanup_engine 每销毁一次引擎递增。让锁时记录的挂起状态
/// 携带当时的代次，恢复时比对——即使 Runtime 地址被释放后复用，
/// 代次不一致也能识别出来（地址比较无法识别复用）。
static JS_ENGINE_GENERATION: AtomicU64 = AtomicU64::new(0);

pub(crate) fn js_engine_generation() -> u64 {
    JS_ENGINE_GENERATION.load(Ordering::Acquire)
}

static RAW_CLONE_JS_THREAD_0: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_1: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_2: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_3: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_4: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_5: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_6: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_7: AtomicU64 = AtomicU64::new(0);

fn raw_clone_js_thread_slots() -> [&'static AtomicU64; 8] {
    [
        &RAW_CLONE_JS_THREAD_0,
        &RAW_CLONE_JS_THREAD_1,
        &RAW_CLONE_JS_THREAD_2,
        &RAW_CLONE_JS_THREAD_3,
        &RAW_CLONE_JS_THREAD_4,
        &RAW_CLONE_JS_THREAD_5,
        &RAW_CLONE_JS_THREAD_6,
        &RAW_CLONE_JS_THREAD_7,
    ]
}

pub struct RawCloneJsThreadGuard {
    id: u64,
}

impl Drop for RawCloneJsThreadGuard {
    fn drop(&mut self) {
        for slot in raw_clone_js_thread_slots() {
            if slot.load(Ordering::Acquire) == self.id {
                let _ = slot.compare_exchange(self.id, 0, Ordering::AcqRel, Ordering::Acquire);
                break;
            }
        }
    }
}

pub fn mark_raw_clone_js_thread() -> RawCloneJsThreadGuard {
    let id = current_thread_id_u64();
    for slot in raw_clone_js_thread_slots() {
        if slot.load(Ordering::Acquire) == id
            || slot
                .compare_exchange(0, id, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return RawCloneJsThreadGuard { id };
        }
    }
    RawCloneJsThreadGuard { id }
}

pub(crate) fn is_raw_clone_js_thread() -> bool {
    let id = current_thread_id_u64();
    raw_clone_js_thread_slots()
        .iter()
        .any(|slot| slot.load(Ordering::Acquire) == id)
}

#[inline]
pub(crate) fn current_thread_id_u64() -> u64 {
    // Must use TPIDR_EL0 directly — on API 36, pthread_self() != TPIDR_EL0.
    // The thunk bypass uses MRS TPIDR_EL0 for thread matching.
    let tpidr: u64;
    unsafe { std::arch::asm!("mrs {}, tpidr_el0", out(reg) tpidr) };
    tpidr
}

#[inline]
pub(crate) fn mark_js_engine_owner_current_thread() {
    JS_ENGINE_OWNER_THREAD.store(current_thread_id_u64(), Ordering::Release);
}

#[inline]
pub(crate) fn clear_js_engine_owner_current_thread() {
    let current = current_thread_id_u64();
    let _ = JS_ENGINE_OWNER_THREAD.compare_exchange(current, 0, Ordering::AcqRel, Ordering::Relaxed);
}

// 只管理 owner 标记，不持有或释放引擎锁；必须与实际持锁作用域配合使用。
struct JsEngineOwnerGuard;

impl JsEngineOwnerGuard {
    fn acquire() -> Self {
        mark_js_engine_owner_current_thread();
        JsEngineOwnerGuard
    }
}

impl Drop for JsEngineOwnerGuard {
    fn drop(&mut self) {
        clear_js_engine_owner_current_thread();
    }
}

/// RAII：宿主执行（顶层脚本 / RPC）结束（含 `?` 提前返回）时从 TLS 取回
/// 引擎 guard 并解锁，同时退出执行域计数。与
/// jsapi::callback_util::host_js_engine_guard_in_tls + note_js_engine_entry 配对。
struct HostedEngineTlsGuard {
    site: &'static str,
}

impl Drop for HostedEngineTlsGuard {
    fn drop(&mut self) {
        jsapi::callback_util::unhost_js_engine_guard_from_tls();
        jsapi::callback_util::note_js_engine_exit(self.site);
    }
}

/// Log callback registered with the C hook engine.
/// Routes hook_engine diagnostic messages through the JS console callback
/// so they appear in the REPL output alongside normal [JS] messages.
unsafe extern "C" fn hook_engine_log_impl(msg: *const std::os::raw::c_char) {
    if msg.is_null() {
        return;
    }
    let s = std::ffi::CStr::from_ptr(msg).to_string_lossy();
    let formatted = format!("[hook_engine] {}", s);
    // 错误/警告永远输出（失败类消息对排错重要），其余全部 verbose 静默
    // 识别关键字: FAILED/failed/失败/ERROR/WARN/\033[31m 红/\033[33m 黄
    let is_error = s.contains("FAILED")
        || s.contains("failed")
        || s.contains("失败")
        || s.contains("ERROR")
        || s.contains("WARN")
        || s.contains("\x1b[31m")
        || s.contains("\x1b[33m");
    if is_error {
        crate::jsapi::console::output_message(&formatted);
    } else {
        crate::jsapi::console::output_verbose(&formatted);
    }
}

/// Initialize the hook engine with executable memory
///
/// # Arguments
/// * `exec_mem` - Pointer to executable memory region (must be RWX)
/// * `size` - Size of the memory region in bytes
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` on failure
pub fn init_hook_engine(exec_mem: *mut u8, size: usize) -> Result<(), String> {
    let result = unsafe { ffi::hook::hook_engine_init(exec_mem as *mut _, size) };

    if result == 0 {
        // Register log callback so wxshadow/prctl diagnostics appear in REPL
        unsafe { ffi::hook::hook_engine_set_log_fn(Some(hook_engine_log_impl)) };
        Ok(())
    } else {
        Err("Failed to initialize hook engine".to_string())
    }
}

/// Cleanup the hook engine
///
/// 对标 Frida: 只 reset 内部状态, 不 munmap 扩展 pool (见 hook_engine.c 注释).
/// 线程若还在 thunk 里执行, 代码页保留直到进程退出, 避免 SIGSEGV。
pub fn cleanup_hook_engine() {
    unsafe {
        ffi::hook::hook_engine_cleanup();
    }
}

/// 同时拥有 Context 和 Runtime 的高层封装。
/// Rust 按字段声明顺序销毁字段：Context 必须先于其依赖的 Runtime 释放。
pub struct JSEngine {
    context: JSContext,
    runtime: JSRuntime,
}

impl JSEngine {
    /// 创建引擎并安装宿主扩展；只完成注册，不代表 Java 应用环境已经就绪。
    pub fn new() -> Option<Self> {
        let runtime = JSRuntime::new()?;
        let context = runtime.new_context()?;

        // 向全局对象添加宿主 API；JavaScript 标准内置对象由 QuickJS 创建 Context 时提供。
        jsapi::register_all_apis(&context);

        // 预缓存 hook callback 热路径用到的 atom（x0..x30 / sp / pc / lr / returnAddress /
        // trampoline / __hookCtxPtr / __hookTrampoline），消除每次回调的 CString+JS_NewAtom 开销。
        unsafe {
            jsapi::callback_util::init_hot_atoms(context.as_ptr());
        }

        Some(JSEngine { runtime, context })
    }

    /// Evaluate a JavaScript script
    pub fn eval(&self, script: &str) -> Result<JSValue, String> {
        self.context.eval(script, "<eval>")
    }

    /// 执行传入的源码字符串；filename 是报错定位名，此方法本身不读取磁盘文件。
    pub fn eval_file(&self, script: &str, filename: &str) -> Result<JSValue, String> {
        self.context.eval(script, filename)
    }

    /// Get the JS context
    pub fn context(&self) -> &JSContext {
        &self.context
    }

    /// Get the JS runtime
    pub fn runtime(&self) -> &JSRuntime {
        &self.runtime
    }

    /// 在当前调用线程处理待执行任务并报告错误；这不是后台线程或独立事件循环。
    pub fn run_pending_jobs(&self) {
        unsafe { context::drain_pending_jobs_reporting(self.context.as_ptr()) };
    }

    /// 顶层脚本结束后交付 Java.ready 队列，使回调能够访问同一脚本后面声明的变量。
    /// raw clone 线程在此跳过交付；具体就绪条件由 Java 层处理。
    pub fn flush_java_ready_callbacks(&self) -> Result<(), String> {
        if is_raw_clone_js_thread() {
            return Ok(());
        }
        let value = self.context.eval(
            "if (globalThis.Java && typeof Java._flushReadyCallbacks === 'function') Java._flushReadyCallbacks();",
            "<java_ready_flush>",
        )?;
        value.free(self.context.as_ptr());
        Ok(())
    }
}

impl Drop for JSEngine {
    fn drop(&mut self) {
        // 外部编排器 (agent::quickjs_loader::cleanup) 在调用 cleanup_engine 之前
        // 已按 cut → drain → free 完成所有 hook 清理。此处不再重复调用 cleanup_java_hooks
        // / cleanup_hooks — 否则 drain 会再跑一次 30s 上限（hook registry 已空，
        // 但 g_thunk_in_flight 可能仍 > 0，纯粹浪费时间）。
        //
        // 若 JSEngine 被独立 drop（非经 orchestrator），调用方负责先 cut/drain/free。
        //
        // Drop 顺序（字段声明顺序）：先 context（这里访问仍有效）→ 再 runtime。
        // 在 context drop 前释放热路径 atom，让 JS_FreeAtom 有合法上下文。
        unsafe {
            jsapi::callback_util::free_hot_atoms(self.context.as_ptr());
        }
    }
}

// 使用约束：共享入口以 Mutex 串行访问引擎；直接使用 JSEngine 的调用者也必须
// 保证互斥、线程状态与生命周期正确，unsafe impl 不会自动落实这些条件。
unsafe impl Send for JSEngine {}
unsafe impl Sync for JSEngine {}

/// 确保共享引擎存在；已初始化时复用，不会清空全局变量或重新执行用户脚本。
pub fn get_or_init_engine() -> Result<(), String> {
    let mut engine = JS_ENGINE
        .lock()
        .map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    let _in_flight = ENGINE_LIFECYCLE
        .try_enter()
        .ok_or_else(|| "JS engine is shutting down; init rejected".to_string())?;
    if engine.is_none() {
        *engine = Some(JSEngine::new().ok_or_else(|| "Failed to create JS engine".to_string())?);
    }
    Ok(())
}

/// 在共享引擎中执行源码，返回结果的字符串表示；undefined 返回字符串 "undefined"。
///
/// 等价于 `load_script_with_filename(script, "<eval>")`。
pub fn load_script(script: &str) -> Result<String, String> {
    load_script_with_filename(script, "<eval>")
}

/// Load + execute with an explicit filename (用于 QuickJS 报错时显示 `filename:line:col`)。
pub fn load_script_with_filename(script: &str, filename: &str) -> Result<String, String> {
    // 引擎 guard 托管进 TLS（与回调入口同一路径），使 NativeFunction 等外部调用
    // 在顶层脚本中同样可以协作式让锁；作用域结束由 HostedEngineTlsGuard 取回并解锁。
    let mut engine_guard = JS_ENGINE
        .lock()
        .map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    // 在同一生命周期临界区查闸门并登记，登记覆盖初始化和全部让锁窗口。
    let _in_flight = ENGINE_LIFECYCLE
        .try_enter()
        .ok_or_else(|| "JS engine is shutting down; script load rejected".to_string())?;
    if engine_guard.is_none() {
        *engine_guard = Some(JSEngine::new().ok_or_else(|| "Failed to create JS engine".to_string())?);
    }
    // JSEngine 位于 static Mutex<Option<...>> 内，地址稳定；引擎置换
    // （cleanup_engine）会等待在途顶层执行归零，因此此引用在整个宿主执行期间有效。
    let engine_ptr = engine_guard.as_ref().unwrap() as *const JSEngine;
    jsapi::callback_util::host_js_engine_guard_in_tls(engine_guard);
    let _tls_unhost = HostedEngineTlsGuard { site: "load-script" };
    let _owner_guard = JsEngineOwnerGuard::acquire();
    let engine = unsafe { &*engine_ptr };
    unsafe { jsapi::callback_util::note_js_engine_entry(engine.context().as_ptr(), "load-script") };
    let _deadline_guard = JsExecutionDeadlineGuard::begin(JS_TOP_LEVEL_EXECUTION_TIMEOUT_MS);
    let value = engine.eval_file(script, filename)?;
    // 先交付就绪回调，再处理其产生的任务；整个过程仍属于本次宿主调用。
    engine.flush_java_ready_callbacks()?;
    engine.run_pending_jobs();
    let result = if value.is_undefined() {
        "undefined".to_string()
    } else {
        value.to_string(engine.context().as_ptr()).unwrap_or_default()
    };
    value.free(engine.context().as_ptr());
    Ok(result)
}

/// 将任意字符串编码成 JS 字符串字面量（带双引号），可直接拼入 JS 源码。
fn js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// 调用 `rpc.exports[method]` 并返回 JSON 字符串化后的结果。
///
/// 使用全局 JS 引擎锁，与 REPL eval 互斥。HTTP RPC 调用应在外层用 Mutex 串行化，
/// 防止多个并发请求竞争同一把 JS 引擎锁。
///
/// # 参数
/// * `method` - 注册在 `rpc.exports` 上的方法名
/// * `args_json` - JSON array 字符串（如 `"[1, 2, 3]"`），空字符串等价于 `"[]"`
///
/// # 返回
/// * `Ok(json)` - 返回值的 JSON 字符串表示；`undefined` 返回 `"null"`
/// * `Err(msg)` - 引擎未初始化 / 方法不存在 / JS 异常
pub fn dispatch_rpc(method: &str, args_json: &str) -> Result<String, String> {
    let engine_guard = JS_ENGINE
        .lock()
        .map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    let _in_flight = ENGINE_LIFECYCLE
        .try_enter()
        .ok_or_else(|| "JS engine is shutting down; RPC rejected".to_string())?;
    if engine_guard.is_none() {
        return Err("JS engine not initialized".to_string());
    }
    // 与 load_script_with_filename 相同的 TLS 托管，让锁语义与回调/顶层一致。
    let engine_ptr = engine_guard.as_ref().unwrap() as *const JSEngine;
    jsapi::callback_util::host_js_engine_guard_in_tls(engine_guard);
    let _tls_unhost = HostedEngineTlsGuard { site: "rpc" };
    let _owner_guard = JsEngineOwnerGuard::acquire();
    let engine = unsafe { &*engine_ptr };
    unsafe { jsapi::callback_util::note_js_engine_entry(engine.context().as_ptr(), "rpc") };
    let _deadline_guard = JsExecutionDeadlineGuard::begin(JS_TOP_LEVEL_EXECUTION_TIMEOUT_MS);

    // 将方法名与参数文本编码成 JS 字符串字面量，避免把传入内容当作源码拼接。
    let script = format!(
        "__rpc_dispatch({}, {})",
        js_string_literal(method),
        js_string_literal(args_json),
    );

    let value = engine.eval(&script)?;
    engine.run_pending_jobs();
    let result = value
        .to_string(engine.context().as_ptr())
        .unwrap_or_else(|| "null".to_string());
    value.free(engine.context().as_ptr());
    Ok(result)
}

/// 清理第一步：关闭顶层脚本 / RPC 新入口，并有界等待在途顶层执行归零。
/// 返回 true 才可以销毁引擎；false 表示仍有挂起调用（可能正让锁阻塞在
/// 外部代码里，C 栈上仍挂着 QuickJS 调用帧），必须保留引擎与相关资源。
/// 编排层应在释放任何 JS 资源（hook 回调、注册表等）之前调用本函数。
///
/// 互斥协议：关闸门在生命周期协议锁下进行，与入口侧"查闸门 → 登记在途"
/// 的临界区互斥——已登记的执行必然被本函数等到，闸门关闭后来晚的执行
/// 必然看到闸门。等待计数归零期间不持任何锁：让锁挂起的调用需要重新
/// 拿 JS_ENGINE 锁才能退出、把计数减到零。
pub fn begin_engine_shutdown(timeout: std::time::Duration) -> bool {
    ENGINE_LIFECYCLE.begin_shutdown(timeout)
}

/// 重新开放顶层脚本 / RPC 入口。
///
/// 仅允许"模块保持加载"的交互式清理路径使用（jsclean / jsclean_soft：
/// 清理中止后恢复原状，或软清理成功、新一代引擎已随销毁递增代次）。
/// 最终卸载路径（cleanup_for_unload*）不得调用——闸门保持关闭，
/// 防止模块卸载途中仍有新执行进入。
pub fn reopen_engine_entry() {
    ENGINE_LIFECYCLE.reopen();
}

/// 销毁共享 Context/Runtime。
///
/// 返回 true 表示引擎已销毁（或本就不存在）；返回 false 表示仍有在途顶层
/// 执行，引擎被保留——此时拿到锁并不代表可以销毁挂起调用依赖的 Runtime。
/// 销毁成功后递增引擎代次，使此前让锁记录的所有挂起状态在恢复时被识别
/// 为失效（配合代次校验，地址复用也逃不过）。
pub fn cleanup_engine() -> bool {
    if !begin_engine_shutdown(std::time::Duration::from_secs(3)) {
        jsapi::console::output_message(
            "[rustfrida] cleanup_engine: top-level executions still in flight after 3s; \
             engine kept alive, cleanup FAILED (resources retained)\n",
        );
        return false;
    }
    let mut engine = match JS_ENGINE.lock() {
        Ok(engine) => engine,
        Err(_) => {
            jsapi::console::output_message("[rustfrida] cleanup_engine: engine lock poisoned; cleanup FAILED\n");
            return false;
        }
    };
    if engine.is_some() {
        *engine = None;
        JS_ENGINE_GENERATION.fetch_add(1, Ordering::AcqRel);
    }
    true
}
