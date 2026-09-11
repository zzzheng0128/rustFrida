// ============================================================================
// Argument marshalling — convert raw JNI register values to JS values
// ============================================================================

/// Convert a raw JNI argument (from register) to a JS value based on its JNI type descriptor.
///
/// Primitive types become JS numbers/booleans/bigints.
/// String objects become JS strings (read via GetStringUTFChars).
/// Other objects become wrapped `{__jptr, __jclass}` for Proxy-based field access.
/// Falls back to BigUint64 if type info is unavailable.
///
/// `fp_raw`: value from the corresponding d-register (for float/double args).
unsafe fn marshal_jni_arg_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    raw: u64,
    fp_raw: u64,
    type_sig: Option<&str>,
) -> ffi::JSValue {
    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => return ffi::JS_NewBigUint64(ctx, raw),
    };

    match sig.as_bytes()[0] {
        b'Z' => JSValue::bool(raw != 0).raw(),
        b'B' => JSValue::int(raw as i8 as i32).raw(),
        b'C' => {
            // char → JS string (single UTF-16 character)
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            JSValue::string(ctx, &s).raw()
        }
        b'S' => JSValue::int(raw as i16 as i32).raw(),
        b'I' => JSValue::int(raw as i32).raw(),
        b'J' => ffi::JS_NewBigUint64(ctx, raw),
        b'F' => {
            // ARM64 ABI: floats are passed in d0-d7 (FP registers).
            // fp_raw comes from HookContext.d[fp_index].
            let f = f32::from_bits(fp_raw as u32);
            JSValue::float(f as f64).raw()
        }
        b'D' => {
            // ARM64 ABI: doubles are passed in d0-d7 (FP registers).
            // fp_raw comes from HookContext.d[fp_index].
            let d = f64::from_bits(fp_raw);
            JSValue::float(d).raw()
        }
        b'L' | b'[' => {
            // Object or array — raw is a jobject local ref
            let obj = raw as *mut std::ffi::c_void;
            if obj.is_null() {
                return ffi::qjs_null();
            }
            // 快速路径: 签名是 String 时直接读 UTF，避免 get_runtime_class_name
            if sig == "Ljava/lang/String;" {
                let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
                let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
                let chars = get_str(env, obj, std::ptr::null_mut());
                if !chars.is_null() {
                    let s = std::ffi::CStr::from_ptr(chars).to_string_lossy().to_string();
                    rel_str(env, obj, chars);
                    return JSValue::string(ctx, &s).raw();
                }
                jni_check_exc(env);
                return ffi::qjs_null();
            }
            // 轻量路径: 用签名类名直接构造 {__jptr, __jclass} wrapper
            // 跳过 get_runtime_class_name (省 2-3 次 JNI/参数)
            let class_name = jni_object_sig_to_class_name(sig);
            wrap_java_object_value(ctx, raw, &class_name)
        }
        _ => ffi::JS_NewBigUint64(ctx, raw),
    }
}

#[inline]
unsafe fn extract_critical_native_arg(
    hook_ctx: &hook_ffi::HookContext,
    is_fp: bool,
    gp_index: &mut usize,
    fp_index: &mut usize,
    stack_index: &mut usize,
) -> (u64, u64) {
    if is_fp {
        let fp_val = if *fp_index < 8 {
            hook_ctx.d[*fp_index]
        } else {
            let sp = hook_ctx.sp as usize;
            let value = *((sp + *stack_index * 8) as *const u64);
            *stack_index += 1;
            value
        };
        *fp_index += 1;
        (0, fp_val)
    } else {
        let gp_val = if *gp_index < 8 {
            hook_ctx.x[*gp_index]
        } else {
            let sp = hook_ctx.sp as usize;
            let value = *((sp + *stack_index * 8) as *const u64);
            *stack_index += 1;
            value
        };
        *gp_index += 1;
        (gp_val, 0)
    }
}

unsafe fn marshal_critical_native_arg_to_js(
    ctx: *mut ffi::JSContext,
    raw: u64,
    fp_raw: u64,
    type_sig: Option<&str>,
) -> ffi::JSValue {
    match type_sig.and_then(|s| s.as_bytes().first().copied()) {
        Some(b'Z') => JSValue::bool(raw != 0).raw(),
        Some(b'B') => JSValue::int(raw as i8 as i32).raw(),
        Some(b'C') => {
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            JSValue::string(ctx, &ch.to_string()).raw()
        }
        Some(b'S') => JSValue::int(raw as i16 as i32).raw(),
        Some(b'I') => JSValue::int(raw as i32).raw(),
        Some(b'J') => ffi::JS_NewBigUint64(ctx, raw),
        Some(b'F') => JSValue::float(f32::from_bits(fp_raw as u32) as f64).raw(),
        Some(b'D') => JSValue::float(f64::from_bits(fp_raw)).raw(),
        _ => ffi::JS_NewBigUint64(ctx, raw),
    }
}

#[inline]
unsafe fn write_primitive_return_to_context(
    ctx_ptr: *mut hook_ffi::HookContext,
    return_type: u8,
    ret_raw: u64,
) {
    if matches!(return_type, b'F' | b'D') {
        (*ctx_ptr).d[0] = ret_raw;
    }
    (*ctx_ptr).x[0] = ret_raw;
}

// ============================================================================
// Hook callback (runs in hooked thread, called by ART JNI trampoline)
// ============================================================================

// 只在诊断构建中追踪前 16 次带 String 参数的回调。记录转换边界，
// 不读取/打印参数内容；非诊断构建不增加热路径计数或输出。
#[cfg(feature = "engine-depth-diagnostics")]
fn begin_jni_argument_trace(param_types: &[String]) -> Option<usize> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static TRACED: AtomicUsize = AtomicUsize::new(0);
    if !param_types.iter().any(|sig| sig == "Ljava/lang/String;") {
        return None;
    }
    TRACED
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            (n < 16).then_some(n + 1)
        })
        .ok()
}

#[cfg(feature = "engine-depth-diagnostics")]
fn trace_jni_argument_stage(trace: Option<usize>, method: u64, stage: &str, index: usize, sig: &str) {
    if let Some(trace) = trace {
        crate::jsapi::console::output_message(&format!(
            "[java.args] trace={} method={:#x} thread={} stage={} arg={} sig={}",
            trace, method, crate::current_thread_id_u64(), stage, index, sig
        ));
    }
}

// ============================================================================
// NativeEntry 调用方甄别
// ============================================================================
//
// NativeEntry 内联 hook 的是已注册 C++ 实现本体。打进来的调用未必都是 ART 按本方法
// 签名分派的 JNI 调用：该实现可能被多个 Java 方法共享注册（实测：抖音 J.N 把多个
// 不同签名的 native 方法注册到同一 C++ 函数，其他方法的 JIT JNI stub 以人家自己的
// 签名打进来，x4=1 之类的 int 被当成 jstring → GetStringUTFChars(1) 必崩），或被
// native 代码以内部约定直接调用。甄别分三层：
//   1. lr 区域过滤：lr 落在普通 .so 文本 = native 直调（外部 ABI）→ 透传。
//      libart / jit-cache(匿名·memfd) / odex·oat = JNI 分派区域 → 进下一层。
//   2. entrypoint 邻近检查：本方法的 quick entrypoint 是专用 stub（非 libart）时，
//      真实调用的 lr 必落在 [E, E+0x400)——其他方法的 stub 在别的地址 → 透传。
//   3. 引用参数可信校验（E 是 libart generic trampoline 时 lr 无法区分）：每个
//      引用参数（L/[ 开头）的句柄必须可读且槽位内容非零、8 字节对齐，否则透传。
struct NativeCallerRanges {
    accept: Vec<(u64, u64)>,
    reject: Vec<(u64, u64)>,
    libart: Vec<(u64, u64)>,
    readable: Vec<(u64, u64)>,
}

static NATIVE_CALLER_RANGES: std::sync::Mutex<Option<NativeCallerRanges>> =
    std::sync::Mutex::new(None);

fn parse_native_caller_ranges() -> NativeCallerRanges {
    let mut ranges = NativeCallerRanges {
        accept: Vec::new(),
        reject: Vec::new(),
        libart: Vec::new(),
        readable: Vec::new(),
    };
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            // 格式: start-end perms offset dev inode [path]
            let mut parts = line.split_whitespace();
            let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
                continue;
            };
            let Some((start_s, end_s)) = range.split_once('-') else {
                continue;
            };
            let (Ok(start), Ok(end)) = (
                u64::from_str_radix(start_s, 16),
                u64::from_str_radix(end_s, 16),
            ) else {
                continue;
            };
            let path = parts.nth(3).unwrap_or(""); // 跳过 offset dev inode
            if perms.starts_with('r') {
                ranges.readable.push((start, end));
            }
            if !perms.contains('x') {
                continue;
            }
            // 普通 .so（非 libart）里的 lr = native 直调（外部 ABI）→ 拒绝；
            // libart / jit-cache(匿名·memfd) / odex·oat / apk 内代码 = JNI 分派 → 接受。
            let is_libart = path.contains("libart.so");
            let is_plain_so = (path.ends_with(".so") || path.contains(".so!")) && !is_libart;
            if is_libart {
                ranges.libart.push((start, end));
            }
            if is_plain_so {
                ranges.reject.push((start, end));
            } else {
                ranges.accept.push((start, end));
            }
        }
    }
    ranges
}

fn native_entry_caller_is_jni(lr: u64) -> bool {
    let mut guard = match NATIVE_CALLER_RANGES.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    for _ in 0..2 {
        if let Some(ranges) = guard.as_ref() {
            if ranges.accept.iter().any(|&(s, e)| lr >= s && lr < e) {
                return true;
            }
            if ranges.reject.iter().any(|&(s, e)| lr >= s && lr < e) {
                return false;
            }
            // 未知区域（新 mmap 的 jit 页等）：重新解析一次再判。
        }
        *guard = Some(parse_native_caller_ranges());
    }
    // 解析后仍未知：按接受处理（宁可拦截也不丢真实 JNI 调用）
    true
}

/// 地址是否落在 libart.so 可执行文本（generic JNI trampoline / dlsym lookup stub）。
fn native_entry_addr_in_libart(addr: u64) -> bool {
    let guard = match NATIVE_CALLER_RANGES.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    guard
        .as_ref()
        .map(|r| r.libart.iter().any(|&(s, e)| addr >= s && addr < e))
        .unwrap_or(false)
}

/// 地址是否落在可读映射内（miss 时重解析一次 maps 再判）。
fn native_entry_is_readable(addr: u64, len: u64) -> bool {
    let mut guard = match NATIVE_CALLER_RANGES.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    for _ in 0..2 {
        if let Some(ranges) = guard.as_ref() {
            if ranges
                .readable
                .iter()
                .any(|&(s, e)| addr >= s && addr + len <= e)
            {
                return true;
            }
        }
        *guard = Some(parse_native_caller_ranges());
    }
    false
}

/// 校验一个 JNI 引用句柄（jstring/jobject/...）是否可信：
/// 句柄非零时必须指向可读内存，且槽位内容（间接引用表项里的对象指针）
/// 非零且 8 字节对齐。其他方法共享 C++ 实现打进来时，"引用位置"上往往是
/// int 小值（如 1）或已清空的槽位——校验失败即外来调用，必须透传而不是 marshal。
fn native_entry_plausible_jni_ref(raw: u64) -> bool {
    if raw == 0 {
        return true; // null 引用是合法的
    }
    if !native_entry_is_readable(raw, 8) {
        return false;
    }
    let slot = unsafe { std::ptr::read_unaligned(raw as *const u64) };
    slot != 0 && slot & 7 == 0
}

/// 外来调用透传：执行原实现并写回返回值，保持外部调用语义完全不变。
/// 日志限流（前 8 次 + 每 512 次），避免共享实现被高频调用时刷屏。
unsafe fn native_entry_foreign_bypass(
    ctx_ptr: *mut hook_ffi::HookContext,
    art_method_addr: u64,
    native_entry_trampoline: u64,
    return_type: u8,
    reason: &str,
) {
    #[cfg(feature = "engine-depth-diagnostics")]
    {
        static BYPASS_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = BYPASS_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n < 8 || n % 512 == 0 {
            crate::jsapi::console::output_message(&format!(
                "[java.args] foreign-call bypass({}) method={:#x} thread={} lr={:#x} n={}\n",
                reason,
                art_method_addr,
                crate::current_thread_id_u64(),
                (*ctx_ptr).x[30],
                n
            ));
        }
    }
    let _ = (art_method_addr, reason);
    let ret = hook_ffi::hook_invoke_trampoline(
        ctx_ptr,
        native_entry_trampoline as *mut std::ffi::c_void,
    );
    if !matches!(return_type, b'F' | b'D') {
        (*ctx_ptr).x[0] = ret;
    }
}

/// Callback invoked by the native hook trampoline when a hooked Java method is called.
/// After "replace with native", ART's JNI trampoline calls our thunk which calls this.
///
/// HookContext contains JNI calling convention registers:
///   x0 = JNIEnv*, x1 = jobject this (instance) or jclass (static), x2-x7 = Java args
///
/// user_data = ArtMethod* address (used for registry lookup).
pub(super) unsafe extern "C" fn java_hook_callback(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let _in_flight_guard = InFlightJavaHookGuard::enter();
    let _callback_scope = JavaHookCallbackScope::enter();
    let _gate_guard = crate::jsapi::java::art_controller::CallbackGateGuard;

    // user_data is ArtMethod* address (used as registry key)
    let art_method_addr = user_data as u64;

    // Copy callback data then release lock before QuickJS operations.
    let (
        ctx_usize,
        callback_bytes,
        is_static,
        param_count,
        return_type,
        return_type_sig,
        param_types,
        class_global_ref,
        quick_trampoline,
        native_entry_trampoline,
    ) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        let hook_data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        (
            hook_data.ctx,
            hook_data.callback_bytes,
            hook_data.is_static,
            hook_data.param_count,
            hook_data.return_type,
            hook_data.return_type_sig.clone(),
            hook_data.param_types.clone(),
            hook_data.class_global_ref,
            hook_data.quick_trampoline,
            hook_data.native_entry_trampoline,
        )
    }; // lock released

    // NativeEntry 模式甄别外来调用：native_entry_trampoline != 0 说明本 hook 是
    // 内联在共享 C++ 实现上的。两层过滤 + 一层兜底校验（见上方注释块）。
    let mut native_entry_need_arg_validation = false;
    if native_entry_trampoline != 0 {
        let lr = (*ctx_ptr).x[30];
        // 第 1 层：lr 落在普通 .so = native 直调（外部 ABI）→ 透传。
        if !native_entry_caller_is_jni(lr) {
            native_entry_foreign_bypass(
                ctx_ptr,
                art_method_addr,
                native_entry_trampoline,
                return_type,
                "non-jni-lr",
            );
            return;
        }
        // 第 2 层：本方法 quick entrypoint 是专用 stub 时，真实调用的 lr 必落在
        // [E, E+0x400)。其他共享实现的方法有它们自己的 stub（同在 jit-cache，
        // 第 1 层拦不住），lr 不同 → 透传。E 在 libart（generic trampoline）时
        // lr 无法区分调用的是哪个方法 → 降级为逐参数校验。
        let ep = crate::jsapi::java::jni_core::ART_METHOD_SPEC
            .get()
            .map(|spec| unsafe {
                std::ptr::read_volatile(
                    (art_method_addr as usize + spec.entry_point_offset) as *const u64,
                )
            })
            .unwrap_or(0);
        if ep != 0 && !native_entry_addr_in_libart(ep) {
            if !(lr >= ep && lr < ep + 0x400) {
                native_entry_foreign_bypass(
                    ctx_ptr,
                    art_method_addr,
                    native_entry_trampoline,
                    return_type,
                    "foreign-stub",
                );
                return;
            }
        } else {
            native_entry_need_arg_validation = true;
        }
    }

    // 同方法重入短路：用户脚本在回调里经 JNI 重新分派到同一个已 hook 方法
    // （如 target.apply(this, args)）时，art_method_addr 已在此线程的重入栈中。
    // 走 trampoline 调原实现——合法递归/间接重调结果正确（仅嵌套层跳过 JS 回调），
    // 同时避免无限递归栈溢出；无 trampoline 可用时兜底返回 0。
    if java_hook_is_reentrant(art_method_addr) {
        let trampoline = if native_entry_trampoline != 0 {
            native_entry_trampoline
        } else if quick_trampoline_entry_valid(art_method_addr, quick_trampoline) {
            // jit-code-cache 回收后安装期 quickCode 悬垂，尾跳会跳进复用槽位
            quick_trampoline
        } else {
            0
        };
        #[cfg(feature = "engine-depth-diagnostics")]
        {
            let h = &*ctx_ptr;
            crate::jsapi::console::output_message(&format!(
                "[java.args] reentrant method={:#x} thread={} x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x} x5={:#x} x6={:#x} x7={:#x} sp={:#x} tramp={:#x}\n",
                art_method_addr,
                crate::current_thread_id_u64(),
                h.x[0], h.x[1], h.x[2], h.x[3], h.x[4], h.x[5], h.x[6], h.x[7], h.sp,
                trampoline
            ));
        }
        if trampoline != 0 {
            let ret = hook_ffi::hook_invoke_trampoline(
                ctx_ptr,
                trampoline as *mut std::ffi::c_void,
            );
            if !matches!(return_type, b'F' | b'D') {
                (*ctx_ptr).x[0] = ret;
            }
        } else {
            crate::jsapi::console::output_verbose(
                "[java hook] reentrant JNI dispatch without trampoline, returning 0",
            );
            (*ctx_ptr).x[0] = 0;
        }
        return;
    }
    let _reentrancy_guard = JavaHookReentrancyGuard::enter(art_method_addr);

    #[cfg(feature = "engine-depth-diagnostics")]
    let argument_trace = begin_jni_argument_trace(&param_types);
    #[cfg(feature = "engine-depth-diagnostics")]
    trace_jni_argument_stage(argument_trace, art_method_addr, "callback-enter", 0, "-");
    // 决定性诊断：dump thunk 入口保存的全部 GP 寄存器，区分"入口寄存器就是错的"
    // 与"入口正确、后面才坏"两种崩溃模式。
    #[cfg(feature = "engine-depth-diagnostics")]
    if argument_trace.is_some() {
        let h = &*ctx_ptr;
        // 安全解引用：仅对疑似用户态映射地址取值，否则标记 -1。
        // 目的：确认句柄槽位内容在入口时是否有效（*x4=0 说明调用方给的就是坏引用）。
        let deref = |v: u64| -> u64 {
            if (0x1000_0000..0x8000_0000_0000).contains(&v) {
                *(v as *const u64)
            } else {
                u64::MAX
            }
        };
        let regs = format!(
            "x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x} x5={:#x} x6={:#x} x7={:#x} sp={:#x} tramp={:#x} lr={:#x} *x2={:#x} *x4={:#x}",
            h.x[0], h.x[1], h.x[2], h.x[3], h.x[4], h.x[5], h.x[6], h.x[7], h.sp,
            h.trampoline as u64, h.x[30], deref(h.x[2]), deref(h.x[4])
        );
        trace_jni_argument_stage(argument_trace, art_method_addr, "regs", 0, &regs);
    }

    let hook_ctx_env: JniEnv = (*ctx_ptr).x[0] as JniEnv;
    let drained = drain_raw_clone_executor(hook_ctx_env);
    if drained != 0 {
        crate::jsapi::console::output_verbose(&format!("[java executor] drained {} raw-clone task(s)", drained));
    }

    // Track whether handle_result was called (false if JS exception occurred)
    let result_was_set = std::cell::Cell::new(false);

    // 第 3 层（仅 NativeEntry 且 entrypoint 是 libart generic trampoline 的降级
    // 路径）：逐引用参数校验句柄可信性。共享实现的其他方法经 generic trampoline
    // 打进来时 lr 与本方法无法区分，但它们的"引用位置"参数是小整数或空槽，
    // 在 marshal 之前拦下，避免 GetStringUTFChars(1) 式崩溃。
    if native_entry_need_arg_validation {
        let hook_ctx = &*ctx_ptr;
        let mut gp_index: usize = 0;
        let mut fp_index: usize = 0;
        let mut stack_index: usize = 0;
        let mut foreign = false;
        for i in 0..param_count {
            let type_sig = param_types.get(i).map(|s| s.as_str());
            let (raw, _fp_raw) = extract_jni_arg(
                hook_ctx,
                is_floating_point_type(type_sig),
                &mut gp_index,
                &mut fp_index,
                &mut stack_index,
            );
            let is_ref = matches!(type_sig, Some(sig) if sig.starts_with('L') || sig.starts_with('['));
            if is_ref && !native_entry_plausible_jni_ref(raw) {
                foreign = true;
                break;
            }
        }
        if foreign {
            native_entry_foreign_bypass(
                ctx_ptr,
                art_method_addr,
                native_entry_trampoline,
                return_type,
                "bad-ref-arg",
            );
            return;
        }
    }

    let had_js_exception = invoke_hook_callback_common_with_env(
        ctx_usize,
        &callback_bytes,
        "java hook",
        art_method_addr,
        hook_ctx_env as *mut std::ffi::c_void,
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;
            let env: JniEnv = hook_ctx.x[0] as JniEnv;
            let atoms = hot_atoms();

            // thisObj for instance methods (x1 = jobject this)
            if !is_static {
                set_js_u64_property_atom(ctx, js_ctx, atoms.this_obj, hook_ctx.x[1]);
            }

            // args[] — ARM64 JNI calling convention (GP x2-x7, FP d0-d7 independent)
            {
                let arr = ffi::JS_NewArray(ctx);
                let mut gp_index: usize = 0;
                let mut fp_index: usize = 0;
                let mut stack_index: usize = 0;
                for i in 0..param_count {
                    let type_sig = param_types.get(i).map(|s| s.as_str());
                    #[cfg(feature = "engine-depth-diagnostics")]
                    trace_jni_argument_stage(argument_trace, art_method_addr, "read", i, type_sig.unwrap_or("?"));
                    let (raw, fp_raw) = extract_jni_arg(
                        hook_ctx,
                        is_floating_point_type(type_sig),
                        &mut gp_index,
                        &mut fp_index,
                        &mut stack_index,
                    );
                    #[cfg(feature = "engine-depth-diagnostics")]
                    if argument_trace.is_some() {
                        let raw_s = format!(
                            "{} raw={:#x} fp={:#x}",
                            type_sig.unwrap_or("?"),
                            raw,
                            fp_raw
                        );
                        trace_jni_argument_stage(argument_trace, art_method_addr, "raw", i, &raw_s);
                    }
                    #[cfg(feature = "engine-depth-diagnostics")]
                    trace_jni_argument_stage(argument_trace, art_method_addr, "convert", i, type_sig.unwrap_or("?"));
                    let val = marshal_jni_arg_to_js(ctx, env, raw, fp_raw, type_sig);
                    #[cfg(feature = "engine-depth-diagnostics")]
                    trace_jni_argument_stage(argument_trace, art_method_addr, "converted", i, type_sig.unwrap_or("?"));
                    ffi::JS_SetPropertyUint32(ctx, arr, i as u32, val);
                }
                #[cfg(feature = "engine-depth-diagnostics")]
                trace_jni_argument_stage(argument_trace, art_method_addr, "args-ready", param_count, "-");
                set_js_value_property_atom(ctx, js_ctx, atoms.args, arr);
            }

            // env (JNIEnv* — from x0)
            set_js_u64_property_atom(ctx, js_ctx, atoms.env, hook_ctx.x[0]);

            // Bind per-callback state to the JS context object so orig()
            // remains valid across nested hook callbacks and JS-side wrappers.
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_ctx_ptr, ctx_ptr as usize as u64);
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_art_method, art_method_addr);

            // orig()
            set_js_cfunction_property(ctx, js_ctx, "orig", js_call_original, 0);

            js_ctx
        },
        // 处理返回值：根据 return_type 将 JS 返回值写入 HookContext.x[0]
        |ctx, _js_ctx, result| {
            result_was_set.set(true);
            if return_type != b'V' {
                let result_val = JSValue(result);
                let ret_u64 = match return_type {
                    b'F' => {
                        if let Some(f) = result_val.to_float() {
                            (f as f32).to_bits() as u64
                        } else {
                            0u64
                        }
                    }
                    b'D' => {
                        if let Some(f) = result_val.to_float() {
                            f.to_bits()
                        } else {
                            0u64
                        }
                    }
                    b'L' | b'[' => {
                        // 优先从 __origJobject 读取原始 JNI ref（ctx.orig() 对 unboxed 值设置）。
                        // 确保 String/Integer/Boolean/Array 等所有类型安全 round-trip。
                        if result_val.is_object() {
                            let atoms = hot_atoms();
                            let orig_raw = ffi::qjs_get_property(ctx, result_val.raw(), atoms.orig_jobject);
                            let orig = JSValue(orig_raw);
                            if !orig.is_undefined() && !orig.is_null() {
                                let r = js_value_to_u64_or_zero(ctx, orig);
                                orig.free(ctx);
                                r
                            } else {
                                orig.free(ctx);
                                let env: JniEnv = hook_ctx_env;
                                if !env.is_null() {
                                    marshal_js_to_jvalue(ctx, env, result_val, Some(&return_type_sig))
                                } else {
                                    js_value_to_u64_or_zero(ctx, result_val)
                                }
                            }
                        } else if result_val.is_null() || result_val.is_undefined() {
                            0u64
                        } else {
                            // JS primitive (string/number/boolean) — 用户自己构造的返回值
                            let env: JniEnv = hook_ctx_env;
                            if !env.is_null() {
                                marshal_js_to_jvalue(ctx, env, result_val, Some(&return_type_sig))
                            } else {
                                0u64
                            }
                        }
                    }
                    _ => {
                        js_value_to_u64_or_zero(ctx, result_val)
                    }
                };
                write_primitive_return_to_context(ctx_ptr, return_type, ret_u64);
            }
        },
        // JS 抛异常透明递传: 调用 js_call_original 代替直接 invoke_original_jni。
        //
        // 为什么不能直接 invoke_original_jni? API 36 上 JS 异常 unwind 后直接进 JNI 会触发:
        //   - "Failed to recognize implicit suspend check ... state=Native" (SIGABRT), 或
        //   - dispatchMessage OAT 代码内 SEGV (stale heap ptr)
        //
        // 实测: 同样参数经 js_call_original 入口 (属性读 + JAVA_HOOK_REGISTRY Mutex + invoke)
        // 则 537+ 次异常 + 完整 UI nav 稳定不崩。推测 Mutex acquire/release barrier
        // 或 QuickJS 属性读清掉了 JS 异常 unwind 留下的脏 CPU/thread state。
        // 详见 memory: js-exception-orig-detour.md
        |ctx, js_ctx_val| {
            let result = js_call_original(ctx, js_ctx_val, 0, std::ptr::null_mut());
            if return_type != b'V' {
                let ret_u64 = js_result_to_raw(ctx, JSValue(result), return_type);
                write_primitive_return_to_context(ctx_ptr, return_type, ret_u64);
            }
            ffi::qjs_free_value(ctx, result);
            result_was_set.set(true);
        },
    );

    // 兜底: JS 异常路径应已通过 on_js_exception 设置返回值；如果 registry/context
    // 异常导致没有返回值，调用原方法保持正确语义。
    let _ = had_js_exception;
    if !result_was_set.get() {
        let env = hook_ctx_env;
        if native_entry_trampoline != 0 {
            let ret = hook_ffi::hook_invoke_trampoline(
                ctx_ptr,
                native_entry_trampoline as *mut std::ffi::c_void,
            );
            if return_type != b'V' {
                if !matches!(return_type, b'F' | b'D') {
                    (*ctx_ptr).x[0] = ret;
                }
            }
        } else if !env.is_null() {
            let hook_ctx = &*ctx_ptr;
            if !is_static && hook_ctx.x[1] == 0 {
                if return_type != b'V' {
                    write_primitive_return_to_context(ctx_ptr, return_type, 0);
                }
            } else {
                let jargs = build_jargs_from_registers(hook_ctx, param_count, &param_types);
                let jargs_ptr = if param_count > 0 {
                    jargs.as_ptr() as *const std::ffi::c_void
                } else {
                    std::ptr::null()
                };
                let ret = invoke_original_jni(
                    env, art_method_addr, class_global_ref,
                    hook_ctx.x[1], return_type, is_static, jargs_ptr, quick_trampoline, false,
                );
                if return_type != b'V' {
                    write_primitive_return_to_context(ctx_ptr, return_type, ret);
                }
            }
        } else {
            (*ctx_ptr).x[0] = 0;
        }
    }

}

/// Callback for @CriticalNative registered entries.
///
/// Critical native ABI has no JNIEnv*/jclass receiver:
///   x0-x7 / d0-d7 = Java primitive arguments directly.
///
/// Object parameters/returns are not valid for CriticalNative and are rejected
/// during installation.
pub(super) unsafe extern "C" fn java_critical_native_hook_callback(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let _in_flight_guard = InFlightJavaHookGuard::enter();
    let _callback_scope = JavaHookCallbackScope::enter();
    let _gate_guard = crate::jsapi::java::art_controller::CallbackGateGuard;

    let art_method_addr = user_data as u64;
    let (
        ctx_usize,
        callback_bytes,
        param_count,
        return_type,
        param_types,
        native_entry_trampoline,
    ) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        let hook_data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        (
            hook_data.ctx,
            hook_data.callback_bytes,
            hook_data.param_count,
            hook_data.return_type,
            hook_data.param_types.clone(),
            hook_data.native_entry_trampoline,
        )
    };

    // 同方法重入短路（同 java_hook_callback）：trampoline 优先，0 兜底。
    if java_hook_is_reentrant(art_method_addr) {
        if native_entry_trampoline != 0 {
            let ret = hook_ffi::hook_invoke_trampoline(
                ctx_ptr,
                native_entry_trampoline as *mut std::ffi::c_void,
            );
            if !matches!(return_type, b'F' | b'D') {
                (*ctx_ptr).x[0] = ret;
            }
        } else {
            crate::jsapi::console::output_verbose(
                "[java hook] reentrant critical-native dispatch without trampoline, returning 0",
            );
            (*ctx_ptr).x[0] = 0;
        }
        return;
    }
    let _reentrancy_guard = JavaHookReentrancyGuard::enter(art_method_addr);

    let result_was_set = std::cell::Cell::new(false);

    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "java critical native hook",
        art_method_addr,
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;
            let atoms = hot_atoms();

            let arr = ffi::JS_NewArray(ctx);
            let mut gp_index: usize = 0;
            let mut fp_index: usize = 0;
            let mut stack_index: usize = 0;
            for i in 0..param_count {
                let type_sig = param_types.get(i).map(|s| s.as_str());
                let (raw, fp_raw) = extract_critical_native_arg(
                    hook_ctx,
                    is_floating_point_type(type_sig),
                    &mut gp_index,
                    &mut fp_index,
                    &mut stack_index,
                );
                let val = marshal_critical_native_arg_to_js(ctx, raw, fp_raw, type_sig);
                ffi::JS_SetPropertyUint32(ctx, arr, i as u32, val);
            }
            set_js_value_property_atom(ctx, js_ctx, atoms.args, arr);

            set_js_u64_property_atom(ctx, js_ctx, atoms.env, 0);
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_ctx_ptr, ctx_ptr as usize as u64);
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_art_method, art_method_addr);
            set_js_cfunction_property(ctx, js_ctx, "orig", js_call_original, 0);

            js_ctx
        },
        |ctx, _js_ctx, result| {
            result_was_set.set(true);
            if return_type != b'V' {
                let ret_u64 = js_result_to_raw(ctx, JSValue(result), return_type);
                write_primitive_return_to_context(ctx_ptr, return_type, ret_u64);
            }
        },
        |ctx, js_ctx_val| {
            let result = js_call_original(ctx, js_ctx_val, 0, std::ptr::null_mut());
            if return_type != b'V' {
                let ret_u64 = js_result_to_raw(ctx, JSValue(result), return_type);
                write_primitive_return_to_context(ctx_ptr, return_type, ret_u64);
            }
            ffi::qjs_free_value(ctx, result);
            result_was_set.set(true);
        },
    );

    if !result_was_set.get() && native_entry_trampoline != 0 {
        let ret = hook_ffi::hook_invoke_trampoline(
            ctx_ptr,
            native_entry_trampoline as *mut std::ffi::c_void,
        );
        if return_type != b'V' {
            let ret_raw = if matches!(return_type, b'F' | b'D') {
                (*ctx_ptr).d[0]
            } else {
                ret
            };
            write_primitive_return_to_context(ctx_ptr, return_type, ret_raw);
        }
    }
}

/// 把 js_call_original 返回的 JSValue 还原为写 x[0] 的 u64。
/// 覆盖 L/[ (__origJobject / __jptr / null) + F/D (bits) + 基本类型。
unsafe fn js_result_to_raw(
    ctx: *mut ffi::JSContext,
    result_val: JSValue,
    return_type: u8,
) -> u64 {
    match return_type {
        b'V' => 0,
        b'F' => result_val.to_float().map(|f| (f as f32).to_bits() as u64).unwrap_or(0),
        b'D' => result_val.to_float().map(|f| f.to_bits()).unwrap_or(0),
        b'L' | b'[' => {
            if result_val.is_null() || result_val.is_undefined() {
                return 0;
            }
            if result_val.is_object() {
                // js_call_original L/[ 返回两种 shape:
                //   {__jptr, __jclass}        — 普通 Object
                //   {value, __origJobject}    — unboxed (String/Integer 等)
                let atoms = hot_atoms();
                let origj = JSValue(ffi::qjs_get_property(ctx, result_val.raw(), atoms.orig_jobject));
                if !origj.is_undefined() && !origj.is_null() {
                    let r = js_value_to_u64_or_zero(ctx, origj);
                    origj.free(ctx);
                    return r;
                }
                origj.free(ctx);
                let jptr = JSValue(ffi::qjs_get_property(ctx, result_val.raw(), atoms.jptr));
                if !jptr.is_undefined() && !jptr.is_null() {
                    let r = js_value_to_u64_or_zero(ctx, jptr);
                    jptr.free(ctx);
                    return r;
                }
                jptr.free(ctx);
            }
            js_value_to_u64_or_zero(ctx, result_val)
        }
        _ => js_value_to_u64_or_zero(ctx, result_val),
    }
}

// ============================================================================
// Quick dispatch — 从 art_router found path 直接调用 JS callback
// ============================================================================

/// ART Quick 调用约定 → JS callback dispatch
///
/// 从 art_router found path 直接调用。HookContext 包含 Quick 调用约定寄存器：
///   x0 = ArtMethod* (original, 通过 user_data 传入)
///   x1 = this (instance) 或 jclass (static)
///   x2-x7 = Java 参数 (GP)
///   d0-d7 = Java 参数 (FP)
///   x19 = Thread* (ART 约定)
///
/// 不经过 JNI trampoline，直接调用 JS callback 并将结果写回 HookContext。
/// 跳过了 ART 的 JNI epilogue，因此:
///   - 需要手动 MonitorEnter/Exit (synchronized 方法)
///   - 对象参数是裸 mirror::Object*，需要标记为 JniTransition 后 NewLocalRef 包装
///   - float/double 返回值写入 d[0]

#[no_mangle]
#[allow(dead_code)]
pub unsafe extern "C" fn java_hook_dispatch_from_quick(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    let _in_flight_guard = InFlightJavaHookGuard::enter();
    let _callback_scope = JavaHookCallbackScope::enter();
    let _gate_guard = crate::jsapi::java::art_controller::CallbackGateGuard;

    let art_method_addr = user_data as u64;

    // 复制 callback 数据，然后释放 lock
    let (ctx_usize, callback_bytes, is_static, param_count, return_type, param_types, quick_trampoline) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => {
                return;
            }
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                return;
            }
        };
        let hook_data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                return;
            }
        };
        (
            hook_data.ctx,
            hook_data.callback_bytes,
            hook_data.is_static,
            hook_data.param_count,
            hook_data.return_type,
            hook_data.param_types.clone(),
            hook_data.quick_trampoline,
        )
    }; // lock released

    // 同方法重入短路：有 quick trampoline 就走 trampoline 调原实现——合法递归/
    // 间接重调结果正确（仅嵌套层跳过 JS 回调）；无 trampoline 时兜底返回 0。
    if java_hook_is_reentrant(art_method_addr) {
        if quick_trampoline_entry_valid(art_method_addr, quick_trampoline) {
            let ret = hook_ffi::hook_invoke_trampoline(
                ctx_ptr,
                quick_trampoline as *mut std::ffi::c_void,
            );
            if !matches!(return_type, b'F' | b'D') {
                (*ctx_ptr).x[0] = ret;
            }
        } else {
            crate::jsapi::console::output_verbose(
                "[java hook] reentrant quick dispatch without trampoline, returning 0",
            );
            (*ctx_ptr).x[0] = 0;
        }
        return;
    }
    let _reentrancy_guard = JavaHookReentrancyGuard::enter(art_method_addr);

    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "java hook (quick)",
        art_method_addr,
        // 构建 JS 上下文对象 — 纯数值, 不调 JNI
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;
            let atoms = hot_atoms();

            // thisObj: 原始值 (BigUint64)
            if !is_static {
                set_js_u64_property_atom(ctx, js_ctx, atoms.this_obj, hook_ctx.x[1]);
            }

            // args[] — 从寄存器读取原始值, 不转 JNI handle
            {
                let arr = ffi::JS_NewArray(ctx);
                let mut gp_index: usize = if is_static { 1 } else { 2 };
                let mut fp_index: usize = 0;
                for i in 0..param_count {
                    let type_sig = param_types.get(i).map(|s| s.as_str());
                    let is_fp = is_floating_point_type(type_sig);
                    let (raw, fp_raw) = if is_fp {
                        let fp_raw = if fp_index < 8 { hook_ctx.d[fp_index] } else { 0 };
                        fp_index += 1;
                        (0, fp_raw)
                    } else {
                        let raw = if gp_index < 8 {
                            hook_ctx.x[gp_index]
                        } else {
                            let sp = hook_ctx.sp as usize;
                            *((sp + (gp_index - 8) * 8) as *const u64)
                        };
                        gp_index += 1;
                        (raw, 0)
                    };
                    // Quick path 不做 JNI marshal。对象/数组以裸 mirror 指针传给 JS。
                    let val = match type_sig.map(|s| s.as_bytes().first().copied()) {
                        Some(Some(b'Z')) => JSValue::bool(raw != 0).raw(),
                        Some(Some(b'B')) => JSValue::int(raw as i8 as i32).raw(),
                        Some(Some(b'C')) => JSValue::int(raw as u16 as i32).raw(),
                        Some(Some(b'S')) => JSValue::int(raw as i16 as i32).raw(),
                        Some(Some(b'I')) => JSValue::int(raw as i32).raw(),
                        Some(Some(b'J')) => ffi::JS_NewBigUint64(ctx, raw),
                        Some(Some(b'F')) => JSValue::float(f32::from_bits(fp_raw as u32) as f64).raw(),
                        Some(Some(b'D')) => JSValue::float(f64::from_bits(fp_raw)).raw(),
                        _ => ffi::JS_NewBigUint64(ctx, raw), // J, L, [, 等 → BigUint64
                    };
                    ffi::JS_SetPropertyUint32(ctx, arr, i as u32, val);
                }
                set_js_value_property_atom(ctx, js_ctx, atoms.args, arr);
            }

            set_js_u64_property_atom(ctx, js_ctx, atoms.env, 0);
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_ctx_ptr, ctx_ptr as usize as u64);
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_art_method, art_method_addr);
            set_js_cfunction_property(ctx, js_ctx, "orig", js_call_original, 0);

            js_ctx
        },
        // undefined = 继续原函数；其他值 = 直接替换返回值
        |ctx, _js_ctx, result| {
            let result_val = JSValue(result);
            if result_val.is_undefined() {
                return;
            }
            if return_type != b'V' {
                (*ctx_ptr).x[0] = js_result_to_raw(ctx, result_val, return_type);
            }
            (*ctx_ptr).intercept_leave = 1;
        },
        // JS 异常时保持默认 action=call original。
        |_ctx, _js_ctx| {},
    );
}
