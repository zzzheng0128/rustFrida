//! Java hook callback and registry + replacedMethods mapping
//!
//! Split into focused fragments:
//! - registry/signature parsing
//! - Java/JS marshalling helpers
//! - Java._invokeMethod / ctx.orig()
//! - hook trampoline callback and replacement mapping

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    ensure_registry_initialized, extract_pointer_address, extract_string_arg, get_js_u64_property_atom, hot_atoms,
    invoke_hook_callback_common, invoke_hook_callback_common_with_env, js_value_to_u64_or_zero,
    set_js_cfunction_property, set_js_u64_property_atom, set_js_value_property_atom, throw_internal_error,
    throw_type_error, BiMap,
};
use crate::value::JSValue;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;

use super::jni_core::*;
use super::reflect::{decode_method_id, find_class_safe, ClassLoaderInfo, MethodInfo, REFLECT_IDS};

thread_local! {
    static IN_JAVA_HOOK_CALLBACK: Cell<bool> = const { Cell::new(false) };
}

/// 当前线程正在执行 Java hook 回调的 ArtMethod 重入栈。
///
/// 用于检测「同方法重入」：当用户脚本在 hook 回调里调用 `target.apply(this, args)`
/// （或其它会经 JNI 重新分派到同一个已 hook 方法的写法）时，会再次进入
/// `java_hook_callback`，若不加保护则会无限递归直到 JS/C 栈溢出。
///
/// 合法的嵌套调用（原方法内部又调用另一个被 hook 的方法）不会命中此栈，
/// 因为 ArtMethod 地址不同。
thread_local! {
    static JAVA_HOOK_REENTRANCY_STACK: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

/// 当前 ArtMethod 是否已在重入栈中（同方法重入）。
fn java_hook_is_reentrant(art_method_addr: u64) -> bool {
    JAVA_HOOK_REENTRANCY_STACK.with(|stack| stack.borrow().contains(&art_method_addr))
}

/// quick_trampoline 包装的是安装期的 quickCode——对 native 方法那往往是
/// jit-code-cache 里的编译型 JNI stub。JIT code cache 回收后 ART 会把原始方法的
/// ep 重置回共享入口，trampoline 的尾跳随之悬垂（槽位复用后跳到任意新代码）。
/// 用前校验：活的 ep 已偏离安装期值即视为不可用。
/// native 方法的 ep 字段我们从不自写（见 install_support Step 9），任何变化都
/// 来自 ART；Java 共享入口分支不产生 quick_trampoline，不在此路径上。
fn quick_trampoline_entry_valid(art_method_addr: u64, quick_trampoline: u64) -> bool {
    if quick_trampoline == 0 {
        return false;
    }
    let Some(spec) = ART_METHOD_SPEC.get() else {
        return true;
    };
    let original_entry_point = {
        let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .and_then(|registry| registry.get(&art_method_addr))
            .map(|data| data.original_entry_point)
            .unwrap_or(0)
    };
    if original_entry_point == 0 {
        return true;
    }
    let live_ep = unsafe {
        std::ptr::read_volatile((art_method_addr as usize + spec.entry_point_offset) as *const u64)
    };
    live_ep == original_entry_point
}

/// 将 ArtMethod 压入重入栈，返回一个 drop 时自动弹出的 guard。
struct JavaHookReentrancyGuard {
    art_method_addr: u64,
}

impl JavaHookReentrancyGuard {
    fn enter(art_method_addr: u64) -> Self {
        JAVA_HOOK_REENTRANCY_STACK.with(|stack| stack.borrow_mut().push(art_method_addr));
        Self { art_method_addr }
    }
}

impl Drop for JavaHookReentrancyGuard {
    fn drop(&mut self) {
        JAVA_HOOK_REENTRANCY_STACK.with(|stack| {
            let mut s = stack.borrow_mut();
            if let Some(pos) = s.iter().rposition(|&a| a == self.art_method_addr) {
                s.remove(pos);
            }
        });
    }
}

pub(crate) struct JavaHookCallbackScope;

impl JavaHookCallbackScope {
    pub(crate) fn enter() -> Self {
        IN_JAVA_HOOK_CALLBACK.with(|flag| flag.set(true));
        Self
    }
}

impl Drop for JavaHookCallbackScope {
    fn drop(&mut self) {
        IN_JAVA_HOOK_CALLBACK.with(|flag| flag.set(false));
    }
}

pub(super) fn in_java_hook_callback() -> bool {
    IN_JAVA_HOOK_CALLBACK.with(|flag| flag.get())
}

include!("registry.rs");
include!("signature.rs");
include!("marshal.rs");
include!("executor.rs");
include!("invoke.rs");
include!("original_call.rs");
include!("hook.rs");
include!("replaced.rs");
