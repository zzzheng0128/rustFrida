//! 宿主扩展 API 的统一注册入口。这些能力由 Rust/C 提供，不属于 QuickJS 标准内置对象。

pub(crate) mod callback_util;
pub mod console;
pub mod file;
pub mod hook_api;
pub mod java;
pub mod jni;
pub mod memory;
pub mod module;
pub mod ptr;
pub mod rpc;
pub(crate) mod util;

pub use console::register_console;
pub use file::register_file_api;
pub use hook_api::register_hook_api;
pub use java::deferred_java_init;
pub use java::register_lazy_java_api;
pub use jni::register_jni_api;
pub use memory::register_memory_api;
pub use module::register_module_api;
pub use ptr::register_ptr;
pub use rpc::register_rpc;

use crate::context::JSContext;

/// 将各模块的对象和函数安装到同一个 Context。
/// 注册与使用是两个阶段：例如 lazy Java 注册完成，不表示应用 ClassLoader 已经就绪。
pub fn register_all_apis(ctx: &JSContext) {
    register_console(ctx);
    register_file_api(ctx);
    register_ptr(ctx);
    register_hook_api(ctx);
    register_jni_api(ctx);
    register_memory_api(ctx);
    register_module_api(ctx);
    register_lazy_java_api(ctx);
    register_rpc(ctx);
}
