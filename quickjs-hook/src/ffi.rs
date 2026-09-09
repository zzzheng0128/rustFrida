//! Rust 与 C 的 ABI 边界。声明由 build.rs 根据头文件生成，实现在对应 C 静态库中。
//! 新增或变更 C 接口时应维护头文件和源文件，不应手改 OUT_DIR 中的生成结果。

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::all)]

// QuickJS 本体及 qjs_* 辅助接口；原始指针和返回值的所有权由上层封装负责。
include!(concat!(env!("OUT_DIR"), "/quickjs_bindings.rs"));

// 调用后端的声明放入独立命名空间，避免与 QuickJS 接口混淆。
pub mod hook {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/hook_bindings.rs"));
}
