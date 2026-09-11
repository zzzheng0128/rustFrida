//! QuickJS Runtime 的所有权封装：创建引擎堆、设置限制，并在退出时释放。
//! 一个 Runtime 可以关联多个 Context；它们共享运行时资源，并非线程隔离单元。

use crate::context::JSContext;
use crate::ffi;
use std::ptr::NonNull;

/// 持有底层 Runtime 指针；关联的 Context 和活动调用必须先于 Runtime 结束。
pub struct JSRuntime {
    ptr: NonNull<ffi::JSRuntime>,
}

impl JSRuntime {
    /// 创建 Runtime，设置默认内存预算并安装宿主中断检查。
    pub fn new() -> Option<Self> {
        let ptr = unsafe { ffi::JS_NewRuntime() };
        NonNull::new(ptr).map(|ptr| {
            unsafe {
                // 限制 QuickJS 管理的分配量，不等于整个进程或外部编译器的内存上限。
                ffi::JS_SetMemoryLimit(ptr.as_ptr(), 64 * 1024 * 1024);
                ffi::JS_SetInterruptHandler(
                    ptr.as_ptr(),
                    Some(crate::jsapi::callback_util::art_interrupt_handler),
                    std::ptr::null_mut(),
                );
            }
            JSRuntime { ptr }
        })
    }

    /// 创建依赖本 Runtime 的 Context；返回类型未用 Rust 生命周期参数表达该依赖。
    pub fn new_context(&self) -> Option<JSContext> {
        JSContext::new(self)
    }

    /// 借出原始指针，不转移所有权，也不延长底层对象的生命期。
    pub fn as_ptr(&self) -> *mut ffi::JSRuntime {
        self.ptr.as_ptr()
    }

    /// 调整 QuickJS 分配器的内存上限，单位为字节。
    pub fn set_memory_limit(&self, limit: usize) {
        unsafe {
            ffi::JS_SetMemoryLimit(self.ptr.as_ptr(), limit);
        }
    }

    /// 在当前线程运行 QuickJS 垃圾回收；调用方仍须保证引擎访问互斥。
    pub fn run_gc(&self) {
        unsafe {
            ffi::JS_RunGC(self.ptr.as_ptr());
        }
    }

    /// 设置引擎的栈使用检查预算；不会改变操作系统分配给线程的实际栈大小。
    pub fn set_max_stack_size(&self, stack_size: usize) {
        unsafe {
            ffi::JS_SetMaxStackSize(self.ptr.as_ptr(), stack_size);
        }
    }
}

impl Drop for JSRuntime {
    fn drop(&mut self) {
        unsafe {
            ffi::JS_FreeRuntime(self.ptr.as_ptr());
        }
    }
}

// 使用约束：宿主必须保证 Runtime 串行访问、线程切换状态正确且引用未失效。
// unsafe impl 仅放宽 Rust 类型检查，本身不会提供锁或让 QuickJS 支持并发执行。
unsafe impl Send for JSRuntime {}
unsafe impl Sync for JSRuntime {}

impl Default for JSRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create JSRuntime")
    }
}
