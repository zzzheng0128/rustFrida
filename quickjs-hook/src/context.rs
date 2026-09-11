//! QuickJS Context 封装：脚本求值、对象操作、函数调用和任务处理。
//! 所有方法都直接操作底层引擎；本类型不自行加锁，调用方负责访问互斥与生命周期。

use crate::ffi;
use crate::runtime::JSRuntime;
use crate::value::JSValue;
use std::ffi::CString;
use std::ptr::NonNull;

/// 拥有一个 Context，并借用其 Runtime 指针；销毁顺序由上层 JSEngine 保证。
pub struct JSContext {
    ptr: NonNull<ffi::JSContext>,
    runtime: *mut ffi::JSRuntime,
}

impl JSContext {
    /// 创建执行环境；这里只安装标准内置对象，宿主扩展由 jsapi 层另行注册。
    pub fn new(runtime: &JSRuntime) -> Option<Self> {
        // JS_NewContext 自带 Object、Date、RegExp、JSON、Proxy、Promise、BigInt 等内置能力。
        let ptr = unsafe { ffi::JS_NewContext(runtime.as_ptr()) };
        NonNull::new(ptr).map(|ptr| JSContext {
            ptr,
            runtime: runtime.as_ptr(),
        })
    }

    /// 借出 Context 指针，不转移所有权；不得在 Context 销毁后继续使用。
    pub fn as_ptr(&self) -> *mut ffi::JSContext {
        self.ptr.as_ptr()
    }

    /// 取得全局对象的一个引用；使用后需要按 JSValue 的引用管理规则释放。
    pub fn global_object(&self) -> JSValue {
        JSValue(unsafe { ffi::JS_GetGlobalObject(self.ptr.as_ptr()) })
    }

    /// 按普通全局脚本执行源码。filename 只参与错误定位，不在这里读取文件。
    pub fn eval(&self, script: &str, filename: &str) -> Result<JSValue, String> {
        let cscript = CString::new(script).map_err(|e| format!("Invalid script: {}", e))?;
        let cfilename = CString::new(filename).map_err(|e| format!("Invalid filename: {}", e))?;

        // 接入统一执行域管理：最外层进入建立栈基准，嵌套进入沿用外层基准，
        // 挂起恢复场景还原本线程保存的基准（不绕过深度管理直接重置栈顶）。
        let _exec_scope = unsafe { crate::jsapi::callback_util::JsEngineExecutionScope::enter(self.ptr.as_ptr()) };

        let val = unsafe {
            ffi::JS_Eval(
                self.ptr.as_ptr(),
                cscript.as_ptr(),
                script.len(),
                cfilename.as_ptr(),
                ffi::JS_EVAL_TYPE_GLOBAL as i32,
            )
        };

        let result = JSValue(val);
        if result.is_exception() {
            let exception = self.get_exception();
            return Err(exception);
        }

        Ok(result)
    }

    /// 按 ES module 语义执行源码；模块依赖解析仍取决于宿主配置。
    pub fn eval_module(&self, script: &str, filename: &str) -> Result<JSValue, String> {
        let cscript = CString::new(script).map_err(|e| format!("Invalid script: {}", e))?;
        let cfilename = CString::new(filename).map_err(|e| format!("Invalid filename: {}", e))?;

        // 与普通脚本入口一样接入统一执行域管理，不单独重置栈检查基准。
        let _exec_scope = unsafe { crate::jsapi::callback_util::JsEngineExecutionScope::enter(self.ptr.as_ptr()) };

        let val = unsafe {
            ffi::JS_Eval(
                self.ptr.as_ptr(),
                cscript.as_ptr(),
                script.len(),
                cfilename.as_ptr(),
                ffi::JS_EVAL_TYPE_MODULE as i32,
            )
        };

        let result = JSValue(val);
        if result.is_exception() {
            let exception = self.get_exception();
            return Err(exception);
        }

        Ok(result)
    }

    /// 取出当前异常并转成消息及调用栈；JS_GetException 会消耗当前异常槽中的值。
    /// 临时属性和异常对象在这里释放，返回的 Rust String 不再依赖 JS 对象存活。
    pub fn get_exception(&self) -> String {
        unsafe {
            let exception = ffi::JS_GetException(self.ptr.as_ptr());
            let exc_val = JSValue(exception);
            let message = exc_val
                .to_string(self.ptr.as_ptr())
                .unwrap_or_else(|| "Unknown error".to_string());
            let stack = exc_val.get_property(self.ptr.as_ptr(), "stack");
            let stack_str = if !stack.is_undefined() {
                stack.to_string(self.ptr.as_ptr()).unwrap_or_default()
            } else {
                String::new()
            };
            stack.free(self.ptr.as_ptr());
            exc_val.free(self.ptr.as_ptr());

            let stack_str = stack_str.trim();
            if stack_str.is_empty() || stack_str == message {
                message
            } else if stack_str.contains(&message) {
                stack_str.to_string()
            } else {
                format!("{}\n{}", message, stack_str)
            }
        }
    }

    /// Create a new object
    pub fn new_object(&self) -> JSValue {
        JSValue(unsafe { ffi::JS_NewObject(self.ptr.as_ptr()) })
    }

    /// Create a new array
    pub fn new_array(&self) -> JSValue {
        JSValue(unsafe { ffi::JS_NewArray(self.ptr.as_ptr()) })
    }

    /// Create a string value
    pub fn new_string(&self, s: &str) -> JSValue {
        JSValue::string(self.ptr.as_ptr(), s)
    }

    /// Create an integer value
    pub fn new_int(&self, val: i32) -> JSValue {
        JSValue::int(val)
    }

    /// Create a float value
    pub fn new_float(&self, val: f64) -> JSValue {
        JSValue::float(val)
    }

    /// Create a BigInt from i64
    pub fn new_bigint(&self, val: i64) -> JSValue {
        JSValue(unsafe { ffi::JS_NewBigInt64(self.ptr.as_ptr(), val) })
    }

    /// Create a BigInt from u64
    pub fn new_biguint(&self, val: u64) -> JSValue {
        JSValue(unsafe { ffi::JS_NewBigUint64(self.ptr.as_ptr(), val) })
    }

    /// 将 C ABI 回调注册成全局 JS 函数；注册不执行回调，调用发生在 JS 求值期间。
    pub fn register_function(&self, name: &str, func: ffi::JSCFunction, argc: i32) -> bool {
        let global = self.global_object();
        let cname = CString::new(name).unwrap();

        let func_val = unsafe { ffi::qjs_new_cfunction(self.ptr.as_ptr(), func, cname.as_ptr(), argc) };

        let result = global.set_property(self.ptr.as_ptr(), name, JSValue(func_val));
        global.free(self.ptr.as_ptr());
        result
    }

    /// Set a property on the global object
    pub fn set_global_property(&self, name: &str, value: JSValue) -> bool {
        let global = self.global_object();
        let result = global.set_property(self.ptr.as_ptr(), name, value);
        global.free(self.ptr.as_ptr());
        result
    }

    /// Get a property from the global object
    pub fn get_global_property(&self, name: &str) -> JSValue {
        let global = self.global_object();
        let prop = global.get_property(self.ptr.as_ptr(), name);
        global.free(self.ptr.as_ptr());
        prop
    }

    /// 同步调用一个已有 JS 函数，不重新解析脚本文本，也不会自动处理后续任务队列。
    /// 参数数组只复制值的表示，不增加引用计数；调用期间原始值必须保持有效。
    pub fn call_function(&self, func: JSValue, this: JSValue, args: &[JSValue]) -> Result<JSValue, String> {
        let argc = args.len() as i32;
        let argv: Vec<ffi::JSValue> = args.iter().map(|v| v.raw()).collect();

        let result = unsafe {
            ffi::JS_Call(
                self.ptr.as_ptr(),
                func.raw(),
                this.raw(),
                argc,
                if argv.is_empty() {
                    std::ptr::null_mut()
                } else {
                    argv.as_ptr() as *mut _
                },
            )
        };

        let val = JSValue(result);
        if val.is_exception() {
            return Err(self.get_exception());
        }
        Ok(val)
    }

    /// 尝试执行一个任务。此布尔接口将“队列空”和“执行异常”都映射为 false；
    /// 需要报告异常的调用路径使用下方 drain_pending_jobs_reporting。
    pub fn execute_pending_job(&self) -> bool {
        let mut pctx: *mut ffi::JSContext = std::ptr::null_mut();
        let ret = unsafe { ffi::JS_ExecutePendingJob(self.runtime, &mut pctx) };
        ret > 0
    }

    /// 只查询队列是否非空，不执行任务，也不会唤醒其他线程。
    pub fn is_job_pending(&self) -> bool {
        unsafe { ffi::JS_IsJobPending(self.runtime) != 0 }
    }
}

/// 排空 pending jobs 并报告任务内异常。
///
/// JS_ExecutePendingJob 返回值：1=执行了一个任务，0=队列空，<0=任务抛异常
/// （此时异常挂在 *pctx 指向的 context 上）。队列空与任务异常必须区分——
/// 异常被静默吞掉会让 queueMicrotask/Promise 里的错误完全无迹可循。
///
/// 调用方必须持有 JS_ENGINE 锁。供 hook 回调边界（invoke_hook_callback_common）
/// 和脚本加载后的 run_pending_jobs 使用。
pub(crate) unsafe fn drain_pending_jobs_reporting(ctx: *mut ffi::JSContext) {
    loop {
        let mut pctx: *mut ffi::JSContext = std::ptr::null_mut();
        let rt = ffi::JS_GetRuntime(ctx);
        let ret = ffi::JS_ExecutePendingJob(rt, &mut pctx);
        if ret > 0 {
            continue;
        }
        if ret < 0 {
            let exc_ctx = if pctx.is_null() { ctx } else { pctx };
            // handle_js_exception 内部自行 JS_GetException 并输出 message+stack
            crate::jsapi::callback_util::handle_js_exception(exc_ctx, ffi::qjs_exception(), "pending job");
            // 任务异常后队列可能还有后续任务，继续排空
            continue;
        }
        break;
    }
}

impl Drop for JSContext {
    fn drop(&mut self) {
        unsafe {
            ffi::JS_FreeContext(self.ptr.as_ptr());
        }
    }
}

// Safety: JSContext is protected by Mutex in the global JS_ENGINE, ensuring single-threaded access
unsafe impl Send for JSContext {}
unsafe impl Sync for JSContext {}
