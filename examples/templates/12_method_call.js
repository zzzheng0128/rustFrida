/*
 * 方法调用模板：同一份脚本同时展示 native 函数和 Java 方法调用。
 * 默认目标是兼容性 demo 的 rf_agent_hot；替换模块、符号、签名即可复用。
 * NativeFunction 的参数签名必须与真实 ABI 一致，结构体按值参数不要直接猜。
 */
(function () {
    "use strict";

    var TAG = "call";
    var TARGET_MODULE = "libcompatdemo.so";
    var TARGET_SYMBOL = "rf_agent_hot";
    var TARGET_OFFSET = null; // 导出被裁剪时填模块内偏移，例如 0x24a4
    var SEED = 7;
    var loaderListeners = [];
    var nativeCalled = false;
    function log(message) { console.log("[" + TAG + "] " + message); }
    function isNull(value) {
        if (value === null || value === undefined) return true;
        try { return String(ptr(value)) === "0x0"; } catch (_) { return true; }
    }

    function stopLoaderWatch() {
        for (var i = 0; i < loaderListeners.length; i++) {
            try { loaderListeners[i].detach(); } catch (_) {}
        }
        loaderListeners = [];
    }
    function callNative(module) {
        if (nativeCalled) return;
        var offset = TARGET_OFFSET === null ? null
            : (typeof TARGET_OFFSET === "number" ? TARGET_OFFSET : parseInt(String(TARGET_OFFSET), 0));
        nativeCalled = true;
        var address = offset === null
            ? Module.findExportByName(TARGET_MODULE, TARGET_SYMBOL)
            : module.base.add(offset);
        if (isNull(address)) {
            log("native export not found: " + TARGET_MODULE + "!" + TARGET_SYMBOL);
            return;
        }
        // rf_agent_hot: uint64_t rf_agent_hot(uint64_t seed)
        var fn = new NativeFunction(address, "uint64", ["uint64"]);
        var result = fn(BigInt(SEED));
        log("native call " + address + "(" + SEED + ") => " + result);
    }

    function waitForNativeModule() {
        var module = null;
        try { module = Process.findModuleByName(TARGET_MODULE); } catch (_) {}
        if (module) { callNative(module); return; }
        ["android_dlopen_ext", "dlopen", "__loader_android_dlopen_ext", "__loader_dlopen"]
            .forEach(function (name) {
                var loader = null;
                try { loader = Module.findExportByName(null, name); } catch (_) {}
                if (isNull(loader)) return;
                try {
                    loaderListeners.push(Interceptor.attach(loader, {
                        onLeave: function () {
                            var loaded = null;
                            try { loaded = Process.findModuleByName(TARGET_MODULE); } catch (_) {}
                            if (loaded) { stopLoaderWatch(); callNative(loaded); }
                        }
                    }));
                } catch (_) {}
            });
        log("waiting for " + TARGET_MODULE + " to load");
    }

    function callJava() {
        if (typeof Java === "undefined" || !Java || !Java.ready) {
            log("Java API unavailable; native call was still attempted");
            return;
        }
        Java.ready(function () {
            try {
                var Native = Java.use("com.rustfrida.compatdemo.Native");
                // static native 方法可像普通 Java 方法一样直接调用。
                log("Java Native.nativeAgentTick() => " + Native.nativeAgentTick());
            } catch (error) {
                log("Java call failed: " + (error.message || error));
            }
        });
    }

    try { waitForNativeModule(); } catch (error) { log("native call failed: " + (error.message || error)); }
    callJava();
})();
