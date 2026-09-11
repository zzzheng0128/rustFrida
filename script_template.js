/*
 * rustFrida JS 模板
 *
 * 这份文件只放通用辅助函数。复制它以后，把业务代码写在“业务代码”区域。
 * QuickJS 提供的是 Frida 风格子集，不能假定完整 Frida API 都存在。
 */
(function () {
    "use strict";

    var TAG = "demo";

    function log(message) {
        console.log("[" + TAG + "] " + String(message));
    }

    // NativePointer、number、bigint 和 null 都可能出现在地址 API 的返回值中。
    function isNullPtr(value) {
        if (value === null || value === undefined) return true;
        if (typeof value === "number") return value === 0;
        if (typeof value === "bigint") return value === BigInt(0);
        try { return value.isNull(); } catch (_) { return false; }
    }

    function toPtr(value) {
        if (value === null || value === undefined) return null;
        if (typeof value === "object") return value;
        return ptr(value);
    }

    function findExport(moduleName, symbolName) {
        try {
            var address = Module.findExportByName(moduleName || null, symbolName);
            if (!isNullPtr(address)) return address;
        } catch (_) {}
        return null;
    }

    // 引擎没有 Module.findGlobalExportByName；先查全局，再查常见 linker 模块。
    function findGlobalExport(symbolName) {
        var address = findExport(null, symbolName);
        if (!isNullPtr(address)) return address;
        var modules = ["libdl.so", "libdl_android.so", "linker64", "linker", "libc.so"];
        for (var i = 0; i < modules.length; i++) {
            address = findExport(modules[i], symbolName);
            if (!isNullPtr(address)) return address;
            // 某些 linker 内部符号只能从模块导出表枚举到。
            try {
                var module = Process.getModuleByName(modules[i]);
                var exports = module.enumerateExports();
                for (var j = 0; j < exports.length; j++) {
                    if (exports[j].name === symbolName) return exports[j].address;
                }
            } catch (_) {}
        }
        return null;
    }

    function nativeFunction(symbolName, returnType, argumentTypes) {
        var address = findGlobalExport(symbolName);
        if (isNullPtr(address)) return null;
        try { return new NativeFunction(address, returnType, argumentTypes); }
        catch (_) { return null; }
    }

    // 旧脚本常用的短名称，保留作复制模板时的兼容别名。
    function nf(symbolName, returnType, argumentTypes) {
        return nativeFunction(symbolName, returnType, argumentTypes);
    }

    function findModule(name) {
        try { return Process.findModuleByName(name); } catch (_) { return null; }
    }

    function moduleAddress(moduleName, offset) {
        var module = findModule(moduleName);
        if (!module) return null;
        return module.base.add(offset);
    }

    function readCString(value) {
        var address = toPtr(value);
        if (isNullPtr(address)) return "<null>";
        try { return address.readCString(); } catch (_) { return "<unreadable>"; }
    }

    function hexBytes(value, length) {
        var address = toPtr(value);
        if (isNullPtr(address)) return "<null>";
        try {
            var bytes = new Uint8Array(address.readByteArray(length));
            var out = "";
            for (var i = 0; i < bytes.length; i++) {
                out += (i ? " " : "") + ("0" + bytes[i].toString(16)).slice(-2);
            }
            return out;
        } catch (e) {
            return "<read failed: " + (e.message || e) + ">";
        }
    }

    function attach(address, callbacks, label) {
        if (isNullPtr(address)) {
            log((label || "target") + ": address not found");
            return null;
        }
        try {
            var listener = Interceptor.attach(address, callbacks);
            log((label || "target") + ": attached at " + address);
            return listener;
        } catch (e) {
            log((label || "target") + ": attach failed: " + (e.message || e));
            return null;
        }
    }

    function detach(listener) {
        if (!listener) return;
        try { listener.detach(); } catch (_) {}
    }

    // 模块可能在脚本之后才加载。此实现不使用定时器：优先直查和 dlopen，
    // 必要时借 openat/epoll_wait 的调用做低频检查。回调只执行一次。
    function waitForModule(name, onReady) {
        var done = false;
        var pollListeners = [];
        var lastPoll = 0;

        function findTarget() { return findModule(name); }
        function stopPoll() {
            for (var i = 0; i < pollListeners.length; i++) detach(pollListeners[i]);
            pollListeners = [];
        }
        function finish(module) {
            if (done || !module) return;
            done = true;
            stopPoll();
            onReady(module.base, module.size, module);
        }
        function check() {
            if (done) return;
            var now = Date.now();
            if (now - lastPoll < 1000) return;
            lastPoll = now;
            var module = findTarget();
            if (module && module.size >= 0x1000) finish(module);
        }

        var existing = findTarget();
        if (existing) { finish(existing); return; }

        ["android_dlopen_ext", "dlopen", "__loader_android_dlopen_ext", "__loader_dlopen"]
            .forEach(function (symbolName) {
                var loader = findGlobalExport(symbolName);
                if (isNullPtr(loader)) return;
                try {
                    pollListeners.push(Interceptor.attach(loader, {
                        onEnter: function (args) {
                            try { this.path = readCString(args[0]); } catch (_) { this.path = ""; }
                        },
                        onLeave: function () {
                            if (!done && String(this.path || "").indexOf(name) >= 0) finish(findTarget());
                        }
                    }));
                } catch (e) { log("watch " + symbolName + " failed: " + (e.message || e)); }
            });

        ["openat", "epoll_wait"].forEach(function (symbolName) {
            var carrier = findGlobalExport(symbolName);
            if (isNullPtr(carrier)) return;
            try { pollListeners.push(Interceptor.attach(carrier, { onEnter: check })); }
            catch (e) { log("poll hook on " + symbolName + " failed: " + (e.message || e)); }
        });
        log("waiting for " + name + " (poll carriers=" + pollListeners.length + ")");
    }

    // 事件很多时只打印少量样本，避免日志反过来影响目标进程。
    function sample(counter, first, every) {
        return counter <= (first || 3) || (every > 0 && counter % every === 0);
    }

    /* ==================== 业务代码 ==================== */

    // 示例：attach 模式下读取 libc 的导出地址。
    // var openat = findExport("libc.so", "openat");
    // attach(openat, { onEnter: function (args) {
    //     log("openat path=" + readCString(args[1]));
    // }}, "libc.openat");

    // 示例：目标库延迟加载时使用 waitForModule。
    // waitForModule("libexample.so", function (base, size) {
    //     log("loaded at " + base + ", size=0x" + size.toString(16));
    // });

    log("loaded; copy this file and replace the example code");
})();
