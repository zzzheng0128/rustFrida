/*
 * script_template.js — rustfrida 脚本通用骨架（QuickJS 引擎，非完整 Frida 兼容）
 *
 * 包含经过实测的公共构件，新脚本直接复制此骨架再写业务逻辑：
 *   1. log               统一日志前缀（输出带 [agent] [JS]）
 *   2. isNullPtr         防御式空指针判断（findExportByName 返回值类型不固定）
 *   3. findGlobalExport  多策略全局符号查找（引擎无 Module.findGlobalExportByName）
 *   4. waitForModule     模块等待三件套：已加载直查 + dlopen 钩子 + 热函数寄生轮询
 *                        （引擎无 setTimeout/setImmediate，轮询只能寄生在热函数上）
 *
 * 运行：
 *   adb push script_template.js /data/local/tmp/
 *   attach: su -c '/data/local/tmp/rustfrida --name <包名> -l /data/local/tmp/script_template.js'
 *   spawn : su -c '/data/local/tmp/rustfrida --spawn <包名> -l /data/local/tmp/script_template.js'
 */
(function () {
    "use strict";

    var TAG = "my-script";
    function log(m) { console.log("[" + TAG + "] " + m); }

    /* ---------- 1. 空指针防御 ---------- */
    // findExportByName 等返回的指针对象不一定是完整 NativePointer，
    // 直接调 .isNull() 可能抛 "TypeError: not a function"，必须这样判。
    function isNullPtr(p) {
        if (p === null || p === undefined) return true;
        if (typeof p === "bigint") return p === BigInt(0);
        if (typeof p === "number") return p === 0;
        try { return p.isNull(); } catch (_) { return false; }
    }

    /* ---------- 2. 全局符号查找 ---------- */
    // 引擎没有 Module.findGlobalExportByName，只能用 Module.findExportByName(null, name)，
    // 再兜底逐个模块 enumerateExports（__loader_* 等 linker 内部符号需要这条路）。
    function findGlobalExport(name) {
        try {
            var global = Module.findExportByName(null, name);
            if (global !== null) return global;
        } catch (_) {
        }
        var mods = ["libdl.so", "libdl_android.so", "linker64", "linker", "libc.so"];
        for (var mi = 0; mi < mods.length; ++mi) {
            try {
                var mod = Process.getModuleByName(mods[mi]);
                var exports = mod.enumerateExports();
                for (var ei = 0; ei < exports.length; ++ei) {
                    if (exports[ei].name === name) return exports[ei].address;
                }
            } catch (_) {
            }
        }
        return null;
    }

    /* ---------- 3. NativeFunction 便捷封装 ---------- */
    function nf(name, ret, args) {
        var p = findGlobalExport(name);
        if (isNullPtr(p)) return null;
        return new NativeFunction(p, ret, args);
    }

    /* ---------- 4. 模块等待（三件套） ---------- */
    // 用法：waitForModule("libxxx.so", function (base, size) { ...安装 hook... });
    function waitForModule(targetName, onReady) {
        var done = false;
        function findTarget() {
            try { return Process.findModuleByName(targetName); } catch (_) { return null; }
        }
        function finish(target) {
            if (done) return;
            done = true;
            stopPoll();
            onReady(target.base, target.size);
        }

        // (a) 已加载则直接用
        var existing = findTarget();
        if (existing !== null) { finish(existing); return; }

        // (b) dlopen 族钩子：常规 System.loadLibrary 路径
        ["android_dlopen_ext", "dlopen", "__loader_android_dlopen_ext", "__loader_dlopen"]
            .forEach(function (name) {
                var loader = findGlobalExport(name);
                if (isNullPtr(loader)) return;
                try {
                    Interceptor.attach(loader, {
                        onEnter: function (args) {
                            try { this.path = args[0].readCString(); } catch (_) { this.path = ""; }
                        },
                        onLeave: function () {
                            if (done || String(this.path || "").indexOf(targetName) < 0) return;
                            var target = findTarget();
                            if (target !== null) finish(target);
                        }
                    });
                } catch (e) {
                    log("watch " + name + " failed: " + e);
                }
            });

        // (c) 热函数寄生轮询：目标绕过 dlopen 自加载（open+mmap 手动重定位）时兜底。
        //     openat 文件 IO、epoll_wait 交互期热；1s 节流；
        //     size 达标才认为加载完成（避免 loader 未映射完就装 hook）。
        //     不要挂 mmap：启动期过热，attach 等 in-flight 可能挂死 JS worker。
        var pollListeners = [];
        var lastPoll = 0;
        function stopPoll() {
            pollListeners.forEach(function (l) { try { l.detach(); } catch (_) {} });
            pollListeners = [];
        }
        function pollCheck() {
            if (done) { stopPoll(); return; }
            var now = Date.now();
            if (now - lastPoll < 1000) return;
            lastPoll = now;
            var target = findTarget();
            if (target !== null && target.size >= 0x10000) finish(target);
        }
        ["openat", "epoll_wait"].forEach(function (fname) {
            var fptr = findGlobalExport(fname);
            if (isNullPtr(fptr)) return;
            try {
                pollListeners.push(Interceptor.attach(fptr, { onEnter: function () { pollCheck(); } }));
            } catch (e) {
                log("poll hook on " + fname + " failed: " + e);
            }
        });
        log("waiting for " + targetName + " (poll carriers=" + pollListeners.length + ")");
    }

    /* ================= 业务逻辑写这里 ================= */

    waitForModule("libmetasec_ml.so", function (base, size) {
        log("target loaded: base=" + base + " size=0x" + size.toString(16));
        // 例：Interceptor.attach(base.add(0x12345), { onEnter: function (args) { ... } });
    });

    log("standalone loaded");
})();
