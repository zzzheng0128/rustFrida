/*
 * GumTrace 指令级追踪模板。
 *
 * 使用前准备：
 *   1. 把 libGumTrace.so 推到 /data/local/tmp/；
 *   2. root 预创建输出文件并给应用写权限；
 *   3. 修改 TARGET_MODULE、TARGET_SYMBOL（或 TARGET_OFFSET）。
 *
 * 这个模板只在目标函数第一次进入时启动一次 GumTrace，函数返回后停止，
 * 避免把整进程变成高频指令日志。spawn 和 attach 都可以使用，不依赖定时器。
 */
(function () {
    "use strict";

    // 按当前目标 APK 修改这三个配置；兼容性 demo 可直接使用默认值。
    var TARGET_MODULE = "libcompatdemo.so";
    var TARGET_SYMBOL = "rf_agent_hot";
    var TARGET_OFFSET = null; // 例如 0x1234；填写后优先按模块基址+偏移定位

    var GUMTRACE_SO = "/data/local/tmp/libGumTrace.so";
    var TRACE_FILE = "/data/local/tmp/gumtrace-template.log";
    var TRACE_MODE = 2; // 0=Stand，1=DEBUG，2=STABLE
    var TRACE_TID = 0;  // 0 交给 GumTrace 选择当前线程

    var gumModule = null;
    var gumInit = null;
    var gumRun = null;
    var gumUnrun = null;
    var targetListener = null;
    var loaderListeners = [];
    var armed = false;
    var tracing = false;
    var tracedOnce = false;

    function log(message) {
        console.log("[gumtrace-template] " + message);
    }

    function validPtr(value) {
        if (value === null || value === undefined) return false;
        try { return String(ptr(value)) !== "0x0"; } catch (_) { return false; }
    }

    function parseOffset(value) {
        if (value === null || value === undefined || String(value).trim() === "") return null;
        var number = typeof value === "number" ? value : parseInt(String(value), 0);
        if (!isFinite(number) || number < 0) throw new Error("invalid TARGET_OFFSET: " + value);
        return number;
    }

    function findModule() {
        try { return Process.findModuleByName(TARGET_MODULE); } catch (_) { return null; }
    }

    function findTarget(module) {
        var offset = parseOffset(TARGET_OFFSET);
        if (offset !== null) return module.base.add(offset);
        if (!TARGET_SYMBOL) throw new Error("TARGET_SYMBOL or TARGET_OFFSET is required");
        try {
            var address = Module.findExportByName(TARGET_MODULE, TARGET_SYMBOL);
            if (validPtr(address)) return address;
        } catch (_) {}
        throw new Error(TARGET_SYMBOL + " export not found in " + TARGET_MODULE);
    }

    function findGlobalExport(name) {
        try {
            if (typeof Module.findGlobalExportByName === "function") {
                var global = Module.findGlobalExportByName(name);
                if (validPtr(global)) return global;
            }
        } catch (_) {}
        try {
            var address = Module.findExportByName(null, name);
            if (validPtr(address)) return address;
        } catch (_) {}
        return null;
    }

    function stopLoaderWatch() {
        for (var i = 0; i < loaderListeners.length; i++) {
            try { loaderListeners[i].detach(); } catch (_) {}
        }
        loaderListeners = [];
    }

    function loadGumTrace() {
        if (gumInit !== null) return true;
        try {
            // tagged=true 使用 memfd 标记加载；不需要时可改为 false 做基线对照。
            gumModule = Module.load(GUMTRACE_SO, 2, true);
            gumInit = new NativeFunction(gumModule.getExportByName("init"),
                "void", ["pointer", "pointer", "int", "pointer"]);
            gumRun = new NativeFunction(gumModule.getExportByName("run"), "void", []);
            gumUnrun = new NativeFunction(gumModule.getExportByName("unrun"), "void", []);
            log("loaded " + gumModule.name + " base=" + gumModule.base);
            return true;
        } catch (error) {
            log("load failed: " + (error.message || error));
            gumModule = null;
            gumInit = null;
            return false;
        }
    }

    function startTrace() {
        if (tracing) return true;
        if (!loadGumTrace()) return false;
        try {
            var names = Memory.allocUtf8String(TARGET_MODULE);
            var output = Memory.allocUtf8String(TRACE_FILE);
            var options = Memory.alloc(8);
            options.writeU64(BigInt(TRACE_MODE));
            gumInit(names, output, TRACE_TID, options);
            gumRun();
            tracing = true;
            log("started module=" + TARGET_MODULE + " output=" + TRACE_FILE);
            return true;
        } catch (error) {
            log("start failed: " + (error.message || error));
            return false;
        }
    }

    function stopTrace() {
        if (!tracing || gumUnrun === null) return;
        try {
            gumUnrun();
            log("stopped; trace file=" + TRACE_FILE);
        } catch (error) {
            log("stop failed: " + (error.message || error));
        } finally {
            tracing = false;
        }
    }

    function armTarget(module) {
        if (armed) return;
        var target = findTarget(module);
        targetListener = Interceptor.attach(target, {
            onEnter: function () {
                if (tracedOnce) return;
                tracedOnce = true;
                log("target entered " + target + " (one-shot)");
                if (!startTrace()) log("target hook remains installed, but GumTrace is inactive");
            },
            onLeave: function () {
                if (tracing) stopTrace();
            }
        });
        armed = true;
        stopLoaderWatch();
        log("armed " + TARGET_MODULE + "!" + target +
            (TARGET_SYMBOL ? " symbol=" + TARGET_SYMBOL : ""));
    }

    function tryArm() {
        if (armed) return;
        var module = findModule();
        if (module === null) return;
        try {
            armTarget(module);
        } catch (error) {
            log("arm failed: " + (error.message || error));
        }
    }

    function watchModuleLoad() {
        ["android_dlopen_ext", "dlopen", "__loader_android_dlopen_ext", "__loader_dlopen"]
            .forEach(function (name) {
                var loader = findGlobalExport(name);
                if (!validPtr(loader)) return;
                try {
                    loaderListeners.push(Interceptor.attach(loader, {
                        onLeave: function () { tryArm(); }
                    }));
                } catch (_) {}
            });
    }

    tryArm();
    if (!armed) {
        watchModuleLoad();
        log("waiting for " + TARGET_MODULE + " to load");
    }
})();
