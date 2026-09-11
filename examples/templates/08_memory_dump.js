/*
 * 模块内存转储模板。
 *
 * 只读取带文件映射的可读区间，并限制总大小，避免一次性把整个进程内存
 * 读进 JS。输出是原始二进制；同时写一个 .map 文件记录每段的地址和长度。
 * 在 Android 上写 /data/local/tmp 前，先由 shell/root 创建并 chmod 666，
 * 或把 OUTPUT 改成目标进程自己可写的目录。
 */
(function () {
    "use strict";

    var TAG = "memory-dump";
    var TARGET_MODULE = "libcompatdemo.so";
    var OUTPUT = "/data/local/tmp/rustfrida-memory.dump";
    var PROTECTION = null; // null 表示模块所有文件映射；也可填 "r-x" 等精确过滤
    var MAX_BYTES = 2 * 1024 * 1024;
    var CHUNK_SIZE = 0x4000;
    var finished = false;
    var loaderListeners = [];

    function log(message) { console.log("[" + TAG + "] " + message); }
    function asNumber(value) {
        if (typeof value === "number") return value;
        if (typeof value === "bigint") return Number(value);
        return Number(String(value));
    }

    function stopLoaderWatch() {
        for (var i = 0; i < loaderListeners.length; i++) {
            try { loaderListeners[i].detach(); } catch (_) {}
        }
        loaderListeners = [];
    }

    function dumpModule() {
        if (finished) return;
        finished = true;
        var file = null;
        var map = [];
        var total = 0;
        try {
            // Module.enumerateRanges 的结果包含 base、size、protection、file.path。
            var ranges = Module.enumerateRanges(TARGET_MODULE, PROTECTION);
            if (!ranges || ranges.length === 0) {
                throw new Error("no readable ranges for " + TARGET_MODULE);
            }

            file = new File(OUTPUT, "wb");
            for (var i = 0; i < ranges.length && total < MAX_BYTES; i++) {
                var range = ranges[i];
                if (String(range.protection || "").indexOf("r") < 0) continue;
                var available = Math.max(0, asNumber(range.size));
                var length = Math.min(available, MAX_BYTES - total);
                var copied = 0;
                while (copied < length) {
                    var step = Math.min(CHUNK_SIZE, length - copied);
                    var bytes = range.base.add(copied).readByteArray(step);
                    file.write(bytes);
                    copied += step;
                    total += step;
                }
                map.push({
                    base: String(range.base),
                    size: length,
                    protection: String(range.protection || ""),
                    path: range.file && range.file.path ? String(range.file.path) : ""
                });
                log("dumped " + range.base + " size=0x" + length.toString(16));
            }
            file.flush();
            file.close();
            file = null;
            File.writeAllText(OUTPUT + ".map", JSON.stringify({
                module: TARGET_MODULE, bytes: total, truncated: total >= MAX_BYTES, ranges: map
            }) + "\n");
            log("done bytes=" + total + " file=" + OUTPUT + " map=" + OUTPUT + ".map");
        } catch (error) {
            if (file !== null) { try { file.close(); } catch (_) {} }
            log("failed: " + (error.message || error));
        }
    }

    function tryDump() {
        if (finished) return;
        var module = null;
        try { module = Process.findModuleByName(TARGET_MODULE); } catch (_) {}
        if (module) {
            stopLoaderWatch();
            dumpModule();
        }
    }

    tryDump();
    if (!finished) {
        ["android_dlopen_ext", "dlopen", "__loader_android_dlopen_ext", "__loader_dlopen"]
            .forEach(function (name) {
                var loader = null;
                try { loader = Module.findExportByName(null, name); } catch (_) {}
                if (loader === null || loader === undefined) return;
                try { loaderListeners.push(Interceptor.attach(loader, { onLeave: tryDump })); }
                catch (_) {}
            });
        log("waiting for " + TARGET_MODULE + " to load");
    }
})();
