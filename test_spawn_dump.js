/*
 * test_spawn_dump.js — 内存 hexdump（rustfrida QuickJS 引擎，spawn 兼容）
 *
 * 用途：打印目标内存的 hexdump（offset + hex + ascii），用于看 .so 头、
 *       函数序言、hook 前后的补丁对比。
 * 引擎无全局 hexdump()，这里用 readU8/readByteArray 纯 JS 实现。
 * 大块 dump（MB 级）不要走 JS 格式化——用文末 fileDump() 直接 fwrite 落盘
 * （文件需 root 预创建：touch + chmod 666，见 SCRIPT_GUIDE.md）。
 * 运行：
 *   adb push test_spawn_dump.js /data/local/tmp/
 *   su -c '(sleep 85; echo exit) | timeout 100 /data/local/tmp/rustfrida --spawn <包名> -l /data/local/tmp/test_spawn_dump.js'
 */
(function () {
    "use strict";
    var TAG = "dump-spawn";
    function log(m) { console.log("[" + TAG + "] " + m); }

    function isNullPtr(p) {
        if (p === null || p === undefined) return true;
        if (typeof p === "bigint") return p === BigInt(0);
        if (typeof p === "number") return p === 0;
        try { return p.isNull(); } catch (_) { return false; }
    }

    // ---- hexdump：每行 16 字节，offset  hex  |ascii| ----
    function hexdump(basePtr, length) {
        var lines = [];
        for (var off = 0; off < length; off += 16) {
            var hex = "", ascii = "";
            for (var i = 0; i < 16 && off + i < length; i++) {
                var b = 0;
                try { b = basePtr.add(off + i).readU8(); } catch (_) { b = -1; }
                if (b < 0) { hex += "?? "; ascii += "."; }
                else {
                    hex += ("0" + b.toString(16)).slice(-2) + " ";
                    ascii += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : ".";
                }
            }
            while (hex.length < 48) hex += " ";
            lines.push(("00000000" + (off).toString(16)).slice(-8) + "  " + hex + " |" + ascii + "|");
        }
        return lines.join("\n");
    }

    // ---- 大块 dump 直接落盘（源指针直接 fwrite，不经 JS 拷贝）----
    function nf(name, ret, args) {
        var p = null;
        try { p = Module.findExportByName(null, name); } catch (e) {}
        if (isNullPtr(p)) return null;
        return new NativeFunction(p, ret, args);
    }
    function fileDump(memPtr, size, path) {
        var fopen = nf("fopen", "pointer", ["pointer", "pointer"]);
        var fwrite = nf("fwrite", "ulong", ["pointer", "ulong", "ulong", "pointer"]);
        var fclose = nf("fclose", "int", ["pointer"]);
        if (!fopen || !fwrite || !fclose) { log("libc io nf unavailable"); return false; }
        var fp = fopen(Memory.allocUtf8String(path), Memory.allocUtf8String("wb"));
        if (isNullPtr(fp)) { log("fopen failed: " + path + "（需 root 预创建+666）"); return false; }
        var written = fwrite(memPtr, 1, size, fp);
        fclose(fp);
        log("fileDump " + path + " written=" + written + "/" + size);
        return written === size;
    }

    // ---- 模块等待（简化版，spawn 下 metasec 自加载用轮询兜底）----
    function waitForModule(targetName, onReady) {
        function findTarget() {
            try { return Process.findModuleByName(targetName); } catch (_) { return null; }
        }
        var existing = findTarget();
        if (existing !== null) { onReady(existing.base, existing.size); return; }
        var done = false, lastPoll = 0, listeners = [];
        function stop() { listeners.forEach(function (l) { try { l.detach(); } catch (_) {} }); listeners = []; }
        function poll() {
            if (done) { stop(); return; }
            var now = Date.now();
            if (now - lastPoll < 1000) return;
            lastPoll = now;
            var t = findTarget();
            if (t !== null && t.size >= 0x10000) { done = true; stop(); onReady(t.base, t.size); }
        }
        ["openat", "epoll_wait"].forEach(function (fname) {
            var fptr = null;
            try { fptr = Module.findExportByName(null, fname); } catch (e) {}
            if (isNullPtr(fptr)) return;
            try { listeners.push(Interceptor.attach(fptr, { onEnter: function () { poll(); } })); } catch (_) {}
        });
        log("waiting for " + targetName);
    }

    // ================= 演示 =================
    waitForModule("libmetasec_ml.so", function (base, size) {
        log("target base=" + base + " size=0x" + size.toString(16));

        log("--- ELF head (64B) ---\n" + hexdump(base, 64));

        var exeVMInner = base.add(0x4cc10);
        log("--- exeVMInner prologue (64B) ---\n" + hexdump(exeVMInner, 64));

        // 大块 dump 示例（需先 su -c 'touch /data/local/tmp/metasec_head.bin && chmod 666 ...'）：
        // fileDump(base, 0x100000, "/data/local/tmp/metasec_head.bin");
    });

    log("standalone loaded");
})();
