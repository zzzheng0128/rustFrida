/*
 * test_spawn_backtrace.js — Frida Thread.backtrace 效果移植（rustfrida QuickJS 引擎）
 *
 * 对标 Frida：
 *   Thread.backtrace(ctx, Backtracer.ACCURATE) → Backtrace.accurate(ctx)
 *     沿 x29 帧指针链走读（有帧指针的代码准确）。
 *   Thread.backtrace(ctx, Backtracer.FUZZY)   → Backtrace.fuzzy(ctx)
 *     栈扫描：sp 起每个 qword 落在可执行映射内即候选返回地址（Frida FUZZY 同原理），
 *     -fomit-frame-pointer 代码断链时兜底。
 *   DebugSymbol.fromAddress(addr)             → Backtrace.symbolize(addr)
 *     "libart.so!_ZN3art3JNI...+0x140"（模块内最近导出符号；无符号段则 +0xoffset）。
 *
 * 引擎前提：hook(addr, fn) 回调的 this = 完整寄存器上下文（x0-x30/sp/pc）；
 *          Interceptor.attach 的 onEnter 没有寄存器上下文，做 backtrace 必须用 hook()。
 * 运行：
 *   adb push test_spawn_backtrace.js /data/local/tmp/
 *   su -c '(sleep 85; echo exit) | timeout 100 /data/local/tmp/rustfrida --spawn <包名> -l /data/local/tmp/test_spawn_backtrace.js'
 */
(function () {
    "use strict";
    var TAG = "bt-spawn";
    function log(m) { console.log("[" + TAG + "] " + m); }

    function isNullPtr(p) {
        if (p === null || p === undefined) return true;
        if (typeof p === "bigint") return p === BigInt(0);
        if (typeof p === "number") return p === 0;
        try { return p.isNull(); } catch (_) { return false; }
    }

    // ================= Backtrace（Frida 效果移植，可直接搬进模板） =================
    var Backtrace = (function () {
        var symCache = {}; // moduleName -> sorted [{addr, name}]（导出符号，符号化用）

        // hook() 的 ctx 寄存器是普通 number，不是 NativePointer，
        // 读写内存/查模块前必须先 ptr() 转换（已是指针对象则原样返回）。
        function P(v) {
            if (v !== null && typeof v === "object") return v;
            return ptr(v);
        }

        function exportsOf(moduleName) {
            if (symCache[moduleName]) return symCache[moduleName];
            var list = [];
            try {
                var exps = Process.getModuleByName(moduleName).enumerateExports();
                for (var i = 0; i < exps.length; i++) {
                    if (exps[i].type === "function") list.push({ addr: exps[i].address, name: exps[i].name });
                }
                list.sort(function (a, b) {
                    var d = a.addr.sub(b.addr);
                    return d.toInt32 ? d.toInt32() : 0;
                });
            } catch (_) {}
            symCache[moduleName] = list;
            return list;
        }

        // DebugSymbol.fromAddress 降级版："libx.so!符号+0xoff" 或 "libx.so!+0xoff"
        function symbolize(addrPtr) {
            var m = null;
            try { m = Process.findModuleByAddress(addrPtr); } catch (_) {}
            if (m === null || m === undefined) return String(addrPtr);
            var off = addrPtr.sub(m.base);
            var syms = exportsOf(m.name);
            // 二分找最近 ≤ addr 的导出符号
            var best = null;
            for (var i = 0; i < syms.length; i++) {
                var cmp = 0;
                try { cmp = syms[i].addr.sub(addrPtr).toInt32(); } catch (_) { break; }
                if (cmp <= 0) best = syms[i]; else break;
            }
            if (best !== null) {
                var delta = addrPtr.sub(best.addr);
                var d32 = 0;
                try { d32 = delta.toUInt32(); } catch (_) { d32 = 0; }
                if (d32 < 0x10000) { // 偏差太大说明不在该导出函数内
                    return m.name + "!" + best.name + "+0x" + d32.toString(16);
                }
            }
            // 注意：sub() 结果的 toString(16) 自带 0x 前缀，不要再拼 "0x"
            var offStr = "0x0";
            try { offStr = off.toUInt32().toString(16); } catch (_) { offStr = String(off); }
            return m.name + "!+0x" + offStr;
        }

        // ACCURATE：x29 帧链
        function accurate(ctx, limit) {
            limit = limit || 16;
            var frames = [P(ctx.pc), P(ctx.x30)];
            var fp = P(ctx.x29);
            for (var i = 0; i < limit; i++) {
                var prevFp = null, retAddr = null;
                try {
                    prevFp = fp.readPointer();
                    retAddr = fp.add(8).readPointer();
                } catch (_) { break; }
                if (isNullPtr(retAddr)) break;
                frames.push(retAddr);
                if (isNullPtr(prevFp)) break;
                try { if (prevFp.sub(fp).toUInt32() > 0x100000) break; } catch (_) { break; }
                fp = prevFp;
            }
            return frames;
        }

        // FUZZY：栈扫描，qword 落在 r-x 映射内即候选（Frida FUZZY 同原理）
        function fuzzy(ctx, limit, scanBytes) {
            limit = limit || 16;
            scanBytes = scanBytes || 0x800;
            var frames = [P(ctx.pc), P(ctx.x30)];
            var sp = P(ctx.sp);
            for (var off = 0; off < scanBytes && frames.length < limit + 2; off += 8) {
                var v = null;
                try { v = sp.add(off).readPointer(); } catch (_) { continue; }
                if (isNullPtr(v)) continue;
                var r = null;
                try { r = Process.findRangeByAddress(v); } catch (_) {}
                if (r === null || r === undefined) continue;
                var prot = String(r.protection || "");
                if (prot.indexOf("x") < 0) continue; // 只要可执行映射
                frames.push(v);
            }
            return frames;
        }

        function format(frames) {
            var out = [];
            for (var i = 0; i < frames.length; i++) {
                if (isNullPtr(frames[i])) continue; // 跳过帧链末端的空地址
                try {
                    var s = symbolize(frames[i]);
                    if (s === "0x0") continue;
                    // 无模块名的原始地址（jit-code-cache 等匿名执行页）保留，可能是 JIT 帧
                    out.push("#" + out.length + " " + s);
                } catch (_) {}
            }
            return out;
        }

        return {
            symbolize: symbolize,
            accurate: function (ctx, limit) { return format(accurate(ctx, limit)); },
            fuzzy: function (ctx, limit, scanBytes) { return format(fuzzy(ctx, limit, scanBytes)); }
        };
    })();
    // ================= /Backtrace =================

    // ---- 模块等待（简化轮询版）----
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

    // ================= 演示 0：epoll_wait 一次性 backtrace（必触发，先验证机制） =================
    // 注意：抖音几乎不走 libc openat 的 PLT，openat 不能当演示载体；epoll_wait 事件循环必热。
    (function demoEpoll() {
        var epollPtr = null;
        try { epollPtr = Module.findExportByName(null, "epoll_wait"); } catch (e) {}
        if (isNullPtr(epollPtr)) { log("epoll_wait not found, skip demo"); return; }
        var fired = false;
        hook(epollPtr, function () {
            if (fired) return;
            fired = true;
            log("=== epoll_wait 一次性 backtrace（机制自检）===");
            var a = Backtrace.accurate(this, 10);
            for (var i = 0; i < a.length; i++) log("  " + a[i]);
            log("=== epoll_wait FUZZY ===");
            var f = Backtrace.fuzzy(this, 10, 0x600);
            for (var j = 0; j < f.length; j++) log("  " + f[j]);
        });
        log("epoll demo armed");
    })();

    // ================= 演示：exeVMInner 前 2 次进入，ACCURATE + FUZZY 各打一次 =================
    var OFF_EXEVMINNER = 0x4cc10;
    var hits = 0;
    waitForModule("libmetasec_ml.so", function (base, size) {
        var entry = base.add(OFF_EXEVMINNER);
        log("hook exeVMInner @ " + entry + " (base=" + base + ")");
        hook(entry, function () {
            hits++;
            if (hits > 2) return; // 热函数，只打前 2 次
            log("=== hit#" + hits + " ACCURATE（帧链）===");
            var a = Backtrace.accurate(this, 12);
            for (var i = 0; i < a.length; i++) log("  " + a[i]);
            log("=== hit#" + hits + " FUZZY（栈扫描）===");
            var f = Backtrace.fuzzy(this, 12, 0x800);
            for (var j = 0; j < f.length; j++) log("  " + f[j]);
        });
    });

    log("standalone loaded");
})();
