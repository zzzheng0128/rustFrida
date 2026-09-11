/*
 * native 堆栈模板（ARM64）。
 *
 * rustFrida 的 hook() 回调 this 是寄存器现场；这里沿 x29 帧指针链读取
 * 返回地址，并用 Process.findModuleByAddress() 做模块+偏移符号化。目标
 * 函数第一次命中时采样，最后调用 $orig() 保留原逻辑。
 *
 * 目标没有帧指针时，准确链会较短；可把 fuzzy 栈扫描逻辑从历史
 * test_spawn_backtrace.js 复制进来作为兜底。
 */
(function () {
    "use strict";

    var TAG = "backtrace";
    var TARGET_MODULE = "libc.so";
    var TARGET_SYMBOL = "epoll_wait";
    var MAX_FRAMES = 12;
    var fired = false;

    function log(message) { console.log("[" + TAG + "] " + message); }
    function P(value) {
        if (value !== null && typeof value === "object") return value;
        return ptr(value);
    }
    function isNull(value) {
        if (value === null || value === undefined) return true;
        try { return String(P(value)) === "0x0"; } catch (_) { return true; }
    }
    function symbolize(value) {
        var address = P(value);
        try {
            var module = Process.findModuleByAddress(address);
            if (!module) return String(address);
            var offset = address.sub(module.base);
            return module.name + "+0x" + offset.toUInt32().toString(16);
        } catch (_) { return String(address); }
    }
    function collect(ctx) {
        var frames = [];
        if (!isNull(ctx.pc)) frames.push(P(ctx.pc));
        if (!isNull(ctx.x30)) frames.push(P(ctx.x30));
        var fp = P(ctx.x29);
        for (var i = 0; i < MAX_FRAMES && !isNull(fp); i++) {
            try {
                var previous = fp.readPointer();
                var returnAddress = fp.add(8).readPointer();
                if (isNull(returnAddress)) break;
                frames.push(returnAddress);
                if (isNull(previous)) break;
                fp = previous;
            } catch (_) { break; }
        }
        return frames;
    }
    function collectFuzzy(ctx) {
        var frames = [];
        if (!isNull(ctx.pc)) frames.push(P(ctx.pc));
        if (!isNull(ctx.x30)) frames.push(P(ctx.x30));
        var sp = P(ctx.sp);
        for (var offset = 0; offset < 0x600 && frames.length < MAX_FRAMES + 2; offset += 8) {
            try {
                var candidate = sp.add(offset).readPointer();
                if (isNull(candidate)) continue;
                var range = Process.findRangeByAddress(candidate);
                if (range && String(range.protection || "").indexOf("x") >= 0) {
                    frames.push(candidate);
                }
            } catch (_) {}
        }
        return frames;
    }

    try {
        var target = Module.findExportByName(TARGET_MODULE, TARGET_SYMBOL);
        if (isNull(target)) throw new Error("export not found");
        hook(target, function () {
            if (!fired) {
                fired = true;
                var frames = collect(this);
                log("hit pc=" + this.pc + " tid=" + Process.getCurrentThreadId());
                for (var i = 0; i < frames.length; i++) {
                    log("  #" + i + " " + symbolize(frames[i]));
                }
                var fuzzy = collectFuzzy(this);
                for (var j = 0; j < fuzzy.length; j++) {
                    log("  [fuzzy] #" + j + " " + symbolize(fuzzy[j]));
                }
            }
            return this.$orig();
        });
        log("armed " + TARGET_MODULE + "!" + TARGET_SYMBOL + " at " + target);
    } catch (error) {
        log("failed: " + (error.message || error));
    }
})();
