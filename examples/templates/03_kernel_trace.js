/*
 * hybrid 的 KT> 桥模板。
 *
 * 先填偏移，再启用对应项。偏移是相对 so 基址的文件/映射偏移：
 *   uprobe: KT>brk libfoo.so 0x1234
 *   执行断点: KT>x libfoo.so+0x1234
 *   读写观察点: KT>r/w/rw libfoo.so+0x5678 8
 *
 * 事件仍会写到 host 的 trace 输出；JS 回调只做低频摘要。
 */
(function () {
    "use strict";

    var TAG = "kt";
    var counts = { svc: 0, uprobe: 0, hwbp: 0 };

    // null 表示不启用该项。按实际目标修改后再运行。
    var UPROBE = { module: "libexample.so", offset: null };
    var HWBP = [
        // { kind: "x",  target: "libexample.so+0x1234" },
        // { kind: "r",  target: "libexample.so+0x5678", len: 8 },
        // { kind: "w",  target: "0x7f000000", len: 8 }
    ];

    function log(message) { console.log("[" + TAG + "] " + message); }
    function sampled(n) { return n <= 3 || n % 100 === 0; }
    function location(event, name) {
        return event && event.locations && event.locations[name]
            ? "(" + event.locations[name] + ")" : "";
    }

    // 释放断点必须用绝对地址。`unsub` 只停止 JS 事件，不会释放内核槽位。
    // 可在 hwbp.hit 中把 event.bp.addr 传给这个函数，然后等待 host 的
    // `[trace-cmd] hwbp detached` 后再调用 armHardwareBreakpoint()。
    function detachHardwareBreakpoint(address) {
        console.log("KT>bpdel " + String(address));
    }
    function armHardwareBreakpoint(kind, target, len) {
        var command = "KT>" + kind + " " + String(target);
        if (kind !== "x") command += " " + (len || 8);
        console.log(command);
    }

    globalThis.__kt_on_ack = function (message) {
        log("ack " + message);
    };

    globalThis.__kt_on_event = function (event) {
        try {
            if (event.type === "svc.enter") {
                counts.svc++;
                if (sampled(counts.svc)) log("svc#" + counts.svc + " " + (event.name || event.nr));
            } else if (event.type === "uprobe.hit") {
                counts.uprobe++;
                if (sampled(counts.uprobe)) log("uprobe#" + counts.uprobe +
                    " pc=" + event.pc + location(event, "pc"));
            } else if (event.type === "hwbp.hit") {
                counts.hwbp++;
                if (sampled(counts.hwbp)) {
                    var window = event.instructions || [];
                    var far = event.addr || event.far;
                    var asm = [];
                    for (var wi = 0; wi < window.length; wi++) {
                        var item = window[wi] || {};
                        asm.push("#" + wi + "@" + (item.pc || "-") + "=" +
                            (item.asm || item.word || "-"));
                    }
                    log("hwbp#" + counts.hwbp + " " + JSON.stringify(event.bp) +
                        " pc=" + event.pc + location(event, "pc") +
                        " far=" + (far || "-") + (far ? location(event, "addr") : "") +
                        " disasm16=" + (asm.join("|") || "-"));
                }
            }
        } catch (e) {
            log("event error: " + (e.message || e));
        }
    };

    // 订阅必须在下发断点前完成。
    console.log("KT>sub");

    if (UPROBE.offset !== null) {
        console.log("KT>brk " + UPROBE.module + " 0x" + Number(UPROBE.offset).toString(16));
    }
    for (var i = 0; i < HWBP.length; i++) {
        var bp = HWBP[i];
        if (!bp || !bp.target) continue;
        var line = "KT>" + bp.kind + " " + bp.target;
        if (bp.kind !== "x") line += " " + (bp.len || 8);
        console.log(line);
    }

    log("loaded; edit UPROBE/HWBP before use");
})();
