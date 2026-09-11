/*
 * 只读内存探针模板。默认读取 libc ELF 头，确认地址解析和内存读取链路。
 * 目标代码/数据地址请先确认映射和长度，不要盲写只读段。
 */
(function () {
    "use strict";

    var TAG = "memory";
    var TARGET_MODULE = "libc.so";
    var TARGET_OFFSET = 0;
    var LENGTH = 16;

    function log(message) { console.log("[" + TAG + "] " + message); }
    function hex(value) {
        var bytes = new Uint8Array(value);
        var out = "";
        for (var i = 0; i < bytes.length; i++) {
            out += (i ? " " : "") + ("0" + bytes[i].toString(16)).slice(-2);
        }
        return out;
    }

    try {
        var module = Process.findModuleByName(TARGET_MODULE);
        if (!module) {
            log("module not found: " + TARGET_MODULE);
        } else {
            var address = module.base.add(TARGET_OFFSET);
            log(TARGET_MODULE + "+0x" + TARGET_OFFSET.toString(16) + " = " + address);
            log("bytes: " + hex(address.readByteArray(LENGTH)));
        }
    } catch (e) {
        log("read failed: " + (e.message || e));
    }
})();
