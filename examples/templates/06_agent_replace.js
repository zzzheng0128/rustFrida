/*
 * agent replace 模板。
 * hook() 是替换式 API：回调不会自动执行原函数，只有显式调用 this.$orig() 才会继续。
 * 这里用 getuid 做“调用原函数并记录返回值”的安全示例；确认链路后再改成目标地址。
 */
(function () {
    "use strict";

    var TAG = "agent";
    var TARGET_MODULE = "libc.so";
    var TARGET_SYMBOL = "getuid";
    var hits = 0;

    function log(message) { console.log("[" + TAG + "] " + message); }
    function isNullPtr(value) {
        if (value === null || value === undefined) return true;
        if (typeof value === "number") return value === 0;
        if (typeof value === "bigint") return value === BigInt(0);
        try { return value.isNull(); } catch (_) { return false; }
    }

    var target = null;
    try { target = Module.findExportByName(TARGET_MODULE, TARGET_SYMBOL); } catch (_) {}
    if (isNullPtr(target)) {
        log("export not found: " + TARGET_MODULE + "!" + TARGET_SYMBOL);
    } else if (typeof hook !== "function") {
        log("hook API unavailable");
    } else {
        try {
            hook(target, function () {
                hits++;
                var result = this.$orig();
                if (hits <= 5) log(TARGET_SYMBOL + " hit#" + hits + " => " + result);
                return result;
            });
            log("replaced " + TARGET_MODULE + "!" + TARGET_SYMBOL + " at " + target);
        } catch (e) {
            log("replace failed: " + (e.message || e));
        }
    }
})();
