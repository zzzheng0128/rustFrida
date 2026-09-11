/*
 * Native 函数观察模板。
 * 把 TARGET_SYMBOL 换成需要观察的导出符号；只记录少量样本。
 * 适用于 --pid/--name，也适用于 --spawn（导出已加载时）。
 */
(function () {
    "use strict";

    var TAG = "native";
    var TARGET_MODULE = "libc.so";
    var TARGET_SYMBOL = "getpid";
    var MAX_LOGS = 5;
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
    } else {
        try {
            Interceptor.attach(target, {
                onEnter: function (args) {
                    hits++;
                    if (hits <= MAX_LOGS) {
                        log(TARGET_SYMBOL + " hit#" + hits + " pc=" + this.pc);
                    }
                },
                onLeave: function (retval) {
                    if (hits <= MAX_LOGS) log(TARGET_SYMBOL + " => " + retval);
                }
            });
            log("attached " + TARGET_MODULE + "!" + TARGET_SYMBOL + " at " + target);
        } catch (e) {
            log("attach failed: " + (e.message || e));
        }
    }
})();
