/*
 * Java 方法观察模板。
 * Spawn 模式下把 Java.use 放进 Java.ready；attach 模式也可直接复用。
 * 把 TARGET_CLASS、TARGET_METHOD 和签名替换成目标类的方法。
 */
(function () {
    "use strict";

    var TAG = "java";
    var TARGET_CLASS = "android.os.Process";
    var TARGET_METHOD = "myPid";
    // 空数组表示使用默认方法包装；有重载时填完整签名，例如
    // ["java.lang.String", "int"]。
    var TARGET_OVERLOAD = [];
    var hits = 0;

    function log(message) { console.log("[" + TAG + "] " + message); }

    function install() {
        try {
            var C = Java.use(TARGET_CLASS);
            var method = TARGET_OVERLOAD.length
                ? C[TARGET_METHOD].overload.apply(C[TARGET_METHOD], TARGET_OVERLOAD)
                : C[TARGET_METHOD];
            method.implementation = function () {
                hits++;
                if (hits <= 5) log(TARGET_CLASS + "." + TARGET_METHOD + " hit#" + hits);
                // 保留原逻辑；需要改返回值时在这里返回新值。
                return this.$orig.apply(this, arguments);
            };
            log("installed " + TARGET_CLASS + "." + TARGET_METHOD);
        } catch (e) {
            log("install failed: " + (e.message || e));
        }
    }

    if (typeof Java !== "undefined" && Java && Java.ready) {
        Java.ready(install);
    } else {
        log("Java API unavailable");
    }
})();
