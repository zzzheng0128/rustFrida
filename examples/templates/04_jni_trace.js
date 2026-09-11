/*
 * JNI RegisterNatives 观察模板。
 * Jni.addr 必须在 Java.ready 中调用，避免 spawn 早期 JVM 尚未就绪。
 */
(function () {
    "use strict";

    var TAG = "jni";
    var MAX_METHODS_PER_CALL = 32;

    function log(message) { console.log("[" + TAG + "] " + message); }

    function install() {
        try {
            var address = Jni.addr("RegisterNatives");
            var listener = Interceptor.attach(address, {
                onEnter: function (args) {
                    try {
                        var className = Jni.env.getClassName(args[1]);
                        var count = Number(args[3]);
                        var methods = Jni.structs.JNINativeMethod.readArray(
                            args[2], Math.min(count, MAX_METHODS_PER_CALL));
                        log("RegisterNatives class=" + className + " count=" + count);
                        for (var i = 0; i < methods.length; i++) {
                            var m = methods[i];
                            log("  " + m.name + " " + m.sig + " -> " + m.fnPtr);
                        }
                    } catch (e) {
                        log("decode failed: " + (e.message || e));
                    }
                }
            });
            log("attached RegisterNatives at " + address);
            return listener;
        } catch (e) {
            log("install failed: " + (e.message || e));
            return null;
        }
    }

    if (typeof Java !== "undefined" && Java && Java.ready) {
        Java.ready(install);
    } else {
        log("Java API unavailable");
    }
})();
