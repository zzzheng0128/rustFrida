/*
 * test_spawn_jnitrace.js — JNI 调用追踪 v2（JNIEnv 表槽 hook，rustfrida QuickJS 引擎）
 *
 * 用途：观察目标进程 JNI 层活动，给 unidbg 补 stub / 分析安全 SDK JNI 注册行为。
 * 原理：libart 的 art::JNI<false>::* 不导出（.dynsym 没有），无法按名 hook；
 *       改为从 Jni._threadEnv() 拿 JNIEnv*，读 JNINativeInterface 表槽地址 hook。
 * 槽位（JNI 1.6 标准）：FindClass=6 GetMethodID=33 GetStaticMethodID=113
 *       NewStringUTF=167 RegisterNatives=215
 * 运行：
 *   adb push test_spawn_jnitrace.js /data/local/tmp/
 *   su -c '(sleep 85; echo exit) | timeout 100 /data/local/tmp/rustfrida --spawn <包名> -l /data/local/tmp/test_spawn_jnitrace.js'
 */
(function () {
    "use strict";
    var TAG = "jnitrace-spawn";
    function log(m) { console.log("[" + TAG + "] " + m); }

    // ---- 槽位定义（JNINativeInterface 索引）----
    var SLOTS = [
        { slot: 6, name: "FindClass", detail: "cstr1" },
        { slot: 33, name: "GetMethodID", detail: "cstr2" },
        { slot: 113, name: "GetStaticMethodID", detail: "cstr2" },
        { slot: 167, name: "NewStringUTF", detail: "cstr1" },
        { slot: 215, name: "RegisterNatives", detail: "register" }
    ];
    var MAX_DETAIL = 5;
    var REPORT_EVERY = 200;

    var counters = {};
    function hookJni(addr, name, detail) {
        counters[name] = 0;
        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    counters[name] += 1;
                    var n = counters[name];
                    if (n <= MAX_DETAIL) {
                        var extra = "";
                        try {
                            if (detail === "cstr1") extra = " '" + args[1].readCString() + "'";
                            else if (detail === "cstr2") extra = " '" + args[2].readCString() + "'";
                            else if (detail === "register") {
                                var mname = args[2].readPointer().readCString();
                                extra = " count=" + args[3].toInt32() + " first='" + mname + "'";
                            }
                        } catch (_) { extra = " <unreadable>"; }
                        log(name + " #" + n + extra);
                    } else if (n % REPORT_EVERY === 0) {
                        log(name + " hits=" + n);
                    }
                }
            });
            return true;
        } catch (e) {
            log("attach " + name + " failed: " + e);
            return false;
        }
    }

    function install() {
        var hooked = 0;
        for (var i = 0; i < SLOTS.length; i++) {
            var s = SLOTS[i];
            var fn = null;
            try { fn = Jni.addr(s.name); } catch (e) {
                log("Jni.addr " + s.name + " failed: " + e);
                continue;
            }
            if (hookJni(fn, s.name, s.detail)) hooked++;
        }
        log("installed " + hooked + "/" + SLOTS.length + " jni table hooks");
    }

    // spawn 下脚本在 JVM 创建前执行，同步调 Jni.* 会挂死 JS worker；
    // 必须用 Java.ready(fn)（引擎在 app dex 加载后、attachBaseContext 前触发；
    // attach 模式立即执行）。
    Java.ready(function () {
        log("java ready, installing");
        install();
    });
    log("standalone loaded, waiting Java.ready");
})();
