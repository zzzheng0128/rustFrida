'use strict';

// rustFrida API capability probe
// Run: rustfrida --pid 5138 -l probe_api.js

var results = {};

function probe(tag, fn) {
    try {
        var r = fn();
        results[tag] = { ok: true, result: r };
        console.log("[PROBE] " + tag + " = OK " + JSON.stringify(r).substring(0, 120));
    } catch (e) {
        results[tag] = { ok: false, error: String(e) };
        console.log("[PROBE] " + tag + " = FAIL: " + e.message);
    }
}

function main() {
    console.log("========== API PROBE START ==========");

    // Timer APIs
    probe("timer.setTimeout", function() { return typeof setTimeout; });
    probe("timer.setInterval", function() { return typeof setInterval; });
    probe("timer.clearTimeout", function() { return typeof clearTimeout; });

    // Native hook APIs
    probe("native.Interceptor.attach", function() {
        var addr = Module.findExportByName("libc.so", "getpid");
        var l = Interceptor.attach(addr, { onEnter: function(args) {} });
        l.detach();
        return "available";
    });

    probe("native.Interceptor.replace", function() {
        var addr = Module.findExportByName("libc.so", "getpid");
        var orig = new NativeFunction(addr, 'int64', []);
        Interceptor.replace(addr, new NativeCallback(function() { return 1; }, 'int64', []));
        Interceptor.revert(addr);
        return "available";
    });

    probe("native.hook_fn", function() {
        // Test if global 'hook' function exists (rustFrida shorthand)
        return typeof hook;
    });

    // JNI APIs
    probe("jni.Jni", function() { return typeof Jni; });
    if (typeof Jni !== "undefined") {
        probe("jni.addr", function() { return typeof Jni.addr; });
        probe("jni.env", function() { return typeof Jni.env; });
    }

    // Java APIs
    probe("java.Java.available", function() { return Java.available; });
    probe("java.Java.perform", function() {
        var done = false;
        Java.perform(function() { done = true; });
        return done;
    });
    probe("java.Java.performNow", function() { return typeof Java.performNow; });
    probe("java.Java.ready", function() { return typeof Java.ready; });
    probe("java.Java.use", function() {
        var r = false;
        Java.perform(function() {
            try { Java.use("java.lang.String"); r = true; } catch(e) {}
        });
        return r;
    });

    // DSL APIs
    probe("dsl.dslImpl", function() {
        var r = false;
        Java.perform(function() {
            try {
                var HM = Java.use("java.util.HashMap");
                var put = HM.put.overload("java.lang.Object", "java.lang.Object");
                r = (typeof put.dslImpl === "function" || typeof put.dsl === "function");
            } catch(e) {}
        });
        return r;
    });

    // impl shorthand
    probe("java.impl_shorthand", function() {
        var r = false;
        Java.perform(function() {
            try {
                var SB = Java.use("java.lang.StringBuilder");
                // Check if .impl exists as shorthand for .implementation
                r = (SB.toString.overload().impl !== undefined);
            } catch(e) {}
        });
        return r;
    });

    // Process APIs
    probe("process.id", function() { return Process.id; });
    probe("process.setExceptionHandler", function() {
        var h = Process.setExceptionHandler(function(d) { return false; });
        return typeof h;
    });

    // Memory APIs
    probe("memory.readByteArray", function() {
        var addr = Module.findExportByName("libc.so", "getpid");
        var b = Memory.readByteArray(addr, 4);
        return b ? b.byteLength : 0;
    });
    probe("memory.Uint8Array", function() {
        var addr = Module.findExportByName("libc.so", "getpid");
        var b = Memory.readByteArray(addr, 4);
        var u = new Uint8Array(b);
        return u.length;
    });

    // File API
    probe("file.File", function() {
        var f = new File("/proc/self/cmdline", "r");
        var line = f.readLine();
        f.close();
        return line ? line.substring(0, 30) : "empty";
    });

    // CModule
    probe("cmodule.CModule", function() {
        var cm = new CModule(`void foo(void) {}`);
        return typeof cm;
    });

    // Date
    probe("date.Date.now", function() { return Date.now() > 0; });

    // NativeFunction types
    probe("native.int64_type", function() {
        var addr = Module.findExportByName("libc.so", "getpid");
        var fn = new NativeFunction(addr, 'int64', []);
        return fn().toInt32() > 0;
    });

    console.log("========== API PROBE DONE ==========");
    console.log("Results summary:");
    var ok = 0, fail = 0;
    for (var k in results) {
        if (results[k].ok) ok++; else fail++;
    }
    console.log("OK=" + ok + " FAIL=" + fail);
}

if (Java.available) {
    Java.perform(main);
} else {
    main();
}

rpc.exports = { probeResults: function() { return results; } };
