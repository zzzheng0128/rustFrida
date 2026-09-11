'use strict';

// Accurate API probe — runs inside Java worker context
function probeAll() {
    var results = {};

    function probe(tag, fn) {
        try {
            var r = fn();
            results[tag] = { ok: true, result: r };
            console.log("[PROBE] " + tag + " = OK");
        } catch (e) {
            results[tag] = { ok: false, error: e.message };
            console.log("[PROBE] " + tag + " = FAIL: " + e.message);
        }
    }

    console.log("========== PROBE START ==========");

    // Timer
    probe("timer.setTimeout", function() { setTimeout(function(){}, 100); return "exists"; });
    probe("timer.setInterval", function() { setInterval(function(){}, 100); return "exists"; });

    // Native hook
    probe("native.Interceptor.attach", function() {
        var a = Module.findExportByName("libc.so", "getpid");
        var l = Interceptor.attach(a, { onEnter: function(args){} });
        l.detach();
        return "ok";
    });
    probe("native.hook_fn", function() {
        var a = Module.findExportByName("libc.so", "getpid");
        hook(a, function(){ return 0; });
        return "ok";
    });
    probe("native.NativeCallback", function() {
        new NativeCallback(function(){}, 'int', []);
        return "ok";
    });

    // JNI
    probe("jni.Jni.addr", function() {
        var a = Jni.addr("RegisterNatives");
        return a ? a.toString() : "null";
    });

    // Java
    probe("java.Java.use", function() {
        var s = Java.use("java.lang.String");
        return s.$className;
    });
    probe("java.Java.perform", function() {
        var done = false;
        Java.perform(function() { done = true; });
        return done;
    });
    probe("java.overload", function() {
        var s = Java.use("java.lang.StringBuilder");
        var o = s.toString.overload();
        return typeof o.implementation + "/" + typeof o.impl;
    });

    // Process
    probe("process.setExceptionHandler", function() {
        Process.setExceptionHandler(function(d){ return false; });
        return "ok";
    });

    // Memory
    probe("memory.readByteArray", function() {
        var a = Module.findExportByName("libc.so", "getpid");
        return Memory.readByteArray(a, 4).byteLength;
    });

    // File
    probe("file.File", function() {
        var f = new File("/proc/self/cmdline", "r");
        var line = f.readLine();
        f.close();
        return line ? line.substring(0, 20) : "empty";
    });

    // CModule
    probe("cmodule.CModule", function() {
        var cm = new CModule(`void foo(void) {}`);
        return typeof cm;
    });

    // Date
    probe("date.Date.now", function() { return Date.now() > 0; });

    // NativeFunction types
    probe("native.type_int", function() {
        var a = Module.findExportByName("libc.so", "getpid");
        var fn = new NativeFunction(a, 'int', []);
        return fn();
    });
    probe("native.type_long", function() {
        var a = Module.findExportByName("libc.so", "getpid");
        var fn = new NativeFunction(a, 'long', []);
        return fn();
    });
    probe("native.type_int64", function() {
        var a = Module.findExportByName("libc.so", "getpid");
        var fn = new NativeFunction(a, 'int64', []);
        return fn().toInt32();
    });
    probe("native.type_pointer", function() {
        var a = Module.findExportByName("libc.so", "getpid");
        var fn = new NativeFunction(a, 'pointer', []);
        return fn().toInt32();
    });

    console.log("========== PROBE DONE ==========");
    return results;
}

var results = {};

if (Java.available) {
    Java.perform(function() {
        results = probeAll();
    });
} else if (Java.performNow) {
    Java.performNow(function() {
        results = probeAll();
    });
} else {
    results = probeAll();
}

rpc.exports = { probeResults: function() { return results; } };
