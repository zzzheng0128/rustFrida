'use strict';

// ============================================================
// test_registernatives.js —— RegisterNatives / native 方法 hook 验证
//
// 背景：之前的测试脚本只覆盖了 libc syscall hook（openat/mmap/...），
//       没有验证「native 方法」（通过 JNI RegisterNatives 注册的 fnPtr）
//       能否被 Java.use hook。
//
// 原理：Java.use(clazz).method.implementation = fn 时，底层检测到该方法是
//       native（ACC_NATIVE）且 original_data 指向已注册的 fnPtr，会走
//       HookType::NativeEntry 分支，对 fnPtr 做 inline hook。
//       本脚本验证这条路径在抖音（含安全 SDK）上真实可命中。
//
// 分层目标：
//   Layer A —— 系统类 native 方法（必然存在，验证基础链路通）
//   Layer B —— 抖音自有 native 方法（验证真机场景）
//   Layer C —— 常见安全 SDK native 方法（libmsaoaidsec 等，若已加载）
// ============================================================

console.log("[RN] Agent loaded, waiting Java.ready");

var stats = {
    installed: 0,
    skipped: 0,
    errors: 0,
    hits: 0,
    perTarget: {}
};

// 全局作用域变量 —— 供 native hook 回调闭包引用（回调在独立 worker 求值，
// 不能访问 installHooks 函数体内的局部变量）
var dyTried = false;
var dyProbeCounter = 0;
var dyTargets = [
    { cls: "com.ss.android.ugc.aweme.app.host.AwemeHostApplication", tag: "dy_aweme" },
    { cls: "com.ss.android.common.applog.NetUtil", tag: "dy_netutil" },
    { cls: "com.bytedance.frameworks.baselib.encrypt.TTEncryptUtils", tag: "dy_ttencrypt" },
    { cls: "com.ss.android.common.applog.GlobalContext", tag: "dy_globalctx" }
];

function rnlog(tag, msg) {
    console.log("[RN][" + tag + "] " + msg);
}

// 探测并 hook 抖音自有 native 方法（全局函数，供回调调用）
function tryDyHooks() {
    if (dyTried) return;
    var anyLoaded = false;
    dyTargets.forEach(function(t) {
        try {
            var C = Java.use(t.cls);
            var methods = C.class.getDeclaredMethods();
            var nativeCount = 0;
            for (var i = 0; i < methods.length; i++) {
                var mm = methods[i];
                if (mm.isNative()) {
                    nativeCount++;
                    if (nativeCount <= 3) {
                        hookNativeMethod(t.cls, mm.getName(), null, t.tag + "_" + mm.getName());
                    }
                }
            }
            if (nativeCount > 0) {
                rnlog("DYNATIVE", t.cls + " has " + nativeCount + " native methods");
                anyLoaded = true;
            }
        } catch (e) {
            // 类未加载，下次命中再试
        }
    });
    if (anyLoaded) dyTried = true;
}

// 通用 hook：单个类的单个 native 方法
function hookNativeMethod(clsName, methodName, overload, tag) {
    try {
        var C = Java.use(clsName);
        var m = C[methodName];
        if (!m) { stats.skipped++; return false; }

        // 有重载时按签名选
        var target = m;
        if (overload) {
            target = m.overload(overload);
        }

        target.implementation = function() {
            stats.hits++;
            stats.perTarget[tag] = (stats.perTarget[tag] || 0) + 1;
            if (stats.hits % 10 === 1) {
                rnlog("HIT", tag + " hits=" + stats.perTarget[tag] + " total=" + stats.hits);
            }
            // 命中时顺带探测抖音 native 类（引擎无 setTimeout，靠此触发）
            if (!dyTried && typeof tryDyHooks === 'function') {
                dyProbeCounter++;
                if (dyProbeCounter % 50 === 0) {
                    tryDyHooks();
                }
            }
            // 继续走原 native 实现
            // 注意：native 方法（fnPtr inline hook）必须用 this.$orig 调原实现，
            // target.apply 会经 JNI 重新分派到已 hook 的入口 → 无限递归 → JS 栈溢出
            return this.$orig.apply(this, arguments);
        };

        stats.installed++;
        rnlog("HOOK", clsName + "." + methodName + (overload ? overload : "") + " -> " + tag);
        return true;
    } catch (e) {
        stats.errors++;
        rnlog("ERR", clsName + "." + methodName + ": " + (e.message || e));
        return false;
    }
}

function installHooks() {
    rnlog("INSTALL", "installing native method hooks");

    // ---- Layer A: 系统类 native 方法（基础链路验证）----
    // System.nanoTime / currentTimeMillis 是 native，调用频率高，必然命中
    // hookNativeMethod("java.lang.System", "nanoTime", null, "sys_nanoTime");
    // hookNativeMethod("java.lang.System", "currentTimeMillis", null, "sys_currentTimeMillis");
    // hookNativeMethod("java.lang.System", "arraycopy", null, "sys_arraycopy");
    // Runtime.availableProcessors / maxMemory 是 native
    hookNativeMethod("java.lang.Runtime", "availableProcessors", null, "rt_availableProcessors");
    hookNativeMethod("java.lang.Runtime", "maxMemory", null, "rt_maxMemory");
    hookNativeMethod("java.lang.Runtime", "freeMemory", null, "rt_freeMemory");
    // // Thread.currentThread / interrupt 是 native
    // hookNativeMethod("java.lang.Thread", "currentThread", null, "thread_currentThread");
    hookNativeMethod("java.lang.Thread", "interrupt", null, "thread_interrupt");
    // // Class.getName / getSuperclass native
    // hookNativeMethod("java.lang.Class", "getName", null, "class_getName");
    // hookNativeMethod("java.lang.Class", "getSuperclass", null, "class_getSuperclass");
    // // String.intern 是 native
    // hookNativeMethod("java.lang.String", "intern", null, "string_intern");
    // // Object.hashCode / getClass native
    // hookNativeMethod("java.lang.Object", "hashCode", null, "obj_hashCode");
    // hookNativeMethod("java.lang.Object", "getClass", null, "obj_getClass");
    // // System.identityHashCode native
    // hookNativeMethod("java.lang.System", "identityHashCode", null, "sys_identityHashCode");
    // // Thread.sleep native
    // hookNativeMethod("java.lang.Thread", "sleep", "(J)V", "thread_sleep");
    // // Math.random / sqrt 是 native（部分版本）
    // hookNativeMethod("java.lang.Math", "sqrt", "(D)D", "math_sqrt");
    // Float.floatToRawIntBits / Double.doubleToRawLongBits native
    // hookNativeMethod("java.lang.Float", "floatToRawIntBits", null, "float_bits");
    // hookNativeMethod("java.lang.Double", "doubleToRawLongBits", null, "double_bits");
    hookNativeMethod("com.ss.android.ugc.aweme.base.model.UrlModel", "getUrlList", null, "urlmodel_getUrlList");

    // ---- Layer B: 抖音自有 native 方法（真机场景，可能延迟注册）----
    // 引擎无 setTimeout，改为「系统类 hook 命中时顺带探测」：每命中 N 次
    // 探测抖音类，一旦能解析就立即 hook 其 native 方法（逻辑见全局 tryDyHooks）。

    rnlog("ARMED", "installed=" + stats.installed + " skipped=" + stats.skipped + " errors=" + stats.errors);
}



console.log("===== start native hook =====");

var cstats = {
    dlopenCalls: 0,
    detectedSo: {},
    confirmedLoaded: {},
    hookedExports: 0,
    hookErrors: 0,
    fullScans: 0
};

function slog(tag, msg) {
    console.log("[SOLOAD][" + tag + "] " + msg);
}

function isNullPtr(p) {
    if (!p) return true;
    if (typeof p.toInt32 === 'function') return p.toInt32() === 0;
    return p.toString() === '0x0';
}

var SO_KEYWORDS = [
    "libttcrypto", "libttboringssl", "libvolc", "libpandora",
    "libmetasec", "libmsaoaidsec", "libtobEmbed", "libttvideo",
    "libttimage", "libSecCrypto", "libnms"
];

var hookedSo = {};
var pendingPaths = {};   // onEnter 记录的 path，onLeave 时处理
var needFullScan = false;

function soBasename(path) {
    var i = path.lastIndexOf("/");
    return i >= 0 ? path.substring(i + 1) : path;
}

function matchKeyword(path) {
    var base = soBasename(path);
    for (var i = 0; i < SO_KEYWORDS.length; i++) {
        if (base.indexOf(SO_KEYWORDS[i]) !== -1) return SO_KEYWORDS[i];
    }
    return null;
}

// ---- 全量扫描已加载 SO，返回命中列表 ----
function fullScan() {
    cstats.fullScans++;
    var hits = [];
    try {
        var mods = Module.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            var m = mods[i];
            var kw = matchKeyword(m.name);
            if (kw) hits.push({ name: m.name, base: m.base, size: m.size, path: m.path || "", kw: kw });
        }
    } catch (e) { /* ignore */ }
    return hits;
}

// ---- 确认单个 SO 已加载 + hook 导出 ----
function confirmByName(soName, kw, path) {
    try {
        var mod = Process.findModuleByName(soName);
        if (!mod) {
            var mods = Module.enumerateModules();
            for (var i = 0; i < mods.length; i++) {
                if (mods[i].name.indexOf(soName) !== -1 || (kw && mods[i].name.indexOf(kw) !== -1)) {
                    mod = mods[i];
                    break;
                }
            }
        }
        if (!mod) return false;

        var key = mod.name;
        if (!cstats.confirmedLoaded[key]) {
            cstats.confirmedLoaded[key] = {
                base: mod.base ? mod.base.toString() : "?",
                size: mod.size,
                path: mod.path || path || ""
            };
            slog("03 LOADED", key + " base=" + cstats.confirmedLoaded[key].base +
                 " size=" + mod.size + " path=" + cstats.confirmedLoaded[key].path);
            hookSoExports(mod.name, key);
        }
        return true;
    } catch (e) {
        return false;
    }
}

function hookSoExports(modName, key) {
    if (hookedSo[key]) return;
    hookedSo[key] = true;
    try {
        console.log("04 hookSoExports: " + modName);
        var exports = Module.enumerateExports(modName);
        var hooked = 0;
        var patterns = [
            "encrypt", "decrypt", "sign", "verify", "hash", "hmac",
            "aes", "des", "rsa", "md5", "sha", "crc",
            "registernative", "jni_onload", "jni", "init", "attach",
            "jni_onload"
        ];
        exports.forEach(function(exp) {
            if (exp.type !== "function") return;
            var lower = exp.name.toLowerCase();
            // 可用
            // console.log("04 hookSoExports: " + modName + " export=" + exp.name);
            // var hit = patterns.some(function(p) { return lower.indexOf(p) !== -1; });
            // if (!hit) return;
            // try {
            //     Interceptor.attach(exp.address, {
            //         onEnter: function(a) {
            //             // console.log("[SOHOOK] " + modName + " export=" + exp.name + " called");
            //             cstats.hookedExports++;
            //         }
            //     });
            //     hooked++;
            // } catch (e) {
            //     cstats.hookErrors++;
            // }
        });
        if (hooked > 0) {
            slog("05 HOOKEXP", modName + ": attached " + hooked + " exports");
        }
    } catch (e) {
        cstats.hookErrors++;
    }
}

// ---- 核心：dlopen onEnter 记录 + onLeave 确认 ----
function hookDlopen() {
    var androidDlopen = Module.findExportByName(null, "android_dlopen_ext");
    var dlopen = Module.findExportByName(null, "dlopen");
    console.log("hookDlopen: android_dlopen_ext=" + androidDlopen + ", dlopen=" + dlopen);
    [androidDlopen,dlopen].forEach(function(addr) {
        if (!addr || isNullPtr(addr)) return;
        Interceptor.attach(addr, {
            onEnter: function(args) {
                cstats.dlopenCalls++;
                try {
                    var path = args[0].readCString();
                    if (path) {
                        var kw = matchKeyword(path);
                        if (kw) {
                            // onEnter 时 SO 未映射，先记录
                            pendingPaths[path] = kw;
                            slog("01 DLOPEN", path + "  [kw=" + kw + "]");
                            if (!cstats.detectedSo[path]) {
                                cstats.detectedSo[path] = 0;
                                
                            }
                            cstats.detectedSo[path]++;
                        }
                    }
                } catch (e) { /* ignore */ }
            },
            onLeave: function(retval) {
                // console.log("dlopen onLeave: retval=" + retval);
                // onLeave 时 SO 已真正加载，立即确认
                if (needFullScan) {
                    needFullScan = false;
                    var hits = fullScan();
                    hits.forEach(function(h) {
                        confirmByName(h.name, h.kw, h.path);
                    });
                }
                for (var p in pendingPaths) {
                    console.log("02 dlopen onLeave: pending path=" + p);
                    var kw = pendingPaths[p];
                    var base = soBasename(p);
                    if (confirmByName(base, kw, p)) {
                        delete pendingPaths[p];
                    }
                }
            }
        });
    });
    slog("DLHOOK", "dlopen + android_dlopen_ext hooked (onEnter+onLeave)");
}

// ---- 启动时先全量扫一遍（捕获启动前已加载的 SO）----
hookDlopen();
var initialHits = fullScan();
slog("INITSCAN", "启动时已加载 " + initialHits.length + " 个目标 SO");
initialHits.forEach(function(h) {
    confirmByName(h.name, h.kw, h.path);
});
// 标记需要后续兜底扫描（捕获不走 dlopen 的）
needFullScan = true;

function dumpArt(tag) {
    var art = Process.findModuleByName("libart.so");
    console.log("[artcheck][" + tag + "] pid=" + Process.id +
        " arch=" + Process.arch +
        " libart=" + (art === null ? "not-loaded" : art.base));
}

function __dyidre_mode_artcheck() {
    console.log("[artcheck] Java ready");
    dumpArt("before-hook");
    try {
        var JN = Java.use("J.N");
        var MnXVOzVo = JN.MnXVOzVo.overload(
        "java.lang.Object",
        "long",
        "java.lang.String",
        "int",
        "int",
        "boolean",
        "boolean",
        "boolean",
        "int",
        "boolean",
        "int",
        "int",
        "long"
        );
        MnXVOzVo.implementation = function (
            a0, a1, url, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12
            ) {
            // 可用
            // console.log("[artcheck][hit] url=" + url);
            return this.$orig.apply(this, arguments);
        };
        console.log("[artcheck] hook installed: J.N.MnXVOzVo");
    } catch (e) {
        console.log("[artcheck] hook install failed: " + e);
    }
    dumpArt("after-hook");
}
try {
    Java.ready(function() {
        installHooks();
        __dyidre_mode_artcheck();
    });
} catch (e) {
    rnlog("ERR", "Java API unavailable: " + (e.message || e) + " — cannot hook native methods");
}
