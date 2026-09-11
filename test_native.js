'use strict';

// ============================================================
// test_soload.js —— SO 加载监控验证（无 setTimeout 版本）
//
// 约束：本 quickjs 引擎不支持 setTimeout/setInterval，延迟确认
//       必须走 dlopen 的 onLeave（此时 SO 已真正映射进进程）。
//
// 三层手段：
//   1) dlopen / android_dlopen_ext 的 onLeave —— SO 加载完成后立即确认
//   2) onLeave 里同步 Module.enumerateModules 匹配 —— 确认真实映射
//   3) 命中目标 SO 后 hook 其关键导出函数 —— 验证可对刚加载 SO 下手
//
// 兜底：不走 dlopen 的 SO（linker 直接加载）用 onEnter 记录 + 下次
//       任意 dlopen onLeave 时全量扫描一次，捕获漏网之鱼。
// ============================================================

console.log("[SOLOAD] Agent loaded");

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
            console.log("04 hookSoExports: " + modName + " export=" + exp.name);
            // 这里批量 native 卡死了，就不测试了
            // var hit = patterns.some(function(p) { return lower.indexOf(p) !== -1; });
            // if (!hit) return;
            // try {
            //     Interceptor.attach(exp.address, {
            //         onEnter: function(a) {
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

rpc.exports = {
    cstats: function() { return cstats; },
    dump: function() { return { detected: cstats.detectedSo, confirmed: cstats.confirmedLoaded }; }
};

slog("START", "SO 加载监控已启动（无定时器版），等待抖音 SO 加载...");
