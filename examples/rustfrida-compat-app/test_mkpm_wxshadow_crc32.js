'use strict';

// ============================================================
// test_wxshadow_crc32_bypass.js —— 验证 WXSHADOW 能否骗过 crc32 检测
//
// 背景：升级文档 §2 / P2 把 WXSHADOW 列为 CRC 欺骗的核心战役。
//   「读见原文、执行走断点」—— 进程内任意对函数头部做 CRC32/hash 巡检的
//   检测方（抖音 safety/libmetasec_ml 等）应当读不出修改痕迹。
//
// 模板：test_all.js（RegisterNatives 验证）的风格（stats / 日志前缀 / try catch）。
//
// 验证策略：
//   目标函数选 libc 里调用频次最高的 openat / close —— 必然被命中，可同时
//   验证「hook 真的触发」与「CRC 没变」。
//
//   多窗口验证：分别抓取 hook 点前 4 / 8 / 16 / 32 / 64 / 128 字节算 CRC32，
//   对应不同深度的检测方：
//     4B   —— 检测文档 5.1 提到的「头部 4 字节」最浅扫描
//     16B  —— 一般 hash 扫描覆盖一个 cache-line 头部
//     64B  —— 中等深度
//     128B —— 接近函数 prologue + 局部 fixup 区
//
//   对照：WXSHADOW 之后再次跑 NORMAL 模式 hook，验证 NORMAL 必然使 CRC 变化，
//   证明 CRC 算法本身没问题，差异完全来自 hook 引擎。
//
// 验收规则：
//   WXSHADOW：所有窗口 CRC32 与原始一致（若 KPM 未生效或权限不足，给出明确降级
//             提示而不静默放过）
//   NORMAL ：所有窗口 CRC32 与原始必不一致 —— 否则 hook 安装失败
//   命中计数：callCount > 0 证明 hook 链路通
// ============================================================

console.log("[CRC] Agent loaded, java=" + (typeof Java));

var stats = {
    targetsConfigured: 0,
    wxHooksInstalled: 0,
    wxHooksFailed: 0,
    normalHooksInstalled: 0,
    normalHooksFailed: 0,
    wxHits: 0,
    normalHits: 0,
    perTarget: {}
};
var crcPhase = "all";

function crclog(tag, msg) {
    console.log("[CRC][" + tag + "] " + msg);
}

function hex(n) {
    if (typeof n === 'bigint') {
        return '0x' + n.toString(16);
    }
    return '0x' + (n >>> 0).toString(16);
}

// ---------------------------------------------------------------
// CRC32 (IEEE 802.3) —— init=0xFFFFFFFF, poly=0xEDB88320, xor=0xFFFFFFFF
// 输入：Uint8Array；输出：unsigned 32-bit CRC 值
// ---------------------------------------------------------------
var CRC32_TABLE = (function () {
    var t = new Uint32Array(256);
    for (var i = 0; i < 256; i++) {
        var c = i;
        for (var k = 0; k < 8; k++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        }
        t[i] = c >>> 0;
    }
    return t;
})();

function crc32(bytes) {
    var crc = 0xFFFFFFFF;
    for (var i = 0; i < bytes.length; i++) {
        crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ bytes[i]) & 0xFF];
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

function crc32OfBytes(bytes) {
    var u8 = (bytes instanceof Uint8Array)
        ? bytes
        : new Uint8Array(bytes.buffer || bytes);
    return crc32(u8);
}

function crc32Hex(bytes) {
    var v = crc32OfBytes(bytes);
    var s = '00000000' + v.toString(16);
    return '0x' + s.slice(s.length - 8);
}

function hexDumpFirstN(bytes, n) {
    var u8 = (bytes instanceof Uint8Array)
        ? bytes
        : new Uint8Array(bytes.buffer || bytes);
    var len = Math.min(n, u8.length);
    var parts = [];
    for (var i = 0; i < len; i++) {
        var s = u8[i].toString(16);
        parts.push(s.length === 1 ? '0' + s : s);
    }
    return parts.join(' ');
}

function callTarget(name, addr, invoke) {
    if (typeof invoke !== "function") {
        crclog("CALL-SKIP", name + " no safe call adapter; only byte comparison");
        return false;
    }
    try {
        var result = invoke(addr);
        crclog("CALL", name + " returned=" + String(result));
        return true;
    } catch (e) {
        crclog("CALL-ERR", name + " invoke failed: " + (e.message || e));
        return false;
    }
}

function captureCrc(addr, windows, baseline) {
    var results = {};
    var allOk = true;
    for (var i = 0; i < windows.length; i++) {
        var w = windows[i];
        var bytes = safeRead(addr, w);
        if (!bytes) {
            results[w] = null;
            allOk = false;
            continue;
        }
        var value = crc32OfBytes(bytes);
        results[w] = value;
        if (baseline[w] === null || value !== baseline[w]) allOk = false;
    }
    return { allOk: allOk, results: results };
}

function crcLine(name, windows, baseline, result, label, expectMatch) {
    var pieces = [];
    var passed = true;
    for (var i = 0; i < windows.length; i++) {
        var w = windows[i];
        var a = baseline[w];
        var b = result[w];
        var ok = a !== null && b !== null && (expectMatch ? b === a : b !== a);
        if (!ok) passed = false;
        pieces.push(w + "B:A=" + (a === null ? "ERR" : "0x" + ("00000000" + a.toString(16)).slice(-8)) +
            " " + label + "=" + (b === null ? "ERR" : "0x" + ("00000000" + b.toString(16)).slice(-8)) +
            " " + (ok ? "PASS" : "FAIL"));
    }
    crclog("COMPARE", name + " " + pieces.join(" | "));
    return passed;
}

function runSinglePhase(name, addr, invoke, baseline, windows) {
    var isNormal = crcPhase === "normal";
    var hookKind = isNormal ? Hook.NORMAL : Hook.WXSHADOW;
    var label = isNormal ? "NORMAL(B)" : "WXSHADOW(A)";
    var hits = 0;
    var installed = false;
    try {
        hook(addr, function () {
            hits++;
            return this.$orig ? this.$orig.apply(this, arguments) : undefined;
        }, hookKind);
        installed = true;
        if (isNormal) stats.normalHooksInstalled++;
        else stats.wxHooksInstalled++;
        crclog("HOOK", name + " " + label + " installed");
    } catch (e) {
        if (isNormal) stats.normalHooksFailed++;
        else stats.wxHooksFailed++;
        crclog("ERR", name + " " + label + " hook failed: " + (e.message || e));
    }
    var called = installed && callTarget(name, addr, invoke);
    var probe = captureCrc(addr, windows, baseline);
    var crcOk = installed && crcLine(name, windows, baseline, probe.results, label, !isNormal);
    // crcLine 的 crcOk 表示“满足当前阶段的期望”：NORMAL 阶段期望
    // B != A，WXSHADOW 阶段期望 A' == A。之前 NORMAL 分支把两种状态
    // 反写，导致每个窗口都 PASS 时仍打印 FAIL_NORMAL_UNCHANGED。
    var state = isNormal ? (crcOk ? "PASS_B_DIFF" : "FAIL_NORMAL_UNCHANGED") :
        (crcOk ? "PASS_WX_A_MATCH" : "FAIL_WX_A_CHANGED");
    crclog("PHASE", "phase=" + crcPhase + " method=" + name +
        " source_call=" + (called ? "yes" : "no") + " hook_hits=" + hits +
        " verdict=" + state);
    stats.perTarget[name] = {
        baseline: baseline, wxResults: isNormal ? {} : probe.results,
        normalResults: isNormal ? probe.results : {}, wxHits: isNormal ? 0 : hits,
        normalHits: isNormal ? hits : 0, phase: crcPhase, phaseVerdict: state
    };
    if (isNormal) stats.normalHits += hits;
    else stats.wxHits += hits;
    if (installed) {
        try { unhook(addr); } catch (e) {}
    }
}

// ---------------------------------------------------------------
// 安全读内存：失败返回 null（避免 readByteArray 抛错中断流程）
// ---------------------------------------------------------------
function safeRead(addr, size) {
    try {
        return new Uint8Array(Memory.readByteArray(addr, size));
    } catch (e) {
        return null;
    }
}

// ---------------------------------------------------------------
// 单个目标完整测试流程：
//   baseline —— 安装 WXSHADOW —— 验证 WXSHADOW + 命中 —— 安装 NORMAL —— 验证 NORMAL
// ---------------------------------------------------------------
function testTarget(name, addr, invoke) {
    stats.targetsConfigured++;
    crclog("BEGIN", name + " @ " + addr);

    if (!addr || (typeof addr.toString === 'function' && addr.toString() === '0x0')) {
        crclog("SKIP", name + ": address null/not-found");
        return;
    }

    // ---- baseline（精简版：只输出一行汇总，不再 6 行 BASE 输出） ----
    var windows = [4, 8, 16, 32, 64, 128];
    var baseline = {};
    var baselineStrs = [];
    for (var i = 0; i < windows.length; i++) {
        var w = windows[i];
        var bytes = safeRead(addr, w);
        if (!bytes) { baseline[w] = null; continue; }
        baseline[w] = crc32OfBytes(bytes);
        baselineStrs.push(w + ":" + crc32Hex(bytes));
    }
    crclog("BASE", name + " crc=" + baselineStrs.join("/"));

    // 任意一个 baseline 失败就别装了
    var anyBaseline = false;
    for (var j = 0; j < windows.length; j++) {
        if (baseline[windows[j]] !== null && baseline[windows[j]] !== undefined) {
            anyBaseline = true; break;
        }
    }
    if (!anyBaseline) {
        crclog("FAIL", name + ": no readable baseline, abort");
        return;
    }
    if (crcPhase !== "all") {
        runSinglePhase(name, addr, invoke, baseline, windows);
        return;
    }

    // ---- 安装 WXSHADOW ----
    var wxHitCount = 0;
    var wxInstalled = false;
    try {
        var wxCb = function (a0, a1, a2, a3, a4, a5, a6, a7) {
            wxHitCount++;
            return this.$orig
                ? this.$orig.apply(this, arguments)
                : undefined;
        };
        hook(addr, wxCb, Hook.WXSHADOW);
        wxInstalled = true;
        stats.wxHooksInstalled++;
        crclog("HOOK", name + " WXSHADOW installed (Hook.WXSHADOW=" + Hook.WXSHADOW + ")");
    } catch (e) {
        stats.wxHooksFailed++;
        crclog("ERR", name + " WXSHADOW hook() failed: " + (e.message || e));
    }

    if (!wxInstalled) {
        crclog("FAIL", name + ": WXSHADOW not installed — KPM/权限可能未配置，降级后续必失败");
    }

    // 立即采集 + 等极短窗口看 crc 变化
    var selfTries = 0;
    function probe(hitCount) {
        var wxResults = {};
        var wxAllOk = true;
        for (var k = 0; k < windows.length; k++) {
            var w = windows[k];
            var bytes = safeRead(addr, w);
            if (!bytes) {
                wxResults[w] = { readOk: false };
                wxAllOk = false;
                continue;
            }
            var nowCrc = crc32OfBytes(bytes);
            var baseCrc = baseline[w] !== null ? baseline[w] : null;
            var match = (baseCrc !== null) && (nowCrc === baseCrc);
            if (!match) wxAllOk = false;
            wxResults[w] = {
                readOk: true,
                crc: nowCrc,
                match: match,
                head: hexDumpFirstN(bytes, 16)
            };
        }
        return { allOk: wxAllOk, results: wxResults, hits: hitCount };
    }

    var calledWx = callTarget(name, addr, invoke);
    var probe1 = probe(wxHitCount);
    crclog("PROBE1",
           name + " source_call=" + (calledWx ? "yes" : "no") +
           " hits=" + probe1.hits + " crc_match=" + probe1.allOk +
           " windows=" + Object.keys(probe1.results)
               .map(function (w) {
                   var r = probe1.results[w];
                   return w + "B:" + (r.readOk ? (r.match ? "MATCH" : "DIFF") : "ERR");
               })
               .join("/"));

    stats.perTarget[name] = {
        baseline: {},
        wxResults: {},
        normalResults: {},
        wxHits: probe1.hits,
        normalHits: 0
    };
    for (var m = 0; m < windows.length; m++) {
        var bw = windows[m];
        // baseline 保存的是 CRC 数字；probe1.results 保存的是带 crc 字段的对象。
        // 之前把 baseline[bw] 当对象读取 `.crc`，会让汇总看不到基线值，
        // 并在 ART 目标缺少 normalResults 时把 Java.ready 回调打崩。
        if (baseline[bw] !== null && baseline[bw] !== undefined)
            stats.perTarget[name].baseline[bw] = baseline[bw];
        if (probe1.results[bw] && probe1.results[bw].crc !== undefined)
            stats.perTarget[name].wxResults[bw] = probe1.results[bw].crc;
    }

    // ---- 拆除 WXSHADOW ----
    try {
        unhook(addr);
        crclog("UNHOOK", name + " WXSHADOW released");
    } catch (e) {
        crclog("ERR", name + " unhook failed: " + (e.message || e));
    }

    // ---- 安装 NORMAL ----
    var normalHitCount = 0;
    var normalInstalled = false;
    try {
        var normalCb = function (a0, a1, a2, a3, a4, a5, a6, a7) {
            normalHitCount++;
            return this.$orig ? this.$orig.apply(this, arguments) : undefined;
        };
        hook(addr, normalCb, Hook.NORMAL);
        normalInstalled = true;
        stats.normalHooksInstalled++;
        crclog("HOOK", name + " NORMAL installed");
    } catch (e) {
        stats.normalHooksFailed++;
        crclog("ERR", name + " NORMAL hook() failed: " + (e.message || e));
    }

    if (normalInstalled) {
        var probe4 = probe(normalHitCount);
        crclog("PROBE2", name + " normal_hits=" + probe4.hits +
               " crc_match_vs_baseline=" + probe4.allOk);
        stats.normalHits += probe4.hits;
        for (var mmm = 0; mmm < windows.length; mmm++) {
            var w3 = windows[mmm];
            if (probe4.results[w3]) {
                stats.perTarget[name].normalResults[w3] = probe4.results[w3].crc;
            }
        }

        try {
            unhook(addr);
            crclog("UNHOOK", name + " NORMAL released");
        } catch (e) { /* ignore */ }
    }

    stats.perTarget[name].wxHits = wxHitCount;
    stats.perTarget[name].normalHits = normalHitCount;
    stats.wxHits += wxHitCount;
    stats.normalHits += normalHitCount;

    crclog("DONE", name + " wxHits=" + wxHitCount + " normalHits=" + normalHitCount);
}

// ---------------------------------------------------------------
// 选目标：libc + libart + libnativehelper，覆盖字节层 / ART 内部回测场景。
// ART 函数名直接用 mangled ABI（C++ Itanium ABI）——rustFrida 的 dlsym 不 demangle。
// ---------------------------------------------------------------
function resolveCandidates() {
    var candidates = [];
    var names = [
        // --- libc: 调用频次保证命中 ---
        { group: "libc", name: "openat",   want: ["openat", "__openat", "__openat_2"],
          invoke: function (a) {
              var fn = new NativeFunction(a, "int", ["int", "pointer", "int", "int"]);
              return fn(-1, Memory.allocUtf8String("/dev/null"), 0, 0);
          } },
        { group: "libc", name: "close",    want: ["close", "__close"],
          invoke: function (a) {
              return new NativeFunction(a, "int", ["int"])(-1);
          } },
        { group: "libc", name: "read",     want: ["read", "__read", "__read_2"],
          invoke: function (a) {
              return new NativeFunction(a, "long", ["int", "pointer", "ulong"])
                  (-1, Memory.alloc(8), 8);
          } },
        { group: "libc", name: "mmap",     want: ["mmap", "__mmap", "__mmap2"] },

        // --- libnativehelper: native 方法注册入口（抖音层 hook 重点）---
        { group: "nativehelper", name: "nh.jniRegisterNativeMethods", want: ["jniRegisterNativeMethods"] },

        // --- libart: ART 内部关键点（抖音对抗面）---
        // 1) 类遍历入口 —— 反注入检测常用它来扫所有加载的类
        { group: "libart",
          name: "art.ClassLinker::VisitClasses",
          want: ["_ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE"] },
        // 2) 动态类查找 —— JNI FindClass 路径
        { group: "libart",
          name: "art.ClassLinker::FindClassInBaseDexClassLoader",
          want: ["_ZN3art11ClassLinker29FindClassInBaseDexClassLoaderEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEEPNS_6ObjPtrINS6_5ClassEEE"] },
        // 3) ArtMethod::CopyFrom —— ART 自己修改 method 表时的入口（hook 这个点
        //    能拦截 ART 自身对 entry_point 的修改；CRC 骗过意味着 ART 不会察觉）
        { group: "libart",
          name: "art.ArtMethod::CopyFrom",
          want: ["_ZN3art9ArtMethod8CopyFromEPS0_NS_11PointerSizeE"] },
        // 4) SetEntryPointFromQuickCompiledCode —— ART 自己改 entry_point 的核心
        //    函数（如果连这个点都能骗过，等同于对 ART 自身的"我写我自己"完全隐身）
        { group: "libart",
          name: "art.ArtMethod::SetEntryPointFromQuickCompiledCode",
          want: ["_ZN3art9ArtMethod41SetEntryPointFromQuickCompiledCodePtrSizeEPKvNS_11PointerSizeE"] }
    ];

    for (var i = 0; i < names.length; i++) {
        var entry = names[i];
        var found = null;
        // 先按 module 限定（libart / libnativehelper），libc 用全 module 搜索
        var modules = entry.group === "libc"
            ? [null]
            : ["lib" + entry.group + ".so", entry.group + ".so"];
        for (var m = 0; m < modules.length && !found; m++) {
            for (var j = 0; j < entry.want.length; j++) {
                try {
                    var p = Module.findExportByName(modules[m], entry.want[j]);
                    if (p && !(typeof p.toInt32 === 'function' && p.toInt32() === 0)) {
                        found = { group: entry.group,
                                  name: entry.name + "(" + entry.want[j] + ")",
                                  addr: p, invoke: entry.invoke };
                        break;
                    }
                } catch (e) { /* try next */ }
            }
        }
        if (found) {
            candidates.push(found);
            crclog("FOUND", found.group + " :: " + found.name + " @ " + found.addr);
        } else {
            crclog("MISS", "[" + entry.group + "] " + entry.name +
                            " (tried " + modules.join("/") + " : " + entry.want.join(",") + ")");
        }
    }
    return candidates;
}

// ART 函数调用频次极低（VisitClasses/FindClass 只在类加载时跑）。
// 在 system_server 稳定运行期间基本不会被命中 —— 强行做 NORMAL 对照会浪费
// rustfrida 的 60s 单命令超时预算（9 target × 完整对照 = 超时）。
// ART 这几个点只验 base + WXSHADOW CRC 一致性已足够回答"骗过 ART 内部回测"。
function testArtTarget(name, addr) {
    crclog("BEGIN-ART", name + " @ " + addr);
    if (!addr || (typeof addr.toString === 'function' && addr.toString() === '0x0')) {
        crclog("SKIP", name + ": address null/not-found");
        return;
    }

    var windows = [4, 8, 16, 32, 64, 128];
    var baseline = {};
    var baseStrs = [];
    for (var i = 0; i < windows.length; i++) {
        var w = windows[i];
        var bytes = safeRead(addr, w);
        if (!bytes) { baseline[w] = null; continue; }
        baseline[w] = crc32OfBytes(bytes);
        baseStrs.push(w + ":" + crc32Hex(bytes));
    }
    crclog("BASE", name + " crc=" + baseStrs.join("/"));

    var installed = false;
    try {
        hook(addr, function () { return undefined; }, Hook.WXSHADOW);
        installed = true;
        stats.wxHooksInstalled++;
        crclog("HOOK", name + " WXSHADOW installed");
    } catch (e) {
        stats.wxHooksFailed++;
        crclog("ERR", name + " hook failed: " + (e.message || e));
    }

    var results = {};
    var allOk = true;
    for (var k = 0; k < windows.length; k++) {
        var w = windows[k];
        var bytes = safeRead(addr, w);
        if (!bytes) { results[w] = null; allOk = false; continue; }
        var nowCrc = crc32OfBytes(bytes);
        results[w] = nowCrc;
        if (nowCrc !== baseline[w]) allOk = false;
    }

    crclog("ART-RESULT", name + " crc_match=" + allOk +
           " windows=" + windows.map(function (w) {
               return w + "B:" + (results[w] === null ? "ERR" :
                       (results[w] === baseline[w] ? "MATCH" : "DIFF"));
           }).join("/"));

    stats.perTarget[name] = {
        group: "libart",
        baseline: baseline,
        wxResults: results,
        normalResults: {},
        wxHits: 0,
        normalHits: 0,
        crcOk: allOk
    };

    if (installed) {
        try { unhook(addr); } catch (e) {}
    }
}

function installAll() {
    try {
        var native = Java.use("com.rustfrida.compatdemo.Native");
        crcPhase = String(native.nativeCrcPhase()).toLowerCase().trim();
    } catch (_) {
        crcPhase = "all";
    }
    if (crcPhase !== "wx" && crcPhase !== "normal" && crcPhase !== "wx-restore")
        crcPhase = "all";
    crclog("PHASE", "selected=" + crcPhase +
        " 语义：A=未 hook 原始字节，B=NORMAL 改写字节，WXSHADOW 应恢复 A");
    // sanity check API surface
    var hooksReady =
        (typeof hook === 'function') &&
        (typeof unhook === 'function') &&
        (typeof Hook === 'object') &&
        (typeof Hook.WXSHADOW !== 'undefined') &&
        (typeof Hook.NORMAL !== 'undefined');

    if (!hooksReady) {
        crclog("FATAL",
               "hook/unhook/Hook.WXSHADOW/Hook.NORMAL not all available — " +
               "Hook.WXSHADOW=" + (typeof Hook !== 'undefined' ? Hook.WXSHADOW : "undef") +
               " Hook.NORMAL=" + (typeof Hook !== 'undefined' ? Hook.NORMAL : "undef") +
               " hook=" + (typeof hook) + " unhook=" + (typeof unhook));
        return;
    }
    crclog("API",
           "Hook.WXSHADOW=" + Hook.WXSHADOW +
           " Hook.NORMAL=" + Hook.NORMAL +
           " Hook.RECOMP=" + (typeof Hook.RECOMP !== 'undefined' ? Hook.RECOMP : "?"));

    var candidates = resolveCandidates();
    crclog("CFG", "candidates=" + candidates.length +
           " (windows 4/8/16/32/64/128) phase=" + crcPhase);

    // libc + libnativehelper（jniRegisterNativeMethods）走完整 WXSHADOW + NORMAL 对照
    // libart 走简化（WXSHADOW only）—— ART 函数调用频次太低，跑 NORMAL 对照浪费时间
    var libcCount = 0;
    var artCount = 0;
    for (var i = 0; i < candidates.length; i++) {
        var c = candidates[i];
        if (c.group === "libart") {
            if (crcPhase === "normal") {
                crclog("SKIP", c.name + " NORMAL(B) phase skipped for low-frequency ART method");
                continue;
            }
            testArtTarget(c.name, c.addr);
            artCount++;
        } else {
            // NORMAL 替换 libc 的 read/close/mmap 会拦截 RustFrida/QuickJS
            // 自身的控制通信、文件描述符和分配路径。之前即使跳过 read/mmap，
            // close 的全局 unhook 仍可能让 agent 失去响应。NORMAL 阶段只需
            // 一个稳定的 openat 目标证明 B != A；WX/WX-restore 仍保留全部
            // 目标的字节一致性检查，因此这里把其余 native 目标明确隔离。
            if (crcPhase === "normal" && c.name.indexOf("openat(") !== 0) {
                crclog("SKIP", c.name + " NORMAL(B) skipped to protect control/allocator path");
                continue;
            }
            testTarget(c.name, c.addr, c.invoke);
            libcCount++;
        }
    }
    crclog("SPLIT", "libc+nh=" + libcCount + " art=" + artCount);

    // === 最终汇总 ===
    var summary = [];
    var keys = Object.keys(stats.perTarget);
    for (var k = 0; k < keys.length; k++) {
        var key = keys[k];
        var t = stats.perTarget[key];
        var tBaseline = t.baseline || {};
        var tWxResults = t.wxResults || {};
        var tNormalResults = t.normalResults || {};
        var wxOk = 0, wxTotal = 0, normalDiff = 0, normalTotal = 0;
        var ws = [4, 8, 16, 32, 64, 128];
        for (var w = 0; w < ws.length; w++) {
            var ww = ws[w];
            if (tBaseline[ww] !== undefined && tBaseline[ww] !== null) {
                wxTotal++;
                if (tWxResults[ww] === tBaseline[ww]) wxOk++;
                normalTotal++;
                if (tNormalResults[ww] !== undefined &&
                    tNormalResults[ww] !== tBaseline[ww]) normalDiff++;
            }
        }
        summary.push({
            name: key,
            wxOk: wxOk, wxTotal: wxTotal,
            normalDiff: normalDiff, normalTotal: normalTotal,
            wxHits: t.wxHits, normalHits: t.normalHits || 0
        });
    }

    console.log("===== [CRC] WXSHADOW crc32 bypass verification summary =====");
    console.log("[CRC] " + JSON.stringify(summary));
    console.log("[CRC] wxHits=" + stats.wxHits +
                " normalHits=" + stats.normalHits +
                " wxInstalled=" + stats.wxHooksInstalled +
                "/" + stats.targetsConfigured +
                " wxFailed=" + stats.wxHooksFailed +
                " normalInstalled=" + stats.normalHooksInstalled +
                " normalFailed=" + stats.normalHooksFailed);

    // 总体结论
    // 关键结论：WXSHADOW 是否骗过 CRC32 检测 → 看 allOk+crc_match（每个目标 4/8/16/32/64/128B 全 MATCH）
    // 命中计数是 sanity bonus（自然调用可能本窗口内没触发，由 dmesg 的 read/exec fault 计数作旁证）
    var allWxCrc = summary.every(function (s) { return s.wxOk === s.wxTotal && s.wxTotal > 0; });
    var allNormalCrc = summary.every(function (s) { return s.normalDiff === s.normalTotal && s.normalTotal > 0; });
    var anyHits = summary.some(function (s) { return s.wxHits > 0; });
    var phasePass = crcPhase === "normal" ? allNormalCrc : allWxCrc;
    console.log("[CRC] === VERDICT ===");
    console.log("[CRC] A=baseline 原始；B=NORMAL 未开 WXSHADOW；A'=WXSHADOW 开启后");
    console.log("[CRC] WXSHADOW_crc32_bypass=" +
                (allWxCrc ? "PASS（A'=A，所有窗口一致）" : "FAIL（A' 与 A 有差异）") +
                " NORMAL_control=" +
                (allNormalCrc ? "PASS（B!=A，hook 确实改写）" : "FAIL（B 未变化，NORMAL 对照无效）") +
                " 命中旁证=" + (anyHits ? "有命中" : "无命中（仅字节对照）"));
    console.log("[CRC][PHASE_VERDICT] phase=" + crcPhase +
                " result=" + (phasePass ? "PASS" : "FAIL"));
}

if (typeof Java !== 'undefined' && Java && Java.ready) {
    Java.ready(function () { installAll(); });
} else {
    // 纯 native 路径，Java 不可用也照跑
    try { installAll(); } catch (e) {
        crclog("FATAL", "installAll exception: " + (e.stack || e.message || e));
    }
}
