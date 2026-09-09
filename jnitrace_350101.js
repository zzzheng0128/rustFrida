// Douyin 350101 MetaSec probe — jnitrace.
// Pure Frida 17 standalone script.
// Load: frida -U -f com.ss.android.ugc.aweme -l jnitrace_350101.js

// ===== mode: jnitrace / JNI 环境补洞 =====
// 历史来源：metasec_jnitrace_spawn_early_wxshadow_lite.js
// 什么时候用：unidbg 缺 MS.b、NewString、FindClass、GetMethodID 等返回时，用真机 JNI 日志补 stub。
// ============================================================

function __dyidre_mode_jnitrace() {
// Light early JNI baseline for libmetasec_ml.so.
//
// Goal:
//   - spawn pre-resume install
//   - WXSHADOW stealth patch for native JNI hook sites
//   - log only baseline-useful metasec events, not every hot JNI call

var TARGET_MODULE = "libmetasec_ml.so";
var STEALTH = (typeof Hook !== "undefined" && Hook.WXSHADOW !== undefined) ? Hook.WXSHADOW : 1;

var classMap = {};
var methodMap = {};
var traceInstalled = false;
var slotSpecs = [];
var hookedAddrs = {};
var envTableExpanded = false;
var libartBase = null;
var seenMethodKeys = {};
var seenStringKeys = {};
var lastReqCostMs = "?";
var reqSeq = 0;
var reqSuppressed = 0;
var reqStats = {};
var reqLastSummaryMs = 0;

// Keep the baseline usable without turning RF/adb into a firehose.
var STRING_MAX = 260;
var REQ_MAX_PER_ENDPOINT = 2;
var REQ_MIN_REPEAT_MS = 30000;
var REQ_SUMMARY_MS = 30000;

// Pixel 6 / Android 15 / libart.so offsets observed on this device.
var FIXED_JNI_OFFSETS = {
    FindClass: 0x73a520,
    GetStaticMethodID: 0x6189bc,
    CallStaticObjectMethodV: 0x43b038,
    CallStaticObjectMethodA: 0x51efa0,
    NewStringUTF: 0x8ace98,
    GetStringUTFChars: 0x737de4,
    RegisterNatives: 0x615b78
};

function now() {
    return String(Date.now());
}

function emit(s) {
    console.log("[metasec-jni-wxshadow-lite] " + now() + " " + s);
}

try {
    Java.setStealth(Hook.WXSHADOW);
    emit("Java.setStealth(WXSHADOW) ok, native stealth=" + STEALTH);
} catch (e) {
    emit("Java.setStealth(WXSHADOW) failed: " + e + ", native stealth=" + STEALTH);
}

function safePtr(v) {
    try {
        return ptr(v);
    } catch (e) {
        return ptr(0);
    }
}

function isNull(p) {
    return p === null || p === undefined || safePtr(p).toString() === "0x0";
}

function key(p) {
    return safePtr(p).toString();
}

function safeCString(p) {
    try {
        if (isNull(p)) {
            return null;
        }
        return safePtr(p).readCString();
    } catch (e) {
        return "<cstring:" + e + ">";
    }
}

function retAddr(ctx) {
    if (ctx.returnAddress !== undefined) return safePtr(ctx.returnAddress);
    if (ctx.lr !== undefined) return safePtr(ctx.lr);
    if (ctx.x30 !== undefined) return safePtr(ctx.x30);
    return ptr(0);
}

function targetCaller(ctx) {
    var ra = retAddr(ctx);
    if (isNull(ra)) return null;
    var m = null;
    try {
        m = Module.findByAddress(ra);
    } catch (e) {
        m = null;
    }
    if (m === null || m.name.indexOf(TARGET_MODULE) < 0) return null;
    return { module: m, ra: ra, off: ra.sub(m.base) };
}

function classDisplay(clazz) {
    var k = key(clazz);
    return classMap[k] || ("<class " + k + ">");
}

function isBridgeSig(sig) {
    return sig === "(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;";
}

function rememberMethod(clazz, mid, name, sig, info) {
    if (isNull(mid)) return;
    var rec = {
        cls: classDisplay(clazz),
        name: name || "<name?>",
        sig: sig || "<sig?>"
    };
    methodMap[key(mid)] = rec;
    var methodKey = rec.name + rec.sig;
    if ((rec.cls.indexOf("metasec") >= 0 || isBridgeSig(rec.sig) || rec.name === "valueOf") &&
        !seenMethodKeys[methodKey]) {
        seenMethodKeys[methodKey] = true;
        emit(info.off + " GetStaticMethodID " + rec.cls + "->" + rec.name + rec.sig + " = " + key(mid));
    }
}

function formatMethod(mid) {
    var rec = methodMap[key(mid)];
    if (rec === undefined) return "<method " + key(mid) + ">";
    return rec.cls + "->" + rec.name + rec.sig;
}

function shouldLogStaticCall(mid) {
    var rec = methodMap[key(mid)];
    if (rec === undefined) return false;
    if (rec.cls.indexOf("com/bytedance/mobsec/metasec/ml/MS") >= 0 && isBridgeSig(rec.sig)) return true;
    if ((rec.name === "a" || rec.name === "b") && isBridgeSig(rec.sig)) return true;
    return false;
}

function interestingString(v) {
    if (v === null) return false;
    if (v === "utf-8") return false;
    if (v === "{}") return false;
    if (v === "\\|") return false;
    if (v === ";" || v === "r") return false;
    return v.indexOf("http_reqsign") >= 0 ||
        v.indexOf("consume_ML_DoHttpReqSignIT") >= 0 ||
        v.indexOf("ApiAndParams") >= 0 ||
        v.indexOf("mssdk.bytedance.com") >= 0 ||
        v.indexOf("sdk_ver=") >= 0 ||
        v.indexOf("v04.09.05") >= 0;
}

function shouldLogString(v) {
    if (!interestingString(v)) return false;
    if (v.indexOf("ApiAndParams") >= 0 || v.indexOf("consume_ML_DoHttpReqSignIT") >= 0) {
        return true;
    }
    if (seenStringKeys[v]) return false;
    seenStringKeys[v] = true;
    return true;
}

function shortString(v) {
    if (v === null) return "null";
    if (v.length > STRING_MAX) return v.substring(0, STRING_MAX) + "...<len=" + v.length + ">";
    return v;
}

function hash32(s) {
    var h = 2166136261 >>> 0;
    for (var i = 0; i < s.length; i++) {
        h ^= s.charCodeAt(i);
        h = Math.imul(h, 16777619) >>> 0;
    }
    return ("00000000" + h.toString(16)).slice(-8);
}

function extractApiUrl(v) {
    var s = String(v);
    var m = /\"ApiAndParams\"\s*:\s*\"([\s\S]*?)\"\s*\}/.exec(s);
    if (m) return m[1];
    return s;
}

function parseUrlLite(url) {
    var s = String(url).replace(/\\\//g, "/");
    var m = /^(https?:\/\/)?([^\/\?\s]+)([^\?\s]*)(?:\?([^\s#]*))?/.exec(s);
    if (!m) {
        return {
            key: shortString(s),
            host: "<raw>",
            path: "",
            qs: "",
            raw: s
        };
    }
    return {
        key: m[2] + m[3],
        host: m[2],
        path: m[3] || "/",
        qs: m[4] || "",
        raw: s
    };
}

function pickQuery(qs) {
    if (!qs) return "";
    var keep = {
        aid: true,
        version_code: true,
        version_name: true,
        manifest_version_code: true,
        update_version_code: true,
        sdk_ver: true,
        sdk_ver_code: true,
        app_ver: true,
        lc_id: true,
        mode: true,
        region_type: true,
        ts: true,
        _rticket: true
    };
    var parts = qs.split("&");
    var out = [];
    for (var i = 0; i < parts.length; i++) {
        var kv = parts[i].split("=", 1)[0];
        if (keep[kv]) out.push(parts[i]);
        if (out.length >= 10) break;
    }
    return out.join("&");
}

function emitReqSummary(force) {
    var t = Date.now();
    if (!force && t - reqLastSummaryMs < REQ_SUMMARY_MS) return;
    reqLastSummaryMs = t;
    var keys = Object.keys(reqStats);
    keys.sort(function (a, b) {
        return reqStats[b].count - reqStats[a].count;
    });
    var top = [];
    for (var i = 0; i < keys.length && i < 5; i++) {
        top.push(keys[i] + "=" + reqStats[keys[i]].count);
    }
    emit("REQ_SUMMARY total=" + reqSeq + " unique=" + keys.length +
        " suppressed=" + reqSuppressed + " top=" + top.join(","));
}

function logApiAndParams(off, v, source) {
    var url = extractApiUrl(v);
    var u = parseUrlLite(url);
    reqSeq++;

    var r = reqStats[u.key];
    if (r === undefined) {
        r = { count: 0, lastEmit: 0 };
        reqStats[u.key] = r;
    }
    r.count++;

    var t = Date.now();
    var shouldEmit = r.count <= REQ_MAX_PER_ENDPOINT || (t - r.lastEmit) >= REQ_MIN_REPEAT_MS;
    if (!shouldEmit) {
        reqSuppressed++;
        emitReqSummary(false);
        return;
    }

    r.lastEmit = t;
    var picked = pickQuery(u.qs);
    emit(off + " REQ#" + reqSeq + " cost_ms=" + lastReqCostMs +
        " src=" + source +
        " host=" + u.host +
        " path=" + u.path +
        (picked ? " qs=" + shortString(picked) : "") +
        " len=" + url.length +
        " h=" + hash32(url));
}

function getLibartBase() {
    if (libartBase !== null) return libartBase;
    try {
        libartBase = Module.findBaseAddress("libart.so");
    } catch (e) {
        libartBase = null;
    }
    if (libartBase === null || libartBase === undefined || safePtr(libartBase).toString() === "0x0") {
        emit("libart base not found");
        return null;
    }
    emit("libart.so base=" + libartBase);
    return libartBase;
}

function fixedJniAddress(name) {
    if (!Object.prototype.hasOwnProperty.call(FIXED_JNI_OFFSETS, name)) return null;
    var base = getLibartBase();
    if (base === null) return null;
    return safePtr(base).add(FIXED_JNI_OFFSETS[name]);
}

function attachSlot(name, index, callbacks, addr, source) {
    if (addr === null || addr === undefined || safePtr(addr).toString() === "0x0") return false;
    var k = safePtr(addr).toString();
    if (hookedAddrs[k]) return true;
    try {
        Interceptor.attach(addr, callbacks, STEALTH);
        hookedAddrs[k] = true;
        emit("hook " + name + "[" + index + "] @ " + addr + " via " + source + " stealth=WXSHADOW");
        return true;
    } catch (e) {
        emit("hook " + name + "[" + index + "] @ " + addr + " failed via " + source + ": " + e);
        return false;
    }
}

function expandSlotsFromEnv(env) {
    if (envTableExpanded || isNull(env)) return;
    envTableExpanded = true;
    try {
        var table = safePtr(env).readPointer();
        emit("expand JNI table from env=" + key(env) + " table=" + key(table));
        for (var i = 0; i < slotSpecs.length; i++) {
            var s = slotSpecs[i];
            var addr = table.add(s.index * 8).readPointer();
            attachSlot(s.name, s.index, s.callbacks, addr, "env-table");
        }
    } catch (e) {
        emit("expand JNI table failed: " + e);
    }
}

function hookSlot(name, index, callbacks) {
    slotSpecs.push({ name: name, index: index, callbacks: callbacks });
    attachSlot(name, index, callbacks, fixedJniAddress(name), "fixed-libart-offset");
}

function installTrace() {
    if (traceInstalled) return;
    traceInstalled = true;
    emit("install target=" + TARGET_MODULE);

    hookSlot("FindClass", 6, {
        onEnter: function (args) {
            expandSlotsFromEnv(args[0]);
            var info = targetCaller(this);
            if (info === null) return;
            this.trace = info;
            this.name = safeCString(args[1]);
        },
        onLeave: function (retval) {
            if (this.trace === undefined) return;
            if (!isNull(retval) && this.name !== null) classMap[key(retval)] = this.name;
            if (String(this.name).indexOf("metasec") >= 0 ||
                String(this.name).indexOf("ms/bd") >= 0 ||
                String(this.name).indexOf("java/lang/Integer") >= 0 ||
                String(this.name).indexOf("java/lang/Long") >= 0 ||
                String(this.name).indexOf("java/lang/Boolean") >= 0) {
                emit(this.trace.off + " FindClass \"" + String(this.name) + "\" => " + key(retval));
            }
        }
    });

    // hookSlot("GetStaticMethodID", 113, {
    //     onEnter: function (args) {
    //         expandSlotsFromEnv(args[0]);
    //         var info = targetCaller(this);
    //         if (info === null) return;
    //         this.trace = info;
    //         this.clazz = args[1];
    //         this.name = safeCString(args[2]);
    //         this.sig = safeCString(args[3]);
    //     },
    //     onLeave: function (retval) {
    //         if (this.trace === undefined) return;
    //         rememberMethod(this.clazz, retval, this.name, this.sig, this.trace);
    //     }
    // });

    hookSlot("RegisterNatives", 215, {
        onEnter: function (args) {
            expandSlotsFromEnv(args[0]);
            var info = targetCaller(this);
            if (info === null) return;
            this.trace = info;
            this.clazz = args[1];
            this.methods = args[2];
            this.count = 0;
            try {
                if (args.length > 3 && args[3] !== undefined) {
                    this.count = args[3].toInt32();
                } else if (this.context !== undefined && this.context.x3 !== undefined) {
                    this.count = safePtr(this.context.x3).toInt32();
                }
            } catch (e) {
                this.count = 0;
            }
        },
        onLeave: function () {
            if (this.trace === undefined) return;
            emit(this.trace.off + " RegisterNatives " + classDisplay(this.clazz) + " count=" + this.count);
            for (var i = 0; i < this.count; i++) {
                try {
                    var ent = safePtr(this.methods).add(i * 24);
                    var name = safeCString(ent.readPointer());
                    var sig = safeCString(ent.add(8).readPointer());
                    var fn = ent.add(16).readPointer();
                    var mod = Module.findByAddress(fn);
                    var where = key(fn);
                    if (mod !== null) where = mod.name + "+" + fn.sub(mod.base);
                    emit("  native " + name + " " + sig + " -> " + where);
                } catch (e) {
                    emit("  native[" + i + "] decode failed: " + e);
                }
            }
        }
    });

    // hookSlot("NewStringUTF", 167, {
    //     onEnter: function (args) {
    //         expandSlotsFromEnv(args[0]);
    //         var info = targetCaller(this);
    //         if (info === null) return;
    //         var v = safeCString(args[1]);
    //         if (!shouldLogString(v)) return;
    //         this.trace = info;
    //         this.value = v;
    //     },
    //     onLeave: function () {
    //         if (this.trace === undefined) return;
    //         var v = String(this.value);
    //         if (v.indexOf("consume_ML_DoHttpReqSignIT") >= 0) {
    //             var cm = /consume_ML_DoHttpReqSignIT\"\s*:\s*(\d+)/.exec(v);
    //             lastReqCostMs = cm ? cm[1] : "?";
    //             return;
    //         }
    //         if (v.indexOf("ApiAndParams") >= 0) {
    //             logApiAndParams(this.trace.off, v, "NewStringUTF");
    //             return;
    //         }
    //         emit(this.trace.off + " NewStringUTF \"" + shortString(v) + "\"");
    //     }
    // });

    // hookSlot("GetStringUTFChars", 169, {
    //     onEnter: function (args) {
    //         expandSlotsFromEnv(args[0]);
    //         var info = targetCaller(this);
    //         if (info === null) return;
    //         this.trace = info;
    //         this.jstr = args[1];
    //     },
    //     onLeave: function (retval) {
    //         if (this.trace === undefined || isNull(retval)) return;
    //         var v = safeCString(retval);
    //         if (!interestingString(v)) return;
    //         if (String(v).indexOf("consume_ML_DoHttpReqSignIT") >= 0) {
    //             var cm = /consume_ML_DoHttpReqSignIT\"\s*:\s*(\d+)/.exec(String(v));
    //             lastReqCostMs = cm ? cm[1] : lastReqCostMs;
    //             return;
    //         }
    //         if (String(v).indexOf("ApiAndParams") >= 0) {
    //             logApiAndParams(this.trace.off, v, "GetStringUTFChars");
    //             return;
    //         }
    //         if (shouldLogString(v)) {
    //             emit(this.trace.off + " GetStringUTFChars jstr=" + key(this.jstr) + " -> \"" + shortString(String(v)) + "\"");
    //         }
    //     }
    // });

    emit("installed");
}

installTrace();

}



(function () {
    console.log("[metasec-jnitrace] standalone loaded (Frida 17)");
    __dyidre_mode_jnitrace();


    Java.ready(function() {
        var Log = Java.use("android.util.Log");

        Log.i.overload("java.lang.String", "java.lang.String").impl = function(tag, msg) {
            console.log("[Log.i]", tag, msg);
            return this.$orig(tag, msg);
        };
    });

})();

