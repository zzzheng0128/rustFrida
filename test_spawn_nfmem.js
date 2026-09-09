/*
 * test_spawn_nfmem.js — NativeFunction / Interceptor.replace / Memory 读写（rustfrida QuickJS 引擎）
 *
 * 三组 API 冒烟测试，spawn/attach 均可跑（不依赖业务模块加载）：
 *   A. NativeFunction：getpid/strlen/abs/snprintf 调用与返回值解析
 *   B. Interceptor.replace：替换 getpid 为 JS 实现，验证调用被路由到 JS；detachAll 还原
 *   C. Memory 读写：writeU64/readU64、writeU32/readU32、writePointer/readPointer、
 *      allocUtf8String/readCString、Memory.protect
 * 运行：
 *   adb push test_spawn_nfmem.js /data/local/tmp/
 *   su -c '(sleep 20; echo exit) | timeout 40 /data/local/tmp/rustfrida --spawn <包名> -l /data/local/tmp/test_spawn_nfmem.js'
 */
(function () {
    "use strict";
    var TAG = "nfmem";
    function log(m) { console.log("[" + TAG + "] " + m); }
    var pass = 0, fail = 0;
    function check(name, cond, detail) {
        if (cond) { pass++; log("PASS " + name + (detail ? " (" + detail + ")" : "")); }
        else { fail++; log("FAIL " + name + (detail ? " (" + detail + ")" : "")); }
    }
    function isNullPtr(p) {
        if (p === null || p === undefined) return true;
        if (typeof p === "bigint") return p === BigInt(0);
        if (typeof p === "number") return p === 0;
        try { return p.isNull(); } catch (_) { return false; }
    }
    function nf(name, ret, args) {
        var p = null;
        try { p = Module.findExportByName(null, name); } catch (e) {}
        if (isNullPtr(p)) return null;
        return new NativeFunction(p, ret, args);
    }
    function exportOf(name) {
        var p = null;
        try { p = Module.findExportByName(null, name); } catch (e) {}
        return p;
    }

    // ================= A. NativeFunction =================
    try {
        var getpid = nf("getpid", "int", []);
        var pid = getpid();
        check("NF getpid", pid > 0 && pid < 0x100000, "pid=" + pid);

        var strlen = nf("strlen", "ulong", ["pointer"]);
        var s = Memory.allocUtf8String("hello rustfrida");
        check("NF strlen", Number(strlen(s)) === 15);

        var absFn = nf("abs", "int", ["int"]);
        check("NF abs", absFn(-42) === 42);

        var snprintf = nf("snprintf", "int", ["pointer", "ulong", "pointer", "int", "pointer"]);
        var buf = Memory.alloc(64);
        var arg = Memory.allocUtf8String("abc");
        var n = snprintf(buf, 64, Memory.allocUtf8String("pid=%d str=%s"), 1234, arg);
        var out = buf.readCString();
        check("NF snprintf", out === "pid=1234 str=abc", "ret=" + n + " out='" + out + "'");
    } catch (e) {
        fail++; log("FAIL NF 组异常: " + e);
    }

    // ================= B. Interceptor.replace =================
    try {
        var getpidAddr = exportOf("getpid");
        var realGetpid = new NativeFunction(getpidAddr, "int", []);
        var realPid = realGetpid();
        var replaceHits = 0;
        Interceptor.replace(getpidAddr, function () {
            replaceHits += 1;
            return 114514; // JS 实现直接替代原函数
        });
        var fakePid = realGetpid();
        check("replace 生效", fakePid === 114514, "fake=" + fakePid + " hits=" + replaceHits);
        Interceptor.detachAll();
        var restoredPid = realGetpid();
        check("detachAll 还原", restoredPid === realPid, "restored=" + restoredPid);
    } catch (e) {
        fail++; log("FAIL replace 组异常: " + e);
    }

    // ================= C. Memory 读写 =================
    try {
        var m = Memory.alloc(16);
        m.writeU64(BigInt("0x1122334455667788"));
        var v64 = m.readU64();
        check("MEM u64", v64.toString(16) === "1122334455667788", "got=0x" + v64.toString(16));

        m.writeU32(0xdeadbeef);
        // 注意：readU32 返回 bigint，不能用 >>>（QuickJS 禁止 bigint 位运算），用 BigInt 比较
        check("MEM u32", m.readU32() === BigInt(0xdeadbeef), "got=0x" + m.readU32().toString(16));

        m.add(8).writeU8(0x5a);
        check("MEM u8", m.add(8).readU8() === 0x5a);

        var str = Memory.allocUtf8String("指针往返");
        var slot = Memory.alloc(8);
        slot.writePointer(str);
        var back = slot.readPointer();
        check("MEM pointer", back.readCString() === "指针往返", "read='" + back.readCString() + "'");

        var before = null;
        try { before = m.readU8(); } catch (_) {}
        Memory.protect(m, 4096, "rwx");
        check("MEM protect", m.readU8() === before, "protect 后读一致");

        // 目标代码页读写（只读映射上写会崩，引擎应自行 mprotect）：读 exeVMInner 序言首字节
        var art = null;
        try { art = Process.getModuleByName("libc.so"); } catch (_) {}
        if (art !== null) {
            var prologue = art.base.add(0x1000).readU8();
            check("MEM 读代码页", prologue >= 0 && prologue <= 255, "byte=0x" + prologue.toString(16));
        }
    } catch (e) {
        fail++; log("FAIL Memory 组异常: " + e);
    }

    log("done: pass=" + pass + " fail=" + fail);
})();
