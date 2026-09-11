// mkpm_ctl.js —— rustFrida 侧控制合并版 mkpm.kpm 的开关
//
// 用法:
//   rustfrida --pid <pid> -l mkpm_ctl.js            (任何带 Java 的进程, 如 me.bmax.apatch)
//   脚本内底部 MAIN 流程按需注释/取消注释, 或改 CMDS 列表批量下发。
//
// ctl0 通道: kpatch su kpm control mkpm "<cmd>"
// 子系统: hide / wxshadow / syscall / ehide / eredirect / evm / emaps / status

'use strict';

var KPATCH = "/data/data/me.bmax.apatch/patch/kpatch";
var MKPM_NAME = "mkpm";
var MKPM_PATH = "/data/local/tmp/mkpm.kpm";

function log(m) { console.log("[mkpm-ctl] " + m); }

Java.perform(function () {
    var Runtime = Java.use("java.lang.Runtime");
    var runtime = Runtime.getRuntime();
    var InputStreamReader = Java.use("java.io.InputStreamReader");
    var BufferedReader = Java.use("java.io.BufferedReader");

    function exec(cmdArray) {
        try {
            var proc = runtime.exec(cmdArray);
            var reader = BufferedReader.$new(InputStreamReader.$new(proc.getInputStream()));
            var errReader = BufferedReader.$new(InputStreamReader.$new(proc.getErrorStream()));
            var out = "", err = "", line;
            while ((line = reader.readLine()) !== null) out += line + "\n";
            reader.close();
            while ((line = errReader.readLine()) !== null) err += line + "\n";
            errReader.close();
            proc.waitFor();
            return { ok: proc.exitValue() === 0, out: out, err: err, code: proc.exitValue() };
        } catch (e) {
            return { ok: false, out: "", err: "" + e, code: -1 };
        }
    }

    function sh(cmdline) {
        return exec(["su", "-c", cmdline]);
    }

    // ---- mkpm ctl0 原语 ----
    function ctl(cmd) {
        var r = sh(KPATCH + " su kpm control " + MKPM_NAME + " \"" + cmd + "\"");
        var text = (r.out || "").trim();
        log("ctl \"" + cmd + "\" -> exit=" + r.code + (text ? " " + text.replace(/\n/g, " | ") : "") +
            (r.err && r.err.trim() ? " err=" + r.err.trim() : ""));
        return r;
    }

    // ---- 模块管理 ----
    function kpmLoad() {
        var r = sh(KPATCH + " su kpm load " + MKPM_PATH);
        log("load -> exit=" + r.code + " out=" + r.out.trim() + " err=" + r.err.trim());
        return r;
    }
    function kpmUnload() {
        var r = sh(KPATCH + " su kpm unload " + MKPM_NAME);
        log("unload -> exit=" + r.code + " out=" + r.out.trim());
        return r;
    }
    function kpmList() {
        var r = sh(KPATCH + " su kpm list");
        log("list -> " + r.out.trim());
        return r;
    }

    // ---- 便捷开关: hide-so ----
    var hide = {
        status:   function () { return ctl("hide status"); },
        on:       function () { return ctl("hide enable"); },
        off:      function () { return ctl("hide disable"); },
        mapsOn:   function () { return ctl("hide enable maps"); },
        mapsOff:  function () { return ctl("hide disable maps"); },
        thrOn:    function () { return ctl("hide enable threads"); },
        thrOff:   function () { return ctl("hide disable threads"); },
        tokenAdd: function (t) { return ctl("hide token add " + t); },
        tokenDel: function (t) { return ctl("hide token del " + t); },
        tokenList:function () { return ctl("hide token list"); },
        prefixSet:function (p) { return ctl("hide prefix set " + p); },
        rangeList:function () { return ctl("hide range list"); },
        rangeClear:function () { return ctl("hide range clear"); },
    };

    // ---- 便捷开关: sysmon (syscall) ----
    var sys = {
        presetIo: function () { return ctl("syscall preset io"); },
        start:    function () { return ctl("syscall start"); },
        stop:     function () { return ctl("syscall stop"); },
        clear:    function () { return ctl("syscall clear"); },
        status:   function () { return ctl("syscall status"); },
        attach:   function (nr, narg) { return ctl("syscall attach " + nr + " " + narg); },
        detachAll:function () { return ctl("syscall detach-all"); },
        filterUid:function (uid) { return ctl("syscall filter uid " + uid); },
        filterTgid:function (pid) { return ctl("syscall filter tgid " + pid); },
        filterClear:function () { return ctl("syscall filter clear"); },
        pathOn:   function () { return ctl("syscall path on"); },
        read:     function (after, max) { return ctl("syscall read " + (after || 0) + " " + (max || 8)); },
    };

    // ================= MAIN: 按需编辑 =================
    kpmList();

    // 首次部署: 加载合并 KPM (hide-so + wxshadow 默认开)
    // kpmUnload();            // 先卸旧版
    // kpmLoad();

    // 状态巡检
    ctl("status");
    hide.status();

    // sysmon 冒烟: 挂上 io 全家桶 -> 开始 -> 让 compat-demo 的 nativeKpmProbe 跑一遍
    // -> 读事件。openat/openat2/read/write/connect/sendto/recvfrom 都应出现。
    sys.presetIo();
    sys.pathOn();
    sys.start();
    log(">>> 现在去 compat-demo app 里点 KPM probe (nativeKpmProbe), 然后继续");
    sys.read(0, 8);

    // hide-so 开关验证: 在 compat-demo 中对照 maps 是否出现/隐藏; 再开
    // hide.mapsOff();
    // hide.mapsOn();

    log("done");
});
