/*
 * JS 侧 KPM 控制模板（直接 supercall 版本）。
 *
 * 调用链：QuickJS -> libc.syscall(45) -> APatch/KernelPatch -> mkpm ctl0
 *
 * 这个版本不启动 su，也不执行 kpctl。这样脚本可以在 spawn 的 raw-clone
 * 线程中立即运行，不依赖应用的 PATH、mount namespace 或 Java worker。
 * KPM 必须先由主机上的 kpctl 加载，目标 UID 也必须被 APatch 允许调用
 * supercall；否则返回负 errno（通常是 -EPERM）。
 *
 * 适用：低频状态检查、实验开关、验证控制面。不要在 HWBP/uprobe 高频
 * 回调中同步调用 control()，因为一次 supercall 仍可能阻塞；严格时序请
 * 由主机脚本发送 kpctl 命令。
 *
 * 运行示例：
 *   rustfrida --pid <pid> -l /data/local/tmp/13_kpm_control.js
 *   rustfrida --spawn com.rustfrida.compatdemo --mode=inject \
 *       -l /data/local/tmp/13_kpm_control.js
 *
 * JS 中可调用：
 *   Kpm.status();
 *   Kpm.control("hide status");
 *   Kpm.control("syscall preset io");
 *   Kpm.boot.uid(10283);
 */
(function () {
    "use strict";

    var TAG = "kpm-js";
    var SUPERKEY = "amigo123"; // 与设备上的 APatch superkey 一致
    var MODULE = "mkpm";
    var NR_SUPERCALL = 45;      // Android arm64 上 KP 使用的 syscall 编号
    var KP_VERSION = 0x0d08;    // 0.13.8，需与设备 APatch/KP 版本同步
    var KP_MAGIC = 0x1158;
    var OUT_SIZE = 4096;

    // scdefs.h 中的命令号；只放模板实际用到的控制面。
    var CMD_HELLO = 0x1000;
    var CMD_KPM_CONTROL = 0x1022;
    var CMD_KPM_NUMS = 0x1030;
    var CMD_KPM_LIST = 0x1031;
    var CMD_KPM_INFO = 0x1032;

    function log(message) { console.log("[" + TAG + "] " + message); }

    function initSupercall() {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) throw new Error("libc.so is not loaded");
        var syscallAddress = libc.getExportByName("syscall");
        if (!syscallAddress) throw new Error("libc syscall() export not found");

        // syscall() 是 C 可变参数函数；这里按每个 KPM 原语声明固定的
        // arm64 参数个数。NativeFunction 会按 ABI 传递这些指针和整数。
        return {
            libc: libc,
            hello: new NativeFunction(syscallAddress, "long",
                ["int", "pointer", "long"]),
            list: new NativeFunction(syscallAddress, "long",
                ["int", "pointer", "long", "pointer", "int"]),
            nums: new NativeFunction(syscallAddress, "long",
                ["int", "pointer", "long"]),
            info: new NativeFunction(syscallAddress, "long",
                ["int", "pointer", "long", "pointer", "pointer", "int"]),
            control: new NativeFunction(syscallAddress, "long",
                ["int", "pointer", "long", "pointer", "pointer", "pointer", "int"])
        };
    }

    // ver_and_cmd = (version_code << 32) | (0x1158 << 16) | command。
    // 当前版本值低于 2^53，转换为 Number 不会丢失位；NativeFunction 的
    // long 参数在 arm64 上按 64 位寄存器传递。
    function verAndCmd(command) {
        return Number((BigInt(KP_VERSION) * 0x100000000n) |
            (BigInt(KP_MAGIC) * 0x10000n) | BigInt(command & 0xffff));
    }

    function keyBuffer() { return Memory.allocUtf8String(SUPERKEY); }

    function readBuffer(buffer) {
        try { return Memory.readUtf8String(buffer) || ""; }
        catch (_) { return ""; }
    }

    function compact(text) {
        return String(text || "").trim().split("\n").join(" | ");
    }

    var sc;

    function result(label, rc, out) {
        var line = label + " -> rc=" + String(rc);
        if (out) line += " out=" + compact(out);
        if (Number(rc) < 0) line += " (负 errno；检查 superkey、UID 授权和 KP_VERSION)";
        log(line);
        return { ok: Number(rc) >= 0, code: Number(rc), out: String(out || "") };
    }

    function hello() {
        var rc = sc.hello(NR_SUPERCALL, keyBuffer(), verAndCmd(CMD_HELLO));
        return result("hello", rc, "");
    }

    function list() {
        var buffer = Memory.alloc(OUT_SIZE);
        Memory.writeU8(buffer, 0);
        var rc = sc.list(NR_SUPERCALL, keyBuffer(), verAndCmd(CMD_KPM_LIST),
            buffer, OUT_SIZE);
        return result("list", rc, readBuffer(buffer));
    }

    function nums() {
        var rc = sc.nums(NR_SUPERCALL, keyBuffer(), verAndCmd(CMD_KPM_NUMS));
        return result("nums", rc, "");
    }

    function info(name) {
        var buffer = Memory.alloc(OUT_SIZE);
        Memory.writeU8(buffer, 0);
        var nameBuffer = Memory.allocUtf8String(String(name || MODULE));
        var rc = sc.info(NR_SUPERCALL, keyBuffer(), verAndCmd(CMD_KPM_INFO),
            nameBuffer, buffer, OUT_SIZE);
        return result("info " + String(name || MODULE), rc, readBuffer(buffer));
    }

    function control(command) {
        var commandText = String(command || "").trim();
        if (!commandText) return result("control", -22, "empty command");
        var nameBuffer = Memory.allocUtf8String(MODULE);
        var commandBuffer = Memory.allocUtf8String(commandText);
        var outputBuffer = Memory.alloc(OUT_SIZE);
        Memory.writeU8(outputBuffer, 0);
        var rc = sc.control(NR_SUPERCALL, keyBuffer(), verAndCmd(CMD_KPM_CONTROL),
            nameBuffer, commandBuffer, outputBuffer, OUT_SIZE);
        return result("control " + commandText, rc, readBuffer(outputBuffer));
    }

    // 暴露一个小而明确的 API；其它 ctl0 命令直接传给 Kpm.control()。
    globalThis.Kpm = {
        hello: hello,
        list: list,
        nums: nums,
        info: info,
        control: control,
        status: function () { return control("status"); },

        hide: {
            status: function () { return control("hide status"); },
            enable: function () { return control("hide enable"); },
            disable: function () { return control("hide disable"); },
            maps: function (enabled) {
                return control("hide " + (enabled ? "enable" : "disable") + " maps");
            },
            threads: function (enabled) {
                return control("hide " + (enabled ? "enable" : "disable") + " threads");
            },
            tokenAdd: function (token) { return control("hide token add " + token); },
            tokenDel: function (token) { return control("hide token del " + token); },
            tokenList: function () { return control("hide token list"); }
        },

        wxshadow: function (enabled) {
            return control("wxshadow " + (enabled ? "enable" : "disable"));
        },
        antidetect: function (enabled) {
            return control("antidetect " + (enabled ? "enable" : "disable"));
        },
        syscall: {
            presetIo: function () { return control("syscall preset io"); },
            start: function () { return control("syscall start"); },
            stop: function () { return control("syscall stop"); },
            clear: function () { return control("syscall clear"); },
            status: function () { return control("syscall status"); },
            pathOn: function () { return control("syscall path on"); },
            attach: function (nr, nargs) { return control("syscall attach " + nr + " " + nargs); },
            read: function (afterSeq, max) {
                return control("syscall read " +
                    (afterSeq === undefined ? 0 : afterSeq) + " " +
                    (max === undefined ? 32 : max));
            },
            filterUid: function (uid) { return control("syscall filter uid " + uid); },
            filterTgid: function (pid) { return control("syscall filter tgid " + pid); },
            filterClear: function () { return control("syscall filter clear"); },
            detachAll: function () { return control("syscall detach-all"); }
        },
        boot: {
            status: function () { return control("boot status"); },
            uid: function (uid) { return control("boot uid " + uid); },
            time: function (seconds, milliseconds) {
                return control("boot time " + seconds + " " + (milliseconds || 0));
            },
            clear: function () { return control("boot clear"); },
            off: function () { return control("boot off"); }
        },
        redirectExact: function (uid, from, to) {
            return control("redirect " + uid + " addexact " + from + " " + to);
        },
        emapsInode: function (uid, match, inode) {
            return control("emaps " + uid + " addino " + match + " " + inode);
        }
    };

    try {
        sc = initSupercall();
        log("loaded; direct supercall libc=" + sc.libc.base +
            " module=" + MODULE + " version=0.13.8");

        // 默认只做只读检查，不自动修改 KPM 状态。
        hello();
        nums();
        list();
        info(MODULE);
        Kpm.status();

        // 按需取消注释，或在后续 jseval/loadjs 中调用：
        // Kpm.hide.maps(false);
        // Kpm.syscall.presetIo(); Kpm.syscall.filterUid(10283);
        // Kpm.syscall.start(); Kpm.syscall.read(0, 32); Kpm.syscall.stop();
        // Kpm.boot.uid(10283); Kpm.boot.time(600, 0); Kpm.boot.status();
        // Kpm.wxshadow(false);
    } catch (error) {
        log("初始化失败: " + String(error));
    }
})();
