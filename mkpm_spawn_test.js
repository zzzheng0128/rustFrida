// mkpm_spawn_test.js — rustfrida spawn 注入到 APatch manager (me.bmax.apatch),
// 通过 Frida NativeFunction 直接调 libc.syscall() 走 supercall 通道控制 mkpm。
//
// 关键设计:
//  - 目标必须能调 supercall: caller uid 要么是 APatch manager, 要么在 su-allow list
//  - me.bmax.apatch 是 manager uid, 所有 supercall 都允许 (但需要在 spawn 前 force-stop)
//  - rustfrida JS worker 不提供 System.run / Rpc.exports / Thread, 不能 Java.perform
//  - 走 KP supercall syscall 直通: syscall(__NR_supercall=45, key, ver_and_cmd, ...)
//  - KP version 0.13.8 -> version_code = (0<<16)|(13<<8)|8 = 0x0D08
//  - ver_and_cmd(key, cmd) = (version_code<<32) | (0x1158<<16) | (cmd&0xFFFF)
//
// 不要用 Java.perform, 不要用 Thread.sleep, 不要用 System.run。

'use strict';

var OUT_BUF_SIZE = 4096;
var KP_VERSION = 0x0D08; // 0.13.8
var KEY = 'su'; // supercall 旁路 key (caller uid is su-allowed)
var MAGIC = 0x1158;
var NR_SUPERCALL = 45;

function log(m) {
    console.log('[mkpm-spawn-test] ' + m);
}

var libc;
var syscallHello, syscallControl, syscallList, syscallInfo, syscallNums;

function initLibc() {
    libc = Process.findModuleByName('libc.so');
    if (!libc) throw new Error('libc not loaded');
    var syscallAddr = libc.getExportByName('syscall');
    // SUPERCALL_HELLO: syscall(45, key, ver_and_cmd)  -- 3 args
    syscallHello = new NativeFunction(syscallAddr, 'long', ['int', 'pointer', 'long']);
    // SUPERCALL_KPM_CONTROL: syscall(45, key, ver, name, ctl, out, outlen) -- 7 args
    syscallControl = new NativeFunction(syscallAddr, 'long',
        ['int', 'pointer', 'long', 'pointer', 'pointer', 'pointer', 'int']);
    // SUPERCALL_KPM_LIST: syscall(45, key, ver, out, outlen) -- 5 args
    syscallList = new NativeFunction(syscallAddr, 'long',
        ['int', 'pointer', 'long', 'pointer', 'int']);
    // SUPERCALL_KPM_NUMS: syscall(45, key, ver) -- 3 args
    syscallNums = new NativeFunction(syscallAddr, 'long', ['int', 'pointer', 'long']);
    // SUPERCALL_KPM_INFO: syscall(45, key, ver, name, out, outlen) -- 6 args
    syscallInfo = new NativeFunction(syscallAddr, 'long',
        ['int', 'pointer', 'long', 'pointer', 'pointer', 'int']);
    log('libc base=' + libc.base + ' syscall @ ' + syscallAddr);
}

function verAndCmd(cmd) {
    return Number(((BigInt(KP_VERSION) << BigInt(32)) |
                   (BigInt(MAGIC) << BigInt(16)) |
                   BigInt(cmd & 0xFFFF)) & BigInt('0xFFFFFFFFFFFFFFFF'));
}

function scHello() {
    var keyBuf = Memory.allocUtf8String(KEY);
    return Number(syscallHello(NR_SUPERCALL, keyBuf, verAndCmd(0x1000)));
}

function kpList(outSize) {
    var keyBuf = Memory.allocUtf8String(KEY);
    var outBuf = Memory.alloc(outSize || 512);
    Memory.writeU8(outBuf, 0);
    var rc = Number(syscallList(NR_SUPERCALL, keyBuf, verAndCmd(0x1031), outBuf, outSize || 512));
    return { rc: rc, out: Memory.readCString(outBuf) };
}

function kpNums() {
    var keyBuf = Memory.allocUtf8String(KEY);
    return Number(syscallNums(NR_SUPERCALL, keyBuf, verAndCmd(0x1030)));
}

function kpInfo(name, outSize) {
    var keyBuf = Memory.allocUtf8String(KEY);
    var nameBuf = Memory.allocUtf8String(name);
    var outBuf = Memory.alloc(outSize || 256);
    Memory.writeU8(outBuf, 0);
    var rc = Number(syscallInfo(NR_SUPERCALL, keyBuf, verAndCmd(0x1032), nameBuf, outBuf, outSize || 256));
    return { rc: rc, out: Memory.readCString(outBuf) };
}

function kpControl(name, ctlArgs, outSize) {
    var keyBuf = Memory.allocUtf8String(KEY);
    var nameBuf = Memory.allocUtf8String(name);
    var ctlBuf = Memory.allocUtf8String(ctlArgs);
    var outBuf = Memory.alloc(outSize || 4096);
    Memory.writeU8(outBuf, 0);
    var rc = Number(syscallControl(NR_SUPERCALL, keyBuf, verAndCmd(0x1022),
                            nameBuf, ctlBuf, outBuf, outSize || 4096));
    return { rc: rc, out: Memory.readCString(outBuf) };
}

function ctl(cmd) {
    var r = kpCall(0x1022, 'mkpm', cmd, 4096);
    log('ctl "' + cmd + '" -> rc=' + r.rc +
        (r.out ? ' out=' + r.out.replace(/\n/g, ' | ').substring(0, 250) : ''));
    return r;
}

function listLoaded() {
    var r = kpList(512);
    log('list -> rc=' + r.rc + ' out="' + r.out + '"');
    return r;
}

function stage0_hello() {
    log('=== STAGE 0: supercall hello probe ===');
    var hello = scHello();
    var expected = 0x11581158;
    log('SUPERCALL_HELLO rc=' + hello.toString(16) + ' (expect ' + expected.toString(16) + ') -> ' +
        (hello === expected ? 'OK' : 'FAIL'));
}

function stage1_moduleVisible() {
    log('=== STAGE 1: kp module visibility ===');
    var nums = kpNums();
    log('nums -> rc=' + nums.rc);
    listLoaded();
    var info = kpCall(0x1032, 'mkpm', null, 256);
    log('info mkpm -> rc=' + info.rc + ' out="' + info.out + '"');
}

function stage2_statusRead() {
    log('=== STAGE 2: ctl0 status reads ===');
    ctl('status');
    ctl('hide status');
    ctl('antidetect status');
    ctl('syscall status');
}

function stage3_hideMaps() {
    log('=== STAGE 3: hide maps token r/w ===');
    ctl('hide token list');
    ctl('hide token add mkpm_spawn_test_token');
    ctl('hide token list');
    ctl('hide token del mkpm_spawn_test_token');
    ctl('hide token list');
}

function stage4_sysmon() {
    log('=== STAGE 4: sysmon full pipeline ===');
    ctl('syscall preset io');
    ctl('syscall path on');
    ctl('syscall clear');
    ctl('syscall start');

    var hits = 0;
    var openat_addr = libc.getExportByName('openat');
    if (openat_addr) {
        Interceptor.attach(openat_addr, {
            onEnter: function (args) {
                this.path = args[1] ? Memory.readUtf8String(args[1]) : '';
                hits++;
            }
        });
        log('hooked libc openat @ ' + openat_addr);
    }
    // 触发几十次 syscall (super call 本身就是 syscall, sysmon 应观察到)
    for (var i = 0; i < 20; i++) {
        kpControl('mkpm', 'syscall filter clear', 256);
    }
    log('hook openat hits=' + hits);
    ctl('syscall read 0 16');
    ctl('syscall stop');
    ctl('syscall clear');
}

function stage5_wxshadow() {
    log('=== STAGE 5: wxshadow toggle ===');
    ctl('wxshadow status');
    ctl('wxshadow enable');
    ctl('wxshadow status');
    ctl('wxshadow disable');
    ctl('wxshadow status');
    ctl('wxshadow enable');
}

function stage6_antidetect() {
    log('=== STAGE 6: antidetect uid-min ===');
    ctl('antidetect status');
    ctl('antidetect uid-min 5000');
    ctl('antidetect status');
    ctl('antidetect uid-min 10000');
    ctl('antidetect status');
}

(function () {
    log('agent loaded, pid=' + Process.id + ' uid=' + Process.uid);
    try {
        initLibc();
        stage0_hello();
        if (scHello() !== 0x11581158) {
            log('FATAL: supercall not responding, abort');
            return;
        }
        stage1_moduleVisible();
        stage2_statusRead();
        stage3_hideMaps();
        stage4_sysmon();
        stage5_wxshadow();
        stage6_antidetect();
    } catch (e) {
        log('FATAL ' + e);
    }
    log('done');
})();