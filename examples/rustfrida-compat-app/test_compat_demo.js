'use strict';

// RustFrida 兼容性 demo 的统一脚本。
// 运行器通过 debug.rustfrida.compat.mode 选择通道：
// all、c、java、svc、jnitrace、hwbp、uprobe、gumtrace，也支持逗号组合。
// 这个文件刻意保持为一个可复制的入口，组合模式不会重复启动多个 agent。

var counts = { java: 0, c: 0, dex: 0, dexPayload: 0, method: 0,
    svc: 0, uprobe: 0, hwbp: 0, jni: 0, jniRegister: 0, jniCall: 0,
    gum: 0, other: 0 };
var info = null;
var nativeApi = null;
var appClassLoader = null;
var dexPayloadHooked = false;
var methodSlot = null;
var methodHooks = Object.create(null);
var methodGateEnabled = false;
var modeSpec = 'all';
var modeSet = Object.create(null);
var sourceBaseline = null;
var setupSourceBefore = null;
var observedBaseline = null;
var setupJniRegisters = 0;
var verificationTimer = null;
var lastVerificationAt = 0;
var jniRegisteredState = 0;
var hwbpMatrixSpecs = [];
var hwbpMatrixHits = Object.create(null);
var hwbpMatrixBaseline = Object.create(null);
var hwbpMatrixLastReportAt = 0;
var hwbpMatrixCallbackLimited = false;
// 轮换实验只保持一个执行断点：命中固定次数后先 bpdel 释放旧地址，
// 再把下一个地址加入命令队列。这样可以验证“取消后复用槽位”，而不是
// 只把多个地址一次性挂满。
var hwbpRotateSpecs = [];
var hwbpRotateIndex = -1;
var hwbpRotateActive = false;
var hwbpRotateHits = 0;
var hwbpRotateRounds = 0;
var hwbpRotateDetachSent = 0;
var hwbpRotateAttachSent = 0;
var HWBP_ROTATE_AFTER = 3;
var uprobeMatrixSpecs = [];
var uprobeMatrixHits = Object.create(null);
var uprobeMatrixBaseline = Object.create(null);
var uprobeMatrixLastReportAt = 0;

function log(message) { console.log('[COMPAT] ' + message); }
function hex(value) { return String(value || '0x0').replace(/^0x/i, ''); }
function key(value) {
    return String(value || '').toLowerCase().replace(/^0x/, '').replace(/[^0-9a-f]/g, '');
}
function untag(value) {
    var h = key(value);
    return '0x' + (h.length === 16 ? h.slice(2) : h);
}
function sparse(name, count, message) {
    if (count <= 3 || count % 500 === 0) log(name + '#' + count + ' ' + message);
}
function location(event, name) {
    return event && event.locations && event.locations[name]
        ? '(' + event.locations[name] + ')' : '';
}
function configureMode(value) {
    var tokens = String(value || 'all').toLowerCase().split(',');
    modeSet = Object.create(null);
    for (var i = 0; i < tokens.length; i++) {
        var token = tokens[i].trim();
        if (token === 'all') { modeSet.all = true; break; }
        // hwbp-matrix 仍启用 hwbp worker，只额外选择 6 个执行断点
        // + 4 个读写观察点；别让 Activity 因为未知 lane 而没有源端流量。
        if (token === 'hwbp-matrix') {
            modeSet.hwbp = true;
            modeSet.hwbpMatrix = true;
        } else if (token === 'hwbp-rotate') {
            modeSet.hwbp = true;
            modeSet.hwbpRotate = true;
        } else if (token === 'uprobe-matrix') {
            modeSet.uprobe = true;
            modeSet.uprobeMatrix = true;
        } else if (token === 'uprobe-limit') {
            modeSet.uprobe = true;
            modeSet.uprobeLimit = true;
        } else if (token) modeSet[token] = true;
    }
    if (Object.keys(modeSet).length === 0) modeSet.all = true;
    if (modeSet.all) modeSpec = 'all';
    else if (modeSet.hwbpMatrix) modeSpec = 'hwbp-matrix';
    else if (modeSet.hwbpRotate) modeSpec = 'hwbp-rotate';
    else if (modeSet.uprobeMatrix) modeSpec = 'uprobe-matrix';
    else if (modeSet.uprobeLimit) modeSpec = 'uprobe-limit';
    else modeSpec = Object.keys(modeSet).join(',');
}
function enabled(lane) { return !!modeSet.all || !!modeSet[lane]; }
function kernelEnabled() { return enabled('svc') || enabled('uprobe') || enabled('hwbp'); }

// 源端计数来自 demo native 的原子计数器；观察端计数来自各个 hook/event 回调。
// 两者按“脚本观察者安装完成后”取增量，避免把 spawn 初始化窗口误算成漏报。
function readSourceCounters() {
    try { return JSON.parse(String(getNative().nativeCounters())); }
    catch (error) {
        log('[VERIFY][ERROR] nativeCounters unavailable: ' + (error.message || error));
        return null;
    }
}
function numberValue(value) {
    var n = Number(value);
    return isFinite(n) && n >= 0 ? n : 0;
}
function counterDelta(now, before, name) {
    var value = numberValue(now && now[name]) - numberValue(before && before[name]);
    return value < 0 ? 0 : value;
}
function observedDelta(name) {
    var value = numberValue(counts[name]) -
        numberValue(observedBaseline && observedBaseline[name]);
    return value < 0 ? 0 : value;
}
function snapshotObservedCounts() {
    observedBaseline = {};
    Object.keys(counts).forEach(function (name) { observedBaseline[name] = counts[name]; });
    hwbpMatrixBaseline = Object.create(null);
    Object.keys(hwbpMatrixHits).forEach(function (name) {
        hwbpMatrixBaseline[name] = hwbpMatrixHits[name];
    });
    uprobeMatrixBaseline = Object.create(null);
    Object.keys(uprobeMatrixHits).forEach(function (name) {
        uprobeMatrixBaseline[name] = uprobeMatrixHits[name];
    });
}
function observedMatrixDelta(name) {
    var value = Number(hwbpMatrixHits[name] || 0) -
        Number(hwbpMatrixBaseline[name] || 0);
    return value < 0 ? 0 : value;
}
function observedUprobeMatrixDelta(name) {
    var value = Number(uprobeMatrixHits[name] || 0) -
        Number(uprobeMatrixBaseline[name] || 0);
    return value < 0 ? 0 : value;
}
function verificationSnapshot(force) {
    var now = readSourceCounters();
    if (!now || !sourceBaseline) return;
    var source = {
        svc: counterDelta(now, sourceBaseline, 'svc_raw'),
        uprobe: counterDelta(now, sourceBaseline, 'uprobe_hot'),
        hwbp_exec: counterDelta(now, sourceBaseline, 'hwbp_hot'),
        hwbp_read: counterDelta(now, sourceBaseline, 'read_slot_reads'),
        hwbp_write: counterDelta(now, sourceBaseline, 'write_slot_writes'),
        method_slot_write: counterDelta(now, sourceBaseline, 'method_slot_writes'),
        method_epoch_write: counterDelta(now, sourceBaseline, 'method_epoch_writes'),
        method_calls: counterDelta(now, sourceBaseline, 'method_v1') +
            counterDelta(now, sourceBaseline, 'method_v2'),
        agent: counterDelta(now, sourceBaseline, 'agent_hot'),
        java: counterDelta(now, sourceBaseline, 'native_agent_tick'),
        dex: counterDelta(now, sourceBaseline, 'dex_load'),
        dexPayload: counterDelta(now, sourceBaseline, 'dex_payload'),
        jni: counterDelta(now, sourceBaseline, 'jni_probe_tick') +
            counterDelta(now, sourceBaseline, 'jni_probe_object'),
        jni_register: setupJniRegisters +
            counterDelta(now, sourceBaseline, 'jni_register_successes')
    };
    // hwbp 脚本当前安装 x(rf_hwbp_hot)+r(read_slot)+w(write_slot)+w(method_slot)。
    source.hwbp = source.hwbp_exec + source.hwbp_read +
        source.hwbp_write + source.method_slot_write;
    if (uprobeMatrixSpecs.length > 0) {
        source.uprobe = 0;
        for (var pmi = 0; pmi < uprobeMatrixSpecs.length; pmi++) {
            source.uprobe += counterDelta(now, sourceBaseline, uprobeMatrixSpecs[pmi].sourceKey);
        }
    }
    if (hwbpMatrixSpecs.length > 0) {
        source.hwbp = 0;
        for (var mi = 0; mi < hwbpMatrixSpecs.length; mi++) {
            source.hwbp += counterDelta(now, sourceBaseline, hwbpMatrixSpecs[mi].sourceKey);
        }
    }
    if (uprobeMatrixSpecs.length > 0) {
        var uprobeMatrixPartial = false;
        var uprobeMatrixMismatch = false;
        for (var ui = 0; ui < uprobeMatrixSpecs.length; ui++) {
            var uprobeSpec = uprobeMatrixSpecs[ui];
            var uprobeSource = counterDelta(now, sourceBaseline, uprobeSpec.sourceKey);
            var uprobeObserved = observedUprobeMatrixDelta(uprobeSpec.hitKey);
            if (uprobeSource > 0 && uprobeObserved === 0) uprobeMatrixMismatch = true;
            else if (uprobeSource > uprobeObserved) uprobeMatrixPartial = true;
        }
        if (uprobeMatrixMismatch) verdict = 'MISMATCH';
        else if (verdict === 'PASS' && uprobeMatrixPartial) verdict = 'PARTIAL';
        if (Date.now() - uprobeMatrixLastReportAt >= 4500) {
            uprobeMatrixLastReportAt = Date.now();
            for (var uri = 0; uri < uprobeMatrixSpecs.length; uri++) {
                var uprobeReportSpec = uprobeMatrixSpecs[uri];
                var uprobeReportSource = counterDelta(now, sourceBaseline, uprobeReportSpec.sourceKey);
                var uprobeReportObserved = observedUprobeMatrixDelta(uprobeReportSpec.hitKey);
                log('[UPROBE-MATRIX] ' + uprobeReportSpec.id +
                    ' target=' + uprobeReportSpec.target +
                    ' source=' + uprobeReportSource + ' observed=' + uprobeReportObserved +
                    ' missing=' + Math.max(0, uprobeReportSource - uprobeReportObserved) +
                    ' verdict=' + (uprobeReportSource === 0 ? 'NO_SOURCE' :
                        (uprobeReportObserved === uprobeReportSource ? 'PASS' :
                            (uprobeReportObserved === 0 ? 'FAIL' : 'PARTIAL'))));
            }
        }
    }
    var observed = {
        svc: observedDelta('svc'), uprobe: observedDelta('uprobe'),
        hwbp: observedDelta('hwbp'), c: observedDelta('c'),
        java: observedDelta('java'), dex: observedDelta('dex'),
        dexPayload: observedDelta('dexPayload'), jni: observedDelta('jniCall'),
        jniRegister: Math.max(observedDelta('jniRegister'), jniRegisteredState),
        method: observedDelta('method')
    };
    var missing = {
        svc: Math.max(0, source.svc - observed.svc),
        uprobe: Math.max(0, source.uprobe - observed.uprobe),
        hwbp: Math.max(0, source.hwbp - observed.hwbp),
        c: Math.max(0, source.agent - observed.c),
        java: Math.max(0, source.java - observed.java),
        dex: Math.max(0, source.dex - observed.dex),
        dexPayload: Math.max(0, source.dexPayload - observed.dexPayload),
        jni: Math.max(0, source.jni - observed.jni),
        jni_register: Math.max(0, source.jni_register - observed.jniRegister),
        method: Math.max(0, source.method_calls - observed.method)
    };
    var exactMismatch = [];
    // Interceptor/JNI onEnter runs just before the native body increments its
    // source counter.  Permit one in-flight callback; a larger source lead is
    // a real missing event and remains a mismatch.
    if (enabled('c') && source.agent > observed.c + 1) exactMismatch.push('c');
    if (enabled('java') && source.java > observed.java + 1) exactMismatch.push('java');
    if (enabled('jnitrace') && source.jni > observed.jni + 1) exactMismatch.push('jnitrace');
    if (enabled('jnitrace') && source.jni_register > 0 &&
        observed.jniRegister < source.jni_register) exactMismatch.push('jni-register');
    if (enabled('hwbp') && !modeSet.hwbpRotate && source.method_calls > observed.method + 1)
        exactMismatch.push('method');
    var partial = ['svc', 'uprobe'].some(function (name) {
        return enabled(name) && missing[name] > 0;
    });
    if (enabled('hwbp') && hwbpMatrixSpecs.length === 0 && !modeSet.hwbpRotate && missing.hwbp > 0) {
        partial = true;
    }
    var verdict = exactMismatch.length ? 'MISMATCH' : (partial ? 'PARTIAL' : 'PASS');
    if (hwbpMatrixSpecs.length > 0) {
        // source 是 native 操作数，observed 是可选 JS 回调数；回调本身
        // 有 token/in-flight 限流，不能用它判断硬件槽位是否挂满。
        var matrixPartial = false;
        for (var hi = 0; hi < hwbpMatrixSpecs.length; hi++) {
            var matrixSpec = hwbpMatrixSpecs[hi];
            var matrixSource = counterDelta(now, sourceBaseline, matrixSpec.sourceKey);
            var matrixObserved = observedMatrixDelta(matrixSpec.hitKey);
            if (matrixSource > matrixObserved) matrixPartial = true;
        }
        hwbpMatrixCallbackLimited = matrixPartial;
        if (Date.now() - hwbpMatrixLastReportAt >= 4500) {
            hwbpMatrixLastReportAt = Date.now();
            for (var ri = 0; ri < hwbpMatrixSpecs.length; ri++) {
                var reportSpec = hwbpMatrixSpecs[ri];
                var reportSource = counterDelta(now, sourceBaseline, reportSpec.sourceKey);
                var reportObserved = observedMatrixDelta(reportSpec.hitKey);
                log('[HWBP-MATRIX] ' + reportSpec.id +
                    ' kind=' + reportSpec.kind + ' target=' + reportSpec.target +
                    ' source=' + reportSource + ' observed=' + reportObserved +
                    ' missing=' + Math.max(0, reportSource - reportObserved) +
                    ' verdict=' + (reportSource === 0 ? 'NO_SOURCE' :
                        (reportObserved === reportSource ? 'PASS' :
                            (reportObserved === 0 ? 'CALLBACK_LIMITED' : 'CALLBACK_PARTIAL'))));
            }
        }
    }
    var nowMs = Date.now();
    // 普通事件路径始终按 4.5s 节流；旧逻辑在 MISMATCH 时绕过节流，
    // 极限档会把验证日志本身刷爆。运行器收尾传 true 强制输出最终快照。
    if (!force && nowMs - lastVerificationAt < 4500) return;
    lastVerificationAt = nowMs;
    log('[VERIFY] verdict=' + verdict +
        ' source_svc=' + source.svc + ' observed_svc=' + observed.svc +
        ' source_uprobe=' + source.uprobe + ' observed_uprobe=' + observed.uprobe +
        ' source_hwbp=' + source.hwbp + ' observed_hwbp=' + observed.hwbp +
        ' source_c=' + source.agent + ' observed_c=' + observed.c +
        ' source_java=' + source.java + ' observed_java=' + observed.java +
        ' source_dex=' + source.dex + ' observed_dex=' + observed.dex +
        ' source_dexPayload=' + source.dexPayload + ' observed_dexPayload=' + observed.dexPayload +
        ' source_jni=' + source.jni + ' observed_jni=' + observed.jni +
        ' source_jni_register=' + source.jni_register + ' observed_jni_register=' + observed.jniRegister +
        ' source_method=' + source.method_calls + ' observed_method=' + observed.method +
        ' missing=' + JSON.stringify(missing) +
        ' gate_timeouts=' + counterDelta(now, sourceBaseline, 'method_gate_timeouts'));
}
// 运行器在结束前通过 `jseval __compat_verify()` 主动取一次最终快照，
// 把仍在 ring/JS worker 路上的最后几条事件纳入对账，而不是停在上一次
// 4.5 秒采样点。
globalThis.__compat_verify = verificationSnapshot;
function startVerification() {
    if (!sourceBaseline || verificationTimer) return;
    // 这个 QuickJS 运行时没有 timer API。把采样挂到实际事件/Interceptor
    // 回调上，避免为了“定时器”再创建线程；高频时按计数抽样，低频时每次
    // 都能在事件到达后刷新一次。verificationTimer 这里只是 started 标记。
    verificationTimer = true;
    verificationSnapshot();
}
function maybeVerify() {
    if (!sourceBaseline || !verificationTimer) return;
    // 调用方本身已经是实际事件回调；采样函数内部按 4.5s 节流，
    // 这里不要再用“恰好命中 64 的倍数”的条件，否则低频运行结束前
    // 可能永远没有最后一条源端/观察端对账记录。
    verificationSnapshot();
}

// 事件回调是实时到达 JS 的；高频通道只采样打印，完整记录由 host --trace-output 保存。
globalThis.__kt_on_ack = function (message) { log('ack ' + message); };
globalThis.__kt_on_event = function (event) {
    try {
        if (!event || !event.type) return;
        if (event.type === 'svc.enter') {
            counts.svc++;
            sparse('svc', counts.svc, 'nr=' + event.nr + ' tid=' + event.tid +
                ' lr=' + event.lr + location(event, 'lr'));
        } else if (event.type === 'uprobe.hit') {
            counts.uprobe++;
            if (uprobeMatrixSpecs.length > 0) {
                var uprobeEventKey = key(event.pc);
                uprobeMatrixHits[uprobeEventKey] = Number(uprobeMatrixHits[uprobeEventKey] || 0) + 1;
            }
            sparse('uprobe', counts.uprobe, 'pc=' + event.pc + location(event, 'pc') +
                ' tid=' + event.tid);
        } else if (event.type === 'hwbp.hit') {
            counts.hwbp++;
            if (event.bp) {
                var eventKind = String(event.bp.kind || '?');
                var eventAddr = event.bp.addr || event.addr || event.pc;
                var eventKey = eventKind + ':' + key(eventAddr);
                hwbpMatrixHits[eventKey] = Number(hwbpMatrixHits[eventKey] || 0) + 1;
            }
            var kind = event.bp && event.bp.kind;
            var far = event.addr || event.far;
            if (modeSet.hwbpRotate && kind === 'x' && hwbpRotateActive &&
                    hwbpRotateIndex >= 0 && event.bp &&
                    key(event.bp.addr || event.pc) === key(hwbpRotateSpecs[hwbpRotateIndex].target)) {
                hwbpRotateHits++;
                log('[HWBP-ROTATE] phase=hit index=' + hwbpRotateIndex +
                    ' id=' + hwbpRotateSpecs[hwbpRotateIndex].id +
                    ' addr=' + hwbpRotateSpecs[hwbpRotateIndex].target +
                    ' hit=' + hwbpRotateHits + '/' + HWBP_ROTATE_AFTER);
                if (hwbpRotateHits >= HWBP_ROTATE_AFTER) rotateHwbpAfterHit();
            }
            // method_slot 写入后 native writer 会等待本回调完成 hook。
            if (kind === 'w' && methodSlot && event.bp &&
                    key(event.bp.addr) === key(methodSlot)) resolveChangedMethodTarget();
            // 事件仍由 host trace-output 完整保存；QuickJS 只在采样行
            // 构造 16 条反汇编和整组寄存器，避免高频格式化拖慢消费。
            if (counts.hwbp <= 3 || counts.hwbp % 500 === 0) {
                var instruction = event.instruction || {};
                var instructions = event.instructions || [];
                var disasm16 = [];
                for (var di = 0; di < instructions.length; di++) {
                    var item = instructions[di] || {};
                    disasm16.push('#' + di + '@' + (item.pc || '-') + '=' + (item.asm || item.word || '-'));
                }
                log('hwbp#' + counts.hwbp +
                    ' kind=' + kind + ' pc=' + event.pc + location(event, 'pc') +
                    ' far=' + (far || '-') + (far ? location(event, 'addr') : '') + ' tid=' + event.tid +
                    ' insn=' + (instruction.word || '-') +
                    ' asm=' + (instruction.asm || '-') +
                    ' disasm16=' + (disasm16.length ? disasm16.join('|') : '-') +
                    ' regs=' + JSON.stringify(event.regs || {}));
            }
        } else {
            counts.other++;
            sparse('event', counts.other, 'type=' + event.type +
                ' keys=' + Object.keys(event).join(','));
        }
        maybeVerify();
    } catch (error) { log('event error: ' + error); }
};

function getNative() {
    if (nativeApi) return nativeApi;
    nativeApi = Java.use('com.rustfrida.compatdemo.Native');
    return nativeApi;
}

function installJavaHooks(Native) {
    var tick = Native.nativeAgentTick;
    tick.implementation = function () {
        counts.java++;
        sparse('java', counts.java, 'Native.nativeAgentTick tid=' + Process.getCurrentThreadId());
        // 先让 native 函数完成计数，再采样源端；否则进入 Java hook
        // 时 native body 还没递增，会把一个 in-flight 调用误报成漏报。
        var result = this.$orig.apply(this, arguments);
        maybeVerify();
        return result;
    };
    var Application = Java.use('com.rustfrida.compatdemo.CompatApplication');
    var onCreate = Application.onCreate;
    onCreate.implementation = function () {
        log('Application.onCreate entered before app startup work');
        return this.$orig.apply(this, arguments);
    };
    installDynamicDexHook();
    log('Java hooks installed');
}

function installDynamicDexHook() {
    var DexProbe = Java.use('com.rustfrida.compatdemo.DexProbe');
    var loadAndRun = DexProbe.loadAndRun.overload('android.content.Context', 'int');
    var getLastLoader = DexProbe.getLastLoader.overload();
    try {
        var loaders = Java.classLoaders();
        if (loaders && loaders.length > 0) appClassLoader = loaders[0];
    } catch (_) {}
    function hookPayload() {
        if (dexPayloadHooked) return;
        var loader = getLastLoader();
        if (!loader) return;
        try {
            Java.setClassLoader(loader);
            var Payload = Java.use('com.rustfrida.compatdemo.payload.DexPayload');
            var run = Payload.run.overload('int');
            run.implementation = function (seed) {
                counts.dexPayload++;
                maybeVerify();
                var result = this.$orig.apply(this, arguments);
                sparse('dexPayload', counts.dexPayload,
                    'run seed=' + seed + ' result=' + String(result));
                return result;
            };
            dexPayloadHooked = true;
            log('dynamic DexPayload.run(int) hook installed');
        } catch (error) {
            log('dynamic DexPayload hook failed: ' + (error.message || error));
        } finally {
            if (appClassLoader) {
                try { Java.setClassLoader(appClassLoader); } catch (_) {}
            }
        }
    }
    loadAndRun.implementation = function () {
        var result = this.$orig.apply(this, arguments);
        counts.dex++;
        maybeVerify();
        sparse('dex', counts.dex, 'loadAndRun result=' + String(result));
        hookPayload();
        return result;
    };
    log('DexProbe.loadAndRun hook installed');
}

function readNativeInfo() {
    if (info) return info;
    info = JSON.parse(String(getNative().nativeInfo()));
    info.object_addr = untag(info.object_addr);
    info.read_addr = untag(info.read_addr);
    info.write_addr = untag(info.write_addr);
    info.method_slot_addr = untag(info.method_slot_addr);
    info.method_epoch_addr = untag(info.method_epoch_addr);
    info.method_v1_addr = untag(info.method_v1_addr);
    info.method_v2_addr = untag(info.method_v2_addr);
    methodSlot = ptr(info.method_slot_addr);
    return info;
}

function installMethodHook(target, label) {
    var address = ptr(target);
    var addressKey = key(address);
    if (!addressKey || addressKey === '0' || methodHooks[addressKey]) return;
    try {
        methodHooks[addressKey] = Interceptor.attach(address, {
            onEnter: function () {
                counts.method++;
                sparse('method', counts.method,
                    label + ' target=' + address + ' x0=' + this.x0 +
                    ' x1=' + this.x1 + ' lr=' + this.lr);
            }
        });
        log('C method hook installed ' + label + ' at ' + address);
    } catch (error) { log('C method hook failed ' + label + ': ' + (error.message || error)); }
}

// HWBP 轮换实验：一次只占用一个执行断点槽位。bpdel 和下一条 x 命令
// 通过同一个 FIFO 命令队列发送，所以 tracer 会先关闭旧地址的所有 link，
// 再尝试挂载新地址；host 的 hwbp detached/attached 行是最终生效证据。
function armNextRotatingHwbp(index) {
    if (!hwbpRotateSpecs.length) return;
    hwbpRotateIndex = index % hwbpRotateSpecs.length;
    hwbpRotateHits = 0;
    hwbpRotateActive = true;
    var spec = hwbpRotateSpecs[hwbpRotateIndex];
    hwbpRotateAttachSent++;
    log('[HWBP-ROTATE] phase=attach index=' + hwbpRotateIndex +
        ' id=' + spec.id + ' addr=' + spec.target +
        ' attach_sent=' + hwbpRotateAttachSent);
    console.log('KT>x ' + spec.target);
}

function rotateHwbpAfterHit() {
    if (!hwbpRotateActive || hwbpRotateIndex < 0) return;
    var oldIndex = hwbpRotateIndex;
    var oldSpec = hwbpRotateSpecs[oldIndex];
    hwbpRotateActive = false;
    hwbpRotateDetachSent++;
    hwbpRotateRounds++;
    log('[HWBP-ROTATE] phase=detach index=' + oldIndex +
        ' id=' + oldSpec.id + ' addr=' + oldSpec.target +
        ' hit=' + hwbpRotateHits + '/' + HWBP_ROTATE_AFTER +
        ' detach_sent=' + hwbpRotateDetachSent +
        ' next_index=' + ((oldIndex + 1) % hwbpRotateSpecs.length));
    // bpdel 只接受绝对地址；这里使用和 KT>x 相同的运行时绝对地址。
    console.log('KT>bpdel ' + oldSpec.target);
    armNextRotatingHwbp((oldIndex + 1) % hwbpRotateSpecs.length);
}

function resolveChangedMethodTarget() {
    if (!methodSlot || !nativeApi) return;
    try {
        var target = methodSlot.readPointer();
        var targetKey = key(target);
        var label = 'rf_method_dynamic';
        if (info && key(info.method_v1_addr) === targetKey) label = 'rf_method_v1';
        if (info && key(info.method_v2_addr) === targetKey) label = 'rf_method_v2';
        log('method slot changed -> ' + target + ' (' + label + ')');
        installMethodHook(target, label);
        nativeApi.nativeMethodHookReady();
        if (!methodGateEnabled) {
            nativeApi.nativeMethodGate(true);
            methodGateEnabled = true;
        }
    } catch (error) {
        log('method target resolve failed: ' + (error.message || error));
        try { nativeApi.nativeMethodHookReady(); } catch (_) {}
    }
}

function installNativeHook() {
    try {
        var nativeInfo = readNativeInfo();
        var offset = parseInt(hex(nativeInfo.agent_offset), 16);
        var target = nativeInfo.base && offset ? ptr(nativeInfo.base).add(offset) : null;
        if (!target) throw new Error('rf_agent_hot export not found');
        Interceptor.attach(target, {
            onEnter: function () {
                counts.c++;
                sparse('c', counts.c, 'rf_agent_hot pc=' + this.pc + ' x0=' + this.x0);
            }
        });
        log('native C hook installed at ' + target);
    } catch (error) { log('native C hook failed: ' + error); }
}

function armKernelTrace() {
    var nativeInfo = readNativeInfo();
    console.log('KT>sub');
    if (enabled('uprobe')) {
        if (modeSet.uprobeMatrix) {
            var uprobeBase = ptr(nativeInfo.base);
            function uprobeModuleAddress(offset) {
                return '0x' + key(uprobeBase.add(parseInt(hex(offset), 16)));
            }
            function addUprobeMatrix(id, offset, sourceKey) {
                var target = uprobeModuleAddress(offset);
                uprobeMatrixSpecs.push({ id: id, target: target,
                    sourceKey: sourceKey, hitKey: key(target) });
                console.log('KT>brk libcompatdemo.so 0x' + hex(offset));
            }
            addUprobeMatrix('rf_uprobe_hot', nativeInfo.uprobe_offset, 'uprobe_hot');
            addUprobeMatrix('rf_hwbp_hot', nativeInfo.hwbp_offset, 'hwbp_hot');
            addUprobeMatrix('rf_agent_hot', nativeInfo.agent_offset, 'agent_hot');
            addUprobeMatrix('rf_object_step', nativeInfo.step_offset, 'object_step');
            // 这两个方法由 nativeUprobeMatrixBurst 每轮各调用一次。
            uprobeMatrixSpecs.push({ id: 'rf_method_v1', target: nativeInfo.method_v1_addr,
                sourceKey: 'method_v1', hitKey: key(nativeInfo.method_v1_addr) });
            console.log('KT>brk ' + nativeInfo.library + ' 0x' +
                hex(parseInt(key(nativeInfo.method_v1_addr), 16) - parseInt(key(nativeInfo.base), 16)));
            uprobeMatrixSpecs.push({ id: 'rf_method_v2', target: nativeInfo.method_v2_addr,
                sourceKey: 'method_v2', hitKey: key(nativeInfo.method_v2_addr) });
            console.log('KT>brk ' + nativeInfo.library + ' 0x' +
                hex(parseInt(key(nativeInfo.method_v2_addr), 16) - parseInt(key(nativeInfo.base), 16)));
            log('UPROBE matrix armed: ' + uprobeMatrixSpecs.length + ' simultaneous targets');
        } else if (modeSet.uprobeLimit) {
            // 极限档使用独立的 32 个函数入口；UPROBE_TARGETS 通过 system
            // property 选择前 N 个，默认 32。每个目标都有独立 source counter。
            var limitBase = ptr(nativeInfo.base);
            var limitInfo = JSON.parse(String(getNative().nativeUprobeMatrixInfo()));
            var limitCount = Number(getNative().nativeUprobeTargetCount());
            if (!isFinite(limitCount) || limitCount < 1) limitCount = Number(limitInfo.count || 1);
            limitCount = Math.max(1, Math.min(limitCount, Number(limitInfo.count || limitCount)));
            for (var li = 0; li < limitCount; li++) {
                var targetInfo = limitInfo.targets[li];
                if (!targetInfo) break;
                var targetPtr = ptr(targetInfo.addr);
                var targetOffset = targetPtr.sub(limitBase).toString();
                uprobeMatrixSpecs.push({ id: targetInfo.id, target: String(targetPtr),
                    sourceKey: targetInfo.counter, hitKey: key(targetPtr) });
                console.log('KT>brk libcompatdemo.so ' + targetOffset);
            }
            log('UPROBE limit matrix armed: ' + uprobeMatrixSpecs.length +
                '/' + limitInfo.count + ' simultaneous targets');
        } else {
            console.log('KT>brk libcompatdemo.so 0x' + hex(nativeInfo.uprobe_offset));
        }
    }
    if (enabled('hwbp')) {
        if (modeSet.hwbpRotate) {
            var rotateBase = ptr(nativeInfo.base);
            function rotateModuleAddress(offset) {
                return '0x' + key(rotateBase.add(parseInt(hex(offset), 16)));
            }
            // 这些入口都由 hwbp lane 的 StressRunner 调用，轮换后每个地址
            // 至少会被触发；method_v1/v2 用来覆盖函数指针切换场景。
            hwbpRotateSpecs = [
                { id: 'rf_hwbp_hot', target: rotateModuleAddress(nativeInfo.hwbp_offset) },
                { id: 'rf_object_step', target: rotateModuleAddress(nativeInfo.step_offset) },
                { id: 'rf_method_v1', target: nativeInfo.method_v1_addr },
                { id: 'rf_method_v2', target: nativeInfo.method_v2_addr }
            ];
            log('[HWBP-ROTATE] configured specs=' + hwbpRotateSpecs.length +
                ' after=' + HWBP_ROTATE_AFTER + ' hits; only one execute slot is active');
            armNextRotatingHwbp(0);
        } else if (modeSet.hwbpMatrix) {
            // Pixel 6/ARM64 的常见上限是 6 个执行断点 + 4 个观察点。
            // 每一项独立记录 source/observed，超过实际槽位时由 host 明确
            // 打印 ENOSPC/partial，而不是静默覆盖前一个断点。
            var base = ptr(nativeInfo.base);
            function moduleAddress(offset) {
                return '0x' + key(base.add(parseInt(hex(offset), 16)));
            }
            function addMatrix(id, kind, target, sourceKey, len) {
                var targetText = String(target);
                hwbpMatrixSpecs.push({ id: id, kind: kind, target: targetText,
                    sourceKey: sourceKey, hitKey: kind + ':' + key(targetText) });
                var command = 'KT>' + kind + ' ' + targetText;
                if (kind !== 'x') command += ' ' + (len || 8);
                console.log(command);
            }
            addMatrix('x-hwbp_hot', 'x', moduleAddress(nativeInfo.hwbp_offset), 'hwbp_hot');
            addMatrix('x-uprobe_hot', 'x', moduleAddress(nativeInfo.uprobe_offset), 'uprobe_hot');
            addMatrix('x-agent_hot', 'x', moduleAddress(nativeInfo.agent_offset), 'agent_hot');
            addMatrix('x-object_step', 'x', moduleAddress(nativeInfo.step_offset), 'object_step');
            addMatrix('x-method_v1', 'x', nativeInfo.method_v1_addr, 'method_v1');
            addMatrix('x-method_v2', 'x', nativeInfo.method_v2_addr, 'method_v2');
            addMatrix('r-read_slot', 'r', nativeInfo.read_addr, 'read_slot_reads', 8);
            addMatrix('w-write_slot', 'w', nativeInfo.write_addr, 'write_slot_writes', 8);
            addMatrix('w-method_slot', 'w', nativeInfo.method_slot_addr, 'method_slot_writes', 8);
            addMatrix('w-method_epoch', 'w', nativeInfo.method_epoch_addr, 'method_epoch_writes', 8);
            log('HWBP matrix armed: ' + hwbpMatrixSpecs.length +
                ' specs (6 execute + 4 watch; actual per-thread slots are reported by host)');
        } else {
            console.log('KT>x libcompatdemo.so+0x' + hex(nativeInfo.hwbp_offset));
            console.log('KT>r ' + nativeInfo.read_addr + ' 8');
            console.log('KT>w ' + nativeInfo.write_addr + ' 8');
            console.log('KT>w ' + nativeInfo.method_slot_addr + ' 8');
        }
        // Do not enable the gate while the asynchronous KT commands are still
        // being attached.  The first method-slot write is allowed to establish
        // the target; resolveChangedMethodTarget() enables the gate only after
        // that watchpoint has reached this JS callback.  Enabling it here made
        // the writer hit its 500 ms fallback before the first attach finished.
        methodGateEnabled = false;
        log('method-slot gate will enable after the first watchpoint callback');
    }
    log('kernel trace commands sent for ' + modeSpec);
}

function validPtr(value) {
    if (value === null || value === undefined) return false;
    try { return String(ptr(value)) !== '0x0'; } catch (_) { return false; }
}
function findGlobalExport(name) {
    try {
        if (typeof Module.findGlobalExportByName === 'function') {
            var global = Module.findGlobalExportByName(name);
            if (validPtr(global)) return global;
        }
    } catch (_) {}
    try {
        var address = Module.findExportByName(null, name);
        if (validPtr(address)) return address;
    } catch (_) {}
    return null;
}

// GumTrace 目标是本 demo 自己的 rf_agent_hot，避免旧的 libmetasec 固定偏移。
function installGumTrace() {
    var targetModule = 'libcompatdemo.so';
    var targetSymbol = 'rf_agent_hot';
    var soPath = '/data/local/tmp/libGumTrace.so';
    var traceFile = '/data/local/tmp/gumtrace-compatdemo.log';
    var armed = false;
    var traced = false;
    var tracing = false;
    var gumUnrun = null;
    function tryArm() {
        if (armed) return;
        var module = null;
        try { module = Process.findModuleByName(targetModule); } catch (_) {}
        if (!module) return;
        try {
            // CMake 的导出表在不同 NDK/strip 配置下可能被裁剪；nativeInfo()
            // 提供当前 ASLR 基址和同一份导出偏移，因此 GumTrace 不依赖 dynsym。
            var nativeInfo = readNativeInfo();
            log('GumTrace nativeInfo base=' + nativeInfo.base + ' agent_offset=' + nativeInfo.agent_offset);
            var target = null;
            if (nativeInfo.base && nativeInfo.agent_offset) {
                target = ptr(nativeInfo.base).add(parseInt(hex(nativeInfo.agent_offset), 16));
            }
            log('GumTrace calculated target=' + target + ' valid=' + validPtr(target));
            if (!validPtr(target)) target = Module.findExportByName(targetModule, targetSymbol);
            if (!validPtr(target)) throw new Error(targetSymbol + ' not found');
            var gum = Module.load(soPath, 2, true);
            var init = new NativeFunction(gum.getExportByName('init'),
                'void', ['pointer', 'pointer', 'int', 'pointer']);
            var run = new NativeFunction(gum.getExportByName('run'), 'void', []);
            gumUnrun = new NativeFunction(gum.getExportByName('unrun'), 'void', []);
            Interceptor.attach(target, {
                onEnter: function () {
                    if (traced) return;
                    traced = true;
                    try {
                        var name = Memory.allocUtf8String(targetModule);
                        var output = Memory.allocUtf8String(traceFile);
                        var options = Memory.alloc(8);
                        options.writeU64(BigInt(2));
                        init(name, output, 0, options);
                        run();
                        tracing = true;
                        counts.gum++;
                        log('GumTrace started at ' + target + ' -> ' + traceFile);
                    } catch (error) { log('GumTrace start failed: ' + (error.message || error)); }
                },
                onLeave: function () {
                    if (!tracing || !gumUnrun) return;
                    try { gumUnrun(); } catch (error) { log('GumTrace stop failed: ' + error); }
                    tracing = false;
                    log('GumTrace stopped');
                }
            });
            armed = true;
            log('GumTrace armed ' + targetModule + '!' + targetSymbol);
        } catch (error) { log('GumTrace arm failed: ' + (error.message || error)); }
    }
    tryArm();
    if (!armed) {
        ['android_dlopen_ext', 'dlopen', '__loader_android_dlopen_ext', '__loader_dlopen']
            .forEach(function (name) {
                var loader = findGlobalExport(name);
                if (validPtr(loader)) try { Interceptor.attach(loader, { onLeave: tryArm }); } catch (_) {}
            });
        log('GumTrace waiting for ' + targetModule);
    }
}

function installJniTrace(Native) {
    try {
        // Java.use 的 native 调用由 app 线程执行；其 JNIEnv 表可能与 JS
        // worker 不同。先让同一个调用路径返回表槽地址，避免只 hook 到
        // worker 私有的 JNIEnv 表而漏掉真正的 RegisterNatives。
        var address = null;
        try { address = ptr(String(Native.nativeJniRegisterNativesAddress())); } catch (_) {}
        if (!validPtr(address)) address = Jni.addr('RegisterNatives');
        var onRegister = function (env, clazz, methodPtr, nativeCount) {
            try {
                    var className = Jni.env.getClassName(clazz);
                    var count = Math.min(Number(nativeCount), 32);
                    var methods = Jni.structs.JNINativeMethod.readArray(methodPtr, count);
                    counts.jni++;
                    counts.jniRegister++;
                    log('RegisterNatives class=' + className + ' count=' + count);
                    for (var i = 0; i < methods.length; i++) {
                        var method = methods[i];
                        log('  [jni] ' + method.name + ' ' + method.sig + ' -> ' + method.fnPtr);
                    }
            } catch (error) { log('JNI decode failed: ' + (error.message || error)); }
            return this.$orig();
        };
        // JNIEnv 表槽在 ART 上是间接入口。hook() 走运行时的寄存器重编译
        // 路径，能覆盖 app 线程的表调用；老版本没有 hook 时再退回 attach。
        if (typeof hook === 'function') hook(address, onRegister);
        else Interceptor.attach(address, { onEnter: function (args) {
            onRegister.call(this, args[0], args[1], args[2], args[3]);
        }});
        log('RegisterNatives hook installed at ' + address);
        // 在观察点安装以后再触发一次动态注册，确保 spawn 早期没有竞态漏报。
        if (Native.nativeRegisterJniProbe()) {
            log('JniProbe registration requested');
            // 某些 ART 构建会为不同线程提供不同的 JNIEnv 表，表槽 hook
            // 可能看不到另一个线程的调用；demo 同时回读注册结果和函数指针，
            // 让 JNI 端到端调用链仍然可以被验证。
            try {
                var probeInfo = JSON.parse(String(Native.nativeJniProbeInfo()));
                jniRegisteredState = Number(probeInfo.registered) === 1 ? 1 : 0;
                log('[jni] registered=' + probeInfo.registered +
                    ' probeTick=' + probeInfo.probeTick +
                    ' probeObject=' + probeInfo.probeObject);
                ['probeTick', 'probeObject'].forEach(function (name) {
                    var target = ptr(probeInfo[name]);
                    if (!validPtr(target)) return;
                    Interceptor.attach(target, { onEnter: function () {
                        counts.jni++;
                        counts.jniCall++;
                        sparse('jni', counts.jni, name + ' fn=' + target +
                            ' x0=' + this.x0 + ' x1=' + this.x1);
                    }});
                });
            } catch (error) { log('JniProbe fallback decode failed: ' + (error.message || error)); }
        }
    } catch (error) { log('RegisterNatives hook failed: ' + (error.message || error)); }
}

log('script loaded; waiting for Java.ready');
if (typeof Java !== 'undefined' && Java && Java.ready) {
    Java.ready(function () {
        try {
            var Native = getNative();
            configureMode(String(Native.nativeDemoMode()));
            log('selected lanes=' + modeSpec);
            setupSourceBefore = readSourceCounters();
            if (enabled('java')) installJavaHooks(Native);
            if (enabled('jnitrace')) installJniTrace(Native);
            if (enabled('c')) installNativeHook();
            if (enabled('gumtrace')) installGumTrace();
            if (kernelEnabled()) armKernelTrace();
            sourceBaseline = readSourceCounters();
            if (setupSourceBefore && sourceBaseline) {
                setupJniRegisters = counterDelta(sourceBaseline, setupSourceBefore,
                    'jni_register_successes');
            }
            // 观察者安装和内核命令下发都可能在源端已经运行后才完成；从
            // 同一个同步点记录接收计数，避免把 spawn 启动窗口误报为漏报。
            snapshotObservedCounts();
            startVerification();
            // REPL 的最终校验通过 Java.perform 路由到当前 worker；在
            // Java.ready 上下文重新绑定，确保 sourceBaseline/observed 变量
            // 属于同一个 QuickJS，而不是 raw worker 的空副本。
            globalThis.__compat_verify = verificationSnapshot;
            log('observers armed for ' + modeSpec);
        } catch (error) { log('setup failed: ' + (error.message || error)); }
    });
} else {
    log('Java API unavailable');
}
