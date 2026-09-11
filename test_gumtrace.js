// Douyin 350101 MetaSec probe — target-scoped exeVMInner GumTrace.
//
// This is a standalone Frida 17 script. It deliberately does not depend on
// metasec_probe_350101.js or its runner. It combines a one-shot raw GumTrace
// with compact JSON events at the VM control points needed by the generic VMP
// runtime work.
//
// Optional configuration before this file is loaded:
//
//   globalThis.METASEC_GUM_EXEVM_CONFIG = {
//     vmCodeOffset: "0x1f7860", // code_ptr - libmetasec_ml.so base
//     rawGumTrace: true,        // false = only structured events
//     maxStepEvents: 12000,
//     // Interior VM instruction hooks are opt-in: they can destabilize other
//     // VM programs before the target code is reached.
//     enableStructuredPoints: false
//   };
//
// Structured event lines start with `[vm35]` and can be separated from the
// raw GumTrace log without heuristic `br x8` pairing.

(function () {
    "use strict";

    var TARGET_MODULE = "libmetasec_ml.so";
    var OFF_EXEVMINNER = 0x4cc10;
    var GUMTRACE_SO = "/data/local/tmp/libGumTrace.so";
    // trace 日志放 /data/local/tmp（该目录 drwxrwx--x，其他应用只能穿越不能列目录，
    // 比放应用私有目录更隐蔽）。应用进程无权在该目录创建文件，必须先由 root 预创建：
    //   su -c 'touch /data/local/tmp/gumtrace.log && chmod 666 /data/local/tmp/gumtrace.log'
    var TRACE_FILE = "/data/local/tmp/gumtrace.log";
    function isNullPtr(p) {
        if (p === null || p === undefined) return true;
        if (typeof p === "bigint") return p === BigInt(0);
        if (typeof p === "number") return p === 0;
        try { return p.isNull(); } catch (_) { return false; }
    }
    var GUMTRACE_MODE = 2; // 0=Stand, 1=DEBUG, 2=STABLE

    var rootCfg = globalThis.METASEC_GUM_EXEVM_CONFIG || {};

    function parseOffset(value, fallback) {
        if (value === undefined || value === null || String(value).trim() === "") {
            return fallback >>> 0;
        }
        var parsed = typeof value === "number" ? value : parseInt(String(value), 0);
        if (!isFinite(parsed) || parsed < 0 || parsed > 0xffffffff) {
            throw new Error("invalid vmCodeOffset: " + value);
        }
        return parsed >>> 0;
    }

    function positiveInt(value, fallback) {
        var n = value === undefined || value === null ? fallback : parseInt(String(value), 10);
        return isFinite(n) && n > 0 ? n : fallback;
    }

    var TARGET_VM_CODE_OFFSET = parseOffset(rootCfg.vmCodeOffset, 0x1f7860);
    var ENABLE_RAW_GUMTRACE = rootCfg.rawGumTrace !== false;
    // This is deliberately opt-in.  Attaching Interceptor hooks to interior
    // dispatch/handler instructions perturbs every exeVMInner invocation, not
    // only the selected code pointer.  First obtain a stable raw trace with
    // the entry gate alone; enable these only for a focused follow-up.
    var ENABLE_STRUCTURED_POINTS = rootCfg.enableStructuredPoints === true;
    var MAX_STEP_EVENTS = positiveInt(rootCfg.maxStepEvents, 12000);

    // These are libmetasec_ml.so-relative offsets for build 350.101.
    var OFF = {
        vmInit: 0x4cd94,
        dispatcherEnter: 0x4ce54,
        dispatcherBranch: 0x4ce94,
        callReg: 0x4f830,
        callLinkWritten: 0x4f85c,
        jmpReg: 0x4f860,
        controlTarget: 0x4f884,
        hostRoute: 0x4f918,
        hostGateCall: 0x4f93c,
        hostReturn: 0x4f940,
        pcCommit: 0x4f8cc,
        hostCallback: 0x125b2c,
        vmExit: 0x5792c,
        // P1: these appeared in the small VM capture and are not implemented
        // by the portable runtime yet. Raw GumTrace provides the memory side.
        unknown0b: 0x5685c,
        unknown13: 0x55fd4,
        unknown2e: 0x565e0,
        unknown3e: 0x55d20,
        // Regression witnesses for recently recovered encodings.
        st64: 0x561b4,
        sll64: 0x4cf20
    };

    var moduleBase = null;
    var moduleSize = 0;
    var entryListener = null;
    var pointListeners = [];
    var gumtraceLoaded = false;
    var gumtraceInit = null;
    var gumtraceRun = null;
    var gumtraceUnrun = null;
    var tracing = false;
    var tracedOnce = false;
    var nextRunId = 1;
    var activeRunStacks = Object.create(null);

    function log(message) {
        console.log("[gum-exevm-350101] " + message);
    }

    function emit(kind, run, fields) {
        var event = {
            event: kind,
            run: run ? run.id : null,
            tid: run ? run.tid : currentTid(),
            seq: run ? run.seq : null
        };
        var key;
        for (key in fields) {
            if (Object.prototype.hasOwnProperty.call(fields, key)) event[key] = fields[key];
        }
        console.log("[vm35] " + JSON.stringify(event));
    }

    function currentTid() {
        try {
            return Process.getCurrentThreadId();
        } catch (_) {
            return 0;
        }
    }

    function stackForTid(tid, create) {
        var key = String(tid);
        var stack = activeRunStacks[key];
        if (!stack && create) {
            stack = [];
            activeRunStacks[key] = stack;
        }
        return stack || null;
    }

    function currentRun() {
        var stack = stackForTid(currentTid(), false);
        return stack && stack.length ? stack[stack.length - 1] : null;
    }

    function pushRun(run) {
        stackForTid(run.tid, true).push(run);
    }

    function popRun(run) {
        var stack = stackForTid(run.tid, false);
        if (!stack) return;
        for (var i = stack.length - 1; i >= 0; --i) {
            if (stack[i] === run) {
                stack.splice(i, 1);
                break;
            }
        }
        if (stack.length === 0) delete activeRunStacks[String(run.tid)];
    }

    function ctxPtr(ctx, name) {
        try {
            if (ctx && ctx[name] !== undefined && ctx[name] !== null) return ptr(ctx[name]);
        } catch (_) {
        }
        return null;
    }

    function ptrText(value) {
        try {
            return value === null || value === undefined ? null : ptr(value).toString();
        } catch (_) {
            return null;
        }
    }

    function samePtr(left, right) {
        try {
            return left !== null && right !== null && ptr(left).equals(ptr(right));
        } catch (_) {
            return false;
        }
    }

    function moduleOffset(value) {
        if (moduleBase === null || value === null || value === undefined) return null;
        try {
            var offset = ptr(value).sub(moduleBase).toUInt32();
            return offset < moduleSize ? "0x" + offset.toString(16) : null;
        } catch (_) {
            return null;
        }
    }

    function moduleOffsetNumber(value) {
        if (moduleBase === null || value === null || value === undefined) return null;
        try {
            var offset = ptr(value).sub(moduleBase).toUInt32();
            return offset < moduleSize ? offset : null;
        } catch (_) {
            return null;
        }
    }

    function readPtr(address) {
        try {
            return ptr(address).readPointer();
        } catch (_) {
            return null;
        }
    }

    function vmPc(ctx) {
        var pcPtr = ctxPtr(ctx, "x28");
        return pcPtr === null ? null : readPtr(pcPtr);
    }

    function readRegs(ctx) {
        var bank = ctxPtr(ctx, "x27");
        if (bank === null) return null;
        var regs = [];
        for (var i = 0; i < 32; ++i) {
            regs.push(ptrText(readPtr(bank.add(i * 8))));
        }
        return regs;
    }

    function wordFromContext(ctx) {
        var x22 = ctxPtr(ctx, "x22");
        if (x22 === null) return null;
        try {
            return x22.toUInt32();
        } catch (_) {
            return null;
        }
    }

    function wordFields(word) {
        if (word === null) return { word: null, op: null, subop: null };
        return {
            word: "0x" + (word >>> 0).toString(16),
            op: word & 0x3f,
            subop: (word >>> 6) & 0x3f
        };
    }

    function controlTargetSlot(word) {
        if (word === null || (word & 0x3f) !== 0x11) return null;
        var subop = (word >>> 6) & 0x3f;
        if (subop === 0x32) return (word >>> 27) & 0x1f; // CALL_REG
        if (subop === 0x1e) return (word >>> 22) & 0x1f; // JMP_REG
        return null;
    }

    function snapshotRunState(ctx, includeRegs) {
        var bank = ctxPtr(ctx, "x27");
        var pcPtr = ctxPtr(ctx, "x28");
        var state = {
            reg_bank: ptrText(bank),
            pc_ptr: ptrText(pcPtr),
            pc: ptrText(vmPc(ctx))
        };
        if (includeRegs) state.regs = readRegs(ctx);
        return state;
    }

    function loadGumTrace() {
        if (!ENABLE_RAW_GUMTRACE || gumtraceLoaded) return true;

        var gumModule;
        try {
            // tagged=true: memfd 隐身加载。maps 里只显示
            // memfd:jit-code-cache-libGumTrace.so（与 ART 的 dalvik-jit-code-cache
            // 同类），不出现 /data/local/tmp 真实路径。文件名本身可任意改。
            gumModule = Module.load(GUMTRACE_SO, 2, true);
        } catch (e) {
            log("Module.load failed: " + e);
            return false;
        }

        try {
            // Frida 17：Module.load() 返回 Module 对象。
            // getExportByName() 找不到符号会抛异常，不会返回 null。
            var initPtr = gumModule.getExportByName("init");
            var runPtr = gumModule.getExportByName("run");
            var unrunPtr = gumModule.getExportByName("unrun");

            gumtraceInit = new NativeFunction(
                initPtr, "void", ["pointer", "pointer", "int", "pointer"]
            );
            gumtraceRun = new NativeFunction(runPtr, "void", []);
            gumtraceUnrun = new NativeFunction(unrunPtr, "void", []);

            gumtraceLoaded = true;
            log("GumTrace loaded: init=" + initPtr +
                " run=" + runPtr + " unrun=" + unrunPtr);
            return true;
        } catch (e) {
            log("GumTrace export lookup failed: " + e);
            return false;
        }
    }

    function startRawTrace() {
        if (!ENABLE_RAW_GUMTRACE) return true;
        if (!loadGumTrace()) return false;
        var names = Memory.allocUtf8String(TARGET_MODULE);
        var output = Memory.allocUtf8String(TRACE_FILE);
        var options = Memory.alloc(8);
        options.writeU64(BigInt(GUMTRACE_MODE));
        gumtraceInit(names, output, 0, options);
        gumtraceRun();
        return true;
    }

    function stopRawTrace() {
        if (!ENABLE_RAW_GUMTRACE || !gumtraceLoaded) return;
        try {
            gumtraceUnrun();
            log("raw trace stopped: " + TRACE_FILE);
        } catch (e) {
            log("unrun exception: " + e);
        }
    }

    var skipOffsets = {};
    if (Array.isArray(rootCfg.skipPointOffsets)) {
        rootCfg.skipPointOffsets.forEach(function (o) {
            skipOffsets["0x" + (parseInt(String(o), 16) >>> 0).toString(16)] = true;
        });
    }
    function hookPoint(offset, handler) {
        if (skipOffsets["0x" + (offset >>> 0).toString(16)]) {
            log("skip hook 0x" + offset.toString(16));
            return;
        }
        pointListeners.push(Interceptor.attach(moduleBase.add(offset), {
            onEnter: function () {
                var run = currentRun();
                if (run === null) return;
                try {
                    handler(run, this.context || this);
                } catch (e) {
                    emit("VM_PROBE_ERROR", run, { offset: "0x" + offset.toString(16), error: String(e) });
                }
            }
        }));
    }

    function installStructuredPoints() {
        hookPoint(OFF.vmInit, function (run, ctx) {
            emit("VM_INIT", run, snapshotRunState(ctx, true));
        });

        hookPoint(OFF.dispatcherEnter, function (run, ctx) {
            if (run.stepCount >= MAX_STEP_EVENTS) {
                if (!run.stepLimitReported) {
                    run.stepLimitReported = true;
                    emit("VM_STEP_LIMIT", run, { max_step_events: MAX_STEP_EVENTS });
                }
                return;
            }
            run.stepCount += 1;
            run.seq += 1;
            var fields = wordFields(wordFromContext(ctx));
            var state = snapshotRunState(ctx, false);
            fields.seq = run.seq;
            fields.pc_before = state.pc;
            fields.reg_bank = state.reg_bank;
            fields.pc_ptr = state.pc_ptr;
            run.lastStep = fields;
            emit("VM_STEP", run, fields);
        });

        // At `br x8`, x8 is the fully resolved native handler.
        hookPoint(OFF.dispatcherBranch, function (run, ctx) {
            var handler = ctxPtr(ctx, "x8");
            var fields = wordFields(wordFromContext(ctx));
            fields.handler = ptrText(handler);
            fields.handler_off = moduleOffset(handler);
            fields.pc = ptrText(vmPc(ctx));
            emit("VM_DISPATCH", run, fields);
        });

        hookPoint(OFF.callReg, function (run, ctx) {
            emit("VM_CALL_REG", run, wordFields(wordFromContext(ctx)));
        });

        hookPoint(OFF.callLinkWritten, function (run, ctx) {
            var word = wordFromContext(ctx);
            var linkSlot = word === null ? null : (word >>> 12) & 0x1f;
            var bank = ctxPtr(ctx, "x27");
            emit("VM_CALL_LINK", run, {
                word: wordFields(word).word,
                link_slot: linkSlot,
                link_value: bank === null || linkSlot === null ? null : ptrText(readPtr(bank.add(linkSlot * 8))),
                pc: ptrText(vmPc(ctx))
            });
        });

        hookPoint(OFF.jmpReg, function (run, ctx) {
            emit("VM_JMP_REG", run, wordFields(wordFromContext(ctx)));
        });

        // +0x4f884 is deliberately used rather than +0x4f880: its ldr has
        // executed, so x8 is already the resolved control target.
        hookPoint(OFF.controlTarget, function (run, ctx) {
            var word = wordFromContext(ctx);
            var target = ctxPtr(ctx, "x8");
            var hostGate = ctxPtr(ctx, "x1");
            var exitGate = ctxPtr(ctx, "x7");
            var route = "VM_PC";
            if (samePtr(target, hostGate)) route = "HOST_CALL";
            else if (samePtr(target, exitGate)) route = "VM_EXIT";
            var fields = wordFields(word);
            fields.target_slot = controlTargetSlot(word);
            fields.target = ptrText(target);
            fields.target_off = moduleOffset(target);
            fields.x1_host_gate = ptrText(hostGate);
            fields.x7_exit_gate = ptrText(exitGate);
            fields.route = route;
            fields.pc = ptrText(vmPc(ctx));
            run.lastControl = fields;
            emit("VM_CONTROL_TARGET", run, fields);
        });

        hookPoint(OFF.hostRoute, function (run, ctx) {
            var word = wordFromContext(ctx);
            emit("VM_HOST_ROUTE", run, {
                pc: ptrText(vmPc(ctx)),
                target: run.lastControl ? run.lastControl.target : null,
                target_slot: run.lastControl ? run.lastControl.target_slot : null,
                link_slot: word === null ? null : (word >>> 12) & 0x1f
            });
        });

        hookPoint(OFF.hostGateCall, function (run, ctx) {
            var gateway = ctxPtr(ctx, "x8");
            emit("VM_HOST_GATE_CALL", run, {
                gateway: ptrText(gateway),
                gateway_off: moduleOffset(gateway),
                x0: ptrText(ctxPtr(ctx, "x0")),
                x1: ptrText(ctxPtr(ctx, "x1")),
                x2: ptrText(ctxPtr(ctx, "x2")),
                x3: ptrText(ctxPtr(ctx, "x3"))
            });
        });

        hookPoint(OFF.hostCallback, function (run, ctx) {
            var callback = ctxPtr(ctx, "x2");
            emit("VM_HOST_CALLBACK", run, {
                callback: ptrText(callback),
                callback_off: moduleOffset(callback),
                x0: ptrText(ctxPtr(ctx, "x0")),
                x1: ptrText(ctxPtr(ctx, "x1"))
            });
        });

        hookPoint(OFF.hostReturn, function (run, ctx) {
            emit("VM_HOST_RETURN", run, {
                result_x0: ptrText(ctxPtr(ctx, "x0")),
                pc: ptrText(vmPc(ctx))
            });
        });

        hookPoint(OFF.pcCommit, function (run, ctx) {
            emit("VM_PC_COMMIT", run, { pc_after: ptrText(vmPc(ctx)) });
        });

        hookPoint(OFF.vmExit, function (run, ctx) {
            emit("VM_EXIT", run, snapshotRunState(ctx, true));
        });

        function unknownOpcodeHandler(name) {
            return function (run, ctx) {
                var fields = wordFields(wordFromContext(ctx));
                fields.handler = name;
                fields.pc = ptrText(vmPc(ctx));
                fields.regs = readRegs(ctx);
                emit("VM_UNRESOLVED_OPCODE", run, fields);
            };
        }

        // 危险观察点（hook 会干扰 VM 执行导致 SIGSEGV，默认禁用）
        if (rootCfg.enableUnknownOpHooks === true) {
            hookPoint(OFF.unknown0b, unknownOpcodeHandler("0x0b@0x5685c"));
            hookPoint(OFF.unknown13, unknownOpcodeHandler("0x13@0x55fd4"));
            hookPoint(OFF.unknown2e, unknownOpcodeHandler("0x2e@0x565e0"));
            hookPoint(OFF.unknown3e, unknownOpcodeHandler("0x3e@0x55d20"));

            hookPoint(OFF.st64, function (run, ctx) {
                emit("VM_REGRESSION_ST64", run, wordFields(wordFromContext(ctx)));
            });
            hookPoint(OFF.sll64, function (run, ctx) {
                emit("VM_REGRESSION_SLL64", run, wordFields(wordFromContext(ctx)));
            });
        }
    }

    function installAtBase(base, size) {
        if (moduleBase !== null) return;
        moduleBase = base;
        moduleSize = size;
        if (ENABLE_STRUCTURED_POINTS) {
            installStructuredPoints();
        }

        var entry = moduleBase.add(OFF_EXEVMINNER);
        log("base=" + moduleBase + " size=0x" + moduleSize.toString(16) +
            " exeVMInner=" + entry + " target_vm_code=0x" + TARGET_VM_CODE_OFFSET.toString(16) +
            " raw_gumtrace=" + ENABLE_RAW_GUMTRACE +
            " structured_points=" + ENABLE_STRUCTURED_POINTS);

        entryListener = Interceptor.attach(entry, {
            onEnter: function (args) {
                var codePtr = args[0];
                var codeOffset = moduleOffsetNumber(codePtr);
                if (codeOffset !== TARGET_VM_CODE_OFFSET || tracedOnce || tracing) {
                    this.run = null;
                    return;
                }

                tracedOnce = true;
                tracing = true;
                var ctx = this.context || this;
                var run = {
                    id: nextRunId++,
                    tid: currentTid(),
                    seq: 0,
                    stepCount: 0,
                    stepLimitReported: false,
                    lastStep: null,
                    lastControl: null
                };
                this.run = run;
                pushRun(run);
                emit("VM_ENTER", run, {
                    module: TARGET_MODULE,
                    module_base: ptrText(moduleBase),
                    code_ptr: ptrText(codePtr),
                    code_offset: "0x" + codeOffset.toString(16),
                    x1: ptrText(args[1]),
                    x2: ptrText(args[2]),
                    x3: ptrText(args[3]),
                    x4: ptrText(args[4]),
                    lr: ptrText(ctxPtr(ctx, "lr") || ctxPtr(ctx, "x30"))
                });

                if (!startRawTrace()) {
                    emit("VM_TRACE_ERROR", run, { error: "raw GumTrace start failed" });
                    tracing = false;
                    popRun(run);
                    this.run = null;
                    return;
                }
                log("target VM trace started run=" + run.id);
            },
            onLeave: function (retval) {
                var run = this.run;
                if (run === null || run === undefined) return;
                emit("VM_LEAVE", run, { retval: ptrText(retval), step_events: run.stepCount });
                stopRawTrace();
                tracing = false;
                popRun(run);
            }
        });
    }

    function findTargetModule() {
        try {
            return Process.findModuleByName(TARGET_MODULE);
        } catch (_) {
            return null;
        }
    }

    function findGlobalExport(name) {
        try {
            if (typeof Module.findGlobalExportByName === "function") {
                var globalExport = Module.findGlobalExportByName(name);
                if (globalExport !== null) return globalExport;
            }
        } catch (_) {
        }
        try {
            var global = Module.findExportByName(null, name);
            if (global !== null) return global;
        } catch (_) {
        }
        // __loader_* 等符号在 linker/libdl 内部，逐个模块找
        var mods = ["libdl.so", "libdl_android.so", "linker64", "linker", "libc.so"];
        for (var mi = 0; mi < mods.length; ++mi) {
            try {
                var mod = Process.getModuleByName(mods[mi]);
                var exports = mod.enumerateExports();
                for (var ei = 0; ei < exports.length; ++ei) {
                    if (exports[ei].name === name) return exports[ei].address;
                }
            } catch (_) {
            }
        }
        return null;
    }

    function waitForTargetModule() {
        var existing = findTargetModule();
        if (existing !== null) {
            installAtBase(existing.base, existing.size);
            return;
        }

        var loaderInstalled = false;
        ["android_dlopen_ext", "dlopen", "__loader_android_dlopen_ext", "__loader_dlopen"].forEach(function (name) {
            var loader = findGlobalExport(name);
            if (loader === null) return;
            try {
                Interceptor.attach(loader, {
                    onEnter: function (args) {
                        try {
                            this.path = args[0].readCString();
                        } catch (_) {
                            this.path = "";
                        }
                    },
                    onLeave: function () {
                        if (moduleBase !== null || String(this.path || "").indexOf(TARGET_MODULE) < 0) return;
                        var install = function () {
                            var target = findTargetModule();
                            if (target === null) {
                                log("loader returned but " + TARGET_MODULE + " base is still unavailable");
                                return;
                            }
                            installAtBase(target.base, target.size);
                        };
                        if (typeof setImmediate === "function") setImmediate(install);
                        else install();
                    }
                });
                loaderInstalled = true;
            } catch (e) {
                log("failed to watch " + name + ": " + e);
            }
        });
        log(loaderInstalled ? "waiting for " + TARGET_MODULE : "cannot find a dlopen export");

        // 轮询兜底：metasec 可能绕过 dlopen 自加载（open+mmap 手动重定位），
        // dlopen 钩子抓不到，只能靠周期性扫 maps。引擎无 setTimeout/setImmediate，
        // 寄生在多个热函数上按 1s 节流轮询（mmap 启动期热、epoll_wait 交互期热、
        // openat 文件 IO），全部段映射完成（size 达标≈加载完毕）才安装，
        // 避免在 loader 重定位/自检前提前打补丁。命中或安装完成即全部摘除。
        var pollListeners = [];
        var lastPoll = 0;
        var stopPoll = function () {
            pollListeners.forEach(function (l) { try { l.detach(); } catch (_) {} });
            pollListeners = [];
        };
        var pollCheck = function () {
            if (moduleBase !== null) { stopPoll(); return; }
            var now = Date.now();
            if (now - lastPoll < 1000) return;
            lastPoll = now;
            var target = findTargetModule();
            if (target !== null && target.size >= 0x200000) {
                log("found " + TARGET_MODULE + " via poll (size=0x" + target.size.toString(16) + ")");
                installAtBase(target.base, target.size);
                stopPoll();
            }
        };
        // 注意：不要挂 mmap——启动期过热，attach 时等 in-flight 可能挂死 JS worker。
        var pollCarriers = ["openat", "epoll_wait"];
        pollCarriers.forEach(function (fname) {
            var fptr = findGlobalExport(fname);
            if (isNullPtr(fptr)) return;
            try {
                pollListeners.push(Interceptor.attach(fptr, { onEnter: function () { pollCheck(); } }));
            } catch (e) {
                log("poll hook on " + fname + " failed: " + e);
            }
        });
        log("poll armed on " + pollListeners.length + " carriers, now=" + Date.now());
    }

    log("standalone loaded; vmCodeOffset=0x" + TARGET_VM_CODE_OFFSET.toString(16));
    waitForTargetModule();
})();
