'use strict';

// ============================================================
// frida_syscall_monitor.js —— 纯 Frida 用户态 SVC 监控（无需 KernelPatch/KPM）
// 修复：comm() 在 hook callback 中触发 read 递归 → 改为全局缓存
// ============================================================

console.log("[SYSCALL-MON] Loading userland syscall monitor (no KernelPatch required)");

var SC_MON = {
    enabled: true,
    verbose: true,
    capturePath: true,
    seq: 0,
    dropped: 0,
    ring: [],
    ringCap: 128,
    hooks: [],

    log: function (tag, msg) {
        if (this.verbose) console.log("[SC-MON::" + tag + "] " + msg);
    }
};

function isNullPtr(ptr) {
    if (!ptr) return true;
    if (typeof ptr.toInt32 === 'function') return ptr.toInt32() === 0;
    return ptr.toString() === '0x0';
}

function tid() {
    return Process.getCurrentThreadId();
}

// 全局缓存进程名，避免在 hook callback 中读取 /proc/self/comm 触发 read 递归
var _cachedComm = "?";
try {
    var _fd = new File("/proc/self/comm", "r");
    _cachedComm = _fd.readLine().trim();
    _fd.close();
} catch (e) {
    _cachedComm = "?";
}

function comm() {
    return _cachedComm;
}

function readCStringSafe(ptrAddr, maxLen) {
    if (!ptrAddr || isNullPtr(ptrAddr)) return null;
    try {
        return ptrAddr.readCString() || "";
    } catch (e) {
        return "<fault>";
    }
}

function hexDump(addr, len) {
    if (!addr || isNullPtr(addr) || len <= 0) return "";
    try {
        var bytes = Memory.readByteArray(addr, Math.min(len, 64));
        var view = new Uint8Array(bytes);
        var hex = "";
        for (var i = 0; i < view.length; i++) {
            hex += (view[i] < 16 ? "0" : "") + view[i].toString(16);
        }
        return hex;
    } catch (e) {
        return "<fault>";
    }
}

function sockaddrToString(addr, addrlen) {
    if (!addr || isNullPtr(addr) || !addrlen) return null;
    try {
        var family = addr.readU16();
        if (family === 2) {
            var port = ((addr.add(2).readU16() & 0xFF) << 8) | ((addr.add(2).readU16() >> 8) & 0xFF);
            var ip = addr.add(4).readByteArray(4);
            var ipView = new Uint8Array(ip);
            return ipView[0] + "." + ipView[1] + "." + ipView[2] + "." + ipView[3] + ":" + port;
        } else if (family === 10) {
            return "[ipv6]";
        } else if (family === 1) {
            var path = addr.add(2).readCString() || "";
            return "unix:" + path;
        }
        return "family=" + family;
    } catch (e) {
        return "<parse-fault>";
    }
}

function record(ev) {
    if (!SC_MON.enabled) return;
    SC_MON.seq++;
    ev.seq = SC_MON.seq;
    ev.tid = tid();
    ev.tgid = Process.id;
    ev.comm = comm();
    ev.ts = Date.now();

    SC_MON.ring.push(ev);
    if (SC_MON.ring.length > SC_MON.ringCap) {
        SC_MON.ring.shift();
        SC_MON.dropped++;
    }

    var line = "seq=" + ev.seq +
        " nr=" + (ev.nr || ev.name) +
        " tid=" + ev.tid +
        " tgid=" + ev.tgid +
        " ret=" + ev.ret +
        " comm=" + ev.comm;
    if (ev.path) line += " path=" + ev.path;
    if (ev.addr) line += " addr=" + ev.addr;
    if (ev.bufHex) line += " buf=" + ev.bufHex;
    SC_MON.log("EVENT", line);
}

function hookOpenat() {
    var symbols = ["openat", "openat64", "__openat", "__openat64"];
    var addr = null;
    for (var i = 0; i < symbols.length; i++) {
        addr = Module.findExportByName("libc.so", symbols[i]);
        if (addr && !isNullPtr(addr)) break;
    }
    if (!addr || isNullPtr(addr)) {
        SC_MON.log("HOOK", "openat not found in libc.so");
        return;
    }

    SC_MON.log("HOOK", "openat @ " + addr);
    var listener = Interceptor.attach(addr, {
        onEnter: function (args) {
            this.dirfd = args[0].toInt32();
            this.pathname = readCStringSafe(args[1], 256);
            this.flags = args[2].toInt32();
        },
        onLeave: function (retval) {
            record({
                name: "openat",
                nr: 56,
                ret: retval.toInt32(),
                path: SC_MON.capturePath ? this.pathname : null,
                a0: this.dirfd,
                a1: this.flags
            });
        }
    });
    SC_MON.hooks.push({ name: "openat", listener: listener });
}

function hookReadWrite(name, nr) {
    var addr = Module.findExportByName("libc.so", name);
    if (!addr || isNullPtr(addr)) {
        SC_MON.log("HOOK", name + " not found");
        return;
    }

    SC_MON.log("HOOK", name + " @ " + addr);
    var listener = Interceptor.attach(addr, {
        onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.count = args[2].toInt32();
        },
        onLeave: function (retval) {
            var ret = retval.toInt32();
            var ev = {
                name: name,
                nr: nr,
                ret: ret,
                a0: this.fd,
                a1: this.count
            };
            if (ret > 0 && ret <= 4096) {
                ev.bufHex = hexDump(this.buf, Math.min(ret, 32));
            }
            record(ev);
        }
    });
    SC_MON.hooks.push({ name: name, listener: listener });
}

function hookConnect() {
    var addr = Module.findExportByName("libc.so", "connect");
    if (!addr || isNullPtr(addr)) {
        SC_MON.log("HOOK", "connect not found");
        return;
    }

    SC_MON.log("HOOK", "connect @ " + addr);
    var listener = Interceptor.attach(addr, {
        onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.addr = args[1];
            this.addrlen = args[2].toInt32();
            this.addrStr = sockaddrToString(this.addr, this.addrlen);
        },
        onLeave: function (retval) {
            record({
                name: "connect",
                nr: 203,
                ret: retval.toInt32(),
                a0: this.fd,
                addr: this.addrStr
            });
        }
    });
    SC_MON.hooks.push({ name: "connect", listener: listener });
}

function hookSendtoRecvfrom(name, nr) {
    var addr = Module.findExportByName("libc.so", name);
    if (!addr || isNullPtr(addr)) {
        SC_MON.log("HOOK", name + " not found");
        return;
    }

    SC_MON.log("HOOK", name + " @ " + addr);
    var listener = Interceptor.attach(addr, {
        onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.len = args[2].toInt32();
            this.flags = args[3].toInt32();
            this.addr = args[4];
            this.addrlen = args[5] ? args[5].readU32() : 0;
            this.addrStr = sockaddrToString(this.addr, this.addrlen);
        },
        onLeave: function (retval) {
            var ret = retval.toInt32();
            var ev = {
                name: name,
                nr: nr,
                ret: ret,
                a0: this.fd,
                a1: this.len,
                addr: this.addrStr
            };
            if (ret > 0 && ret <= 4096) {
                ev.bufHex = hexDump(this.buf, Math.min(ret, 32));
            }
            record(ev);
        }
    });
    SC_MON.hooks.push({ name: name, listener: listener });
}

function hookMmap() {
    var addr = Module.findExportByName("libc.so", "mmap");
    if (!addr || isNullPtr(addr)) return;
    SC_MON.log("HOOK", "mmap @ " + addr);
    var listener = Interceptor.attach(addr, {
        onEnter: function (args) {
            this.addr_hint = args[0];
            this.len = args[1].toInt32();
            this.prot = args[2].toInt32();
            this.flags = args[3].toInt32();
            this.fd = args[4].toInt32();
            this.offset = args[5].toInt32();
        },
        onLeave: function (retval) {
            record({
                name: "mmap",
                nr: 222,
                ret: retval.toInt32(),
                a0: this.fd,
                a1: this.len,
                a2: this.prot,
                a3: this.flags
            });
        }
    });
    SC_MON.hooks.push({ name: "mmap", listener: listener });
}

function installHooks() {
    SC_MON.log("INIT", "Installing hooks ...");
    hookOpenat();
    hookReadWrite("read", 63);
    hookReadWrite("write", 64);
    hookConnect();
    hookSendtoRecvfrom("sendto", 206);
    hookSendtoRecvfrom("recvfrom", 207);
    hookMmap();
    SC_MON.log("INIT", "Installed " + SC_MON.hooks.length + " hooks");
}

function uninstallHooks() {
    SC_MON.hooks.forEach(function (h) {
        if (h.listener) h.listener.detach();
    });
    SC_MON.hooks = [];
    SC_MON.log("INIT", "All hooks detached");
}

installHooks();

rpc.exports = rpc.exports || {};
rpc.exports.syscallMon = {
    status: function () {
        return {
            enabled: SC_MON.enabled,
            hooks: SC_MON.hooks.length,
            events: SC_MON.seq,
            dropped: SC_MON.dropped,
            ringSize: SC_MON.ring.length
        };
    },
    read: function (afterSeq, limit) {
        var result = [];
        var start = afterSeq || 0;
        var count = 0;
        for (var i = SC_MON.ring.length - 1; i >= 0; i--) {
            if (SC_MON.ring[i].seq > start) {
                result.unshift(SC_MON.ring[i]);
                count++;
                if (limit && count >= limit) break;
            }
        }
        return { events: result, next: SC_MON.seq };
    },
    start: function () { SC_MON.enabled = true; return "ok"; },
    stop: function () { SC_MON.enabled = false; return "ok"; },
    clear: function () { SC_MON.ring = []; SC_MON.seq = 0; SC_MON.dropped = 0; return "ok"; }
};
