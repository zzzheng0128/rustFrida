'use strict';
console.log("[NF] loaded");
Java.ready(function() {
    var usleepPtr = Module.findExportByName(null, "usleep");
    var getpidPtr = Module.findExportByName(null, "getpid");
    var usleep = new NativeFunction(usleepPtr, 'int', ['uint']);
    var getpidEx = new NativeFunction(getpidPtr, 'int', [], { scheduling: 'exclusive' });
    console.log("[NF] getpid(exclusive)=" + getpidEx());
    var C = Java.use("java.lang.Runtime");
    var hits = 0;
    C.maxMemory.implementation = function() {
        hits++;
        usleep(1000); // cooperative：回调内调外部 native，让出引擎锁
        var r = this.$orig();
        if (hits % 50 === 1) console.log("[NF][HIT] maxMemory hits=" + hits + " ret=" + r);
        return r;
    };
    console.log("[NF] ARMED");
});
