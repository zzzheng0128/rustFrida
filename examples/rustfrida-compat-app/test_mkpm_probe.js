// compat-demo 的 mkpm 集成探针。
//
// 所有动作都在 app/src/main/cpp/native_demo.c 的 nativeKpmProbe() 中完成；
// 这里仅通过 Java bridge 调用一次并打印 JSON。这样可以单独观察 kpctl
// 对 syscall、hide、redirect 等模块的开关效果，不依赖任何外部 App。
'use strict';

function runProbe() {
    try {
        var Native = Java.use('com.rustfrida.compatdemo.Native');
        var result = Native.nativeKpmProbe();
        console.log('[mkpm-probe] ' + result);
    } catch (e) {
        console.log('[mkpm-probe] failed: ' + (e.stack || e));
    }
}

if (typeof Java !== 'undefined' && Java && Java.ready)
    Java.ready(runProbe);
else
    runProbe();
