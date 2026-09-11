// openat-guard KPM 的最小用户态触发器。
//
// 先在设备上创建可读测试文件，再用 KPM 控制口执行：
//   deny <目标 UID> /data/local/tmp/rustfrida-openat-demo-
// 然后 attach 本脚本。命中时 FileInputStream 应抛出 Permission denied；
// 执行 `observe` 后再次运行，应该恢复为正常读取。
'use strict';

function runOpenatProbe() {
    var path = '/data/local/tmp/rustfrida-openat-demo-file';
    try {
        var FileInputStream = Java.use('java.io.FileInputStream');
        var stream = FileInputStream.$new(path);
        console.log('[openat-demo] allow path=' + path);
        stream.close();
    } catch (e) {
        console.log('[openat-demo] open failed path=' + path + ' error=' + e);
    }
}

if (typeof Java !== 'undefined' && Java && Java.ready)
    Java.ready(runOpenatProbe);
else
    runOpenatProbe();
