'use strict';
function hexAt(ptr, n) {
    var s = "";
    try {
        var u = new Uint8Array(Memory.readByteArray(ptr, n));
        for (var i = 0; i < u.length; i++) s += ("0" + u[i].toString(16)).slice(-2);
    } catch (e) { s = "ERR:" + (e.message || e); }
    return s;
}
var libc = Module.findBaseAddress("libc.so");
console.log("[DUMP] libc_base=" + libc);
// malloc @ vaddr 0x45880 (崩溃路径), 连续 96 字节
console.log("[DUMP] malloc=" + hexAt(libc.add(0x45880), 96));
// scudo 相关: malloc 前后再扫 0x45880±0x2000 里有没有 B/BL 到匿名页的补丁痕迹
var found = 0;
for (var off = 0x44000; off < 0x60000 && found < 6; off += 4) {
    try {
        var w = Memory.readU32(libc.add(off));
        // B imm26: 0x14000000 掩码 0xFC000000
        if ((w & 0xFC000000) === 0x14000000) {
            var imm = (w & 0x03FFFFFF) << 2;
            if (imm & 0x08000000) imm -= 0x10000000 << 2;
            var target = libc.add(off + imm);
            // 跳到 libc 映射范围之外 = 可疑补丁
            var mod = Process.findModuleByAddress(target);
            if (!mod || mod.name.indexOf("libc") === -1) {
                console.log("[DUMP] SUSPECT branch at libc+" + off.toString(16) + " -> " + target + " mod=" + (mod ? mod.name : "anon"));
                found++;
            }
        }
    } catch (e) {}
}
console.log("[DUMP] scan done, suspects=" + found);
