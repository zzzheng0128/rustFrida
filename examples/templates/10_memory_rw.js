/*
 * 内存读写模板。
 *
 * 先在 Memory.alloc() 得到的私有可写区验证读写，再按实际目标替换为
 * 已确认的地址。修改代码页前必须明确权限、长度和恢复策略；本模板不碰
 * 目标模块代码，避免把验证脚本变成不可逆补丁。
 */
(function () {
    "use strict";

    var TAG = "memory-rw";
    function log(message) { console.log("[" + TAG + "] " + message); }
    function hex(buffer) {
        var bytes = new Uint8Array(buffer);
        var out = [];
        for (var i = 0; i < bytes.length; i++) {
            out.push(("0" + bytes[i].toString(16)).slice(-2));
        }
        return out.join(" ");
    }

    try {
        var block = Memory.alloc(32);
        block.writeU32(0x12345678);
        block.add(4).writeU64(BigInt("0x1122334455667788"));
        block.add(12).writePointer(block);
        block.add(20).writeBytes(new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]));

        log("address=" + block);
        log("u32=0x" + block.readU32().toString(16));
        log("u64=" + block.add(4).readU64());
        log("pointer=" + block.add(12).readPointer());
        log("bytes=" + hex(block.readByteArray(24)));
    } catch (error) {
        log("failed: " + (error.message || error));
    }
})();
