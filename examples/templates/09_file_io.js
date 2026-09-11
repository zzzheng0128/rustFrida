/*
 * 文件读写模板。
 *
 * File 同时支持静态便捷函数和 new File(path, mode) 流式接口：
 *   File.readAllText / writeAllText
 *   File.readAllBytes / writeAllBytes
 *   file.readText / readBytes / write / seek / flush / close
 */
(function () {
    "use strict";

    var TAG = "file";
    var OUTPUT = "/data/local/tmp/rustfrida-file-template.log";
    function log(message) { console.log("[" + TAG + "] " + message); }

    try {
        // 流式写入后回到文件头读取，适合持续记录事件的场景。
        var file = new File(OUTPUT, "w+");
        file.write("第一行：rustFrida\n");
        file.write("第二行：File API\n");
        file.flush();
        file.seek(0, File.SEEK_SET);
        log("stream read: " + JSON.stringify(file.readText()));
        file.close();

        // 二进制便捷接口接收 ArrayBuffer、TypedArray 或 Array<number>。
        var bytes = new Uint8Array([0x52, 0x46, 0x2d, 0x42, 0x49, 0x4e]);
        var binaryPath = OUTPUT + ".bin";
        File.writeAllBytes(binaryPath, bytes);
        var roundTrip = new Uint8Array(File.readAllBytes(binaryPath));
        log("binary bytes=" + roundTrip.length + " first=0x" +
            roundTrip[0].toString(16));
        File.writeAllText(OUTPUT + ".txt", "静态写入成功\n");
        log("done: " + OUTPUT);
    } catch (error) {
        log("failed: " + (error.message || error));
    }
})();
