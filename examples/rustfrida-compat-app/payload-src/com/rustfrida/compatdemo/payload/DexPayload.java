package com.rustfrida.compatdemo.payload;

/** 运行时从 payload.dex 加载；该类故意不放进 APK 自带的 classes.dex。 */
public final class DexPayload {
    private DexPayload() {}

    public static String run(int seed) {
        com.rustfrida.compatdemo.Native.nativeSourceMark(3);
        long value = (seed * 0x9e3779b9L) ^ 0x4458504cL;
        return "dynamic-dex-ok seed=" + seed + " value=" + Long.toHexString(value);
    }
}
