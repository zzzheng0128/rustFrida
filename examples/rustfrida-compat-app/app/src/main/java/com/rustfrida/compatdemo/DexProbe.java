package com.rustfrida.compatdemo;

import android.content.Context;

import dalvik.system.InMemoryDexClassLoader;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;

/** 从 assets 加载 payload.dex，但不把其中的类加入应用默认 classpath。 */
public final class DexProbe {
    private static final String PAYLOAD_CLASS = "com.rustfrida.compatdemo.payload.DexPayload";
    // 强引用最近一次的 loader，便于测试脚本在动态 Dex 创建后切换 Java.use()
    // 的查找上下文；否则 loader 可能在下一次 GC 后无法再定位。
    private static volatile ClassLoader lastLoader;
    private static volatile Context applicationContext;

    private DexProbe() {}

    /** 返回最近创建的内存 Dex loader，供脚本安装动态类 hook。 */
    public static ClassLoader getLastLoader() {
        return lastLoader;
    }

    /**
     * 保存进程级 ApplicationContext。压测线程只传基本类型，避免把跨线程
     * 的 Context JNI 句柄交给反射/Java hook 路径，触发 CheckJNI stale ref。
     */
    public static void initialize(Context context) {
        if (context != null) applicationContext = context.getApplicationContext();
    }

    /**
     * 压测专用入口只接收 int。真正的 Context 从进程级 ApplicationContext
     * 取得，避免 Java hook/反射跨线程传递 Context 造成 stale global reference。
     */
    public static String loadAndRunForStress(int seed) {
        Context context = applicationContext;
        if (context == null) return "dynamic-dex-error app-context-not-ready";
        return loadAndRun(context, seed);
    }

    public static String loadAndRun(Context context, int seed) {
        Native.nativeSourceMark(2);
        try {
            byte[] bytes;
            try (InputStream input = context.getAssets().open("payload.dex")) {
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int count;
                while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
                bytes = output.toByteArray();
            }
            ClassLoader parent = context.getClassLoader();
            ClassLoader loader = new InMemoryDexClassLoader(ByteBuffer.wrap(bytes), parent);
            lastLoader = loader;
            Class<?> payload = Class.forName(PAYLOAD_CLASS, true, loader);
            Method run = payload.getMethod("run", int.class);
            return String.valueOf(run.invoke(null, seed));
        } catch (Throwable error) {
            return "dynamic-dex-error " + error;
        }
    }
}
