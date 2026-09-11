package com.rustfrida.compatdemo;

/**
 * 专门给 jnitrace 模式使用的类。
 *
 * 方法故意不在 Java 层声明对应的导出 JNI 符号，而是在运行时由
 * Native.nativeRegisterJniProbe() 调用 RegisterNatives 注册。这样脚本可以
 * 直接观察真实的 JNI 注册表和函数指针。
 */
public final class JniProbe {
    public static native long probeTick(long seed);
    public static native long probeObject(int loops);

    private JniProbe() {}
}
