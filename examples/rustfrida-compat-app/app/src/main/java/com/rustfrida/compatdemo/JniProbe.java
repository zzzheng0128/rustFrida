package com.rustfrida.compatdemo;

/**
 * 专门给 jnitrace 模式使用的类。
 *
 * 方法故意不在 Java 层声明对应的导出 JNI 符号，而是在运行时由
 * Native.nativeRegisterJniProbe() 调用 RegisterNatives 注册。这样脚本可以
 * 直接观察真实的 JNI 注册表和函数指针。
 */
public final class JniProbe {
    // 这些字段和构造函数只为 native JNI exercise 提供稳定的反射/字段目标。
    // 它们不是业务状态，改变后不会影响其他实验通道。
    public int exerciseInt;
    public Object exerciseObject;
    public static int exerciseStaticInt;
    public static Object exerciseStaticObject;

    public static native long probeTick(long seed);
    public static native long probeObject(int loops);
    /** 主动调用一组 JNI 1.6 表槽，便于 jnitrace 模式验证实际命中。 */
    public static native long probeExercise(int rounds);

    public JniProbe() {}
}
