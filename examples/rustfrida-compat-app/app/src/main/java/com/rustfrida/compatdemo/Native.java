package com.rustfrida.compatdemo;

public final class Native {
    static {
        System.loadLibrary("compatdemo");
    }

    public static native String nativeInfo();
    /** 返回触发端原子计数快照，用来和 RustFrida 接收计数对账。 */
    public static native String nativeCounters();
    /** 记录 Java/Dex 源端调用：1=onCreate，2=loadAndRun，3=payload.run。 */
    public static native void nativeSourceMark(int kind);
    /** 读取运行器通过 system property 选择的实验通道。 */
    public static native String nativeDemoMode();
    /** CRC32 三阶段对照：wx、normal、wx-restore。 */
    public static native String nativeCrcPhase();
    public static native boolean nativeExtremeEnabled();
    /** 低频档开关；运行器默认打开，便于逐条查看事件和现场。 */
    public static native boolean nativeLowFrequencyEnabled();
    public static native String nativeCheck();
    /** mkpm 演示探针：在本 App 内触发 raw SVC、procfs、socket、mmap 和线程路径。 */
    public static native String nativeKpmProbe();
    public static native long nativeSvcBurst(int loops);
    public static native long nativeUprobeBurst(int loops);
    public static native long nativeUprobeMatrixBurst(int loops);
    /** 轮询一组可调数量的独立软件探针入口，做 1/4/8/16/32 阶梯压测。 */
    public static native long nativeUprobeLimitBurst(int loops);
    public static native int nativeUprobeTargetCount();
    public static native String nativeUprobeMatrixInfo();
    public static native long nativeHwbpBurst(int loops);
    public static native long nativeAgentTick();
    public static native long nativeObjectExercise(int loops);
    /** 通过 RegisterNatives 动态注册 JniProbe 的两个 JNI 方法。 */
    public static native boolean nativeRegisterJniProbe();
    public static native boolean nativeJniProbeRegistered();
    /** 返回动态注册的 JNI 方法地址，供 demo 脚本在表 hook 不可用时核对。 */
    public static native String nativeJniProbeInfo();
    /** 返回当前调用线程 JNIEnv 表中的 RegisterNatives 地址。 */
    public static native String nativeJniRegisterNativesAddress();
    // 结构体方法实验：调用、切换函数指针，以及 JS hook 的握手控制。
    public static native long nativeMethodExercise(int loops);
    public static native long nativeMethodSwitch(int variant);
    public static native void nativeMethodGate(boolean enabled);
    public static native void nativeMethodHookReady();

    private Native() {}
}
