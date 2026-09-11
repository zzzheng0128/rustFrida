package com.rustfrida.compatdemo;

import android.app.Application;
import android.os.SystemClock;
import android.util.Log;

/**
 * Earliest app-owned startup path used by the compatibility experiment.
 * Loading Native here makes libcompatdemo.so and its .init_array constructor
 * run before the first Activity is created. The calls are deliberately small
 * and deterministic so a spawn-mode observer can verify the startup window.
 */
public final class CompatApplication extends Application {
    @Override
    public void onCreate() {
        long begin = SystemClock.elapsedRealtimeNanos();
        Log.i("RFCompatDemo", "[BOOT] Application.onCreate begin");
        super.onCreate();
        Native.nativeSourceMark(1);
        boolean extreme = Native.nativeExtremeEnabled();
        boolean lowFrequency = Native.nativeLowFrequencyEnabled();
        String mode = Native.nativeDemoMode();
        MainActivity.configureExtremeMode(extreme);
        MainActivity.configureLowFrequencyMode(lowFrequency && !extreme);
        MainActivity.configureDemoMode(mode);
        Log.i("RFCompatDemo", "[BOOT] stress mode=" + (extreme ? "extreme" :
                (lowFrequency ? "low-frequency" : "normal")) +
                " lanes=" + mode);
        String info = Native.nativeInfo();
        long object = MainActivity.enabled("hwbp") ? Native.nativeObjectExercise(1) : 0;
        long svc = MainActivity.enabled("svc") ? Native.nativeSvcBurst(1) : 0;
        long uprobe = MainActivity.enabled("uprobe") ? Native.nativeUprobeBurst(1) : 0;
        long hwbp = MainActivity.enabled("hwbp") ? Native.nativeHwbpBurst(1) : 0;
        long agent = (MainActivity.enabled("c") || MainActivity.enabled("java") ||
                MainActivity.enabled("gumtrace")) ? Native.nativeAgentTick() : 0;
        Log.i("RFCompatDemo", "[BOOT] Application.onCreate nativeInfo=" + info);
        Log.i("RFCompatDemo", "[BOOT] Application.onCreate object=" + object +
                " svc=" + svc + " uprobe=" + uprobe + " hwbp=" + hwbp +
                " agent=" + agent + " elapsed_ns=" +
                (SystemClock.elapsedRealtimeNanos() - begin));
        String dex = MainActivity.enabled("java") ? DexProbe.loadAndRun(this, 1) : "disabled";
        Log.i("RFCompatDemo", "[BOOT] Application.onCreate dex=" + dex);
    }
}
