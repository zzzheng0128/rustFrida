package com.rustfrida.compatdemo;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.TypedValue;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * Standalone RustFrida compatibility target. It runs a small startup probe,
 * then starts native lanes so each tracing path has a deterministic
 * source. The app has no network or external service dependency.
 */
public final class MainActivity extends Activity {
    private static volatile MainActivity active;
    private static volatile boolean extremeMode;
    private static volatile boolean lowFrequencyMode = true;
    private static volatile String demoMode = "all";
    private final Handler handler = new Handler(Looper.getMainLooper());
    private StressRunner stress;
    private TextView output;

    public static String runDexProbe(int seed) {
        MainActivity activity = active;
        return activity == null ? "dynamic-dex-error activity-not-ready" :
                DexProbe.loadAndRun(activity, seed);
    }

    public static void configureExtremeMode(boolean enabled) {
        extremeMode = enabled;
    }

    public static void configureLowFrequencyMode(boolean enabled) {
        lowFrequencyMode = enabled;
    }

    public static void configureDemoMode(String mode) {
        demoMode = mode == null || mode.trim().isEmpty() ? "all" : mode.trim();
    }

    /** 统一给 Application、Activity 和 StressRunner 使用的通道判断。 */
    public static boolean enabled(String lane) {
        if ("all".equalsIgnoreCase(demoMode)) return true;
        if ("hwbp".equals(lane) && "hwbp-matrix".equalsIgnoreCase(demoMode)) return true;
        if ("hwbp".equals(lane) && "hwbp-rotate".equalsIgnoreCase(demoMode)) return true;
        if ("uprobe".equals(lane) && "uprobe-matrix".equalsIgnoreCase(demoMode)) return true;
        if ("uprobe".equals(lane) && "uprobe-limit".equalsIgnoreCase(demoMode)) return true;
        String[] parts = demoMode.toLowerCase().split(",");
        for (String part : parts) if (lane.equals(part.trim())) return true;
        return false;
    }

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        active = this;
        stress = new StressRunner(this);
        buildUi();
        append("[BOOT] native=" + Native.nativeInfo());

        // Start from the first application frame. The native library's
        // constructor has already run before nativeInfo() returns.
        handler.postDelayed(this::startupProbe, 250);
        handler.postDelayed(new Runnable() {
            @Override public void run() {
                if (!isFinishing()) {
                    if (enabled("hwbp")) Native.nativeHwbpBurst(1);
                    handler.postDelayed(this, 250);
                }
            }
        }, 250);
    }

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        LinearLayout buttons = new LinearLayout(this);
        buttons.setOrientation(LinearLayout.HORIZONTAL);
        Button check = button("CHECK", v -> runChecks());
        Button dex = button("LOAD DEX", v -> append("[DEX] " + runDexProbe(7)));
        Button start = button("START", v -> startStress());
        Button stop = button("STOP", v -> { if (stress != null) stress.stop(); });
        buttons.addView(check, new LinearLayout.LayoutParams(0, -2, 1));
        buttons.addView(dex, new LinearLayout.LayoutParams(0, -2, 1));
        buttons.addView(start, new LinearLayout.LayoutParams(0, -2, 1));
        buttons.addView(stop, new LinearLayout.LayoutParams(0, -2, 1));
        root.addView(buttons);
        output = new TextView(this);
        output.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        output.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(output);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(root);
    }

    private Button button(String title, View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(title);
        button.setOnClickListener(listener);
        return button;
    }

    private void startupProbe() {
        if (enabled("java") || enabled("c")) runChecks();
        if (enabled("java")) append("[DEX] " + runDexProbe(1));
        startStress();
    }

    private void runChecks() {
        new Thread(() -> append("[CHECK] " + Checks.run(this)), "rf-checks").start();
    }

    private void startStress() {
        if (stress.start(120, extremeMode, lowFrequencyMode, demoMode)) {
            append("[STRESS] started mode=" + (extremeMode ? "extreme" :
                    (lowFrequencyMode ? "low-frequency" : "normal")) +
                    " lanes=" + demoMode);
        }
    }

    private void append(String line) {
        runOnUiThread(() -> {
            if (output == null) return;
            output.append(line + "\n");
        });
    }

    @Override
    protected void onDestroy() {
        if (stress != null) stress.stop();
        active = null;
        super.onDestroy();
    }
}
