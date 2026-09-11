package com.rustfrida.compatdemo;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Debug;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Arrays;
import java.util.List;

/** 用于兼容性 demo 的小型、可重复环境检查。 */
public final class Checks {
    private static final List<String> ROOT_PATHS = Arrays.asList(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/adb/magisk",
            "/data/adb/ksu", "/data/adb/modules");

    private Checks() {}

    public static String run(Context context) {
        try {
            JSONObject out = new JSONObject();
            JSONObject build = new JSONObject();
            build.put("model", Build.MODEL);
            build.put("brand", Build.BRAND);
            build.put("device", Build.DEVICE);
            build.put("fingerprint", Build.FINGERPRINT);
            build.put("sdk", Build.VERSION.SDK_INT);
            build.put("debuggable", (context.getApplicationInfo().flags
                    & ApplicationInfo.FLAG_DEBUGGABLE) != 0);
            build.put("debugger", Debug.isDebuggerConnected());
            out.put("build", build);

            JSONArray roots = new JSONArray();
            for (String path : ROOT_PATHS) {
                if (new File(path).exists()) roots.put(path);
            }
            out.put("root_paths", roots);
            out.put("tracer_pid", tracerPid());
            out.put("suspicious_maps", suspiciousMaps());
            out.put("native", new JSONObject(Native.nativeCheck()));
            return out.toString();
        } catch (Throwable error) {
            return "{\"error\":" + JSONObject.quote(String.valueOf(error)) + "}";
        }
    }

    private static int tracerPid() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("TracerPid:")) return Integer.parseInt(line.substring(10).trim());
            }
        } catch (Throwable ignored) {}
        return -1;
    }

    private static JSONArray suspiciousMaps() {
        JSONArray hits = new JSONArray();
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase();
                if (lower.contains("frida") || lower.contains("gum-js") ||
                        lower.contains("xposed") || lower.contains("substrate")) {
                    hits.put(line);
                }
            }
        } catch (Throwable ignored) {}
        return hits;
    }
}
