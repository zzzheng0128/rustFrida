#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/Users/freeman/Library/Android/sdk}}"
BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-$SDK_ROOT/build-tools/34.0.0}"
PLATFORM="${ANDROID_PLATFORM:-$SDK_ROOT/platforms/android-34/android.jar}"
TMP="${TMPDIR:-/tmp}/rf-compat-dex"
PAYLOAD_CLASSES="$TMP/classes"
PAYLOAD_OUT="$TMP/dex"
PAYLOAD_STUB_SRC="$TMP/stub-src"

# AGP resolves the SDK independently of d8, so make the selected SDK visible
# to Gradle as well as to this script.
export ANDROID_HOME="$SDK_ROOT"
export ANDROID_SDK_ROOT="$SDK_ROOT"

if [[ ! -x "$BUILD_TOOLS/d8" ]]; then
    echo "d8 not found: $BUILD_TOOLS/d8" >&2
    exit 2
fi
if [[ ! -f "$PLATFORM" ]]; then
    echo "android.jar not found: $PLATFORM" >&2
    exit 2
fi

mkdir -p "$PAYLOAD_CLASSES" "$PAYLOAD_OUT" "$PAYLOAD_STUB_SRC/com/rustfrida/compatdemo" "$ROOT/app/src/main/assets"
# DexPayload 只需要 Native.nativeSourceMark 的编译期符号。Native.java 属于
# APK 主 dex，不能把它整份打进动态 dex，否则 ART 会遇到重复类；这里生成
# 一个仅用于 javac 的 stub，打包 d8 时只放入 DexPayload.class。
cat > "$PAYLOAD_STUB_SRC/com/rustfrida/compatdemo/Native.java" <<'EOF_STUB'
package com.rustfrida.compatdemo;
public final class Native {
    public static native void nativeSourceMark(int kind);
    private Native() {}
}
EOF_STUB
javac -source 8 -target 8 -classpath "$PLATFORM" \
    -d "$PAYLOAD_CLASSES" \
    "$PAYLOAD_STUB_SRC/com/rustfrida/compatdemo/Native.java" \
    "$ROOT/payload-src/com/rustfrida/compatdemo/payload/DexPayload.java"
# 只把动态 payload 放进 jar；上面的 Native.class 仅作为 javac/d8 的解析依赖。
jar cf "$TMP/payload.jar" -C "$PAYLOAD_CLASSES" com/rustfrida/compatdemo/payload/DexPayload.class
"$BUILD_TOOLS/d8" --min-api 26 --output "$PAYLOAD_OUT" "$TMP/payload.jar"
cp "$PAYLOAD_OUT/classes.dex" "$ROOT/app/src/main/assets/payload.dex"

if [[ -n "${GRADLE_BIN:-}" ]]; then
    GRADLE=("$GRADLE_BIN")
elif command -v gradle >/dev/null 2>&1; then
    GRADLE=("$(command -v gradle)")
elif [[ -x "${HOME:-}/.gradle/wrapper/dists/gradle-8.10-bin/deqhafrv1ntovfmgh0nh3npr9/gradle-8.10/bin/gradle" ]]; then
    # Android Studio/CI 常只缓存 Gradle 分发包，不把 gradle 放进 PATH。
    # 优先使用与当前 AGP 兼容的 8.10；仍可用 GRADLE_BIN 覆盖。
    GRADLE=("$HOME/.gradle/wrapper/dists/gradle-8.10-bin/deqhafrv1ntovfmgh0nh3npr9/gradle-8.10/bin/gradle")
else
    echo "gradle/gradlew not found; set GRADLE_BIN" >&2
    exit 2
fi

"${GRADLE[@]}" -p "$ROOT" :app:assembleDebug --no-daemon
echo "APK: $ROOT/app/build/outputs/apk/debug/app-debug.apk"
