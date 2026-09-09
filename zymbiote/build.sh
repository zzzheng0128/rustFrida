#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 查找 NDK clang（多路径 fallback：Linux/macOS Android Studio 默认路径）
NDK_BASE=""
for candidate in "$HOME/Android/Sdk/ndk" "$HOME/Library/Android/sdk/ndk" /opt/android-sdk/ndk /usr/local/lib/android/sdk/ndk; do
    if [ -d "$candidate" ]; then
        NDK_BASE="$candidate"
        break
    fi
done

NDK_CC=""
if [ -n "$NDK_BASE" ]; then
    NDK_CC=$(find "$NDK_BASE" -name "aarch64-linux-android33-clang" 2>/dev/null | sort -V | tail -1)
    if [ -z "$NDK_CC" ]; then
        # 尝试其他 API level
        NDK_CC=$(find "$NDK_BASE" -name "aarch64-linux-android*-clang" 2>/dev/null | grep -v '++' | sort -V | tail -1)
    fi
fi

if [ -z "$NDK_CC" ]; then
    echo "错误: 未找到 Android NDK clang，请确认 NDK 已安装在 ~/Android/Sdk/ndk/ 或 ~/Library/Android/sdk/ndk/"
    exit 1
fi

echo "使用 NDK clang: $NDK_CC"

mkdir -p build

$NDK_CC -shared -nostdlib \
    -Wl,-T,helper.lds \
    -fvisibility=hidden \
    -fno-function-sections \
    -fno-data-sections \
    -fno-asynchronous-unwind-tables \
    -Os \
    -o build/zymbiote.elf \
    zymbiote.c

echo "编译完成: build/zymbiote.elf"
ls -la build/zymbiote.elf
