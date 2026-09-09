#!/bin/bash
# rustFrida Android 构建脚本 (macOS)
# 用法: bash .build-android.sh [agent|rust_frida|all] [--ndk25|--ndk29|--emutls] [--depth-diagnostics]
# 默认 ndk25（与原始可运行产物一致，clang 14 无 TLSDESC 重定位）
set -eo pipefail
cd "$(dirname "$0")"

TARGET=${1:-all}
MODE=${2:-ndk25}
DEPTH_DIAGNOSTICS=${3:-}
if [ -n "$DEPTH_DIAGNOSTICS" ] && [ "$DEPTH_DIAGNOSTICS" != "--depth-diagnostics" ]; then
    echo "Unknown option: $DEPTH_DIAGNOSTICS" >&2
    exit 2
fi

NDK_BASE=$HOME/Library/Android/sdk/ndk
case "$MODE" in
    --ndk29|--emutls)
        NDK=$NDK_BASE/29.0.14206865
        BUILTINS_LIB="\$PREBUILT/lib/clang/21/lib/linux"
        ;;
    *)
        NDK=$NDK_BASE/25.2.9519653
        BUILTINS_LIB="\$PREBUILT/lib64/clang/14.0.7/lib/linux"
        ;;
esac
PREBUILT=$NDK/toolchains/llvm/prebuilt/darwin-x86_64
CLANG="$PREBUILT/bin/aarch64-linux-android33-clang"
PROJ=$PWD

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CLANG"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$PREBUILT/bin/llvm-ar"
export CC_aarch64_linux_android="$CLANG"
export CXX_aarch64_linux_android="$PREBUILT/bin/aarch64-linux-android33-clang++"
export AR_aarch64_linux_android="$PREBUILT/bin/llvm-ar"
export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$PREBUILT/sysroot"
export LLVM_STRIP="$PREBUILT/bin/llvm-strip"

TLSFLAG=""
CFLAG_TLS=""
BUILTINSDIR=$(eval echo "$BUILTINS_LIB")
if [ "$MODE" = "--emutls" ]; then
    TLSFLAG="-Ztls-model=emulated "
    CFLAG_TLS="-femulated-tls "
fi

export RUSTFLAGS="$TLSFLAG-L $BUILTINSDIR -l clang_rt.builtins-aarch64-android -C link-arg=-Wl,-Bstatic -C link-arg=-lclang_rt.builtins-aarch64-android -C link-arg=-Wl,-Bdynamic --remap-path-prefix=$PROJ=/rf --remap-path-prefix=$HOME/.cargo/registry/src=/cargo --remap-path-prefix=$HOME/.rustup/toolchains=/rustup"
CFLAGS="${CFLAG_TLS}-ffile-prefix-map=$PROJ=/rf -fmacro-prefix-map=$PROJ=/rf"

build() {
    local pkg=$1
    local feature_args=()
    if [ "$DEPTH_DIAGNOSTICS" = "--depth-diagnostics" ] && [ "$pkg" = "agent" ]; then
        feature_args=(--features quickjs-hook/engine-depth-diagnostics)
    fi
    if [ "$MODE" = "--emutls" ]; then
        env "CC_aarch64-linux-android=$CLANG" \
            "CXX_aarch64-linux-android=$PREBUILT/bin/aarch64-linux-android33-clang++" \
            "AR_aarch64-linux-android=$PREBUILT/bin/llvm-ar" \
            "CFLAGS_aarch64-linux-android=$CFLAGS" \
            cargo +nightly build -p "$pkg" --release "${feature_args[@]}" 2>&1 | tail -3
    else
        env "CC_aarch64-linux-android=$CLANG" \
            "CXX_aarch64-linux-android=$PREBUILT/bin/aarch64-linux-android33-clang++" \
            "AR_aarch64-linux-android=$PREBUILT/bin/llvm-ar" \
            "CFLAGS_aarch64-linux-android=$CFLAGS" \
            cargo build -p "$pkg" --release "${feature_args[@]}" 2>&1 | tail -3
    fi
}

case "$TARGET" in
    agent) build agent ;;
    rust_frida)
        # 宿主通过 include_bytes! 内嵌 agent；诊断开关必须先作用于 agent。
        if [ "$DEPTH_DIAGNOSTICS" = "--depth-diagnostics" ]; then
            build agent
        fi
        build rust_frida
        ;;
    all) build agent; build rust_frida ;;
esac

# 保留独立名称，避免随后普通构建覆盖诊断产物。
if [ "$DEPTH_DIAGNOSTICS" = "--depth-diagnostics" ] && \
    { [ "$TARGET" = "rust_frida" ] || [ "$TARGET" = "all" ]; }; then
    cp target/aarch64-linux-android/release/rustfrida \
       target/aarch64-linux-android/release/rustfrida-depth-diagnostics
    echo "Diagnostic binary: target/aarch64-linux-android/release/rustfrida-depth-diagnostics"
fi
