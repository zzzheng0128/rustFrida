#!/bin/bash
# rustFrida Android 构建脚本 (macOS)
# 用法: bash .build-android.sh [agent|rust_frida|all] [--ndk25|--ndk29|--emutls] [--depth-diagnostics]
# 默认 ndk25（与原始可运行产物一致，clang 14 无 TLSDESC 重定位）
set -eo pipefail
cd "$(dirname "$0")"

PROJ=$PWD
# 统一 Android 产物目录，避免 host 二进制误嵌入另一套 target 里的旧 agent。
# 旧行为仍可显式保留：CARGO_TARGET_DIR=target bash .build-android.sh rust_frida
if [ -z "${CARGO_TARGET_DIR:-}" ]; then
    CARGO_TARGET_DIR="$PROJ/rustfrida_target"
fi
case "$CARGO_TARGET_DIR" in
    /*) CARGO_TARGET_ROOT="$CARGO_TARGET_DIR" ;;
    *) CARGO_TARGET_ROOT="$PROJ/$CARGO_TARGET_DIR" ;;
esac
export CARGO_TARGET_DIR

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
    if [ -n "$FEATURES" ]; then
        feature_args+=(--features "$FEATURES")
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
        # 宿主通过 include_bytes! 内嵌 agent；两者必须使用同一个
        # CARGO_TARGET_DIR，否则自定义 target 目录会把旧 agent 嵌进去。
        build agent
        # kernel-trace(svc/uprobe 采集)是当前主用途,--trace-* 参数全部
        # 挂在 feature 后面,漏带会得到一个"能跑但拒绝 --trace-lib 的废binary",
        # 且 cargo 按 feature 变更重链会静默覆盖掉旧的完整 binary。
        FEATURES=kernel-trace build rust_frida
        ;;
    all) build agent; build rust_frida ;;
esac

# 保留独立名称，避免随后普通构建覆盖诊断产物。
if [ "$DEPTH_DIAGNOSTICS" = "--depth-diagnostics" ] && \
    { [ "$TARGET" = "rust_frida" ] || [ "$TARGET" = "all" ]; }; then
    cp "$CARGO_TARGET_ROOT/aarch64-linux-android/release/rustfrida" \
       "$CARGO_TARGET_ROOT/aarch64-linux-android/release/rustfrida-depth-diagnostics"
    echo "Diagnostic binary: $CARGO_TARGET_ROOT/aarch64-linux-android/release/rustfrida-depth-diagnostics"
fi
