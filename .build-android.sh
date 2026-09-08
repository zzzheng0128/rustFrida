#!/bin/bash
# rustFrida Android 构建脚本 (macOS)
# 用法: bash .build-android.sh [agent|rust_frida|all] [--ndk25|--ndk29|--emutls]
# 默认 ndk25（与原始可运行产物一致，clang 14 无 TLSDESC 重定位）
set -e
cd "$(dirname "$0")"

TARGET=${1:-all}
MODE=${2:-ndk25}

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
    TLSFLAG="-Ztls-model=emulated"
    CFLAG_TLS="-femulated-tls "
fi

export RUSTFLAGS="$TLSFLAG-L $BUILTINSDIR -l clang_rt.builtins-aarch64-android -C link-arg=-Wl,-Bstatic -C link-arg=-lclang_rt.builtins-aarch64-android -C link-arg=-Wl,-Bdynamic --remap-path-prefix=$PROJ=/rf --remap-path-prefix=$HOME/.cargo/registry/src=/cargo --remap-path-prefix=$HOME/.rustup/toolchains=/rustup"
CFLAGS="${CFLAG_TLS}-ffile-prefix-map=$PROJ=/rf -fmacro-prefix-map=$PROJ=/rf"

build() {
    pkg=$1
    if [ "$MODE" = "--emutls" ]; then
        env "CC_aarch64-linux-android=$CLANG" \
            "CXX_aarch64-linux-android=$PREBUILT/bin/aarch64-linux-android33-clang++" \
            "AR_aarch64-linux-android=$PREBUILT/bin/llvm-ar" \
            "CFLAGS_aarch64-linux-android=$CFLAGS" \
            cargo +nightly build -p "$pkg" --release 2>&1 | tail -3
    else
        env "CC_aarch64-linux-android=$CLANG" \
            "CXX_aarch64-linux-android=$PREBUILT/bin/aarch64-linux-android33-clang++" \
            "AR_aarch64-linux-android=$PREBUILT/bin/llvm-ar" \
            "CFLAGS_aarch64-linux-android=$CFLAGS" \
            cargo build -p "$pkg" --release 2>&1 | tail -3
    fi
}

case "$TARGET" in
    agent) build agent ;;
    rust_frida) build rust_frida ;;
    all) build agent; build rust_frida ;;
esac
