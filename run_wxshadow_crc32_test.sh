#!/bin/sh
# run_wxshadow_crc32_test.sh —— 一键跑 wxshadow CRC32 bypass 验证
# 用法：./run_wxshadow_crc32_test.sh
# 流程（基于 kpctl/apkpm —— 工具链在 /Users/freeman/project/douyin/dyidre/tools/kpctl/）：
#   1) apkpm hello 验证 KernelPatch 通信
#   2) apkpm list 确认 wxshadow.kpm 已装（不在则尝试 load；失败要真 key）
#   3) 选 attach 目标（默认 system_server）
#   4) rustfrida attach + 跑 test_wxshadow_crc32_bypass.js
#   5) 收集 dmesg + 摘要

set -u

SERIAL=${ANDROID_SERIAL:-18201FDF6002GR}
DEVICE_SH="adb -s ${SERIAL} shell"
DEVICE_SU="adb -s ${SERIAL} shell su -c"
ADB="/Users/freeman/Library/Android/sdk/platform-tools/adb"

LOG_DIR="/tmp/wxshadow_crc32_test_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"
MAIN_LOG="$LOG_DIR/run.log"

echo "[$(date +%H:%M:%S)] === wxshadow crc32 bypass test (serial=$SERIAL) ===" | tee -a "$MAIN_LOG"
echo "[$(date +%H:%M:%S)] log dir = $LOG_DIR" | tee -a "$MAIN_LOG"

# ---------- 1) KernelPatch 通信验证 ----------
echo "[$(date +%H:%M:%S)] [STEP1] apkpm hello — KP 通信" | tee -a "$MAIN_LOG"
$DEVICE_SU "apkpm hello 2>&1" 2>&1 | tee -a "$MAIN_LOG" | head -3

# ---------- 2) unload → load wxshadow（验完整 apkpm 链路）----------
echo "[$(date +%H:%M:%S)] [STEP2] apkpm unload → load wxshadow.kpm" | tee -a "$MAIN_LOG"

# 先卸（已装的话）
$DEVICE_SU "apkpm unload wxshadow 2>&1" 2>&1 | tee -a "$MAIN_LOG" | head -3

# 再装
echo "[$(date +%H:%M:%S)]   apkpm load /data/local/tmp/wxshadow.kpm ..." | tee -a "$MAIN_LOG"
$DEVICE_SU "apkpm load /data/local/tmp/wxshadow.kpm 2>&1" 2>&1 | tee -a "$MAIN_LOG" | head -5

# 确认已装
echo "[$(date +%H:%M:%S)]   apkpm list:" | tee -a "$MAIN_LOG"
$DEVICE_SU "apkpm list 2>&1" 2>&1 | tee -a "$MAIN_LOG" | head -10

WX_PRESENT=$($DEVICE_SU "apkpm list 2>&1" 2>&1 | grep -c '^wxshadow$')
if [ "$WX_PRESENT" = "0" ]; then
    echo "[$(date +%H:%M:%S)]   FAIL: unload+load 后 wxshadow 仍没起来，看上一步日志" | tee -a "$MAIN_LOG"
    exit 1
fi

# ---------- 3) 选 attach 目标 ----------
# 优先 system_server（libc + libart 都被重度使用、不被安全 SDK 监控、且重 attach 不易触发 KPM 残留冲突）。
TARGET_PID=$($DEVICE_SH pidof system_server)
if [ -z "$TARGET_PID" ]; then
    TARGET_PID=$($DEVICE_SH pidof com.android.shell)
fi
if [ -z "$TARGET_PID" ]; then
    echo "[$(date +%H:%M:%S)]   FAIL: 无可用 attach 目标" | tee -a "$MAIN_LOG"
    exit 1
fi
TARGET_NAME=$($DEVICE_SH "cat /proc/$TARGET_PID/cmdline 2>/dev/null | tr '\0' ' '" | head -1)
echo "[$(date +%H:%M:%S)]   目标 PID=$TARGET_PID ($TARGET_NAME)" | tee -a "$MAIN_LOG"

# ---------- 4) rustfrida attach + 执行测试脚本 ----------
# 用空喂管道保活 110s（rustfrida REPL 检测 stdin 关闭会主动退出）
echo "[$(date +%H:%M:%S)] [STEP3] rustfrida attach + 跑 test_wxshadow_crc32_bypass.js" | tee -a "$MAIN_LOG"
( sleep 110 ) | $DEVICE_SU "/data/local/tmp/rustfrida --pid $TARGET_PID --load-script /data/local/tmp/test_wxshadow_crc32_bypass.js" > "$LOG_DIR/rustfrida.log" 2>&1 || true

echo "[$(date +%H:%M:%S)] [STEP4] rustfrida log 摘要" | tee -a "$MAIN_LOG"
grep -E "\[CRC\]|=====|VERDICT|FOUND|MISS|crc32_bypass" "$LOG_DIR/rustfrida.log" | head -100 | tee -a "$MAIN_LOG"

echo "[$(date +%H:%M:%S)] [STEP5] dmesg（wxshadow 内部行为）" | tee -a "$MAIN_LOG"
$DEVICE_SU "dmesg | grep -iE 'wxshadow|shadow|hook_attach' | tail -30" > "$LOG_DIR/dmesg_wxshadow.log" 2>&1 || true
cat "$LOG_DIR/dmesg_wxshadow.log" | tee -a "$MAIN_LOG"

echo "[$(date +%H:%M:%S)] === 完成 ===" | tee -a "$MAIN_LOG"
echo "[$(date +%H:%M:%S)]   完整日志: $LOG_DIR" | tee -a "$MAIN_LOG"
echo "[$(date +%H:%M:%S)]   rustfrida.log : $LOG_DIR/rustfrida.log" | tee -a "$MAIN_LOG"