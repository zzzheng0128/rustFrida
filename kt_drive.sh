#!/bin/bash
# ============================================================
# kt_drive.sh — kernel-trace 一键测试驱动(host 侧,macOS)
#
# 把"构建→推送→清数据→启动 tracer→UI 驱动→采集→对账→拉日志"
# 整套手动流程固化为一条命令。
#
# 用法:
#   bash kt_drive.sh                  # 默认: trace 模式, libmetasec_ml.so, 90s
#   bash kt_drive.sh -n 270           # 专抓 process_vm_readv(宽匹配 metasec 全家)
#   bash kt_drive.sh -m hybrid -s test_kt_only.js -c -u   # 冷启动 hybrid 全流程
#
# 选项:
#   -m MODE    trace|hybrid          (默认 trace;hybrid 才会注入+跑 JS)
#   -s SCRIPT  hybrid 的 JS 脚本名    (默认 test_kt_only.js;必须在 repo 根目录)
#   -l LIB     --trace-lib 过滤       (默认 libmetasec_ml.so;逗号分隔/all/包名)
#   -n NR      --trace-nr            (默认不过滤;270=process_vm_readv)
#   -d SEC     采集时长               (默认 90)
#   -c         pm clear 冷启动        (自动跑 drive_ui.sh 点隐私弹窗+滑动)
#   -u         采集期间跑 drive_ui.sh (不清数据也可用)
#   -b         先重新构建 rust_frida  (默认只推现有 binary)
#   -p PKG     目标包名               (默认 com.ss.android.ugc.aweme)
#   -o DIR     本地输出目录           (默认 out/kt_YYYYMMDD_HHMMSS)
#   --no-kill  结束后保留 tracer 继续跑
# ============================================================
set -eo pipefail
cd "$(dirname "$0")"

MODE=trace
SCRIPT=test_kt_only.js
LIB=libmetasec_ml.so
NR=""
DUR=90
CLEAR=0
UI=0
BUILD=0
PKG=com.ss.android.ugc.aweme
OUT=""
KILL=1

while [ $# -gt 0 ]; do
    case "$1" in
        -m) MODE=$2; shift 2;;
        -s) SCRIPT=$2; shift 2;;
        -l) LIB=$2; shift 2;;
        -n) NR=$2; shift 2;;
        -d) DUR=$2; shift 2;;
        -c) CLEAR=1; shift;;
        -u) UI=1; shift;;
        -b) BUILD=1; shift;;
        -p) PKG=$2; shift 2;;
        -o) OUT=$2; shift 2;;
        --no-kill) KILL=0; shift;;
        *) echo "未知参数: $1" >&2; exit 2;;
    esac
done

[ -z "$OUT" ] && OUT="out/kt_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

DEV=/data/local/tmp
RLOG=$DEV/kt_drive.log
RJSONL=$DEV/kt_drive.jsonl
TARGET_DIR="${CARGO_TARGET_DIR:-rustfrida_target}"
case "$TARGET_DIR" in
    /*) TARGET_ROOT="$TARGET_DIR" ;;
    *) TARGET_ROOT="$PWD/$TARGET_DIR" ;;
esac
BIN="$TARGET_ROOT/aarch64-linux-android/release/rustfrida"

step() { echo ""; echo "==> $*"; }

# ---- 1. 构建(可选) ----
if [ $BUILD -eq 1 ]; then
    step "构建 rust_frida(带 kernel-trace feature)"
    CARGO_TARGET_DIR="$TARGET_DIR" bash .build-android.sh rust_frida 2>&1 | tail -3
fi
[ -f "$BIN" ] || { echo "binary 不存在: $BIN (加 -b 构建)" >&2; exit 1; }

# ---- 2. 推送 ----
step "推送 binary$( [ $MODE = hybrid ] && echo " + $SCRIPT" )"
adb push "$BIN" $DEV/rustfrida >/dev/null
adb shell "su -c 'chmod 755 $DEV/rustfrida'"
if [ "$MODE" = hybrid ]; then
    [ -f "$SCRIPT" ] || { echo "JS 不存在: $SCRIPT" >&2; exit 1; }
    adb push "$SCRIPT" "$DEV/$SCRIPT" >/dev/null
fi

# ---- 3. 设备清理(注意:pkill -f 模式绝不能匹配 su 壳自身命令行) ----
step "清理旧进程$([ $CLEAR -eq 1 ] && echo " + pm clear $PKG")"
adb shell "su -c 'pkill -x rustfrida; pkill -f \"drive_u[i]\"; pkill -f kt_ru[n]; am force-stop $PKG; sleep 1'"
if [ $CLEAR -eq 1 ]; then
    adb shell "su -c 'pm clear $PKG'" >/dev/null
    UI=1   # 冷启动必弹隐私协议,必须驱动 UI
fi
adb shell "su -c 'logcat -c; rm -f $RLOG $RJSONL'"

# ---- 4. 组装命令并启动(stdin 用 tail 吊命,防交互模式吃 EOF 自杀) ----
ARGS="--mode=$MODE --spawn $PKG --trace-lib $LIB --trace-lib-only --trace-decode-args --trace-output $RJSONL"
[ -n "$NR" ] && ARGS="$ARGS --trace-nr $NR"
[ "$MODE" = hybrid ] && ARGS="$ARGS -l $DEV/$SCRIPT"

step "启动 tracer: rustfrida $ARGS"
adb shell "su -c 'nohup sh -c \"tail -f /dev/null | $DEV/rustfrida $ARGS\" > $RLOG 2>&1 & echo UP'"
[ $UI -eq 1 ] && adb shell "su -c 'nohup sh $DEV/drive_ui.sh >/dev/null 2>&1 & echo UI_UP'"

# ---- 5. 采集(每 15s 打一次对账) ----
step "采集 ${DUR}s ..."
elapsed=0
while [ $elapsed -lt $DUR ]; do
    sleep 15; elapsed=$((elapsed+15))
    acct=$(adb shell "su -c 'grep 对账 $RLOG 2>/dev/null | tail -1'" | tr -d '\r')
    alive=$(adb shell "su -c 'pgrep -x rustfrida >/dev/null && echo Y || echo N'" | tr -d '\r')
    echo "  [${elapsed}s] tracer=$alive $acct"
    [ "$alive" = N ] && { echo "!! tracer 中途退出,日志见 $OUT"; break; }
done

# ---- 6. 汇总 ----
step "汇总"
adb shell "su -c '
echo \"--APP--\"; ps -A | grep -c \"${PKG}\$\" | head -1
echo \"--ACCT--\"; grep 对账 $RLOG | tail -2
echo \"--NR--\"; grep -o "nr=[0-9]* [a-z_]*" $RLOG | sort | uniq -c | sort -rn | head -8
echo \"--RSS--\"; for p in \$(pgrep -x rustfrida); do grep VmRSS /proc/\$p/status; done
'" 2>/dev/null | tr -d '\r' | tee "$OUT/summary.txt"

# ---- 7. 拉日志 + 截图 ----
step "拉取结果到 $OUT/"
adb exec-out "cat $RLOG" > "$OUT/trace.log" 2>/dev/null || true
adb exec-out "cat $RJSONL" > "$OUT/trace.jsonl" 2>/dev/null || true
[ -s "$OUT/trace.jsonl" ] || rm -f "$OUT/trace.jsonl"
adb exec-out screencap -p > "$OUT/screen.png" 2>/dev/null || true

if [ $KILL -eq 1 ]; then
    adb shell "su -c 'pkill -x rustfrida; pkill -f \"drive_u[i]\"'" 2>/dev/null || true
    echo "tracer 已停止(--no-kill 可保留)"
fi

echo ""
echo "==> 完成: $OUT/{trace.log,trace.jsonl,summary.txt,screen.png}"
