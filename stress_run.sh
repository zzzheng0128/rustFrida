#!/bin/bash
# ============================================================
# stress_run.sh — rustfrida 抖音压测驱动脚本
# 用法:
#   stress_run.sh <场景名> <时长秒> [--wait-go]
#     --wait-go: init 后等待 $DIR/go 文件出现再开始负载（用于手动注入）
#   stress_run.sh collect          # 手动收尾（debuggerd + 汇总）
# 产物: stress_logs/<场景>_<时间戳>/ 下的 run/ops/monitor/anr/截屏/dump/summary
# ============================================================
set -u
PKG=com.ss.android.ugc.aweme
ROOT="$(cd "$(dirname "$0")" && pwd)"
LOGROOT="$ROOT/stress_logs"
ADB=${ADB:-adb}

ts() { date +%H:%M:%S; }

main_pid() {
  $ADB shell "pidof $PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}'
}

cmd="${1:-}"
case "$cmd" in
  collect) shift; do_collect "$@" ; exit $? ;;
  ""|-h|--help) grep '^#' "$0" | head -8; exit 0 ;;
esac

SCENARIO="$cmd"
DURATION="${2:?need duration seconds}"
WAIT_GO="${3:-}"
TS=$(date +%Y%m%d_%H%M%S)
DIR="$LOGROOT/${SCENARIO}_${TS}"
mkdir -p "$DIR/screens"
echo "$DIR" > "$LOGROOT/.current"

log() { echo "[$(ts)] $*" | tee -a "$DIR/run.log"; }

# ---------- init ----------
log "=== $SCENARIO 开始, 时长 ${DURATION}s, DIR=$DIR"
$ADB shell "logcat -c"
$ADB shell "svc power stayon true"
$ADB shell "input keyevent KEYCODE_WAKEUP"
$ADB shell "su -c 'am force-stop $PKG'"
sleep 2
$ADB shell "su -c 'ls /data/tombstones/ | wc -l'" | tr -d '\r' > "$DIR/tombstones_baseline.txt"
log "tombstone 基线: $(cat $DIR/tombstones_baseline.txt)"

# ---------- logcat ANR/crash 监控（后台） ----------
$ADB shell "logcat -v threadtime" 2>/dev/null | \
  grep -E --line-buffered "am_anr|ANR in|F libc|Fatal signal|am_proc_died.*aweme|am_kill.*aweme" | \
  while IFS= read -r line; do echo "[$(ts)] $line"; done >> "$DIR/anr.log" &
MONPID=$!
echo $MONPID > "$DIR/.monitor_pid"
log "logcat 监控已启动 (pid=$MONPID)"

# ---------- 采样循环（后台）：每 30s 记 ps/线程/RSS/FD，每 60s 截屏 ----------
(
  i=0
  while true; do
    i=$((i+1))
    PID=$(main_pid)
    if [ -n "$PID" ]; then
      THREADS=$($ADB shell "ls /proc/$PID/task 2>/dev/null | wc -l" | tr -d '\r ')
      RSS=$($ADB shell "grep VmRSS /proc/$PID/status 2>/dev/null" | tr -d '\r' | awk '{print $2$3}')
      FDS=$($ADB shell "su -c \"ls /proc/$PID/fd 2>/dev/null | wc -l\"" 2>/dev/null | tr -d '\r ')
      WCHAN=$($ADB shell "cat /proc/$PID/wchan 2>/dev/null" | tr -d '\r')
      echo "[$(ts)] pid=$PID threads=$THREADS rss=$RSS fds=$FDS wchan=$WCHAN" >> "$DIR/monitor.log"
    else
      echo "[$(ts)] pid=NONE (进程不存在)" >> "$DIR/monitor.log"
    fi
    if [ $((i % 2)) -eq 1 ]; then
      $ADB shell "screencap -p /data/local/tmp/_stress_cap.png" 2>/dev/null
      $ADB pull /data/local/tmp/_stress_cap.png "$DIR/screens/cap_$(date +%H%M%S).png" >/dev/null 2>&1
    fi
    sleep 30
  done
) &
SAMPID=$!
echo $SAMPID > "$DIR/.sample_pid"
log "采样循环已启动 (pid=$SAMPID)"

# ---------- 等待 go 标记（手动注入窗口） ----------
if [ "$WAIT_GO" = "--wait-go" ]; then
  log "等待注入: 请执行注入后 touch \"$DIR/go\""
  while [ ! -f "$DIR/go" ]; do sleep 2; done
  log "收到 go，开始负载"
fi

# ---------- 负载循环 ----------
END=$(( $(date +%s) + DURATION ))
i=0
LASTMD5=""
LASTCAP=""
while [ "$(date +%s)" -lt "$END" ]; do
  i=$((i+1))
  TOP=$($ADB shell "dumpsys activity activities 2>/dev/null | grep 'topResumedActivity' | head -1")
  case "$TOP" in
    *$PKG*)
      $ADB shell "input swipe 540 1800 540 600 400"
      echo "[$(ts)] swipe #$i" >> "$DIR/ops.log"
      if [ $((i % 10)) -eq 0 ]; then
        $ADB shell "input tap 540 1200"
        echo "[$(ts)] tap #$((i/10))" >> "$DIR/ops.log"
      fi
      ;;
    *)
      echo "[$(ts)] skip (前台非抖音: $(echo $TOP | grep -o 'topResumedActivity.*' | cut -c1-80))" >> "$DIR/ops.log"
      ;;
  esac
  # P3 响应性：仅当出现「新」截屏文件时才与上一张比较 md5
  NEWEST=$(ls -t "$DIR/screens"/*.png 2>/dev/null | head -1)
  if [ -n "$NEWEST" ] && [ "$NEWEST" != "$LASTCAP" ]; then
    MD5=$(md5 -q "$NEWEST" 2>/dev/null)
    if [ -n "$LASTMD5" ] && [ "$MD5" = "$LASTMD5" ]; then
      echo "[$(ts)] WARN 截屏无变化 ($NEWEST)" >> "$DIR/ops.log"
    fi
    LASTMD5="$MD5"
    LASTCAP="$NEWEST"
  fi
  sleep 3
done
log "负载结束 ($i 次操作)"

# ---------- 收尾 ----------
kill $SAMPID 2>/dev/null
sleep 1
PID=$(main_pid)
if [ -n "$PID" ]; then
  log "收集 debuggerd 回溯 pid=$PID"
  $ADB shell "su -c 'debuggerd -b $PID'" > "$DIR/final_dump.txt" 2>&1
  STUCK=$(grep -c "<unknown>" "$DIR/final_dump.txt" 2>/dev/null || echo 0)
  log "debuggerd 完成, unknown PC 帧数=$STUCK"
else
  log "WARN 收尾时进程不存在"
fi
kill $MONPID 2>/dev/null
$ADB shell "ls /data/tombstones/ | wc -l" | tr -d '\r' > "$DIR/tombstones_final.txt"
$ADB shell "svc power stayon false"

# ---------- 汇总 ----------
{
  echo "# $SCENARIO 汇总 ($(date '+%F %T'))"
  echo "- tombstone: $(cat $DIR/tombstones_baseline.txt) → $(cat $DIR/tombstones_final.txt)"
  echo "- ANR/crash 事件: $(grep -c . "$DIR/anr.log" 2>/dev/null || echo 0) 条（见 anr.log）"
  echo "- 负载操作: $(grep -c 'swipe\|tap' "$DIR/ops.log" 2>/dev/null || echo 0) 次"
  echo "- 截屏无变化告警: $(grep -c 'WARN' "$DIR/ops.log" 2>/dev/null || echo 0) 次"
  echo "- unknown PC 帧: ${STUCK:-N/A}"
  echo "- 最终进程: ${PID:-NONE}"
} | tee "$DIR/summary.md"
log "=== $SCENARIO 结束"
