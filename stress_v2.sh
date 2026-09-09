#!/bin/bash
# ============================================================
# stress_v2.sh — rustfrida 抖音压测驱动 v2
# 新增: preflight(KPM/应用/设备清理) + 模块健康门禁 +
#       异常实时响应(5s) + 失败现场自动收集
# 用法:
#   stress_v2.sh preflight                          # 场景前检查/清理
#   stress_v2.sh <场景> <时长秒> [--wait-go]         # 跑场景（注意：没有 run 子命令）
# ============================================================
set -u
PKG=com.ss.android.ugc.aweme
ROOT="$(cd "$(dirname "$0")" && pwd)"
LOGROOT="$ROOT/stress_logs"
ADB=${ADB:-adb}

ts() { date +%H:%M:%S; }
main_pid() { $ADB shell "pidof $PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}'; }
count_matches() {
  local pattern="$1" file="$2"
  if [ -f "$file" ]; then
    grep -c "$pattern" "$file" 2>/dev/null || true
  else
    echo 0
  fi
}

# ---------- 失败现场收集 ----------
capture_incident() {
  local DIR="$1" reason="$2"
  local IDIR="$DIR/incident_$(date +%H%M%S)"
  mkdir -p "$IDIR"
  echo "$reason" > "$IDIR/REASON"
  echo "[$(ts)] !!! 异常: $reason → 收集现场到 $IDIR" | tee -a "$DIR/run.log"
  local PID=$(main_pid)
  $ADB shell "screencap -p /data/local/tmp/_incident.png" 2>/dev/null
  $ADB pull /data/local/tmp/_incident.png "$IDIR/screen.png" >/dev/null 2>&1
  if [ -n "$PID" ]; then
    timeout 25 $ADB shell "su -c 'debuggerd -b $PID'" > "$IDIR/debuggerd.txt" 2>&1
  fi
  $ADB shell "logcat -d -v threadtime" > "$IDIR/logcat_full.txt" 2>&1
  $ADB shell "su -c 'dmesg'" > "$IDIR/dmesg.txt" 2>&1
  local TOMB=$($ADB shell "su -c 'ls -t /data/tombstones/ | head -1'" | tr -d '\r')
  [ -n "$TOMB" ] && $ADB pull "/data/tombstones/$TOMB" "$IDIR/" >/dev/null 2>&1
  local ANR=$($ADB shell "su -c 'ls -t /data/anr/ 2>/dev/null | head -1'" | tr -d '\r')
  [ -n "$ANR" ] && $ADB shell "su -c 'cat /data/anr/$ANR'" > "$IDIR/anr_trace.txt" 2>&1
  for f in session.log ops.log monitor.log anr.log; do
    [ -f "$DIR/$f" ] && cp "$DIR/$f" "$IDIR/"
  done
  echo "FAIL" > "$DIR/VERDICT"
}

# ---------- preflight ----------
if [ "${1:-}" = "preflight" ]; then
  echo "[$(ts)] preflight 开始"
  # 1) su 可用
  SU=$($ADB shell "su -c 'id -u'" 2>/dev/null | tr -d '\r')
  [ "$SU" = "0" ] || { echo "FATAL: su 不可用"; exit 1; }
  # 2) rustfrida 在位
  $ADB shell "su -c 'test -x /data/local/tmp/rustfrida'" || { echo "FATAL: rustfrida 缺失"; exit 1; }
  # 3) 清掉应用与残留
  $ADB shell "su -c 'am force-stop $PKG; pkill -f rustfrida'" 2>/dev/null
  sleep 2
  LEFT=$($ADB shell "pidof $PKG" | tr -d '\r')
  [ -z "$LEFT" ] || { echo "FATAL: $PKG 未清干净 pid=$LEFT"; exit 1; }
  # 4) KPM 模块仍在（重启后需重载，由人工/脚本先行加载；这里只校验）
  KPM=$($ADB shell "su -c 'dmesg | grep -c KernelPatch'" 2>/dev/null | tr -d '\r')
  echo "[$(ts)] preflight OK (KernelPatch dmesg 行数=$KPM)"
  exit 0
fi

# ---------- run ----------
SCENARIO="${1:?need scenario}"
DURATION="${2:?need duration}"
WAIT_GO="${3:-}"
case "$DURATION" in
  ''|*[!0-9]*) echo "FATAL: duration 必须是正整数"; exit 2 ;;
  0) echo "FATAL: duration 必须大于 0"; exit 2 ;;
esac
case "$WAIT_GO" in
  ''|--wait-go) ;;
  *) echo "FATAL: 未知参数: $WAIT_GO"; exit 2 ;;
esac
TS=$(date +%Y%m%d_%H%M%S)
DIR="$LOGROOT/${SCENARIO}_${TS}"
mkdir -p "$DIR/screens"
echo "$DIR" > "$LOGROOT/.current"

log() { echo "[$(ts)] $*" | tee -a "$DIR/run.log"; }

log "=== $SCENARIO 开始(v2), 时长 ${DURATION}s, DIR=$DIR"
$ADB shell "logcat -c"
$ADB shell "svc power stayon true"
$ADB shell "input keyevent KEYCODE_WAKEUP"
$ADB shell "su -c 'am force-stop $PKG; pkill -f rustfrida'" 2>/dev/null
sleep 2
$ADB shell "su -c 'ls /data/tombstones/ | wc -l'" | tr -d '\r' > "$DIR/tombstones_baseline.txt"
log "tombstone 基线: $(cat $DIR/tombstones_baseline.txt)"

# logcat 异常流（带时间戳）
$ADB shell "logcat -v threadtime" 2>/dev/null | \
  grep -E --line-buffered "am_anr|ANR in|F libc|Fatal signal|am_proc_died.*aweme|am_kill.*aweme" | \
  while IFS= read -r line; do echo "[$(ts)] $line"; done >> "$DIR/anr.log" &
MONPID=$!; echo $MONPID > "$DIR/.monitor_pid"

# 采样循环 30s
(
  while true; do
    PID=$(main_pid)
    if [ -n "$PID" ]; then
      THREADS=$($ADB shell "ls /proc/$PID/task 2>/dev/null | wc -l" | tr -d '\r ')
      RSS=$($ADB shell "grep VmRSS /proc/$PID/status 2>/dev/null" | tr -d '\r' | awk '{print $2$3}')
      FDS=$($ADB shell "su -c \"ls /proc/$PID/fd 2>/dev/null | wc -l\"" 2>/dev/null | tr -d '\r ')
      echo "[$(ts)] pid=$PID threads=$THREADS rss=$RSS fds=$FDS" >> "$DIR/monitor.log"
    else
      echo "[$(ts)] pid=NONE" >> "$DIR/monitor.log"
    fi
    $ADB shell "screencap -p /data/local/tmp/_stress_cap.png" 2>/dev/null
    $ADB pull /data/local/tmp/_stress_cap.png "$DIR/screens/cap_$(date +%H%M%S).png" >/dev/null 2>&1
    sleep 30
  done
) &
SAMPID=$!; echo $SAMPID > "$DIR/.sample_pid"

# ---------- 异常实时响应（5s） ----------
(
  ARMED_SEEN=0
  while true; do
    sleep 5
    # 1) 目标进程死亡（go 之后才算）
    if [ -f "$DIR/go" ]; then
      PID=$(main_pid)
      if [ -z "$PID" ]; then
        capture_incident "$DIR" "目标进程消失"
        exit 99
      fi
    fi
    # 2) anr.log 出现被测包名条目
    if [ -f "$DIR/anr.log" ] && grep -q "ugc.aweme" "$DIR/anr.log" 2>/dev/null; then
      sleep 2  # 等多行落盘
      capture_incident "$DIR" "logcat 出现 aweme ANR/crash: $(grep 'ugc.aweme' "$DIR/anr.log" | head -1 | cut -c1-160)"
      exit 99
    fi
    # 3) 模块健康门禁：go 后 60s 内 session.log 必须出现 armed 标记
    if [ -f "$DIR/go" ] && [ "$ARMED_SEEN" = "0" ]; then
      GOAGE=$(( $(date +%s) - $(stat -f %m "$DIR/go") ))
      if [ -f "$DIR/session.log" ] && grep -qE "armed|Agent loaded|Agent 已连接" "$DIR/session.log" 2>/dev/null; then
        ARMED_SEEN=1
        echo "[$(ts)] 模块健康门禁通过（armed 标记确认）" >> "$DIR/run.log"
      elif [ "$GOAGE" -gt 60 ] && [ -f "$DIR/session.log" ]; then
        capture_incident "$DIR" "模块未运行：go 后 60s 内未见 armed 标记"
        exit 99
      fi
    fi
    # 4) 框架内异常检测事件（rustfrida 内建 watchdog，比 logcat ANR 快且无延迟）
    if [ -f "$DIR/session.log" ] && grep -qE "RF-EVENT.*(deadlock|_stuck|stall_confirmed|process_died|unexpected_disconnect|dstate)" "$DIR/session.log" 2>/dev/null; then
      sleep 2  # 等 auto_dump 落盘
      capture_incident "$DIR" "框架内异常事件: $(grep -E 'RF-EVENT' "$DIR/session.log" | head -1 | cut -c1-200)"
      exit 99
    fi
  done
) &
WATCHPID=$!; echo $WATCHPID > "$DIR/.watch_pid"
log "监控/采样/异常响应已启动 (mon=$MONPID samp=$SAMPID watch=$WATCHPID)"

if [ "$WAIT_GO" = "--wait-go" ]; then
  log "等待注入: 注入完成后 touch \"$DIR/go\"，并把 rustfrida 会话输出重定向到 $DIR/session.log"
  while [ ! -f "$DIR/go" ]; do sleep 2; done
  log "收到 go，开始负载"
fi

# ---------- 负载循环 ----------
END=$(( $(date +%s) + DURATION ))
i=0; LASTMD5=""; LASTCAP=""
while [ "$(date +%s)" -lt "$END" ]; do
  [ -f "$DIR/VERDICT" ] && break   # 异常响应已判失败
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
      echo "[$(ts)] skip (前台非抖音)" >> "$DIR/ops.log"
      ;;
  esac
  NEWEST=$(ls -t "$DIR/screens"/*.png 2>/dev/null | head -1)
  if [ -n "$NEWEST" ] && [ "$NEWEST" != "$LASTCAP" ]; then
    MD5=$(md5 -q "$NEWEST" 2>/dev/null)
    if [ -n "$LASTMD5" ] && [ "$MD5" = "$LASTMD5" ]; then
      echo "[$(ts)] WARN 截屏无变化 ($NEWEST)" >> "$DIR/ops.log"
    fi
    LASTMD5="$MD5"; LASTCAP="$NEWEST"
  fi
  sleep 3
done

# ---------- 收尾 ----------
kill $SAMPID $WATCHPID 2>/dev/null
sleep 1
if [ -f "$DIR/VERDICT" ]; then
  VERDICT=$(cat "$DIR/VERDICT")
  case "$VERDICT" in
    PASS|FAIL) ;;
    *)
      VERDICT="FAIL"
      echo "VERDICT 内容无效" > "$DIR/VERDICT"
      ;;
  esac
else
  VALIDATION_ERROR=""
  PID=$(main_pid)
  [ -n "$PID" ] || VALIDATION_ERROR="收尾时目标进程不存在"
  [ -s "$DIR/monitor.log" ] || VALIDATION_ERROR="${VALIDATION_ERROR:+$VALIDATION_ERROR; }没有有效监控采样"
  ls "$DIR"/screens/*.png >/dev/null 2>&1 || VALIDATION_ERROR="${VALIDATION_ERROR:+$VALIDATION_ERROR; }没有有效截图采样"
  [ "$(count_matches 'swipe\|tap' "$DIR/ops.log")" -gt 0 ] || VALIDATION_ERROR="${VALIDATION_ERROR:+$VALIDATION_ERROR; }没有执行负载操作"
  if [ "$WAIT_GO" = "--wait-go" ]; then
    [ -s "$DIR/session.log" ] || VALIDATION_ERROR="${VALIDATION_ERROR:+$VALIDATION_ERROR; }缺少会话日志"
    grep -qE "armed|Agent loaded|Agent 已连接" "$DIR/session.log" 2>/dev/null || VALIDATION_ERROR="${VALIDATION_ERROR:+$VALIDATION_ERROR; }会话未出现健康标记"
  fi

  if [ -n "$VALIDATION_ERROR" ]; then
    VERDICT="FAIL"
    echo "$VALIDATION_ERROR" > "$DIR/VERDICT"
    log "FAIL: $VALIDATION_ERROR"
  else
    VERDICT="PASS"
    echo "$VERDICT" > "$DIR/VERDICT"
  fi
fi

if [ "$VERDICT" = "PASS" ]; then
  PID=$(main_pid)
  if [ -z "$PID" ]; then
    VERDICT="FAIL"
    echo "debuggerd 采集前目标进程已退出" > "$DIR/VERDICT"
  elif ! timeout 30 $ADB shell "su -c 'debuggerd -b $PID'" > "$DIR/final_dump.txt" 2>&1; then
    VERDICT="FAIL"
    echo "debuggerd 回溯采集失败" > "$DIR/VERDICT"
    log "FAIL: debuggerd 回溯采集失败"
  else
    STUCK=$(count_matches "<unknown>" "$DIR/final_dump.txt")
    log "debuggerd 完成, unknown PC 帧数=$STUCK"
  fi
fi
kill $MONPID 2>/dev/null
if ! $ADB shell "su -c 'ls /data/tombstones/ | wc -l'" 2>/dev/null | tr -d '\r' > "$DIR/tombstones_final.txt" ||
   ! grep -qE '^[0-9]+$' "$DIR/tombstones_final.txt"; then
  VERDICT="FAIL"
  echo "tombstone 收尾计数采集失败" > "$DIR/VERDICT"
  log "FAIL: tombstone 收尾计数采集失败"
fi
$ADB shell "svc power stayon false"

{
  echo "# $SCENARIO 汇总 ($(date '+%F %T'))"
  echo "- 判定: **$VERDICT**"
  echo "- tombstone: $(cat $DIR/tombstones_baseline.txt) → $(cat $DIR/tombstones_final.txt)"
  echo "- ANR/crash 事件: $(count_matches . "$DIR/anr.log") 条"
  echo "- 负载操作: $(count_matches 'swipe' "$DIR/ops.log") swipe + $(count_matches 'tap' "$DIR/ops.log") tap"
  echo "- 截屏无变化告警: $(count_matches 'WARN' "$DIR/ops.log") 次"
  echo "- unknown PC 帧: ${STUCK:-N/A}"
  [ -d "$DIR" ] && ls -d "$DIR"/incident_* 2>/dev/null | head -3 | sed 's/^/- 现场: /'
} | tee "$DIR/summary.md"
log "=== $SCENARIO 结束 ($VERDICT)"

[ "$VERDICT" = "PASS" ]
