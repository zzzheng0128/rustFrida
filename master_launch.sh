#!/system/bin/sh
# master_launch.sh v4 — 稳定版: tail -f -n 0 管道 + 等待抖音启动后再监控
# 用法: su -c 'sh /data/local/tmp/master_launch.sh [测试时长秒]'

DURATION="${1:-1800}"
PKG="com.ss.android.ugc.aweme"
LOG_DIR="/data/local/tmp/stress_test_$(date +%Y%m%d_%H%M%S)"
STOP_FILE="/data/local/tmp/stop_stress_test"
KEEPALIVE="/data/local/tmp/keepalive"
mkdir -p "$LOG_DIR"

log() {
    echo "[MASTER $(date '+%H:%M:%S')] $1" | tee -a "$LOG_DIR/master.log"
}

swipe_feed() {
    input swipe 540 2000 540 800 200 2>/dev/null
    sleep 0.5
    input swipe 540 800 540 2000 200 2>/dev/null
    sleep 0.5
}

# ── 0. 清理 ──
log "清理旧进程..."
rm -f "$STOP_FILE"
# 关键：清空 keepalive，避免旧 exit 被读取
> "$KEEPALIVE"
for p in $(pidof rustfrida 2>/dev/null); do
    kill -9 $p 2>/dev/null
    log "  killed old rustfrida pid=$p"
done
am force-stop "$PKG" 2>/dev/null
sleep 1

# ── 1. 加载 KPM ──
log "加载 KPM..."
echo "exit" | /data/local/tmp/rustfrida --name me.bmax.apatch --load-script /data/local/tmp/apatch_kpm_load_v2.js > "$LOG_DIR/kpm_load.log" 2>&1
log "KPM 加载完成"

KPM_LIST=$(dmesg | grep -iE "wxshadow|hide.so|kpm|dysvcpit" | tail -10 2>/dev/null)
if [ -n "$KPM_LIST" ]; then
    log "KPM 内核日志:"
    echo "$KPM_LIST" | tee -a "$LOG_DIR/master.log"
fi

# ── 2. 启动 rustfrida spawn (tail -f -n 0 只读新内容) ──
log "启动 rustfrida spawn: $PKG"
tail -f -n 0 "$KEEPALIVE" | /data/local/tmp/rustfrida --spawn "$PKG" --load-script /data/local/tmp/douyin_test_5hooks_lite.js > "$LOG_DIR/rustfrida.log" 2>&1 &
RF_PID=$!
log "rustfrida PID=$RF_PID"

# 等待抖音启动并稳定
log "等待抖音启动..."
for i in $(seq 1 30); do
    if [ -n "$(pidof "$PKG" 2>/dev/null)" ]; then
        log "抖音已启动，pid=$(pidof $PKG)"
        break
    fi
    sleep 1
done
sleep 5

# ── 3. 启动监控 ──
log "启动实时监控 (${DURATION}s)..."
nohup sh /data/local/tmp/real_time_monitor.sh "$DURATION" > "$LOG_DIR/monitor.log" 2>&1 &
MON_PID=$!
log "监控 PID=$MON_PID"

echo "$MON_PID $RF_PID" > /data/local/tmp/stress_test_pids

# ── 4. 主控循环 ──
START=$(date +%s)
LAST_HEARTBEAT=0
LAST_SWIPE=0
while true; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START))

    if [ "$((ELAPSED - LAST_HEARTBEAT))" -ge 30 ]; then
        DOUYIN_PID=$(pidof "$PKG" 2>/dev/null)
        MEM=$(dumpsys meminfo "$PKG" 2>/dev/null | grep "TOTAL PSS" | awk '{print $3}')
        log "heartbeat t=${ELAPSED}s douyin_pid=$DOUYIN_PID mem=$MEM"
        LAST_HEARTBEAT=$ELAPSED
    fi

    if [ "$((ELAPSED - LAST_SWIPE))" -ge 30 ]; then
        if [ -n "$(pidof "$PKG" 2>/dev/null)" ]; then
            swipe_feed > /dev/null 2>&1 &
        fi
        LAST_SWIPE=$ELAPSED
    fi

    if [ -f "$STOP_FILE" ]; then
        log "收到停止信号"
        break
    fi

    if ! kill -0 $MON_PID 2>/dev/null; then
        log "监控脚本已退出 (异常)"
        cat "$LOG_DIR/monitor.log" >> "$LOG_DIR/master.log" 2>/dev/null
        break
    fi

    if [ -z "$(pidof rustfrida 2>/dev/null)" ]; then
        log "rustfrida 已退出"
        break
    fi

    if [ "$ELAPSED" -ge "$DURATION" ]; then
        log "时间到达 ${DURATION}s，测试完成"
        break
    fi

    sleep 5
done

# ── 5. 优雅停止 rustfrida ──
log "发送 exit 到 rustfrida..."
echo "exit" >> "$KEEPALIVE"
for i in $(seq 1 45); do
    if [ -z "$(pidof rustfrida 2>/dev/null)" ]; then
        log "rustfrida 已正常退出"
        break
    fi
    sleep 1
done
if [ -n "$(pidof rustfrida 2>/dev/null)" ]; then
    log "强制终止 rustfrida"
    kill -9 $(pidof rustfrida 2>/dev/null) 2>/dev/null
fi

# 停止监控
kill $MON_PID 2>/dev/null

# ── 6. 收集日志 ──
log "收集日志..."
for f in /data/tombstones/tombstone_*; do
    [ -f "$f" ] && cp "$f" "$LOG_DIR/" 2>/dev/null
done
logcat -d -v threadtime > "$LOG_DIR/logcat_final.txt" 2>/dev/null
dmesg > "$LOG_DIR/dmesg_final.txt" 2>/dev/null
ps -A > "$LOG_DIR/ps_final.txt" 2>/dev/null

# ── 7. 结果 ──
log "===== 测试结束 ====="
log "日志目录: $LOG_DIR"
log " rustfrida.log: $(wc -l < "$LOG_DIR/rustfrida.log" 2>/dev/null || echo 0) 行"
log " monitor.log: $(wc -l < "$LOG_DIR/monitor.log" 2>/dev/null || echo 0) 行"
log " alerts.txt: $(wc -l < "$LOG_DIR/alerts.txt" 2>/dev/null || echo 0) 行"
log " tombstones: $(ls "$LOG_DIR"/tombstone_* 2>/dev/null | wc -l) 个"

if [ -f "$LOG_DIR/alerts.txt" ]; then
    log "关键告警:"
    tail -20 "$LOG_DIR/alerts.txt" | while read line; do
        log "  $line"
    done
fi
if [ -f "$LOG_DIR/exit_reason.txt" ]; then
    log "退出原因: $(cat "$LOG_DIR/exit_reason.txt")"
fi

echo "RESULT_DIR=$LOG_DIR"
