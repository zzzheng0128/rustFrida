#!/system/bin/sh
# real_time_monitor.sh — 实时监控抖音+rustfrida+内核日志，异常即熔断
# 用法: sh /data/local/tmp/real_time_monitor.sh [测试时长秒，默认1800]

DURATION="${1:-1800}"
PKG="com.ss.android.ugc.aweme"
LOG_DIR="/data/local/tmp/crash_logs_$(date +%Y%m%d_%H%M%S)"
STOP_FILE="/data/local/tmp/monitor_stop"
PID_FILE="/data/local/tmp/monitor.pid"

mkdir -p "$LOG_DIR"
echo $$ > "$PID_FILE"
echo "[MONITOR] 启动实时监控，时长 ${DURATION}s，日志目录 $LOG_DIR"
echo "[MONITOR] 创建停止标记文件: touch $STOP_FILE"

# 清空旧日志缓存
logcat -c 2>/dev/null

# 启动后台 logcat 抓取
logcat -v threadtime > "$LOG_DIR/logcat_full.txt" 2>&1 &
LOGCAT_PID=$!

# 启动后台 dmesg 轮询
dmesg -w > "$LOG_DIR/dmesg_live.txt" 2>&1 &
DMESG_PID=$!

# 异常计数器
FATAL_COUNT=0
ANR_COUNT=0
TOMBSTONE_COUNT=0
RUSTFRIDA_TIMEOUT_COUNT=0
LAST_CHECK=0

# 时间标记
START_TIME=$(date +%s)

# 辅助函数
alert() {
    echo "[ALERT] $(date '+%H:%M:%S') $1" | tee -a "$LOG_DIR/alerts.txt"
}

collect_snapshot() {
    local reason="$1"
    local snap_dir="$LOG_DIR/snapshot_$(date +%H%M%S)_${reason}"
    mkdir -p "$snap_dir"
    cp "$LOG_DIR/logcat_full.txt" "$snap_dir/" 2>/dev/null
    cp "$LOG_DIR/dmesg_live.txt" "$snap_dir/" 2>/dev/null
    logcat -d -v threadtime > "$snap_dir/logcat_dump.txt" 2>/dev/null
    dmesg > "$snap_dir/dmesg_dump.txt" 2>/dev/null
    ps -A > "$snap_dir/ps.txt" 2>/dev/null
    cat /proc/meminfo > "$snap_dir/meminfo.txt" 2>/dev/null
    ls -la /data/tombstones/ > "$snap_dir/tombstones_list.txt" 2>/dev/null
    for f in /data/tombstones/tombstone_*; do
        [ -f "$f" ] && cp "$f" "$snap_dir/" 2>/dev/null && break
    done
    echo "$snap_dir"
}

cleanup_and_exit() {
    local code="$1"
    local reason="$2"
    alert "熔断退出: $reason"
    kill $LOGCAT_PID 2>/dev/null
    kill $DMESG_PID 2>/dev/null
    rm -f "$PID_FILE"
    echo "$reason" > "$LOG_DIR/exit_reason.txt"
    echo "[MONITOR] 已收集快照到 $LOG_DIR"
    echo "[MONITOR] 退出码 $code"
    exit "$code"
}

# 主循环
while true; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TIME))

    # 检查外部停止信号
    if [ -f "$STOP_FILE" ]; then
        cleanup_and_exit 0 "收到外部停止信号"
    fi

    # 检查超时
    if [ "$ELAPSED" -ge "$DURATION" ]; then
        alert "测试时间 ${DURATION}s 到达，正常结束"
        cleanup_and_exit 0 "时间到达正常结束"
    fi

    # 每分钟输出一次心跳
    if [ "$((ELAPSED - LAST_CHECK))" -ge 60 ]; then
        PID=$(pidof "$PKG" 2>/dev/null)
        MEM=$(dumpsys meminfo "$PKG" 2>/dev/null | grep "TOTAL PSS" | awk '{print $3}')
        alert "心跳 t=${ELAPSED}s PID=$PID MEM=$MEM"
        LAST_CHECK=$ELAPSED
    fi

    # ── 检查1: 抖音进程是否存活 ──
    PID=$(pidof "$PKG" 2>/dev/null)
    if [ -z "$PID" ]; then
        FATAL_COUNT=$((FATAL_COUNT + 1))
        alert "抖音进程不存在 (计数=$FATAL_COUNT)"
        if [ "$FATAL_COUNT" -ge 2 ]; then
            SNAP=$(collect_snapshot "douyin_dead")
            alert "抖音连续 ${FATAL_COUNT} 次检测不到，判定死亡。快照: $SNAP"
            cleanup_and_exit 2 "抖音进程死亡"
        fi
    else
        FATAL_COUNT=0
    fi

    # ── 检查2: logcat 中最近是否有真正的崩溃 ──
    RECENT=$(logcat -d -t 50 -v threadtime 2>/dev/null)

    # 真正的 FATAL / CRASH：排除 SIGQUIT(signal 3) 和正常 dump 日志
    if echo "$RECENT" | grep -qiE "FATAL EXCEPTION" && \
       ! echo "$RECENT" | grep -q "reacting to signal 3"; then
        ANR_COUNT=$((ANR_COUNT + 1))
        alert "检测到 FATAL/CRASH (计数=$ANR_COUNT)"
        echo "$RECENT" | grep -i "FATAL EXCEPTION" | tail -5 >> "$LOG_DIR/fatal_lines.txt"
        if [ "$ANR_COUNT" -ge 2 ]; then
            SNAP=$(collect_snapshot "fatal_crash")
            alert "连续崩溃，熔断！快照: $SNAP"
            cleanup_and_exit 3 "检测到崩溃"
        fi
    fi

    # 真正的 ANR：ActivityManager 报告的 ANR
    if echo "$RECENT" | grep -qiE "ActivityManager:.*ANR in.*$PKG|ActivityManager:.*ANR.*$PKG"; then
        alert "检测到 ANR"
        SNAP=$(collect_snapshot "anr")
        cleanup_and_exit 4 "检测到ANR"
    fi

    # libstagefright 崩溃：排除 registered intercept 等正常日志
    if echo "$RECENT" | grep -qiE "libstagefright.*crash|libstagefright.*SIG(SEGV|ABRT|ILL)" && \
       ! echo "$RECENT" | grep -q "tombstoned: registered intercept"; then
        alert "检测到 libstagefright 崩溃！"
        SNAP=$(collect_snapshot "libstagefright_crash")
        cleanup_and_exit 5 "libstagefright崩溃"
    fi

    # ── 检查3: rustfrida 清理超时 ──
    if echo "$RECENT" | grep -q "agent 清理等待超过"; then
        RUSTFRIDA_TIMEOUT_COUNT=$((RUSTFRIDA_TIMEOUT_COUNT + 1))
        alert "rustfrida 清理超时 (计数=$RUSTFRIDA_TIMEOUT_COUNT)"
        if [ "$RUSTFRIDA_TIMEOUT_COUNT" -ge 2 ]; then
            SNAP=$(collect_snapshot "rustfrida_timeout")
            cleanup_and_exit 6 "rustfrida清理超时"
        fi
    fi

    # ── 检查4: zygote 是否崩溃 ──
    ZYGOTE_PID=$(pidof zygote64 2>/dev/null)
    if [ -z "$ZYGOTE_PID" ]; then
        alert "zygote64 不存在！系统可能重启或崩溃"
        cleanup_and_exit 7 "zygote64死亡"
    fi

    # ── 检查5: 内存压力 ──
    MEM_AVAIL=$(cat /proc/meminfo | grep MemAvailable | awk '{print $2}')
    if [ -n "$MEM_AVAIL" ] && [ "$MEM_AVAIL" -lt 50000 ]; then
        alert "内存严重不足: MemAvailable=${MEM_AVAIL}KB"
        SNAP=$(collect_snapshot "low_memory")
        cleanup_and_exit 8 "内存不足"
    fi

    # 每5秒检查一次
    sleep 5
done
