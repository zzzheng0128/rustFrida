#!/system/bin/sh
# 持久化启动 rustfrida --no-repl，脱离 adb shell 的 SIGHUP 和进程组

LOG_DIR=/data/local/tmp/stress_test_$(date +%Y%m%d_%H%M%S)
mkdir -p "$LOG_DIR"

echo "[launcher] Starting persistent rustfrida stress test..." > "$LOG_DIR/launcher.log"
echo "[launcher] LOG_DIR=$LOG_DIR" >> "$LOG_DIR/launcher.log"

# Kill old rustfrida processes
for pid in $(ps -A -o PID,NAME | grep rustfrida | grep -v grep | awk '{print $1}'); do
    echo "[launcher] Killing old rustfrida pid=$pid" >> "$LOG_DIR/launcher.log"
    kill -9 $pid 2>/dev/null
done
sleep 1

# 先加载 KPM (dysvcpit + wxshadow + hide-so) —— 不加 --no-repl，用 exit 命令让它正常退出
echo "[launcher] Loading KPM modules..." >> "$LOG_DIR/launcher.log"
(
  cd /data/local/tmp
  echo "exit" | /data/local/tmp/rustfrida --name me.bmax.apatch --load-script /data/local/tmp/apatch_kpm_load_v2.js > "$LOG_DIR/kpm_load.log" 2>&1
)
echo "[launcher] KPM load exit code=$?" >> "$LOG_DIR/launcher.log"

# 等待 KPM 稳定
sleep 3

# 启动抖音注入（setsid + nohup 双重保护，脱离 adb shell session）
echo "[launcher] Spawning Douyin with instrumentation..." >> "$LOG_DIR/launcher.log"
setsid nohup /data/local/tmp/rustfrida --no-repl --spawn com.ss.android.ugc.aweme --load-script /data/local/tmp/douyin_test_5hooks_lite.js > "$LOG_DIR/rustfrida.log" 2>&1 &
RUSTPID=$!
echo "$RUSTPID" > /data/local/tmp/stress_rustfrida.pid
echo "[launcher] rustfrida pid=$RUSTPID" >> "$LOG_DIR/launcher.log"

# 等待抖音启动
sleep 8

# 启动独立监控进程（同样 setsid + nohup）
setsid nohup sh /data/local/tmp/real_time_monitor.sh "$LOG_DIR" > "$LOG_DIR/monitor.log" 2>&1 &
MONPID=$!
echo "$MONPID" > /data/local/tmp/stress_monitor.pid
echo "[launcher] monitor pid=$MONPID" >> "$LOG_DIR/launcher.log"

# 记录启动完成标记
echo "$LOG_DIR" > /data/local/tmp/stress_active.dir
echo "[launcher] All done. LOG_DIR=$LOG_DIR" >> "$LOG_DIR/launcher.log"
