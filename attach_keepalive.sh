#!/system/bin/sh
PID=$1
SCRIPT=$2
while true; do echo; sleep 1; done | /data/local/tmp/rustfrida --pid "$PID" -l "$SCRIPT"
