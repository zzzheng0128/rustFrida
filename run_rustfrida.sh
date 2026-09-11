#!/system/bin/sh
PID=$1
SCRIPT=$2
PIPE=/data/local/tmp/rf_pipe_$$
rm -f "$PIPE"
mkfifo "$PIPE" 2>/dev/null || exit 1
( while true; do echo; done ) > "$PIPE" &
BG=$!
/data/local/tmp/rustfrida --pid "$PID" -l "$SCRIPT" < "$PIPE"
kill $BG 2>/dev/null
rm -f "$PIPE"
