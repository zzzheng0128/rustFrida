#!/system/bin/sh
# Run only the companion sample in this directory, using an explicit PID filter.
set -eu
if [ "$#" -ne 1 ]; then
    echo 'Usage: sh run.sh FRESH_SAMPLE_DIRECTORY' >&2
    exit 2
fi
sample_dir=$1
for file in start finish events.jsonl sample.log tracer.log sample.pid sample.exit; do
    if [ -e "$sample_dir/$file" ]; then
        echo "Use a fresh sample directory: $file already exists." >&2
        exit 2
    fi
done
for file in sample rustfrida; do
    if [ ! -x "$sample_dir/$file" ]; then
        echo "Missing or non-executable sample file: $file" >&2
        exit 2
    fi
done
sample_pid=
tracer_pid=

fail() {
    failure_status=$1
    shift
    echo "self_trace: $*" >&2
    exit "$failure_status"
}

stop_child() {
    stopping_pid=$1
    stopping_name=$2
    if kill -0 "$stopping_pid" 2>/dev/null; then
        kill -TERM "$stopping_pid" 2>/dev/null || true
        stopping_step=0
        while kill -0 "$stopping_pid" 2>/dev/null && [ "$stopping_step" -lt 40 ]; do
            stopping_step=$((stopping_step + 1))
            sleep 0.05
        done
        if kill -0 "$stopping_pid" 2>/dev/null; then
            kill -KILL "$stopping_pid" 2>/dev/null || true
            stopping_step=0
            while kill -0 "$stopping_pid" 2>/dev/null && [ "$stopping_step" -lt 20 ]; do
                stopping_step=$((stopping_step + 1))
                sleep 0.05
            done
        fi
    fi
    if kill -0 "$stopping_pid" 2>/dev/null; then
        echo "self_trace: could not stop owned $stopping_name PID $stopping_pid within cleanup deadline" >&2
        return 1
    fi
    # Only reap after exit has been observed, so wait cannot block indefinitely.
    wait "$stopping_pid" 2>/dev/null || true
}

cleanup() {
    cleanup_status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$tracer_pid" ]; then
        if ! stop_child "$tracer_pid" tracer; then cleanup_status=1; fi
    fi
    if [ -n "$sample_pid" ]; then
        if ! stop_child "$sample_pid" sample; then cleanup_status=1; fi
    fi
    exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# This count recognizes this tracer's compact JSONL layout and complete objects.
# validate.py performs the separate strict JSON/parameter checks offline.
count_reads() {
    if [ ! -f "$sample_dir/events.jsonl" ]; then
        echo 0
        return
    fi
    if read_count=$(LC_ALL=C grep -Ec "^\{\"type\":\"svc\.enter\",.*\"pid\":$capture_pid,.*\"nr\":63,.*\}$" "$sample_dir/events.jsonl"); then
        echo "$read_count"
    else
        grep_status=$?
        if [ "$grep_status" -eq 1 ]; then echo 0; else return "$grep_status"; fi
    fi
}

"$sample_dir/sample" "$sample_dir/libktrace_sample_a.so" "$sample_dir/libktrace_sample_b.so" "$sample_dir/start" "$sample_dir/finish" < /dev/null > "$sample_dir/sample.log" 2>&1 &
sample_pid=$!
capture_pid=$sample_pid
printf '%s\n' "$sample_pid" > "$sample_dir/sample.pid"
# Both explicit sample libraries must exist before the first maps scan.
# "all" selects Android app directories; these owned fixtures live in /data/local/tmp.
i=0
while ! grep -Fxq "sample pid=$sample_pid ready" "$sample_dir/sample.log"; do
    if ! kill -0 "$sample_pid" 2>/dev/null; then cat "$sample_dir/sample.log"; fail 6 'sample exited before ready'; fi
    i=$((i + 1))
    if [ "$i" -gt 100 ]; then cat "$sample_dir/sample.log"; fail 6 'sample readiness deadline exceeded'; fi
    sleep 0.05
done
"$sample_dir/rustfrida" --mode=trace --trace-pid "$sample_pid" --trace-lib libktrace_sample_a.so,libktrace_sample_b.so --trace-lib-only --trace-decode-args --trace-output "$sample_dir/events.jsonl" < /dev/null > "$sample_dir/tracer.log" 2>&1 &
tracer_pid=$!
i=0
while ! grep -q "LIB_FILTER 激活: pid=$sample_pid " "$sample_dir/tracer.log"; do
    if ! kill -0 "$sample_pid" 2>/dev/null; then fail 7 'sample exited while waiting for tracer'; fi
    if ! kill -0 "$tracer_pid" 2>/dev/null; then cat "$sample_dir/tracer.log"; fail 7 'tracer exited before filter activation'; fi
    i=$((i + 1))
    if [ "$i" -gt 100 ]; then cat "$sample_dir/tracer.log"; fail 8 'filter activation deadline exceeded'; fi
    sleep 0.05
done
: > "$sample_dir/start"
i=0
while ! grep -Fxq "sample pid=$sample_pid done: 6400 reads, 3200 per library" "$sample_dir/sample.log"; do
    if ! kill -0 "$sample_pid" 2>/dev/null; then cat "$sample_dir/sample.log"; fail 9 'sample exited before completing all reads'; fi
    if ! kill -0 "$tracer_pid" 2>/dev/null; then fail 9 'tracer exited during workload'; fi
    i=$((i + 1))
    if [ "$i" -gt 200 ]; then fail 9 'workload completion deadline exceeded'; fi
    sleep 0.05
done

i=0
while :; do
    if ! kill -0 "$sample_pid" 2>/dev/null; then fail 10 'sample exited before records were written'; fi
    if ! kill -0 "$tracer_pid" 2>/dev/null; then fail 10 'tracer exited before records were written'; fi
    captured=$(count_reads) || fail 10 'could not count output records'
    if [ "$captured" -gt 6400 ]; then fail 10 "unexpected read count: $captured (expected 6400)"; fi
    if [ "$captured" -eq 6400 ]; then break; fi
    i=$((i + 1))
    if [ "$i" -gt 200 ]; then
        fail 10 "output deadline exceeded: $captured/6400 reads written; inspect filtering, drop and output counters"
    fi
    sleep 0.05
done

: > "$sample_dir/finish"
i=0
while kill -0 "$sample_pid" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 100 ]; then fail 11 'sample exit deadline exceeded'; fi
    sleep 0.05
done
if wait "$sample_pid"; then
    printf '0\n' > "$sample_dir/sample.exit"
    sample_pid=
else
    sample_status=$?
    printf '%s\n' "$sample_status" > "$sample_dir/sample.exit"
    sample_pid=
    fail 11 "sample exited with status $sample_status"
fi
# Freeze the artifact before the final count; this does not assume TERM flushes.
stop_child "$tracer_pid" tracer || fail 12 'tracer cleanup failed'
tracer_pid=
captured=$(count_reads) || fail 12 'could not count final output records'
if [ "$captured" -ne 6400 ]; then fail 12 "final read count changed: $captured/6400"; fi
echo "self_trace: 6400 matching read records written; run validate.py for strict offline validation"
cat "$sample_dir/sample.log"
cat "$sample_dir/tracer.log"
