#!/system/bin/sh
# service.sh - Auto-load dysvcpit.kpm after boot
# Waits for APatch app, then injects via rustfrida to load KPM

LOGFILE="/data/local/tmp/dysvcpit-autoload.log"
KPM_PATH="/data/local/tmp/dysvcpit.kpm"
JS_PATH="/data/local/tmp/load_dysvcpit_apatch.js"
RUSTFRIDA="/data/local/tmp/rustfrida"

log() {
    echo "[$(date '+%m-%d %H:%M:%S')] $1" >> "$LOGFILE"
}

# Wait for boot completion
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 2
done
sleep 10

log "Boot completed, waiting for APatch..."

# Wait for APatch app to start
APID=""
for i in $(seq 1 60); do
    APID=$(pidof me.bmax.apatch 2>/dev/null)
    if [ -n "$APID" ]; then
        break
    fi
    sleep 2
done

if [ -z "$APID" ]; then
    log "ERROR: APatch not running after 2min"
    exit 1
fi

log "APatch pid=$APID, loading KPM..."

# Ensure KPM and JS exist
if [ ! -f "$KPM_PATH" ]; then
    log "ERROR: KPM not found: $KPM_PATH"
    exit 1
fi

if [ ! -f "$JS_PATH" ]; then
    log "ERROR: JS script not found: $JS_PATH"
    exit 1
fi

# Inject APatch to load KPM
# Use timeout to avoid hanging
"$RUSTFRIDA" --pid "$APID" -l "$JS_PATH" > /data/local/tmp/dysvcpit-load.out 2>&1 &
BGPID=$!

# Wait up to 30s for injection
for i in $(seq 1 30); do
    if ! kill -0 $BGPID 2>/dev/null; then
        break
    fi
    sleep 1
done

# Kill if still running
kill $BGPID 2>/dev/null
wait $BGPID 2>/dev/null

# Check output
if grep -q "load path=.*rc=0" /data/local/tmp/dysvcpit-load.out 2>/dev/null; then
    log "SUCCESS: dysvcpit KPM loaded"
    grep "ctl0" /data/local/tmp/dysvcpit-load.out | while read line; do
        log "$line"
    done
else
    log "WARNING: KPM load may have failed, check /data/local/tmp/dysvcpit-load.out"
    tail -20 /data/local/tmp/dysvcpit-load.out >> "$LOGFILE" 2>/dev/null
fi

log "Done"
