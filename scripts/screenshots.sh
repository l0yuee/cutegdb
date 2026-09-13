#!/bin/bash
# Generates the README screenshots by driving cutegdb on an anti-VM example with
# the CPUID-spoof plugin enabled, on an X11 display. Keys go through xkey.py
# (XTEST); xdotool is used only for the window, mouse and typing.
#
#   scripts/screenshots.sh   ->  docs/images/cpu-view.png, docs/images/plugins-log.png
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
APP="$ROOT/target/debug/cutegdb"
KEY="python3 $ROOT/scripts/xkey.py"
OUT="$ROOT/docs/images"
TMP=$(mktemp -d)
mkdir -p "$OUT"

release_keys() { xdotool keyup Alt_L Alt_R Control_L Control_R Shift_L Shift_R Super_L 2>/dev/null; }
if xfce4-screensaver-command --query 2>/dev/null | grep -q "is active"; then
    echo "FAIL: the screen is locked; unlock the session first"
    exit 1
fi
INHIBIT=
if command -v xfce4-screensaver-command >/dev/null; then
    xfce4-screensaver-command --inhibit --application-name cutegdb-shots --reason "screenshots" >/dev/null 2>&1 &
    INHIBIT=$!
fi
PID=
cleanup() {
    release_keys
    [ -n "$INHIBIT" ] && kill "$INHIBIT" 2>/dev/null
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT
release_keys

cargo build -p cutegdb --manifest-path "$ROOT/Cargo.toml" || exit 1
make -C "$ROOT/examples" >/dev/null || exit 1
EXE="$ROOT/examples/build/anti-vm/cpuid"

# Pre-enable the CPUID-spoof plugin so it is applied automatically at the entry point.
export XDG_CONFIG_HOME="$TMP/config" XDG_DATA_HOME="$TMP/data"
mkdir -p "$XDG_CONFIG_HOME/cutegdb"
printf '[plugins]\nenabled=cpuid_spoof\n' >"$XDG_CONFIG_HOME/cutegdb/cutegdb.conf"

CUTEGDB_UI_LOG=1 "$APP" "$EXE" >"$TMP/app.out" 2>&1 &
PID=$!

MARK=0
mark() { MARK=$(wc -l <"$TMP/app.out"); }
wait_log() {
    for _ in $(seq 1 150); do
        tail -n +$((MARK + 1)) "$TMP/app.out" | grep -qF -- "$1" && return 0
        sleep 0.1
    done
    echo "FAIL: timed out waiting for: $1"
    tail -20 "$TMP/app.out"
    exit 1
}

WID=$(timeout 15 xdotool search --sync --onlyvisible --name "cutegdb - cpuid" | head -1)
[ -z "$WID" ] && { echo "FAIL: window not found"; exit 1; }
xdotool windowactivate --sync "$WID"
xdotool windowsize "$WID" 1200 760
sleep 0.5

wait_log "System breakpoint reached!"
mark; $KEY F9
wait_log "entry breakpoint"
wait_log "Countermeasures active"

# Show the example's main() in the disassembly for the CPU-view shot.
xdotool mousemove --window "$WID" 320 150 click 1
sleep 0.2
$KEY Control_L+g
sleep 0.6
xdotool type --delay 12 "main"
$KEY Return
sleep 0.7
import -window "$WID" "$OUT/cpu-view.png"

# Run to exit; the checks print to the Log, then switch to the Log tab and capture it.
mark; $KEY F9
wait_log "RESULT: CLEAN"
$KEY Alt_L+l
sleep 0.6
import -window "$WID" "$OUT/plugins-log.png"

$KEY Alt_L+x
sleep 1
echo "screenshots written to $OUT"
