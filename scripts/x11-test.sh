#!/bin/bash
# Drives the real cutegdb window on an X11 display through the CPU view workflow:
# open → system breakpoint → F9 entry → bp via command bar → F9 → F8/Ctrl+F9/F7 → Ctrl+G →
# register assignment → Alt+F2 → Alt+X. Screenshots land in target/x11-test/.
#
# Key chords go through scripts/xkey.py (XTEST by keycode); xdotool is only used for window
# lookup, mouse clicks and typing text.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/target/x11-test"
APP="$ROOT/target/debug/cutegdb"
KEY="python3 $ROOT/scripts/xkey.py"
mkdir -p "$OUT"
rm -f "$OUT"/*.png

release_keys() { xdotool keyup Alt_L Alt_R Control_L Control_R Shift_L Shift_R Super_L 2>/dev/null; }
# A locked screen grabs the keyboard, so every key would silently go to the unlock dialog.
if xfce4-screensaver-command --query 2>/dev/null | grep -q "is active"; then
    echo "FAIL: the screensaver is active (screen locked); unlock the session first"
    exit 1
fi
INHIBIT=
if command -v xfce4-screensaver-command >/dev/null; then
    xfce4-screensaver-command --inhibit --application-name cutegdb-x11-test --reason "GUI test" >/dev/null 2>&1 &
    INHIBIT=$!
fi
cleanup() { release_keys; [ -n "$INHIBIT" ] && kill "$INHIBIT" 2>/dev/null; }
trap cleanup EXIT
release_keys
held=$(python3 -c "
import ctypes, ctypes.util
x = ctypes.cdll.LoadLibrary(ctypes.util.find_library('X11')); x.XOpenDisplay.restype = ctypes.c_void_p
d = x.XOpenDisplay(None); k = (ctypes.c_char * 32)(); x.XQueryKeymap(ctypes.c_void_p(d), k)
print(' '.join(str(i * 8 + b) for i in range(32) for b in range(8) if k[i][0] >> b & 1))")
if [ -n "$held" ]; then
    echo "FAIL: keys held on the X server before starting (keycodes: $held); release them first"
    exit 1
fi

gcc -g -O0 -o "$OUT/hello" "$ROOT/tests/fixtures/hello.c" || exit 1
# Keep the annotation database of this run out of the user's data directory and earlier runs.
rm -rf "$OUT/data" "$OUT/config"
export XDG_DATA_HOME="$OUT/data"
export XDG_CONFIG_HOME="$OUT/config"
CUTEGDB_UI_LOG=1 "$APP" "$OUT/hello" >"$OUT/app.out" 2>&1 &
PID=$!

fail() {
    echo "FAIL: $*"
    tail -25 "$OUT/app.out"
    kill $PID 2>/dev/null
    exit 1
}
# Waits for a log line that appears after the current end of the log.
mark() { MARK=$(wc -l <"$OUT/app.out"); }
wait_log() {
    for _ in $(seq 1 150); do
        tail -n +$((MARK + 1)) "$OUT/app.out" | grep -qF -- "$1" && return 0
        sleep 0.1
    done
    fail "timed out waiting for log line: $1"
}
shot() { sleep "${2:-0.8}"; import -window "$WID" "$OUT/$1"; }
command_bar() {
    xdotool mousemove --window "$WID" $((WIDTH / 2)) $((HEIGHT - 40)) click 1
    sleep 0.2
    xdotool type --delay 15 "$1"
    $KEY Return
}

MARK=0
WID=$(timeout 15 xdotool search --sync --onlyvisible --name "cutegdb - hello" | head -1)
[ -z "$WID" ] && fail "window not found"
xdotool windowactivate --sync "$WID"
eval "$(xdotool getwindowgeometry --shell "$WID")"

wait_log "System breakpoint reached!"
shot system.png

mark; $KEY F9
wait_log "[action] Run"
wait_log '"entry breakpoint" at <hello.EntryPoint>'
shot entry.png

mark; command_bar "bp add"
wait_log "set!"
mark; $KEY F9
wait_log "INT3 breakpoint at <hello.add>"
shot add.png

mark; $KEY F8
wait_log "[action] Step over"
sleep 0.5
$KEY F8
shot stepped.png

mark; $KEY Control_L+F9
wait_log "[action] Execute till return"
shot rtr.png 1.2
mark; $KEY F7
wait_log "[action] Step into"
shot back-in-main.png

# Ctrl+G in the disassembly view: focus it first by clicking inside it.
xdotool mousemove --window "$WID" $((WIDTH / 4)) $((HEIGHT / 5)) click 1
sleep 0.3
$KEY Control_L+g
sleep 0.8
xdotool type --delay 15 "hello.main"
$KEY Return
shot goto-main.png

mark; command_bar "rax=1234"
sleep 0.8
command_bar "rax"
wait_log "rax: 1234"
shot assigned.png

# M2 views: hardware watchpoint from the command bar, breakpoint list actions, info views.
mark; command_bar "bph hello.counter, w, 4"
wait_log "Hardware watchpoint"
$KEY Alt_L+b
sleep 0.8
$KEY Down
sleep 0.3
mark; $KEY space
wait_log "[action] Enable/Disable"
shot breakpoints-disabled.png
mark; $KEY Delete
wait_log "[action] Delete"
shot breakpoints-deleted.png
$KEY Alt_L+k
shot callstack.png
$KEY Alt_L+t
shot threads.png
$KEY Alt_L+m
shot memmap.png
$KEY Alt_L+e
shot symbols.png
$KEY Alt_L+s
shot signals.png
$KEY Alt_L+c
sleep 0.3

# M3: comment, label, bookmark and assemble on an already executed line of main, then the patches.
xdotool mousemove --window "$WID" $((WIDTH / 4)) $((HEIGHT / 5)) click 1
sleep 0.3
mark; $KEY semicolon
sleep 0.8
xdotool type --delay 15 "set up the call"
$KEY Return
wait_log "[action] Comment"
mark; $KEY Shift_L+colon
sleep 0.8
xdotool type --delay 15 "my_label"
$KEY Return
wait_log "[action] Label"
$KEY Control_L+d
sleep 0.3
mark; $KEY space
sleep 0.8
xdotool type --delay 15 "nop"
$KEY Return
wait_log "[action] Assemble"
shot annotated.png
mark; command_bar "my_label"
wait_log "my_label: "
mark; $KEY Control_L+p
wait_log "[action] Patches"
sleep 0.8
# The patches dialog is its own top-level window.
PATCHES=$(xdotool search --onlyvisible --name "^Patches$" | head -1)
[ -z "$PATCHES" ] && fail "patches dialog not found"
import -window "$PATCHES" "$OUT/patches.png"
$KEY Escape
sleep 0.3

# M4: string references from the command bar, then a pattern search with Ctrl+B.
mark; command_bar "strref hello.main"
wait_log "String references in hello:"
shot references-strings.png
$KEY Alt_L+c
sleep 0.3
xdotool mousemove --window "$WID" $((WIDTH / 4)) $((HEIGHT / 5)) click 1
sleep 0.3
mark; $KEY Control_L+b
sleep 0.8
xdotool type --delay 15 "55 48 89 E5"
$KEY Return
wait_log "[action] Find pattern"
wait_log "result(s)"
shot references-pattern.png
$KEY Alt_L+c
sleep 0.3

# M6: graph view (G), a script from a file, gdb's Python, and a conditional trace.
# (x64dbg's trace shortcuts Ctrl+Alt+F7/F8 switch Linux virtual consoles, so tracing uses the command bar.)
xdotool mousemove --window "$WID" $((WIDTH / 4)) $((HEIGHT / 5)) click 1
sleep 0.3
mark; $KEY g
wait_log "[action] Graph"
shot graph.png 1.2
$KEY Alt_L+c
sleep 0.3

cat >"$OUT/test-script.txt" <<'SCRIPT'
// cutegdb script test: rax was set to 1234 from the command bar
log "script started"
cmp rax, 1234
jne wrong
log "script compare ok"
ret
wrong:
log "script compare failed"
SCRIPT
$KEY Alt_L+i
sleep 0.5
mark; $KEY Control_L+o
sleep 1.2
xdotool type --delay 10 "$OUT/test-script.txt"
$KEY Return
wait_log "[action] Script loaded"
sleep 0.3
$KEY space
wait_log "Script finished"
grep -q "script compare ok" "$OUT/app.out" || fail "script comparison did not hold"
shot script.png 0.5

mark; command_bar "python print('python-' + 'ok')"
wait_log "python-ok"

$KEY Alt_L+c
sleep 0.3
mark; command_bar "tocnd byte:[cip]==C3, .5000"
wait_log "Trace finished after"
wait_log "[action] Trace view:"
grep -q "\[action\] Trace view: [1-9]" "$OUT/app.out" || fail "the trace view has no rows"
shot trace.png 1
$KEY Alt_L+c
sleep 0.3

# x64dbg's Alt+F2 (Close) is grabbed by Xfce (xfrun4) before any application sees it, so use
# the Debug menu's accelerators instead: Alt+D, then C for "&Close".
mark; $KEY Alt_L+d
sleep 0.4
$KEY c
wait_log "[action] Close"
wait_log "Debugging stopped!"
shot stopped.png

# M5: attach to a running process from the command bar, detach again, then the Attach dialog (Alt+A).
# (x64dbg's Detach shortcut Ctrl+Alt+F2 switches Linux to text console 2, so it is never pressed here.)
"$OUT/hello" loop >/dev/null 2>&1 &
LOOP=$!
sleep 0.5
mark; command_bar "attach .$LOOP"
wait_log "Attach breakpoint reached!"
shot attached.png
mark; command_bar "detach"
wait_log "Detached from process"
sleep 0.3
kill -0 $LOOP 2>/dev/null || fail "the process died after detaching"
kill $LOOP
mark; $KEY Alt_L+a
sleep 1
ATTACH=$(xdotool search --onlyvisible --name "^Attach$" | head -1)
[ -z "$ATTACH" ] && fail "attach dialog not found"
import -window "$ATTACH" "$OUT/attach-dialog.png"
$KEY Escape
sleep 0.3

$KEY Alt_L+x
sleep 2
status=0
if kill -0 $PID 2>/dev/null; then echo "FAIL: Alt+X did not exit"; kill $PID; status=1; fi
pgrep -f "gd[b].*--interpreter=mi3" >/dev/null && { echo "FAIL: gdb process still alive"; status=1; }
grep -i "ambiguous" "$OUT/app.out" && { echo "FAIL: ambiguous shortcut"; status=1; }
grep -E "^Error|not paused|Command aborted" "$OUT/app.out" && { echo "FAIL: errors in log"; status=1; }
[ $status -eq 0 ] && echo "X11 TEST PASS (screenshots in $OUT)"
exit $status
