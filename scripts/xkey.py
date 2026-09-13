#!/usr/bin/env python3
"""Sends key chords to the focused X11 window through XTEST, by keycode.

Usage: xkey.py F9 Control_L+F9 Alt_L+x Return

Each argument is a chord of X keysym names joined with '+': keys are pressed in order and
released in reverse. xdotool 3.20160805 is not used for keys because it delivers function keys
with a spurious Alt modifier (F9 arrives as Alt+F9) or not at all.
"""

import ctypes
import ctypes.util
import sys
import time

x11 = ctypes.cdll.LoadLibrary(ctypes.util.find_library("X11"))
xtst = ctypes.cdll.LoadLibrary(ctypes.util.find_library("Xtst"))
x11.XOpenDisplay.restype = ctypes.c_void_p
x11.XStringToKeysym.argtypes = [ctypes.c_char_p]
x11.XStringToKeysym.restype = ctypes.c_ulong
x11.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
x11.XKeysymToKeycode.restype = ctypes.c_ubyte
x11.XFlush.argtypes = [ctypes.c_void_p]
xtst.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]


def keycode(display, name):
    keysym = x11.XStringToKeysym(name.encode())
    code = x11.XKeysymToKeycode(display, keysym) if keysym else 0
    if not code:
        sys.exit(f"xkey.py: unknown key {name!r}")
    return code


def main():
    display = x11.XOpenDisplay(None)
    if not display:
        sys.exit("xkey.py: cannot open display")
    for chord in sys.argv[1:]:
        codes = [keycode(display, name) for name in chord.split("+")]
        for code in codes:
            xtst.XTestFakeKeyEvent(display, code, 1, 0)
        for code in reversed(codes):
            xtst.XTestFakeKeyEvent(display, code, 0, 0)
        x11.XFlush(display)
        time.sleep(0.05)


if __name__ == "__main__":
    main()
