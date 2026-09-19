# cutegdb usage guide

[中文版本](usage.zh-CN.md) · [← README](../README.md)

This guide covers day-to-day use: the window, keyboard shortcuts, the command
bar, scripting, and the anti-anti-debug / anti-anti-VM plugins.

## 1. Opening a target

- **File → Open** (or a path argument on the command line) loads and starts a
  program. Execution stops at the *system breakpoint* (the loader's first
  instruction), exactly like x64dbg.
- **File → Attach** (Alt+A) attaches to a running process.
- **File → Connect to remote target** debugs over `gdbserver` or a QEMU gdb stub.

From the system breakpoint, **F9** runs to the *entry breakpoint* (the program's
entry point) and then to your breakpoints.

## 2. The CPU view

The default tab mirrors x64dbg: disassembly (top-left), registers (top-right),
an info box and arguments panel, memory dumps and the stack (bottom). Jump arrows
are drawn in the disassembly, changed registers are highlighted, and the info box
explains the selected instruction.

## 3. Keyboard shortcuts

cutegdb uses x64dbg's default keybindings. The most common:

| Key | Action |
|---|---|
| F9 | Run / continue |
| F7 | Step into |
| F8 | Step over |
| Ctrl+F9 | Execute till return |
| F2 | Toggle breakpoint |
| F4 | Run to selection |
| Ctrl+G | Go to expression |
| G | Function graph of the selection |
| X | Find references to the selected address |
| Ctrl+B | Find pattern (bytes, with `?` wildcards) |
| Space | Assemble at the selected instruction |
| ; | Set a comment |
| : | Set a label |
| Ctrl+P | Patch manager |
| Alt+B / Alt+K / Alt+M | Breakpoints / Call stack / Memory map |

The full table is defined in `crates/app/ui/shortcuts.cpp`.

## 4. The command bar

The bar at the bottom accepts three kinds of input; the dropdown on the right
chooses **Default** or **Python**.

- **x64dbg commands**, translated to GDB — e.g. `bp add`, `bph counter,w,4`,
  `rax=1234`, `g` (go), `t`/`p` (step), `ticnd`/`tocnd` (conditional trace).
- **Raw GDB** — anything GDB understands passes straight through (`info
  registers`, `-data-evaluate-expression …`, etc.).
- **Python** — with the dropdown set to Python, the line runs in GDB's embedded
  interpreter (`print(gdb.selected_frame().pc())`).

Expressions accept registers, symbols, `module.symbol`, hex/dec numbers and
`[addr]` memory dereferences.

## 5. Scripting

The **Script** tab runs x64dbg-style scripts: one command per line, `label:`
definitions, `cmp` with conditional jumps (`je`/`jne`/`jl`/…), `call`/`ret`, and
`pause`. Controls follow x64dbg: **Ctrl+O** open, **Ctrl+L** load the edited text,
**Ctrl+R** reload, **Ctrl+U** unload to edit, **Space** run, **Tab** step,
**Esc** abort. The running line is highlighted.

For heavier automation, use Python from the command bar or GDB's `source`.

## 6. Trace & graph

- **Tracing → Trace into / over** (or `ticnd`/`tocnd`) records executed
  instructions until a break condition holds or the step limit is reached. The
  **Trace** tab lists each instruction with the registers it changed, and can
  export the trace.
- **G** in the disassembly builds the **Graph** of the current function: basic
  blocks with taken (green), not-taken (red) and unconditional (blue) edges.
  Ctrl+wheel zooms; double-click follows a block in the disassembly.

## 7. Anti-anti-debug & anti-anti-VM plugins

### Using them

Open the **Plugins** menu. Countermeasures are grouped into **Anti-anti-debug**
and **Anti-anti-VM**, each a checkable item (hover for a description; *Enable
all* / *Disable all* are at the bottom of each submenu). Your selection is saved
and re-applied automatically whenever a new process reaches its entry point or
you attach — so enable what you want once and forget it. Toggling while the
target is paused applies immediately.

**Plugins → Plugin status…** shows the active countermeasures and how many checks
each has neutralized so far.

### How they work

Each plugin injects a small GDB Python module that installs silent breakpoints —
they patch the debuggee's view of the world and resume without ever surfacing a
stop, so they never interfere with your own breakpoints or stepping. Activity is
written to the Log (`[cutegdb-plugin] …`):

![The Log tab: the anti-VM CPUID example reports clean with CPUID spoof active](images/plugins-log.png)

### The plugins

| Plugin | Neutralizes | Notes |
|---|---|---|
| **ptrace guard** | `ptrace(PTRACE_TRACEME/ATTACH)` returning failure under a debugger; `PTRACE_PEEKUSER` reads of the debug registers | hooks the libc `ptrace` wrapper |
| **procfs & environment cloak** | `/proc/*/status` TracerPid, tracing state, a debugger parent's name; `getenv` of `LD_PRELOAD` etc. | rewrites `read()` results |
| **timing normalizer** | `rdtsc`/`rdtscp` and `clock_gettime`/`gettimeofday` deltas used to detect single-stepping | **best-effort**: virtualizes time, so the target no longer sees real time; very large single-step delays elsewhere still cost wall-clock time |
| **software-breakpoint cloak** | self-checksums that read the program's own code through `/proc/self/mem` and look for `0xCC` | **best-effort**: restores original bytes on such reads; checksums built from direct CPU reads cannot be intercepted — prefer hardware breakpoints there |
| **CPUID spoof** | the hypervisor-present bit (leaf 1), hypervisor vendor leaf (`0x40000000`) and brand string | x86/x86-64 only |
| **VM file & device cloak** | DMI vendor/product strings, the `/proc/cpuinfo` hypervisor flag, VM NIC MAC OUIs, and VM device nodes (`/dev/vboxguest`, `/dev/vmci`, …) | makes VM files read as bare metal and VM devices look absent |
| **VM syscall cloak** | `uname`, the hostname (e.g. an analysis box named `kali`) and the reported memory size | normalizes to an ordinary workstation |

### Limitations

- Hooks target the libc wrappers, so a statically linked target issuing raw
  `syscall`/`cpuid` before its entry point can bypass them.
- Fork children are not followed by default, so checks run from a child process
  are not covered.
- The two best-effort plugins are marked ⚠ in the menu and log what they could
  not fully hide.

## 8. IDA Pro sync (ret-sync)

The **IDA Pro sync** plugin keeps a live IDA Pro session in step with the
debugger. It is a [ret-sync](https://github.com/bootleg/ret-sync) *debugger
client*, so it talks to the **stock ret-sync IDA plugin** — nothing extra is
installed on the IDA side, and the same dispatcher works for a local or remote
IDA.

### Set-up

1. In IDA, install ret-sync as usual and open your IDB for the target. Start it
   (Alt-Shift-S) and enable syncing (Ctrl-Shift-S) so its dispatcher is
   listening. IDA matches the debugger to the right IDB by the module's file
   name; if the IDB name differs, use ret-sync's *Overwrite idb name* / `.sync`
   `[ALIASES]`.
2. In cutegdb, tick **Plugins → Debugger integration → IDA Pro sync**. The
   choice is saved and re-enabled on the next launch.
3. Load and run the target. As soon as it pauses, IDA's cursor jumps to the
   current instruction.

### What syncs

- **Debugger → IDA** — every pause (single-step, step over/into, run-to-return,
  a breakpoint hit, *goto*, the end of a trace, …) moves IDA's cursor to the same
  instruction and highlights the line. Because cutegdb reports one pause per
  action — at the final instruction — IDA does not flicker through the
  intermediate steps of a synthesized step-over or run-to-return. Breakpoints set
  in cutegdb are marked at their address in IDA (best-effort colour; ret-sync has
  no dedicated debugger→IDA breakpoint marker).
- **IDA → debugger** — ret-sync's debugger hotkeys drive cutegdb back:

  | IDA hotkey | Action in cutegdb |
  |---|---|
  | F10 | single-step |
  | F11 | single-trace (step) |
  | Alt-F5 | continue |
  | F2 / F3 | breakpoint / one-shot breakpoint at the cursor |
  | Ctrl-F2 | hardware breakpoint at the cursor |

  These arrive as ordinary GDB commands and run through the normal command path,
  so cutegdb's views refresh and the resulting location syncs straight back.

### Rebasing and remote IDA

cutegdb sends the module's runtime base and the absolute program counter; IDA
rebases with its own image base, so ASLR/PIE and shared libraries are handled
without any manual offset. The dispatcher endpoint defaults to `127.0.0.1:9100`.
For an IDA on another machine, or a non-default port, point cutegdb at it with
either:

- the `CUTEGDB_RETSYNC` environment variable — `host` or `host:port`, e.g.
  `CUTEGDB_RETSYNC=192.168.1.20:9100 cargo run`; or
- a `~/.sync` file (the same one ret-sync reads):

  ```ini
  [INTERFACE]
  host=192.168.1.20
  port=9100
  ```

The endpoint is read when gdb starts, so set it before launching cutegdb. The
current sync target and count are shown in **Plugins → Plugin status…**.

> The reverse channel runs the GDB commands IDA sends, so only enable the plugin
> with a dispatcher you trust (localhost, or a host you configured).

## 9. Examples

[`examples/`](../examples/) contains one small program per technique. Build and
run them:

```sh
cd examples && make
./build/anti-vm/cpuid            # prints DETECTED lines on a VM
```

Then open the same binary in cutegdb, enable the matching plugin, and press F9 —
the Log shows the checks turning `clean`. See [`examples/README.md`](../examples/README.md)
for the full table.

## 10. Testing

```sh
cargo test -p cutegdb-mi -p cutegdb-core -p cutegdb-cmd   # unit + integration (needs gdb, gcc)
cargo clippy --workspace --all-targets
```

- **Headless smoke test**: `QT_QPA_PLATFORM=offscreen cargo run -- --smoke-test out.png <prog>`
  opens the program, runs to the entry breakpoint and screenshots the CPU tab.
- **Live GUI test**: `scripts/x11-test.sh` drives a real window through the whole
  workflow (including enabling a plugin) on an X11 display, saving screenshots
  under `target/x11-test/`. It sends keys via `scripts/xkey.py` (XTEST) and skips
  itself if the screen is locked.

The anti-VM integration tests only assert detection→clean when the host is a
hypervisor guest; on bare metal they skip with a message.

- **Screenshots**: `scripts/screenshots.sh` regenerates the images in this guide
  by driving cutegdb on the `anti-vm/cpuid` example with the plugin enabled.
