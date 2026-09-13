# cutegdb

An [x64dbg](https://x64dbg.com/)-style graphical front-end for **GDB**, written
in Rust. It keeps x64dbg's layout, keyboard shortcuts and operating logic, but
drives GDB/MI underneath so it debugs everything GDB does — and adds built-in
**anti-anti-debugging and anti-anti-VM** countermeasures for malware analysts.

📖 [中文说明](README.zh-CN.md) · [Usage guide](docs/usage.md) ([中文](docs/usage.zh-CN.md))

---

## Features

- **x64dbg-style CPU view** — synchronized disassembly, registers, stack and
  memory dumps, an info box, jump arrows and register-change highlighting.
- **Familiar controls** — x64dbg's default shortcuts (F9 run, F7/F8 step, Ctrl+F9
  run-to-return, F2 breakpoint, Ctrl+G goto, …) and operating logic.
- **Full debugging** — software/hardware breakpoints, watchpoints, conditional and
  log breakpoints, call stack, threads, memory map, signals, symbols, handles.
- **Patching & annotations** — inline assembler, byte editing, a patch manager,
  plus comments, labels and bookmarks kept in a per-binary database.
- **Search & analysis** — pattern (with wildcards) and string search, cross-
  references, string references.
- **Trace, graph & scripting** — instruction trace with a break condition, a
  control-flow graph (G), an x64dbg-style script interpreter, and Python through
  GDB's embedded interpreter.
- **Wide target support** — x86-64 and x86 ELF, ARM/AArch64, and remote targets
  over `gdbserver`/QEMU.
- **Dual command bar** — type x64dbg commands (translated to GDB) or raw GDB
  commands; a dropdown switches to a Python line.
- **Anti-anti-debug / anti-anti-VM plugins** — see below.

## Anti-anti-debugging & anti-anti-VM

Malware routinely refuses to run under a debugger or inside a VM. cutegdb ships
built-in countermeasures that make the target see an ordinary, un-observed
machine. They are driven from the **Plugins** menu, remembered across sessions,
and re-applied automatically each time a process starts or you attach.

| Plugin | Category | What it neutralizes |
|---|---|---|
| **ptrace guard** | anti-debug | `PTRACE_TRACEME`/`ATTACH` detection and debug-register reads |
| **procfs & environment cloak** | anti-debug | `/proc` TracerPid, parent-process name, debugger env vars |
| **timing normalizer** ⚠ | anti-debug | `rdtsc`/`rdtscp` and clock-syscall timing checks |
| **software-breakpoint cloak** ⚠ | anti-debug | self-checksums that scan for `0xCC` via `/proc/self/mem` |
| **CPUID spoof** | anti-VM | hypervisor-present bit, hypervisor vendor & brand strings |
| **VM file & device cloak** | anti-VM | DMI, `/proc/cpuinfo`, NIC MAC, VM device nodes |
| **VM syscall cloak** | anti-VM | `uname`, hostname and reported memory size |

⚠ = best-effort: it logs what it could and could not fully hide (timing slowdown
from single-stepping, or checksums built from direct CPU reads).

Working example programs for every technique live in [`examples/`](examples/),
and they double as the integration-test corpus.

## Requirements

- Rust (edition 2024) and Cargo
- GDB built with Python 3 (`gdb --interpreter=mi3`)
- Qt 6 base development files and `qmake6`
- A C compiler (`gcc`/`cc`) to build targets and examples
- Optional: `gcc-i686-linux-gnu`, `gcc-aarch64-linux-gnu`, `gdbserver`,
  `qemu-user` for 32-bit / ARM / remote targets

On Debian/Kali:

```sh
sudo apt install build-essential gdb qt6-base-dev libclang-dev
# optional cross/remote support:
sudo apt install gcc-i686-linux-gnu gcc-aarch64-linux-gnu gdbserver qemu-user
```

## Build & run

```sh
cargo build --release
cargo run --release -- /path/to/target            # open a program
cargo run --release -- --smoke-test out.png prog  # headless screenshot (offscreen)
```

`cargo build` compiles the thin C++ Qt Widgets layer itself via `cxx-qt-build`;
no separate CMake step is needed. If `qmake6` is not on `PATH`, point
`.cargo/config.toml`'s `QMAKE` at it.

## Quick start: defeating a check

```sh
cd examples && make                 # build the example programs
cargo run --release -- examples/build/anti-vm/cpuid
```

In the window: **Plugins → Anti-anti-VM → CPUID spoof** (or *Enable all*), then
press **F9**. The program's output in the Log turns from `DETECTED` to `clean`.

## Testing

```sh
cargo test -p cutegdb-mi -p cutegdb-core -p cutegdb-cmd   # unit + integration
cargo clippy --workspace --all-targets                    # lint
QT_QPA_PLATFORM=offscreen cargo run -- --smoke-test /tmp/s.png examples/build/anti-vm/cpuid
scripts/x11-test.sh                                        # live GUI workflow (X11)
```

The anti-VM tests assume the host is itself a hypervisor guest and skip
themselves (with a message) on bare metal.

## Project layout

```
crates/
  mi/      GDB/MI3 protocol client (async, tokio)
  core/    debugger engine: state, memory, symbols, disasm, plugins
  cmd/     x64dbg command & expression translation, script interpreter
  app/     Qt Widgets UI driven through cxx-qt
examples/  anti-debug / anti-VM demonstration programs (+ tests)
scripts/   GUI test driver and helpers
tests/     generic debugger test fixtures
docs/      usage guides (EN / 中文)
```

## Intended use

cutegdb is a debugging and analysis tool. Use it and its anti-anti-debug /
anti-anti-VM plugins only on software you are authorized to analyze — malware
analysis, security research, CTFs and your own programs.

## License

Released under the [MIT License](LICENSE). cutegdb runs GDB as a separate process
and links Qt dynamically; those components keep their own licenses (GPLv3 and
LGPLv3 respectively).
