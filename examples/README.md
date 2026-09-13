# Anti-debugging & anti-VM examples

Small, self-contained programs that probe for a debugger or a virtual machine the
way real malware does. Each one prints one line per check (`clean` or
`DETECTED`) and a final `RESULT` line. Run them on their own to see them detect
the analysis environment, then run them under cutegdb with the matching plugin
enabled (Plugins menu) to watch the detections turn `clean`.

These sources are also the cutegdb integration-test corpus
(`crates/core/tests/{antidebug,antivm,timing}.rs`).

## Build & run

```sh
make                     # builds everything into build/
./build/anti-debug/antidebug
./build/anti-vm/cpuid
```

## What each demonstrates

| Example | Techniques | Defeated by |
|---|---|---|
| `anti-debug/antidebug.c` | `ptrace(PTRACE_TRACEME)`, `/proc/self/status` TracerPid, parent-process name | `ptrace_guard`, `procfs_cloak` |
| `anti-debug/timing.c` | `rdtsc` and `clock_gettime` deltas across a pause | `timing_normalizer` |
| `anti-debug/selfmod.c` | self-checksum of code via `/proc/self/mem` (finds `0xCC`) | `swbp_cloak` |
| `anti-vm/cpuid.c` | `CPUID` hypervisor-present bit and hypervisor vendor leaf | `cpuid_spoof` |
| `anti-vm/sysfiles.c` | DMI vendor/product, `/proc/cpuinfo` flag, NIC MAC OUI, hostname | `vm_file_cloak`, `vm_syscall_cloak` |

## Trying them under cutegdb

1. `cutegdb ./build/anti-vm/cpuid`
2. Plugins → Anti-anti-VM → enable **CPUID spoof** (or Enable all).
3. Run to exit (F9). The program's output in the Log turns every check `clean`.

The `timing.c` and `selfmod.c` cases model a debugger pause with a real sleep and
a software breakpoint respectively; see `docs/usage.md` for details and the
best-effort caveats of those two countermeasures.

> These programs are harmless and exist only to test the countermeasures. Use
> cutegdb and its plugins for authorized analysis, research, and CTFs.
