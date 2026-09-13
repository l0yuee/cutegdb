"""cutegdb built-in countermeasures against anti-debugging and anti-VM checks.

This module is injected into the gdb session by the Rust core
(crates/core/src/plugins.rs) and driven through the `cutegdb` namespace it
defines:

    cutegdb.activate(ids)   (re)install exactly the listed plugins for the
                            current inferior; plugins not listed are removed.
    cutegdb.active_line()   one "CUTEGDB_ACTIVE ..." line the core logs.
    cutegdb.dump_stats()    print one "CUTEGDB_STATS ..." line the core parses.

Each plugin silently patches the debuggee's view of the world: its
gdb.Breakpoint subclasses return False from stop(), so gdb resumes without ever
reporting the stop to the UI. Plugin ids here must match the catalog in
plugins.rs.
"""
import gdb
import struct
import sys
import traceback

TAG = "[cutegdb-plugin]"


def emit(plugin, message):
    # Written to gdb's stdout; the core surfaces these console lines in its log
    # when it is idle. Correctness never depends on the core reading them.
    sys.stdout.write("%s %s: %s\n" % (TAG, plugin, message))
    sys.stdout.flush()


def last_error():
    return traceback.format_exc().strip().splitlines()[-1]


class Plugin(object):
    """Base class: subclasses set `id` and implement install()."""

    id = "?"

    def __init__(self):
        self.count = 0
        self._objs = []
        # In-flight FunctionHook return breakpoints, cleared when the plugin is removed.
        self._pending = set()

    def install(self):
        raise NotImplementedError

    def remove(self):
        for obj in list(self._pending):
            try:
                obj.delete()
            except Exception:
                pass
        self._pending.clear()
        for obj in self._objs:
            try:
                obj.delete()
            except Exception:
                pass
        self._objs = []
        self.teardown()

    def teardown(self):
        # Overridden by plugins that register event handlers rather than breakpoints.
        pass

    def track(self, obj):
        self._objs.append(obj)
        return obj

    def note(self, message):
        self.count += 1
        emit(self.id, message)


class Silent(gdb.Breakpoint):
    """A breakpoint that patches state and never stops the UI.

    `owner.on_hit(self)` runs for each hit; the breakpoint always resumes.
    """

    def __init__(self, location, owner):
        super(Silent, self).__init__(location, type=gdb.BP_BREAKPOINT, internal=True)
        self.owner = owner
        self.silent = True

    def stop(self):
        try:
            self.owner.on_hit(self)
        except Exception:
            emit(self.owner.id, "error: " + last_error())
        return False


_REGISTRY = {}
_ACTIVE = {}


def register(cls):
    _REGISTRY[cls.id] = cls
    return cls


def activate(ids):
    """Install exactly `ids`, removing any active plugin not in the list.

    Called again for every new process, so each plugin is torn down and
    reinstalled against the current inferior's addresses.
    """
    wanted = set(ids)
    for pid in list(_ACTIVE):
        if pid not in wanted:
            _remove(pid)
    applied = []
    for pid in wanted:
        cls = _REGISTRY.get(pid)
        if cls is None:
            continue
        _remove(pid)
        inst = cls()
        try:
            inst.install()
        except Exception:
            emit(pid, "install failed: " + last_error())
            continue
        _ACTIVE[pid] = inst
        applied.append(pid)
    return applied


def _remove(pid):
    inst = _ACTIVE.pop(pid, None)
    if inst is not None:
        try:
            inst.remove()
        except Exception:
            pass


def active_line():
    return "CUTEGDB_ACTIVE " + " ".join(sorted(_ACTIVE))


def dump_stats():
    parts = ["CUTEGDB_STATS"]
    for pid, inst in sorted(_ACTIVE.items()):
        parts.append("%s=%d" % (pid, inst.count))
    sys.stdout.write(" ".join(parts) + "\n")
    sys.stdout.flush()


def registered():
    return sorted(k for k in _REGISTRY if not k.startswith("_"))


# --- target inspection helpers ---------------------------------------------
def inferior():
    return gdb.selected_inferior()


def read_mem(addr, size):
    return bytes(inferior().read_memory(addr, size))


def write_mem(addr, data):
    inferior().write_memory(addr, bytes(data))


def read_cstr(addr, limit=4096):
    if not addr:
        return None
    try:
        raw = read_mem(addr, limit)
    except Exception:
        # Near a page boundary: fall back to a short bounded read.
        raw = b""
        while len(raw) < limit:
            try:
                b = read_mem(addr + len(raw), 1)
            except Exception:
                break
            if b == b"\x00":
                break
            raw += b
        return raw
    end = raw.find(b"\x00")
    return raw if end < 0 else raw[:end]


def symbol_addr(name):
    try:
        value = gdb.parse_and_eval(name)
    except Exception:
        return None
    try:
        addr = value.address
        return int(addr) if addr is not None else int(value)
    except Exception:
        return None


def arch_name():
    try:
        return gdb.selected_frame().architecture().name()
    except Exception:
        return "i386:x86-64"


_ARG_REGS = {
    "i386:x86-64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "aarch64": ["x0", "x1", "x2", "x3", "x4", "x5"],
    "arm": ["r0", "r1", "r2", "r3"],
}
_RET_REG = {"i386:x86-64": "rax", "aarch64": "x0", "arm": "r0", "i386": "eax"}


def _reg(name):
    return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFFFFFFFFFF


def arg(index):
    """The `index`-th integer argument of the function stopped at its entry."""
    name = arch_name()
    regs = _ARG_REGS.get(name)
    if regs is not None and index < len(regs):
        return _reg(regs[index])
    if name == "i386":
        # cdecl: arguments sit above the return address at the entry.
        esp = _reg("esp")
        return int.from_bytes(read_mem(esp + 4 * (index + 1), 4), "little")
    return 0


def set_retval(value):
    reg = _RET_REG.get(arch_name(), "rax")
    gdb.execute("set $%s = %d" % (reg, value & 0xFFFFFFFFFFFFFFFF), to_string=True)


# --- function hooking -------------------------------------------------------
class _EntryBP(gdb.Breakpoint):
    def __init__(self, location, hook):
        super(_EntryBP, self).__init__(location, type=gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        self.hook = hook

    def stop(self):
        try:
            self.hook._entry()
        except Exception:
            emit(self.hook.plugin.id, "error: " + last_error())
        return False


class _ReturnBP(gdb.FinishBreakpoint):
    def __init__(self, hook, ctx):
        super(_ReturnBP, self).__init__(internal=True)
        self.silent = True
        self.hook = hook
        self.ctx = ctx

    def stop(self):
        try:
            self.hook.plugin._pending.discard(self)
            self.hook.on_return(self.ctx)
        except Exception:
            emit(self.hook.plugin.id, "return error: " + last_error())
        return False

    def out_of_scope(self):
        self.hook.plugin._pending.discard(self)


class FunctionHook(object):
    """Hooks a libc function at its entry.

    `on_entry()` reads the arguments and returns a context (or None to ignore the
    call); when it returns a context, `on_return(ctx)` runs at the return with the
    return value available for editing.
    """

    def __init__(self, plugin, name):
        self.plugin = plugin
        self.name = name
        self.entry = None

    def install(self):
        if symbol_addr(self.name) is None:
            return False
        self.entry = _EntryBP("*" + self.name, self)
        return True

    def delete(self):
        if self.entry is not None:
            try:
                self.entry.delete()
            except Exception:
                pass
            self.entry = None

    def _entry(self):
        ctx = self.on_entry()
        if ctx is None:
            return
        try:
            self.plugin._pending.add(_ReturnBP(self, ctx))
        except ValueError:
            # No usable return location (e.g. tail call); skip this call.
            pass

    def on_entry(self):
        return None

    def on_return(self, ctx):
        pass


# --- ptrace guard -----------------------------------------------------------
@register
class PtraceGuard(Plugin):
    """Fakes the results of the ptrace() calls used to detect a debugger.

    Hooks the libc ptrace wrapper (the common case). Direct-syscall ptrace from a
    statically linked target is not covered and is reported when it cannot hook.
    """

    id = "ptrace_guard"

    PTRACE_TRACEME = 0
    PTRACE_PEEKUSER = 3
    PTRACE_ATTACH = 16
    PTRACE_SEIZE = 0x4206
    # offsetof(struct user, u_debugreg) on x86-64: PEEKUSER at or past this reads DR0..DR7.
    DEBUGREG_OFFSET = 848

    def install(self):
        hook = _PtraceHook(self, "ptrace")
        if not hook.install():
            emit(self.id, "no ptrace symbol; direct-syscall ptrace is not hooked")
            return
        self.track(hook)


class _PtraceHook(FunctionHook):
    def on_entry(self):
        return (arg(0) & 0xFFFFFFFF, arg(2))  # (request, addr)

    def on_return(self, ctx):
        request, addr = ctx
        plugin = self.plugin
        if request == PtraceGuard.PTRACE_TRACEME:
            set_retval(0)
            plugin.note("faked PTRACE_TRACEME success")
        elif request in (PtraceGuard.PTRACE_ATTACH, PtraceGuard.PTRACE_SEIZE):
            set_retval(0)
            plugin.note("faked PTRACE_ATTACH success")
        elif request == PtraceGuard.PTRACE_PEEKUSER and addr >= PtraceGuard.DEBUGREG_OFFSET:
            set_retval(0)
            plugin.note("hid a debug register (PTRACE_PEEKUSER)")


# --- shared file-cloaking machinery ----------------------------------------
DEBUGGER_NAMES = (b"gdb", b"cutegdb", b"strace", b"ltrace", b"lldb", b"gdbserver")
ENV_HIDE = ("LINES", "COLUMNS", "LD_PRELOAD", "LD_AUDIT")

# Strings that reveal a hypervisor in DMI and other system files, and VM MAC OUIs.
VM_TOKENS = (b"vmware", b"virtualbox", b"vbox", b"innotek", b"qemu", b"bochs",
             b"kvm", b"xen", b"parallels", b"hyper-v")
VM_MAC_OUIS = ("00:05:69", "00:0c:29", "00:1c:14", "00:50:56",  # VMware
               "08:00:27", "0a:00:27",                          # VirtualBox
               "52:54:00",                                      # QEMU/KVM
               "00:16:3e",                                      # Xen
               "00:1c:42")                                      # Parallels
BENIGN_MAC = b"00:1a:2b:3c:4d:5e"
DEVICE_DENY = ("/dev/vboxguest", "/dev/vboxuser", "/dev/vmci", "/dev/vmmon",
               "/dev/vmnet", "/dev/vgem", "/proc/xen", "/proc/vz")


class _OpenHook(FunctionHook):
    """Denies opens of hidden paths and tracks descriptors onto rewritten paths."""

    def on_entry(self):
        path = read_cstr(arg(self.plugin.path_index(self.name)))
        if path and self.plugin.should_deny(path):
            return ("deny", path.decode("latin-1", "replace"))
        kind = self.plugin.classify_open(path)
        return ("track", kind) if kind else None

    def on_return(self, ctx):
        what, value = ctx
        if what == "deny":
            set_retval(-1)
            self.plugin.note("hid %s" % value)
            return
        fd = _reg(_RET_REG.get(arch_name(), "rax"))
        if fd < 0x80000000:  # a successful, non-negative fd
            self.plugin.tracked_fds[fd] = value


class _ReadHook(FunctionHook):
    def on_entry(self):
        kind = self.plugin.tracked_fds.get(arg(0))
        if kind is None:
            return None
        return (kind, arg(1), arg(2))  # (kind, buffer address, buffer capacity)

    def on_return(self, ctx):
        kind, buf, capacity = ctx
        count = _reg(_RET_REG.get(arch_name(), "rax"))
        if count <= 0 or count > (1 << 20):
            return
        try:
            data = read_mem(buf, count)
        except Exception:
            return
        new, note = self.plugin.rewrite(kind, data)
        if new is None:
            return
        # Never write past what the caller's buffer can hold.
        new = new[:capacity] if capacity else new
        write_mem(buf, new)
        if len(new) != count:
            set_retval(len(new))
        self.plugin.note(note)


class _DenyHook(FunctionHook):
    """Makes access()/stat() of a hidden path fail, as if it did not exist."""

    def on_entry(self):
        path = read_cstr(arg(self.plugin.path_index(self.name)))
        if path and self.plugin.should_deny(path):
            return path.decode("latin-1", "replace")
        return None

    def on_return(self, path):
        set_retval(-1)
        self.plugin.note("hid %s" % path)


class FileCloak(Plugin):
    """Base for plugins that rewrite file reads and optionally hide paths.

    Subclasses override classify_open/rewrite and, to hide paths, should_deny plus
    denies_paths. Hooks that alias the same libc address are installed only once.
    """

    OPEN_NAMES = ("open", "open64", "openat", "openat64")
    READ_NAMES = ("read", "pread", "pread64")
    STAT_NAMES = ("stat", "stat64", "lstat", "lstat64", "newfstatat", "access", "faccessat")

    def install(self):
        self.tracked_fds = {}  # fd -> rewrite kind
        self._seen_addrs = set()
        # A list (not a generator) so every variant is attempted, not just up to the first success.
        opened = [self._add(_OpenHook(self, name)) for name in self.OPEN_NAMES]
        for name in self.READ_NAMES:
            self._add(_ReadHook(self, name))
        if self.denies_paths():
            for name in self.STAT_NAMES:
                self._add(_DenyHook(self, name))
        self.extra_hooks()
        if not any(opened):
            emit(self.id, "no open symbol; file reads are not hooked")

    def _add(self, hook):
        addr = symbol_addr(hook.name)
        if addr is None or addr in self._seen_addrs:
            return False
        if not hook.install():
            return False
        self._seen_addrs.add(addr)
        self.track(hook)
        return True

    def teardown(self):
        self.tracked_fds = {}

    def path_index(self, name):
        # The *at family (openat, faccessat, newfstatat) takes a dirfd before the path.
        return 1 if name.startswith(("openat", "faccessat", "newfstatat")) else 0

    # --- subclass API ---
    def classify_open(self, path):
        return None

    def rewrite(self, kind, data):
        return (None, "")

    def should_deny(self, path):
        return False

    def denies_paths(self):
        return False

    def extra_hooks(self):
        pass


# --- procfs & environment cloak --------------------------------------------
@register
class ProcfsCloak(FileCloak):
    """Hides the debugger from /proc and the environment.

    Rewrites read() results for sensitive /proc paths so TracerPid is 0, the
    process looks running, and the parent is not a debugger, and nulls
    debugger-revealing getenv() lookups.
    """

    id = "procfs_cloak"

    def classify_open(self, path):
        if not path or b"/proc/" not in path:
            return None
        if path.endswith(b"/status"):
            return "status"
        if path.endswith(b"/comm"):
            return "comm"
        if path.endswith(b"/stat"):
            return "stat"
        return None

    def rewrite(self, kind, data):
        if kind == "status":
            return _rewrite_status(data)
        if kind == "comm":
            return _rewrite_comm(data)
        if kind == "stat":
            return _rewrite_stat(data)
        return (None, "")

    def extra_hooks(self):
        self._add(_GetenvHook(self, "getenv"))


# --- VM file & device cloak ------------------------------------------------
@register
class VmFileCloak(FileCloak):
    """Rewrites the files that reveal a virtual machine and hides VM device nodes."""

    id = "vm_file_cloak"

    def denies_paths(self):
        return True

    def should_deny(self, path):
        p = path.decode("latin-1", "replace")
        return any(p == d or p.startswith(d) for d in DEVICE_DENY)

    def classify_open(self, path):
        if not path:
            return None
        p = path.decode("latin-1", "replace")
        if "/dmi/id/" in p:
            return "dmi"
        if p == "/proc/cpuinfo" or p.endswith("/proc/cpuinfo"):
            return "cpuinfo"
        if "/sys/class/net/" in p and p.endswith("/address"):
            return "mac"
        if p in ("/proc/scsi/scsi", "/proc/modules") or "/sys/hypervisor/" in p:
            return "vmtext"
        return None

    def rewrite(self, kind, data):
        if kind == "dmi":
            return _rewrite_dmi(data)
        if kind == "cpuinfo":
            return _rewrite_cpuinfo(data)
        if kind == "mac":
            return _rewrite_mac(data)
        if kind == "vmtext":
            return _rewrite_vmtext(data)
        return (None, "")


def _has_vm_token(data):
    low = data.lower()
    return any(token in low for token in VM_TOKENS)


def _scrub_tokens(data, tokens):
    out = data
    for token in tokens:
        idx = out.lower().find(token)
        while idx >= 0:
            out = out[:idx] + b" " * len(token) + out[idx + len(token):]
            idx = out.lower().find(token, idx + len(token))
    return out


def _rewrite_dmi(data):
    if _has_vm_token(data):
        return (b"Dell Inc.\n", "spoofed a DMI vendor string")
    return (None, "")


def _rewrite_cpuinfo(data):
    if b"hypervisor" in data:
        # Same-length blanking keeps the rest of the flags line intact.
        return (data.replace(b"hypervisor", b" " * len(b"hypervisor")), "removed the cpuinfo hypervisor flag")
    return (None, "")


def _rewrite_mac(data):
    mac = data.strip().lower().decode("latin-1", "replace")
    if any(mac.startswith(oui) for oui in VM_MAC_OUIS):
        trimmed = data.rstrip()
        return (BENIGN_MAC + data[len(trimmed):], "spoofed a VM MAC address")
    return (None, "")


def _rewrite_vmtext(data):
    if not _has_vm_token(data):
        return (None, "")
    return (_scrub_tokens(data, VM_TOKENS), "scrubbed hypervisor markers from a system file")


def _rewrite_status(data):
    changed = False
    out = data
    marker = b"TracerPid:"
    at = out.find(marker)
    if at >= 0:
        i = at + len(marker)
        while i < len(out) and out[i] in b" \t":
            i += 1
        j = i
        while j < len(out) and out[j:j + 1].isdigit():
            j += 1
        if j > i and out[i:j] != b"0":
            # Same-length replacement keeps every following offset stable.
            out = out[:i] + b"0" + b" " * (j - i - 1) + out[j:]
            changed = True
    # State: t (tracing stop) -> R (running)
    at = out.find(b"State:")
    if at >= 0:
        i = at + len(b"State:")
        while i < len(out) and out[i] in b" \t":
            i += 1
        if i < len(out) and out[i:i + 1] in (b"t", b"T"):
            out = out[:i] + b"R" + out[i + 1:]
            changed = True
    return (out, "cleared TracerPid in /proc status") if changed else (None, "")


def _rewrite_comm(data):
    lowered = data.strip().lower()
    if any(name in lowered for name in DEBUGGER_NAMES):
        return (b"bash\n", "spoofed a debugger parent's comm")
    return (None, "")


def _rewrite_stat(data):
    # "pid (comm) STATE ppid ..." -> force STATE to R when it marks tracing.
    close = data.rfind(b") ")
    if close >= 0 and close + 2 < len(data) and data[close + 2:close + 3] in (b"t", b"T"):
        return (data[:close + 2] + b"R" + data[close + 3:], "cleared tracing state in /proc stat")
    return (None, "")


class _GetenvHook(FunctionHook):
    def on_entry(self):
        name = read_cstr(arg(0), 64)
        if name and name.decode("latin-1") in ENV_HIDE:
            return name.decode("latin-1")
        return None

    def on_return(self, name):
        if _reg(_RET_REG.get(arch_name(), "rax")) != 0:
            set_retval(0)
            self.plugin.note("hid environment variable %s" % name)


# --- CPUID spoof ------------------------------------------------------------
def reg32(name):
    return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFF


def set32(name, value):
    gdb.execute("set $%s = %d" % (name, value & 0xFFFFFFFF), to_string=True)


class _AddrBP(gdb.Breakpoint):
    """A silent breakpoint at a raw address that runs `handler` and resumes."""

    def __init__(self, addr, plugin, handler):
        super(_AddrBP, self).__init__("*0x%x" % addr, type=gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        self.plugin = plugin
        self.handler = handler

    def stop(self):
        try:
            self.handler()
        except Exception:
            emit(self.plugin.id, "error: " + last_error())
        return False


def _executable_ranges():
    """(start, end) of the target's own executable mappings, from info proc mappings."""
    try:
        text = gdb.execute("info proc mappings", to_string=True)
    except Exception:
        return []
    try:
        main = gdb.current_progspace().filename
    except Exception:
        main = None
    ranges = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or not parts[0].startswith("0x"):
            continue
        try:
            start, end = int(parts[0], 16), int(parts[1], 16)
        except ValueError:
            continue
        if "x" not in parts[4]:
            continue
        objfile = parts[5] if len(parts) >= 6 else ""
        # The main executable and anonymous executable memory (unpacked code); not libc/ld.
        if objfile and main and objfile != main:
            continue
        ranges.append((start, end))
    return ranges


VM_BRAND_TOKENS = (b"QEMU", b"KVM", b"VMware", b"Virtual", b"Xen", b"Bochs")


@register
class CpuidSpoof(Plugin):
    """Hides a hypervisor from CPUID.

    Breakpoints every cpuid site in the target and, after each executes, clears the
    hypervisor-present bit (leaf 1), blanks the hypervisor vendor leaves
    (0x40000000..) and scrubs the brand string (0x80000002..).
    """

    id = "cpuid_spoof"

    def install(self):
        if arch_name() not in ("i386", "i386:x86-64"):
            emit(self.id, "CPUID spoofing applies to x86 targets only")
            return
        self.leaf = {}  # thread ptid -> (requested leaf, subleaf), set at each cpuid, used after
        try:
            self._arch = gdb.selected_frame().architecture()
        except Exception:
            self._arch = None
        count = 0
        for start, end in _executable_ranges():
            try:
                blob = read_mem(start, end - start)
            except Exception:
                continue
            i = blob.find(b"\x0f\xa2")
            while i >= 0:
                addr = start + i
                if self._is_cpuid(addr):
                    # Capture the requested leaf before cpuid runs; patch results just after.
                    self.track(_AddrBP(addr, self, self._pre))
                    self.track(_AddrBP(addr + 2, self, self._post))
                    count += 1
                i = blob.find(b"\x0f\xa2", i + 1)
        emit(self.id, "watching %d cpuid site(s)" % count)

    def _is_cpuid(self, addr):
        if self._arch is None:
            return True
        try:
            insns = self._arch.disassemble(addr, count=1)
        except Exception:
            return False
        return bool(insns) and insns[0]["length"] == 2 and insns[0]["asm"].split()[0] == "cpuid"

    def _ptid(self):
        try:
            return gdb.selected_thread().ptid
        except Exception:
            return 0

    def _pre(self):
        self.leaf[self._ptid()] = (reg32("eax"), reg32("ecx"))

    def _post(self):
        leaf, _sub = self.leaf.pop(self._ptid(), (None, None))
        if leaf is None:
            return
        if leaf == 1:
            ecx = reg32("ecx")
            if ecx & (1 << 31):
                set32("ecx", ecx & ~(1 << 31))
                self.note("cleared CPUID hypervisor-present bit")
        elif 0x40000000 <= leaf <= 0x400000FF:
            if any(reg32(r) for r in ("eax", "ebx", "ecx", "edx")):
                for r in ("eax", "ebx", "ecx", "edx"):
                    set32(r, 0)
                self.note("hid CPUID hypervisor leaf 0x%08x" % leaf)
        elif leaf in (0x80000002, 0x80000003, 0x80000004):
            raw = struct.pack("<IIII", reg32("eax"), reg32("ebx"), reg32("ecx"), reg32("edx"))
            scrubbed = _scrub_tokens(raw, VM_BRAND_TOKENS)
            if scrubbed != raw:
                values = struct.unpack("<IIII", scrubbed)
                for name, value in zip(("eax", "ebx", "ecx", "edx"), values):
                    set32(name, value)
                self.note("scrubbed CPUID brand string")


# --- VM syscall cloak -------------------------------------------------------
UNAME_MARKERS = (b"kali", b"microsoft", b"wsl", b"sandbox", b"cuckoo", b"remnux",
                 b"vbox", b"virtualbox", b"vmware", b"qemu", b"xen", b"malware", b"analyst")
UTSNAME_FIELD = 65  # _UTSNAME_LENGTH on Linux; utsname has six fields back to back.


@register
class VmSyscallCloak(Plugin):
    """Normalizes uname(), gethostname() and sysinfo() so an analysis VM looks like a workstation."""

    id = "vm_syscall_cloak"

    def install(self):
        seen = set()
        for cls, name in ((_UnameHook, "uname"), (_UnameHook, "__uname"),
                          (_HostnameHook, "gethostname"), (_SysinfoHook, "sysinfo")):
            addr = symbol_addr(name)
            if addr is None or addr in seen:
                continue
            hook = cls(self, name)
            if hook.install():
                seen.add(addr)
                self.track(hook)


def _scrub_uname_field(index, field):
    text = field.split(b"\x00", 1)[0]
    low = text.lower()
    # Field 1 is nodename (the hostname): replace it wholesale when it names an analysis box.
    if index == 1 and any(marker in low for marker in UNAME_MARKERS):
        name = b"desktop"
        return name + b"\x00" * (len(field) - len(name))
    scrubbed = _scrub_tokens(text, UNAME_MARKERS)
    if scrubbed != text:
        return scrubbed + b"\x00" * (len(field) - len(scrubbed))
    return None


class _UnameHook(FunctionHook):
    def on_entry(self):
        return arg(0)  # struct utsname *

    def on_return(self, buf):
        if _reg(_RET_REG.get(arch_name(), "rax")) != 0 or not buf:
            return
        changed = False
        for index in range(6):  # sysname, nodename, release, version, machine, domainname
            off = buf + index * UTSNAME_FIELD
            try:
                field = read_mem(off, UTSNAME_FIELD)
            except Exception:
                continue
            new = _scrub_uname_field(index, field)
            if new is not None:
                write_mem(off, new)
                changed = True
        if changed:
            self.plugin.note("normalized uname()")


class _HostnameHook(FunctionHook):
    def on_entry(self):
        return (arg(0), arg(1))  # (buffer, size)

    def on_return(self, ctx):
        buf, size = ctx
        if _reg(_RET_REG.get(arch_name(), "rax")) != 0 or not buf or not size:
            return
        try:
            data = read_mem(buf, min(size, 256))
        except Exception:
            return
        name = data.split(b"\x00", 1)[0]
        if any(marker in name.lower() for marker in UNAME_MARKERS):
            write_mem(buf, b"desktop\x00"[:size])
            self.plugin.note("spoofed gethostname()")


class _SysinfoHook(FunctionHook):
    # struct sysinfo (LP64): totalram at offset 32, freeram at 40, mem_unit at 104.
    TARGET_RAM = 16 * 1024 ** 3

    def on_entry(self):
        return arg(0)  # struct sysinfo *

    def on_return(self, buf):
        if arch_name() not in ("i386:x86-64", "aarch64") or not buf:
            return
        if _reg(_RET_REG.get(arch_name(), "rax")) != 0:
            return
        try:
            totalram = int.from_bytes(read_mem(buf + 32, 8), "little")
            mem_unit = int.from_bytes(read_mem(buf + 104, 4), "little") or 1
        except Exception:
            return
        if totalram * mem_unit >= self.TARGET_RAM:
            return
        units = self.TARGET_RAM // mem_unit
        write_mem(buf + 32, units.to_bytes(8, "little"))
        write_mem(buf + 40, (units // 2).to_bytes(8, "little"))
        self.plugin.note("raised reported memory size")


# --- internal self-test plugin (hidden from the catalog) --------------------
@register
class _SelfTest(Plugin):
    """Counts silent hits at `main`; exercises the framework in tests."""

    id = "_selftest"

    def install(self):
        self.track(Silent("main", self))

    def on_hit(self, bp):
        self.note("reached main")
