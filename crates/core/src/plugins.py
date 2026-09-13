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


# --- procfs & environment cloak --------------------------------------------
DEBUGGER_NAMES = (b"gdb", b"cutegdb", b"strace", b"ltrace", b"lldb", b"gdbserver")
ENV_HIDE = ("LINES", "COLUMNS", "LD_PRELOAD", "LD_AUDIT")


@register
class ProcfsCloak(Plugin):
    """Hides the debugger from /proc and the environment.

    Tracks file descriptors opened onto sensitive /proc paths and rewrites the
    bytes returned by read() so TracerPid is 0, the process looks running, and the
    parent process is not a debugger. Also nulls debugger-revealing getenv() lookups.
    """

    id = "procfs_cloak"

    def install(self):
        self.tracked_fds = {}  # fd -> path kind ("status" / "comm" / "stat")
        # Several of these names alias the same libc code (openat/openat64); only hook each
        # address once so a call is not intercepted twice.
        self._seen_addrs = set()
        # A list (not a generator) so every variant is attempted, not just up to the first success.
        opened = [self._add(_OpenHook(self, name)) for name in ("open", "open64", "openat", "openat64")]
        hooked = any(opened)
        for name in ("read", "pread", "pread64"):
            self._add(_ReadHook(self, name))
        self._add(_GetenvHook(self, "getenv"))
        if not hooked:
            emit(self.id, "no open symbol; /proc reads are not hooked")

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


def _proc_kind(path):
    if not path or b"/proc/" not in path:
        return None
    if path.endswith(b"/status"):
        return "status"
    if path.endswith(b"/comm"):
        return "comm"
    if path.endswith(b"/stat"):
        return "stat"
    return None


class _OpenHook(FunctionHook):
    def on_entry(self):
        # open(path,...) takes the path first; openat(dirfd, path, ...) takes it second.
        path = read_cstr(arg(1) if self.name.startswith("openat") else arg(0))
        kind = _proc_kind(path)
        return kind if kind else None

    def on_return(self, kind):
        fd = _reg(_RET_REG.get(arch_name(), "rax"))
        if fd < 0x80000000:  # a successful, non-negative fd
            self.plugin.tracked_fds[fd] = kind


class _ReadHook(FunctionHook):
    def on_entry(self):
        fd = arg(0)
        kind = self.plugin.tracked_fds.get(fd)
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
        new, note = _rewrite_proc(kind, data)
        if new is None:
            return
        # Never write past what the caller's buffer can hold.
        new = new[:capacity] if capacity else new
        write_mem(buf, new)
        if len(new) != count:
            set_retval(len(new))
        self.plugin.note(note)


def _rewrite_proc(kind, data):
    if kind == "status":
        return _rewrite_status(data)
    if kind == "comm":
        return _rewrite_comm(data)
    if kind == "stat":
        return _rewrite_stat(data)
    return (None, "")


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


# --- internal self-test plugin (hidden from the catalog) --------------------
@register
class _SelfTest(Plugin):
    """Counts silent hits at `main`; exercises the framework in tests."""

    id = "_selftest"

    def install(self):
        self.track(Silent("main", self))

    def on_hit(self, bp):
        self.note("reached main")
