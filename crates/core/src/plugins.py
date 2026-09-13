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

    def install(self):
        raise NotImplementedError

    def remove(self):
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


# --- internal self-test plugin (hidden from the catalog) --------------------
@register
class _SelfTest(Plugin):
    """Counts silent hits at `main`; exercises the framework in tests."""

    id = "_selftest"

    def install(self):
        self.track(Silent("main", self))

    def on_hit(self, bp):
        self.note("reached main")
