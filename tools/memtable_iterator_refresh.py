"""Python model of the node #94 MemtableIterator refresh handler family.

Implements the five windows mapped in
research/work-items/RE-001-memtable-iterator-refresh-94/:
0x5167ba0, 0x5167cf0, 0x5167e40, 0x5167fd0 and 0x51684d0, plus the known
predicate 0x51647b0. The reader 0x5167040 and the report routine
0x522e770 are injected callables: the packet pins the handler's use of
them, not their internals.

Field offsets are iterator-relative, matching the packet records.
"""

REPORT_FORMAT = "[%s:538] In MemtableIterator: %s"
REPORT_FILE = "db/memtable.cc"
REPORT_LEVEL = 3

# variant -> (first virtual slot on the +0x50 object or None,
#             perf counter key or None)
VARIANTS = {
    "ba0": (0x48, None),
    "cf0": (0x50, None),
    "e40": (0x28, 0x150),
    "fd0": (0x20, 0x148),
    "84d0": (None, None),
}


def known_predicate(iterator):
    """The 0x51647b0 rule: ready and not already installed."""
    return bool(iterator.ready) and iterator.code == 0


class MemtableIterator:
    """Iterator state plus injectable virtuals and counters."""

    def __init__(self, *, ready=False, width=0, code=0, sub=0, detail=None,
                 context=None, predicate_kind="known", predicate_fn=None,
                 memtable_first=None, memtable_ready=None,
                 memtable_buffer=None, perf_slot_present=False,
                 perf_level=0, perf_counters=None):
        self.ready = ready
        self.width = width
        self.code = code
        self.sub = sub
        self.detail = detail
        self.context = context
        self.predicate_kind = predicate_kind
        self.predicate_fn = predicate_fn
        self.memtable_first = memtable_first
        self.memtable_ready = memtable_ready
        self.memtable_buffer = memtable_buffer
        self.perf_slot_present = perf_slot_present
        self.perf_level = perf_level
        self.perf_counters = perf_counters if perf_counters is not None else {}
        self.events = []

    def _perf_prologue(self, counter_key):
        if self.perf_slot_present:
            self.events.append(("tls_getter",))
        if self.perf_level > 1:
            self.events.append(("perf_start",))
            self.perf_counters[counter_key] = self.perf_counters.get(counter_key, 0) + 1
            self.events.append(("perf_counter", counter_key,
                                self.perf_counters[counter_key]))


def refresh(iterator, variant, reader, report, delete_array):
    """Run one handler variant. Returns None; side effects are recorded.

    reader(buffer, width, mode) -> (code, sub, detail).
    report(level, context, format, file, detail) is the tail call.
    delete_array(pointer) frees an old detail buffer.
    """
    first_slot, perf_key = VARIANTS[variant]
    if perf_key is not None:
        iterator._perf_prologue(perf_key)
    if first_slot is not None:
        iterator.memtable_first()
        iterator.events.append(("first_virtual", first_slot))
        iterator.ready = bool(iterator.memtable_ready())
        iterator.events.append(("ready_stored", iterator.ready))
    if iterator.width == 0:
        iterator.events.append(("return_width_zero",))
        return
    if iterator.predicate_kind == "known":
        iterator.events.append(("known_predicate",))
        if not iterator.ready:
            iterator.events.append(("return_not_ready",))
            return
        if iterator.code != 0:
            iterator.events.append(("return_already_installed",))
            return
    else:
        result = iterator.predicate_fn()
        iterator.events.append(("predicate", result))
        if not result:
            iterator.events.append(("return_predicate_false",))
            return
        # The binary reloads field +0x60 here; the value is unchanged.
        _ = iterator.width
    buffer = iterator.memtable_buffer()
    iterator.events.append(("buffer", buffer))
    code, sub, detail = reader(buffer, iterator.width, 0)
    iterator.events.append(("reader", buffer, iterator.width, code, sub, detail))
    old_detail = iterator.detail
    iterator.code, iterator.sub, iterator.detail = code, sub, detail
    iterator.events.append(("install", code, sub, detail))
    if old_detail is not None:
        delete_array(old_detail)
        iterator.events.append(("free_old", old_detail))
    if iterator.code != 0:
        report(REPORT_LEVEL, iterator.context, REPORT_FORMAT, REPORT_FILE,
               iterator.detail)
        iterator.events.append(("report", REPORT_LEVEL, iterator.context,
                                iterator.detail))
