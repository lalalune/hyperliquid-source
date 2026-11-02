"""Model of node #94's WAL flush driver, window 0x50ebfb0..0x50ec9d7 (RE-001).

The model pins the driver's own control flow: gate order, log calls and
their value slots, the collection rule, the per-item copy/stop rules, the
post-loop phase order and gating, the marking loop, and teardown. The
per-item handler and every phase are injectable callables: only their
call contracts (arguments and ordering) are pinned, not their internals,
exactly as the evidence packet records them.

Result struct layout: u32 code at +0, u16 subcode at +4, heap pointer
at +8. The loop and the phase chain continue only while the low byte of
the +0 field is 0.
"""

MAIN_FILE = "db/db_impl/db_impl_write.cc"
MAIN_FORMAT = (
    "[%s:1638] Flushing all column families with data in WAL number %lu. "
    "Total log size is %lu while max_total_wal_size is %lu"
)
SWEEP_FORMAT = (
    "[%s:1621] Unable to release oldest log due to uncommitted transaction"
)

CONTEXT_INIT = {
    0x00: 0,
    0x08: 0x400000000,
    0x10: 0,
    0x18: 0,
    0x28: 0,
    0x38: 0,
    0x48: 0,
    0x50: 0x100,
    0x58: 0,
    0x60: 0x00FFFFFFFFFFFFFF,
    0x68: 0,
    0x70: 0,
    0x78: 0,
    0x80: 0,
    0xF0: 0,
}

PHASE_E_CONTEXT = {
    0x00: None,  # pointer slot; filled with the context's own address
    0x08: 1,
    0x10: 0,
    0x18: 0,
    0x20: 1.0,
    0x28: 0,
    0x30: 0,
}


class Result:
    """The driver's result struct (u32 code, u16 subcode, pointer)."""

    def __init__(self, code=0, subcode=0, ptr=None):
        self.code = code & 0xFFFFFFFF
        self.subcode = subcode & 0xFFFF
        self.ptr = ptr

    def zero(self):
        self.code = 0
        self.subcode = 0
        self.ptr = None

    @property
    def low_byte(self):
        return self.code & 0xFF

    def __repr__(self):
        return f"Result(code={self.code}, subcode={self.subcode}, ptr={self.ptr!r})"


class Item:
    """One collection-list item. Only the fields the driver reads or writes."""

    def __init__(self, flagged=False, score=0, value900=0):
        self.flagged = flagged  # byte at +0x3d
        self.score = score  # 0x4feb700 return value
        self.refcount = 0  # field at +0x38, locked-incremented
        self.value900 = value900  # s32 at +0x900
        self.mark905 = False  # byte at +0x905
        self.mark8f0 = False  # byte at +0x8f0
        self.handler_result = Result()  # what the handler writes


class Db:
    """The manager struct. Only the fields the driver reads or writes."""

    def __init__(self, wal_number=0, c28=0):
        self.wal_number = wal_number  # gate-A struct first field
        self.gate_a_flag = False  # gate-A struct byte +0x10
        self.flag_4a3 = False  # db + 0x4a3
        self.flag_4c7 = False  # db + 0x4c7 (read fresh at each use)
        self.flag_17b0 = False  # db + 0x17b0
        self.flag_1511 = False  # db + 0x1511 (sweep-log once-flag)
        self.c28 = c28  # db + 0xc28, second main-log value
        self.items = []  # collection list in walk order
        self.sweep_result = 0  # 0x5160560 return value


class Hooks:
    """Injectable callees. Tests subclass this to record calls."""

    def entry_hook(self, db):
        pass

    def third_log_value(self, db):
        return 0

    def log(self, level, file, fmt, values):
        pass

    def sweep(self, db):
        return db.sweep_result

    def score(self, item):
        return item.score

    def phase_a(self, db, count_slot, overflow):
        pass

    def phase_b(self, db, context):
        pass

    def phase_c(self, db, context):
        pass

    def phase_d(self, db, context):
        pass

    def phase_e(self, db, context):
        pass

    def phase_f(self, db, context):
        pass

    def phase_g(self, db, context):
        pass

    def marking_phase(self, db, item, context):
        pass

    def handler(self, db, item, arg3, context):
        return item.handler_result

    def release(self, item):
        pass

    def free(self, ptr):
        pass

    def destroy_condition_variable(self, context):
        pass


def _teardown(db, context, hooks, overflow):
    if context[0x50] & 0xFF:
        hooks.destroy_condition_variable(context)
    # Context heap buffers and the overflow buffer are freed when
    # non-null; the model has no heap buffers, so only the overflow
    # list is dropped here (recorded by the caller through hooks).


def drive_flush(out, db, arg3, hooks=None):
    """Run one full driver pass, writing into ``out`` and returning it."""
    hooks = hooks or Hooks()
    hooks.entry_hook(db)
    out.zero()
    if db.gate_a_flag:
        return out
    if db.flag_4a3:
        swept = hooks.sweep(db)
        if swept == 0 or swept != db.wal_number:
            db.flag_1511 = False
            db.gate_a_flag = True
            return _main_body(out, db, arg3, hooks)
        if db.flag_1511:
            return out
        hooks.log(2, MAIN_FILE, SWEEP_FORMAT, [])
        db.flag_1511 = True
        # Restart jumps straight to the 0x50e6a90 call: no reset of
        # flag_1511 and no gate-A flag store on this path.
        return _main_body(out, db, arg3, hooks)
    db.flag_1511 = False
    db.gate_a_flag = True
    return _main_body(out, db, arg3, hooks)


def _main_body(out, db, arg3, hooks):
    third = hooks.third_log_value(db)
    hooks.log(1, MAIN_FILE, MAIN_FORMAT, [db.wal_number, db.c28, third])
    inline = []
    overflow = []
    context = dict(CONTEXT_INIT)
    if db.flag_4c7:
        # Phase G runs on a preliminary context; the canonical init
        # that follows overwrites the pinned fields, while any other
        # phase-G field survives.
        hooks.phase_g(db, context)
        context.update(CONTEXT_INIT)
    else:
        for item in db.items:
            if item.flagged:
                continue
            if hooks.score(item) < db.wal_number:
                continue
            if len(inline) < 8:
                inline.append(item)
            else:
                overflow.append(item)
        hooks.phase_a(db, len(inline) + len(overflow), overflow)
    items = inline + overflow
    total = len(items)
    if db.flag_17b0:
        hooks.phase_b(db, context)
    i = 0
    while i < total:
        item = items[i]
        item.refcount += 1
        result = hooks.handler(db, item, arg3, context)
        old_ptr = out.ptr
        out.code = result.code & 0xFFFFFFFF
        out.subcode = result.subcode & 0xFFFF
        out.ptr = result.ptr
        result.subcode = 0  # the result slot's u16 is consumed
        if old_ptr is not None:
            hooks.free(old_ptr)
        hooks.release(item)
        if out.low_byte != 0:
            break
        i += 1
    # Post-loop chain.
    if db.flag_17b0:
        hooks.phase_c(db, context)
    if out.low_byte != 0:
        _teardown(db, context, hooks, overflow)
        return out
    if db.flag_4c7:
        hooks.phase_d(db, context)
        phase_e_ctx = dict(PHASE_E_CONTEXT)
        hooks.phase_e(db, phase_e_ctx)
        hooks.phase_f(db, context)
    else:
        if total > 0:
            for item in items:
                item.mark905 = True
                if item.value900 > 0:
                    item.mark8f0 = True
                if not db.flag_4c7:
                    hooks.marking_phase(db, item, context)
        phase_e_ctx = dict(PHASE_E_CONTEXT)
        hooks.phase_e(db, phase_e_ctx)
        hooks.phase_f(db, context)
    _teardown(db, context, hooks, overflow)
    return out
