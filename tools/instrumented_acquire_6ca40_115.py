"""Model of node #115 instrumented acquire, 0x606ca40..0x606cc6a (RE-001).

The routine takes one object pointer (rdi) and returns void. It acquires
the object's lock through the stub at 0x606ca00 (mapped in PR #2588),
optionally surrounded by perf-gated instrumentation. Only the ordering,
gates and argument lists below are pinned; the callees 0x606dd10 and
0x5fe2680, the TLS perf-level accessor and the virtual slots are opaque
here -- their internals are not claimed, only when they are called.

Object layout used by the routine (offsets from the object pointer):
  +0x28  context pointer (r12); null means ungated.
  +0x30  nonzero flag; the gate needs this AND a non-null context.
  +0x38  type code (r15d); 0x34 selects the virtual-timer path.
Context layout: byte at +0x20, compared unsigned against 4.
TLS layout: byte at (thread pointer - 0x10b0), compared unsigned
against 4; counter at (thread pointer - 0x350 + 0x1b8).
Stack record passed to 0x5fe2680 (address rsp+0x10):
  +0x00  record flag byte (the TLS byte > 4 result),
  +0x01  zero byte,
  +0x04  type code (int).
The record's +0x10 slot (rsp+0x20) holds the first timer result; the
cleanup block disposes the record through 0x606c94c only when that
slot is nonzero, then resumes unwinding.
"""

PERF_BYTE_LIMIT = 4
TIMER_TYPE = 0x34


class NullObjectError(ValueError):
    """Raised when the routine's object pointer is null."""


def acquire(obj, hooks):
    """Run the instrumented acquire over a fake object.

    obj is None for a null pointer, otherwise a dict with keys:
      ctx (None or a dict with key 'byte', the +0x20 byte),
      flag_nonzero (bool, the +0x30 field),
      type_code (int, the +0x38 field).
    hooks is a dict of callables/lists the model records into:
      prologue: called once, no pinned arguments (callee 0x606dd10).
      tls_getter: called only when hooks['global_nonzero'] is true.
      begin: called with the stack record dict (callee 0x5fe2680).
      now: called for each virtual slot 0xa0 read; returns an int.
      lock: called for the stub at 0x606ca00 (the actual lock).
      observe: called with (ctx, type_code, elapsed) for slot 0xb0.
      counter: a one-element list holding the TLS counter value.
      tls_byte: int, the byte at (thread pointer - 0x10b0).
      global_nonzero: bool, the qword at 0x64ed2b0.
    Returns a dict with the ordered event names, the record flag,
    whether the cleanup guard would dispose the record on unwind,
    and the final counter value.
    """
    if obj is None:
        raise NullObjectError("instrumented acquire on a null object")
    events = []

    def emit(name, *args):
        events.append(name)
        fn = hooks.get(name)
        if callable(fn):
            return fn(*args)
        return None

    # (1) Opaque prologue, called on every path, return value unused.
    emit("prologue")
    # (2) Global gate for the TLS accessor; its return value is unused.
    if hooks.get("global_nonzero"):
        emit("tls_getter")
    ctx = obj.get("ctx")
    gated = bool(obj.get("flag_nonzero")) and ctx is not None
    tls_flag = hooks.get("tls_byte", 0) > PERF_BYTE_LIMIT
    # Fast path: gated and the context byte is above the limit.
    # Fallback path: the context and the gate flag are zeroed, so the
    # observe step can never run there; only the TLS flag decides
    # whether the begin/timer path is taken.
    fast = gated and ctx["byte"] > PERF_BYTE_LIMIT
    observe_allowed = fast
    begin_called = fast or tls_flag
    record = {
        "flag": tls_flag,
        "zero_byte": 0,
        "type_code": obj["type_code"],
    }
    if begin_called:
        emit("begin", record)
    guard_dispose = False
    if begin_called and obj["type_code"] == TIMER_TYPE:
        first = emit("now")
        emit("lock")
        if first:
            second = emit("now")
            elapsed = second - first
            if tls_flag:
                hooks["counter"][0] += elapsed
            if observe_allowed:
                emit("observe", ctx, obj["type_code"], elapsed)
            guard_dispose = True
        # A zero first timer result skips the second read, the
        # counter add and the observe call, and leaves the record
        # slot zero, so the cleanup guard would not dispose it.
    else:
        emit("lock")
    return {
        "events": events,
        "record_flag": tls_flag,
        "guard_dispose_on_unwind": guard_dispose,
        "counter": hooks["counter"][0],
    }
