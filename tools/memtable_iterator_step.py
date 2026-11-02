"""RE-001: node #94 memtable iterator step (0x5168160).

One complete iterator step end to end, not a lone-window fragment:
refresh the underlying iterator, run the memtable entry check when a
tag width is present, install the check record, report a failed check,
and fill the caller's key slice.  This is the neighbour of the
refresh-handler family mapped in #1984 and of the entry check mapped
in #1985: it drives both (the refresh virtuals, then the reader
0x5167040) and adds the key-slice fill that the handlers lack.

Observed (from the disassembly window in the evidence packet):

* Signature: ``step(this, key_out) -> bool``.  The binary takes
  ``(this, key_out)``; the model returns ``(ok, key, state, log)``
  instead of writing through a pointer.
* State fields on ``this`` (offsets verbatim from the window):
  ``+0x50`` inner iterator object, ``+0x58`` ready flag,
  ``+0x60`` tag width, ``+0x68`` check code, ``+0x6c`` check subcode,
  ``+0x70`` check detail string, ``+0x78`` report context.
* Head gate: the vtable slot at ``+0x38`` is compared against the
  relocated GOT value 0x5167fd0 (the #1984 fd0 refresh handler
  address).  Equal -> the inline perf + refresh path below.
  Unequal -> call that virtual, take its return value as the ready
  flag, and join the width path (the inner ``+0x20``/``+0x10``
  virtuals are skipped).
* Inline refresh: call the inner object's ``+0x20`` virtual, then
  its ``+0x10`` virtual; store that result to ``+0x58`` (ready).
  Perf prologue, inline path only: when the perf-level slot
  0x5777ef8 is nonzero its getter (0x56606a0) is called; when the
  TLS byte at fs:0-0x10a8 is above 1, the perf helper 0x52cd6e0 is
  called and the counter at TLS-0x350+0x148 is incremented.
* Width path: ``width == 0`` skips the reader; ``width != 0`` runs it.
  Predicate gate: the vtable slot at ``+0x10`` is compared against
  the known predicate 0x51647b0.  Known -> the gate is inlined:
  ready must be nonzero and code must be zero.  Unknown -> the
  predicate virtual is called and its bool result is the gate.
* Reader install (width != 0, gate passed): buffer = inner
  ``+0x18`` virtual; call the entry check 0x5167040 as
  ``reader(record, buffer, width, 0)``; install its code/sub/detail
  to ``+0x68/+0x6c/+0x70``; free the previous detail string
  afterwards (install-before-free, as in the window).
* After the install the flow rejoins the predicate gate: known ->
  ready and code == 0 again (so a failed check returns False after
  its report); unknown -> the predicate is called again and must
  still be true to reach the slice.  A failed check (code != 0)
  reports first, via 0x522e770 at level 3 with context ``+0x78``,
  format ``"[%s:538] In MemtableIterator: %s"`` and file
  ``"db/memtable.cc"``.
* Key slice fill (all True paths): the vtable slot at ``+0x50`` is
  compared against the relocated GOT value 0x51657e0.  Equal -> the
  default provider is inlined: buffer = inner ``+0x18`` virtual,
  then a length-prefix parse of that buffer (first byte below 0x80
  is the length, slice starts one byte later; otherwise a bounded
  LEB128 varint at the buffer start, limit buffer + 5, decoded by
  0x541cec0, slice starts past the varint).  Unequal -> call that
  virtual; its ``(ptr, len)`` return is the slice.  Every True path
  writes the u16 value 0x100 at key ``+0x10``; the meaning of that
  tag is recorded as unresolved, only its value is pinned.
* Quirks, modelled literally and tested: (a) in the width != 0
  path an unknown predicate that returns False is called a second
  time after rejoining the gate; if the second call returns True
  the slice is filled with no reader call at all.  (b) After a
  failed check, an unknown predicate that still returns True
  reaches the slice, so the step reports and still returns True;
  a predicate that mirrors the known gate (ready and code == 0)
  returns False there, as the known gate does.

The reader itself is by contract here (mapped in #1985); the model
takes it as a callable so the step's own logic is what the tests
pin.
"""


def parse_length_prefixed(buffer):
    """Length-prefix parse shared with the default key provider.

    Returns ``(ptr_offset, length)``: the slice of ``buffer`` that
    the binary's key fill returns.  ``buffer`` is a bytes object.
    """
    if not buffer:
        raise ValueError("empty buffer has no length prefix")
    first = buffer[0]
    if first < 0x80:
        return (1, first)
    # Bounded LEB128 at buffer[0:], at most 5 bytes (limit buffer+5).
    value = 0
    shift = 0
    for i in range(5):
        if i >= len(buffer):
            raise ValueError("varint runs past the buffer")
        byte = buffer[i]
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return (i + 1, value)
    raise ValueError("varint exceeds the 5-byte limit")


class IterState:
    """The ``this`` fields the step reads and writes."""

    def __init__(self, width=0, ready=False, code=0, sub=0,
                 detail=None, context=None):
        self.width = width
        self.ready = ready
        self.code = code
        self.sub = sub
        self.detail = detail
        self.context = context
        self.predicate_calls = 0
        self.buffer_calls = 0
        self.perf_counter = 0


class Inner:
    """The ``+0x50`` object: next (+0x20), valid (+0x10), buffer (+0x18)."""

    def __init__(self, buffer=b"", valid=True, key_other=None):
        self._buffer = buffer
        self._valid = valid
        self.key_other = key_other  # (ptr, len) or None for default
        self.next_calls = 0
        self.valid_calls = 0

    def next(self):
        self.next_calls += 1

    def valid(self):
        self.valid_calls += 1
        return self._valid

    def buffer(self, state):
        state.buffer_calls += 1
        return self._buffer


def known_predicate(state):
    """The inlined gate for the known predicate 0x51647b0."""
    return bool(state.ready) and state.code == 0


def step(state, inner, head_kind="fd0", head_other=None,
         predicate_kind="known", predicate=None, reader=None,
         perf_present=False, tls_level_byte=0):
    """Run one iterator step.

    ``head_kind``: ``"fd0"`` (vtable +0x38 equals 0x5167fd0, inline
    path) or ``"other"`` (call ``head_other()`` for the ready flag).
    ``predicate_kind``: ``"known"`` (inlined gate) or ``"other"``
    (call ``predicate(state)``).  ``reader``: callable
    ``(buffer, width, flag) -> (code, sub, detail)``; required only
    when width != 0 and the gate passes.  Returns
    ``(ok, key, log)`` where ``key`` is ``(ptr, length, tag)`` or
    None and ``log`` is the ordered action list.
    """
    log = []

    # Head gate + inline refresh.
    if head_kind == "fd0":
        if perf_present:
            log.append("perf_getter")
        if tls_level_byte > 1:
            log.append("perf_helper")
            state.perf_counter += 1
            log.append("perf_counter++")
        inner.next()
        state.ready = inner.valid()
        log.append("refresh:next+valid ready=%s" % state.ready)
    else:
        state.ready = bool(head_other())
        log.append("refresh:head_other ready=%s" % state.ready)

    def fill_key():
        if inner.key_other is None:
            buf = inner.buffer(state)
            ptr, length = parse_length_prefixed(buf)
            log.append("key:default_parse ptr=%d len=%d" % (ptr, length))
        else:
            ptr, length = inner.key_other()
            log.append("key:other_provider ptr=%s len=%s" % (ptr, length))
        return (ptr, length, 0x100)

    def gate_known():
        return known_predicate(state)

    def gate_other():
        state.predicate_calls += 1
        return bool(predicate(state))

    width = state.width
    if width == 0:
        if predicate_kind == "known":
            if not gate_known():
                log.append("gate:known fail")
                return (False, None, log)
        else:
            if not gate_other():
                log.append("gate:other fail calls=%d" % state.predicate_calls)
                return (False, None, log)
        return (True, fill_key(), log)

    # Width != 0.
    if predicate_kind == "known":
        if not state.ready:
            log.append("gate:known not-ready")
            return (False, None, log)
        if state.code != 0:
            log.append("gate:known stale-code")
            return (False, None, log)
    else:
        if not gate_other():
            # Quirk (a): the false result rejoins the gate, which
            # calls the predicate a second time; a True second call
            # reaches the slice with no reader call.
            if not gate_other():
                log.append("gate:other fail calls=%d" % state.predicate_calls)
                return (False, None, log)
            log.append("gate:other second-call true -> slice, no reader")
            return (True, fill_key(), log)

    # Reader install.
    buf = inner.buffer(state)
    code, sub, detail = reader(buf, width, 0)
    old_detail = state.detail
    state.code, state.sub, state.detail = code, sub, detail
    log.append("reader:install code=%d sub=%d" % (code, sub))
    if old_detail is not None:
        log.append("free_old_detail")
    if code != 0:
        log.append("report level=3 format=[%%s:538] In MemtableIterator: %%s "
                   "file=db/memtable.cc detail=%r" % detail)
    # Rejoin the gate after install/report.
    if predicate_kind == "known":
        if not gate_known():
            log.append("gate:known post-install fail")
            return (False, None, log)
    else:
        if not gate_other():
            log.append("gate:other post-install fail calls=%d"
                       % state.predicate_calls)
            return (False, None, log)
    return (True, fill_key(), log)
