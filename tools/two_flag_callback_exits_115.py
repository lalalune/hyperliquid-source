"""Python model of node #115's two callback exits 0x606a170 and
0x606a650 -- the two callees the merged packet
RE-001-two-flag-lazy-init-115 reached only "by contract".

Implements the semantics pinned by
research/work-items/RE-001-two-flag-callback-exits-115:

- ``free_mem_with_cache`` (0x606a170) is the callback's
  [object + 0x20] != 0 arm target: it subtracts the amount from a
  running total under a mutex, then walks a chain of up to five
  cache objects, at each level either deferring to that object's
  own flavour of the +0x10 virtual when it differs from the
  previous level's, or locking the object's mutex and descending.
- ``maybe_end_write_stall`` (0x606a650) is the callback's tail-jump
  target on every path: gated on a flag byte and on the total being
  below a limit, it clears a second flag under a mutex, notifies
  every element of an embedded intrusive list, then detaches the
  whole list and frees only the 0x18-byte list nodes.

State is a flat byte-addressed ``Mem`` so the model can be compared
byte-for-byte with an emulator run of the real code. Callees the
binary reaches through function pointers or PLT entries are
injected callables / configuration, mirroring how the packet pins
them:

- ``lock_fail``: {mutex_address: errno} -- the return value the
  pthread_mutex_lock PLT call produces for that mutex (0 = locked).
  A nonzero value makes the body call __throw_system_error(errno)
  at once; the model raises :class:`ThrowSystemError` after logging
  the unwind unlocks the LSDA assigns to that call site.
- ``chain_call`` / ``notify_call`` / ``direct_call``: stand-ins for
  the virtual and direct callees. They may raise
  :class:`CalleeThrow` to model a throwing callee; the model then
  logs the landing-pad unlock sequence and re-raises.

The event log records, in order: ('lock', addr, rc),
('unlock', addr), ('vcall', fn, obj, total) for the 0x606a170 chain
calls, ('vcall1', fn, elem) for the 0x606a650 unknown-flavour
notify, ('ncall', target, arg) for the three known-flavour notify
calls, ('delete_array', ptr) for operator delete[], ('delete',
ptr, size) for operator delete(ptr, size), and ('throw', errno)
when __throw_system_error is entered. Memory writes themselves are
not logged; they are compared through the final memory image.

Model-side conventions (not binary behaviour, stated explicitly):
the 0x18-byte out struct the chain virtual writes through is
zero-initialised here; in the binary it is uninitialised stack.
The two flavour sentinels are the runtime values of the qwords at
0x64ece40 and 0x64ed568 after their R_X86_64_RELATIVE relocations
(addends 0x5d8aee0 and 0x5d48820, pinned in the packet's
relocations.txt).
"""

MASK64 = (1 << 64) - 1

KNOWN_CHAIN_FN = 0x5D8AEE0    # runtime value of qword at 0x64ece40
KNOWN_NOTIFY_FN = 0x5D48820   # runtime value of qword at 0x64ed568
NOTIFY_CALLS = (0x60D5230, 0x60D52F0, 0x60D5700)
NODE_SIZE = 0x18


class ThrowSystemError(Exception):
    """__throw_system_error(errno) was entered; carries the code."""

    def __init__(self, code):
        super().__init__("system error %d" % code)
        self.code = code


class CalleeThrow(Exception):
    """An injected callee raised; the frame unwinds via its LSDA."""


class Mem:
    """Flat byte-addressed memory over [base, base + size)."""

    def __init__(self, base, size):
        self.base = base
        self.buf = bytearray(size)

    def _i(self, addr, n):
        i = addr - self.base
        if i < 0 or i + n > len(self.buf):
            raise IndexError("address out of range: %#x" % addr)
        return i

    def q(self, addr):
        i = self._i(addr, 8)
        return int.from_bytes(self.buf[i:i + 8], "little")

    def setq(self, addr, value):
        i = self._i(addr, 8)
        self.buf[i:i + 8] = (value & MASK64).to_bytes(8, "little")

    def byte(self, addr):
        return self.buf[self._i(addr, 1)]

    def setbyte(self, addr, value):
        self.buf[self._i(addr, 1)] = value & 0xFF

    def dword(self, addr):
        i = self._i(addr, 4)
        return int.from_bytes(self.buf[i:i + 4], "little")

    def setdword(self, addr, value):
        i = self._i(addr, 4)
        self.buf[i:i + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")


def _lock(log, lock_fail, addr):
    rc = lock_fail.get(addr, 0)
    log.append(("lock", addr, rc))
    return rc


def _unwind(log, held, outer_mutex):
    """Landing-pad unlock sequence: held sub-mutexes in reverse
    acquisition order, then the outer mutex."""
    for addr in reversed(held):
        log.append(("unlock", addr))
    log.append(("unlock", outer_mutex))


def free_mem_with_cache(mem, log, this, size, lock_fail=None,
                        chain_call=None):
    """0x606a170(this, size): subtract size from [this + 0x10] and
    propagate the new total down the cache chain. Returns the new
    total. Raises ThrowSystemError on a mutex failure and re-raises
    CalleeThrow from a chain callee, in both cases after logging
    the unlock sequence the LSDA assigns to the failing call site
    (the this-mutex's own failure has no landing pad: no unlocks).
    """
    lock_fail = lock_fail or {}
    if chain_call is None:
        def chain_call(fn, out, obj, total):
            return None
    outer = this + 0x30
    rc = _lock(log, lock_fail, outer)
    if rc != 0:
        log.append(("throw", rc))
        raise ThrowSystemError(rc)
    total = (mem.q(this + 0x10) - size) & MASK64
    mem.setq(this + 0x10, total)
    out = Mem(0, 0x18)
    held = []
    obj = mem.q(this + 0x20)
    fn = mem.q(mem.q(obj) + 0x10)
    expect = KNOWN_CHAIN_FN
    try:
        depth = 1
        while True:
            if fn != expect:
                log.append(("vcall", fn, obj, total))
                chain_call(fn, out, obj, total)
                break
            rc = _lock(log, lock_fail, obj + 0x18)
            if rc != 0:
                log.append(("throw", rc))
                _unwind(log, held, outer)
                raise ThrowSystemError(rc)
            held.append(obj + 0x18)
            if depth == 4:
                last = mem.q(obj + 0x40)
                fn5 = mem.q(mem.q(last) + 0x10)
                log.append(("vcall", fn5, last, total))
                chain_call(fn5, out, last, total)
                break
            expect = fn
            obj = mem.q(obj + 0x40)
            fn = mem.q(mem.q(obj) + 0x10)
            depth += 1
    except CalleeThrow:
        _unwind(log, held, outer)
        raise
    for addr in reversed(held):
        log.append(("unlock", addr))
    if out.q(0x08) != 0:
        log.append(("delete_array", out.q(0x08)))
    log.append(("unlock", outer))  # tail jump to pthread_mutex_unlock
    return total


def maybe_end_write_stall(mem, log, this, local_head, lock_fail=None,
                          notify_call=None, direct_call=None):
    """0x606a650(this): maybe notify the embedded list and drain it.

    ``local_head`` is the address of the body's stack-local list
    head; it is observable only through the write of that address
    into the last detached node's +0x08 field during the splice.
    Returns 'gated_flag', 'gated_total', 'idle' or 'drained'.
    Raises ThrowSystemError on a mutex failure (the landing pad
    frees only the still-empty local list: no log events) and
    re-raises CalleeThrow after logging the pad's mutex unlock.
    """
    lock_fail = lock_fail or {}
    if notify_call is None:
        def notify_call(fn, elem):
            return None
    if direct_call is None:
        def direct_call(target, arg):
            return None
    if mem.byte(this + 0x98) == 0:
        return "gated_flag"
    if mem.q(this + 0x10) >= mem.q(this + 0x00):
        return "gated_total"
    mutex = this + 0x70
    rc = _lock(log, lock_fail, mutex)
    if rc != 0:
        log.append(("throw", rc))
        raise ThrowSystemError(rc)
    if mem.byte(this + 0x99) == 0:
        log.append(("unlock", mutex))
        return "idle"
    mem.setbyte(this + 0x99, 0)
    sentinel = this + 0x58
    node = mem.q(sentinel)
    try:
        while node != sentinel:
            elem = mem.q(node + 0x10)
            fn = mem.q(mem.q(elem) + 0x18)
            if fn == KNOWN_NOTIFY_FN:
                log.append(("ncall", NOTIFY_CALLS[0], elem + 0x08))
                direct_call(NOTIFY_CALLS[0], elem + 0x08)
                mem.setdword(elem + 0x68, 1)
                log.append(("ncall", NOTIFY_CALLS[1], elem + 0x08))
                direct_call(NOTIFY_CALLS[1], elem + 0x08)
                log.append(("ncall", NOTIFY_CALLS[2], elem + 0x30))
                direct_call(NOTIFY_CALLS[2], elem + 0x30)
            else:
                log.append(("vcall1", fn, elem))
                notify_call(fn, elem)
            node = mem.q(node)
    except CalleeThrow:
        log.append(("unlock", mutex))
        raise
    first = mem.q(sentinel)
    nodes = []
    if first != sentinel:
        node = first
        while True:
            nodes.append(node)
            nxt = mem.q(node)
            if nxt == sentinel:
                break
            node = nxt
        last = mem.q(this + 0x60)
        mem.setq(last, local_head)        # last node's next
        mem.setq(first + 0x08, local_head)  # first node's prev
        mem.setq(sentinel, sentinel)
        mem.setq(this + 0x60, sentinel)
        mem.setq(this + 0x68, 0)
    log.append(("unlock", mutex))
    for node in nodes:
        log.append(("delete", node, NODE_SIZE))
    return "drained"
