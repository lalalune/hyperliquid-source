"""Model of node #115 routine 0x5d51d10: drain until quiet.

The routine takes one argument: an object pointer in rdi. It
keeps calling the worker at 0x606ccb0 with the object's field at
+0xa10 (the address of that field, via lea) until the object is
quiet, where quiet means BOTH pending indicators are zero:

  * the qword at object +0x1430, and
  * the dword at object +0x143c.

The check order, read from the whole-function excerpt in the
packet, matters for what is observed per iteration: each
iteration reads the +0x1430 qword first; only when it is zero
does the iteration read the +0x143c dword. A non-zero qword
calls the worker immediately without reading the dword, and a
zero qword with a non-zero dword calls the worker as well. The
routine returns (in rax, the original object pointer) only after
an iteration that reads a zero qword and then a zero dword.

The routine writes nothing itself and makes exactly one kind of
call: the worker at 0x606ccb0, always with the same argument
(object +0xa10). It has no tail jump out and no landing-pad
block inside its FDE range; the bytes after the range
(0x5d51d53..0x5d51d80) are int3 padding followed by a separate
routine's landing-pad block, not part of this routine.

NOT claimed: what the worker does, what the two pending fields
denote, or what the +0xa10 field denotes. The model therefore
takes the worker as a caller-supplied callable and the pending
fields as plain integers, and pins only the loop contract: the
call argument, the termination condition, the check order, and
the read counts per iteration.
"""

ROUTINE_ADDRESS = 0x5D51D10
ROUTINE_FDE = "0x5d51d10..0x5d51d53"
ROUTINE_SIZE_BYTES = 67
WORKER_ADDRESS = 0x606CCB0
CALLEE_ARG_OFFSET = 0xA10
PENDING_QWORD_OFFSET = 0x1430
PENDING_DWORD_OFFSET = 0x143C

UINT64_MAX = 2 ** 64 - 1
UINT32_MAX = 2 ** 32 - 1


def _check_pending(value, limit, label):
    if not isinstance(value, int) or isinstance(value, bool) \
            or not 0 <= value <= limit:
        raise ValueError("%s must be an integer 0..%d" % (label, limit))


class DrainObject:
    """The object as the routine sees it.

    ``pending_qword`` is the qword at +0x1430 and
    ``pending_dword`` is the dword at +0x143c. A worker mutates
    these fields (in the model, by holding a reference to this
    object); the routine itself only reads them.
    """

    def __init__(self, pending_qword=0, pending_dword=0):
        _check_pending(pending_qword, UINT64_MAX, "pending_qword")
        _check_pending(pending_dword, UINT32_MAX, "pending_dword")
        self.pending_qword = pending_qword
        self.pending_dword = pending_dword


class DrainTrace:
    """What one drain run observed: call count and read counts."""

    def __init__(self, calls, qword_reads, dword_reads):
        self.calls = calls
        self.qword_reads = qword_reads
        self.dword_reads = dword_reads


def drain_until_quiet(obj, worker):
    """Run the routine's loop over ``obj`` with ``worker``.

    ``worker`` is called with the single argument
    ``CALLEE_ARG_OFFSET`` (the object field at +0xa10, passed by
    address in the binary) once per loop iteration that finds a
    pending indicator non-zero. Returns a DrainTrace. The loop
    has no bound in the binary: a worker that never clears both
    pending fields never returns, so callers must use a worker
    that clears them (the tests do).
    """
    if not isinstance(obj, DrainObject):
        raise TypeError("obj must be a DrainObject")
    if not callable(worker):
        raise TypeError("worker must be callable")
    calls = 0
    qword_reads = 0
    dword_reads = 0
    while True:
        qword_reads += 1
        if obj.pending_qword != 0:
            worker(CALLEE_ARG_OFFSET)
            calls += 1
            continue
        dword_reads += 1
        if obj.pending_dword != 0:
            worker(CALLEE_ARG_OFFSET)
            calls += 1
            continue
        return DrainTrace(calls, qword_reads, dword_reads)
