#!/usr/bin/env python3
"""Python model of node #115 routine 0x5d5a350 (FDE 0x5d5a350..0x5d5a6aa).

The routine is a composite teardown for a holder at rdi. It returns
nothing, pushes r15/r14/r13/r12/rbp/rbx, reserves 0x38 bytes of stack
and performs no canary check. The holder itself is never freed.

One 0x40-byte record is torn down the same way wherever it appears:
its 0x18-byte plain-node list at +0x18 is drained first (next pointer
at node +0x00 loaded before each sized delete of exactly 0x18 via
the _ZdlPvm PLT 0x63f0d80); then its buffer at +0x08 is memset to
zero over count * 8 bytes (count at +0x10) via the memset PLT
0x63f0a90; then +0x20 and +0x18 are zeroed; then, unless the buffer
begin equals the record's own inline storage at record + 0x38, the
buffer is freed by a sized delete of (begin, count * 8). The buffer
phase runs for every record, even for a null begin with count 0.
Record bytes at +0x00 are never read, so no role is claimed for them.

The four phases run in this fixed order:

1. Middle chunks: for each chunk pointer in [holder+0x28 + 8,
   holder+0x48), each pointed-to 0x200-byte chunk holds eight
   0x40-byte records, torn down in order. This phase runs only
   when holder+0x28 + 8 < holder+0x48.
2. First chunk's live records: records in [holder+0x10,
   holder+0x20), stepping 0x40. Runs only when the start and
   finish chunk pointers differ (holder+0x28 != holder+0x48);
   an empty range runs zero iterations.
3. Last chunk's live records: records in [holder+0x38,
   holder+0x30), stepping 0x40, when the start and finish chunk
   pointers differ. When they are the same chunk
   (holder+0x28 == holder+0x48), phases 1 and 2 are skipped and
   this phase instead walks records from holder+0x10 while not
   equal to holder+0x30, stepping 0x40.
4. Chunk blocks and pointer array: if holder+0x00 is null the
   routine returns plainly. Otherwise every 0x200-byte chunk
   pointed to by [holder+0x28, holder+0x48 + 8) is freed by a
   sized delete of exactly 0x200, and the routine tail-jumps to
   a sized delete of (holder+0x00, holder+0x08 * 8).

The chunk array's end slot at +0x48 is read as the address of the
last chunk pointer: phase 1 stops before it, phase 4 includes it.

Inference, not observation: the layout matches a std::deque's
_M_map (+0x00, with size at +0x08), _M_start iterator
(_M_cur +0x10, _M_first +0x18, _M_last +0x20, _M_node +0x28)
and _M_finish iterator (_M_cur +0x30, _M_first +0x38,
_M_last +0x40, _M_node +0x48), with 0x200-byte buffers holding
eight 0x40-byte records — the libstdc++ deque buffer size for a
0x40-byte value type. The value type's name is not in the binary,
so the model pins only the iteration bounds above, not the
container's identity.
"""

PLT_DELETE = 0x63F0D80
PLT_MEMSET = 0x63F0A90
RECORD_SIZE = 0x40
CHUNK_SIZE = 0x200
RECORDS_PER_CHUNK = CHUNK_SIZE // RECORD_SIZE
NODE_SIZE = 0x18
INLINE_DELTA = 0x38


class Record:
    """One 0x40-byte record: a node list plus a counted buffer."""

    def __init__(self, nodes=(), buf_begin=None, buf_count=0):
        self.nodes = list(nodes)
        self.buf_begin = buf_begin
        self.buf_count = buf_count


class Holder:
    """Minimal holder state the model observes.

    `chunk_ptrs` lists the chunk addresses stored in the pointer
    array, in array order, from `chunk_begin` to `chunk_end`
    inclusive. `chunks` maps each chunk address to its eight
    records. `records` maps every record address in the first
    chunk's live range, the last chunk's live range (and, when
    start and finish share one chunk, the single combined range)
    to its Record. Field roles in deque terms (inference): the
    pointer array at +0x00/+0x08 is the chunk map; `rec_a_begin`
    / `rec_a_end` are the start iterator's current and last
    pointers (+0x10/+0x20); `rec_c_begin` / `rec_c_end` are the
    finish iterator's first and current pointers (+0x38/+0x30);
    `chunk_begin` / `chunk_end` are the start and finish
    iterators' chunk pointers (+0x28/+0x48).
    """

    def __init__(self, chunk_ptr=None, chunk_count=0,
                 rec_a_begin=None, rec_a_end=None,
                 chunk_begin=None, chunk_end=None,
                 rec_c_end=None, rec_c_begin=None,
                 chunk_ptrs=(), chunks=None, records=None):
        self.chunk_ptr = chunk_ptr
        self.chunk_count = chunk_count
        self.rec_a_begin = rec_a_begin
        self.rec_a_end = rec_a_end
        self.chunk_begin = chunk_begin
        self.chunk_end = chunk_end
        self.rec_c_end = rec_c_end
        self.rec_c_begin = rec_c_begin
        self.chunk_ptrs = list(chunk_ptrs)
        self.chunks = dict(chunks or {})
        self.records = dict(records or {})


def _teardown_record(trace, record, record_addr):
    """Append the observable effects of tearing down one record."""
    for node in record.nodes:
        trace.append(("free_node", PLT_DELETE, NODE_SIZE, node))
    trace.append(("memset", PLT_MEMSET, record.buf_begin,
                  record.buf_count * 8))
    trace.append(("zero", "+0x20"))
    trace.append(("zero", "+0x18"))
    if record.buf_begin != record_addr + INLINE_DELTA:
        trace.append(("free_buffer", PLT_DELETE, record.buf_begin,
                      record.buf_count * 8))


def destruct(holder):
    """Return the ordered observable-effect trace for `holder`.

    Effects are tuples; a sized delete records its PLT target,
    the freed address and the size, not the freed bytes.
    """
    trace = []
    chunk_begin = holder.chunk_begin
    chunk_end = holder.chunk_end
    # Phase 1: middle chunks, skipping the first chunk.
    cursor = chunk_begin + 8
    while cursor < chunk_end:
        chunk_addr = holder.chunk_ptrs[(cursor - chunk_begin) // 8]
        chunk = holder.chunks[chunk_addr]
        if len(chunk) != RECORDS_PER_CHUNK:
            raise ValueError("a chunk holds exactly eight records")
        for index, record in enumerate(chunk):
            _teardown_record(trace, record,
                             chunk_addr + index * RECORD_SIZE)
        cursor += 8
    if chunk_begin != chunk_end:
        # Phase 2: the first chunk's live records.
        cursor = holder.rec_a_begin
        while cursor != holder.rec_a_end:
            _teardown_record(trace, holder.records[cursor], cursor)
            cursor += RECORD_SIZE
        # Phase 3: the last chunk's live records.
        cursor = holder.rec_c_begin
        while cursor != holder.rec_c_end:
            _teardown_record(trace, holder.records[cursor], cursor)
            cursor += RECORD_SIZE
    else:
        # Start and finish share one chunk: phases 1 and 2 are
        # skipped and phase 3 walks the single combined range.
        cursor = holder.rec_a_begin
        while cursor != holder.rec_c_end:
            _teardown_record(trace, holder.records[cursor], cursor)
            cursor += RECORD_SIZE
    # Phase 4: chunk blocks, then the pointer array (tail delete).
    if holder.chunk_ptr is None:
        trace.append(("return",))
        return trace
    cursor = chunk_begin
    while cursor < chunk_end + 8:
        chunk_addr = holder.chunk_ptrs[(cursor - chunk_begin) // 8]
        trace.append(("free_chunk", PLT_DELETE, chunk_addr, CHUNK_SIZE))
        cursor += 8
    trace.append(("free_chunk_array_tail", PLT_DELETE, holder.chunk_ptr,
                  holder.chunk_count * 8))
    return trace
