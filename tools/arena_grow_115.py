"""Node #115 arena grow routine (0x605d000) with its region helpers.

Models, literally as written, the arena member routine found in the
node #115 binary that the merged allocate-aligned packet
(RE-001-arena-allocate-aligned-115) cites as its "grow" callee
0x605d000, by contract only:

* ``grow(arena, size)`` -- window 0x605d000..0x605d3a1 (929 bytes):
  asks the region producer for a fresh memory region of ``size``
  bytes; on success it appends the region's 16-byte descriptor
  (address, length) to the back of the block deque embedded in the
  arena object at +0x868, adds ``size`` to the accumulated-bytes
  counter at +0x8e0, runs the notify callee when the tracker pointer
  at +0x8e8 is nonzero, and returns the region address.  A failed
  production (address zero) returns zero with the object untouched.

* The producer chain is modelled literally too: the wrapper
  0x60d5050 forwards (descriptor slot, size, flag byte 1) to the
  region creator 0x60d5000, which stores {0, size} and, for a
  nonzero size, calls mmap(NULL, size, PROT_READ|PROT_WRITE,
  (flag << 0x12) | 0x22, -1, 0) -- with flag 1 the flags word is
  0x40022 (MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB) -- and folds a
  MAP_FAILED result back to address 0.  The destroy helper
  0x60d4f70 munmaps (address, length) when the address is nonzero;
  the install helper 0x60d4fe0 zeroes the destination descriptor
  and move-assigns the slot into it via 0x60d4fa0 (destroy the
  zeroed destination, copy 16 bytes, zero the source).

* The deque is the libstdc++-shaped std::deque of 16-byte
  descriptors: a map array of node slots (+0x868), a map size
  (+0x870), a start iterator (+0x878 cur, +0x880 first, +0x888
  last, +0x890 node) and a finish iterator (+0x898 cur, +0x8a0
  first, +0x8a8 last, +0x8b0 node); each node is a 0x200-byte chunk
  holding 32 descriptors.  Appending into a finish node that has
  exactly one free descriptor slot left (finish.cur ==
  finish.last - 16) takes the auxiliary path: the deque element
  count is recomputed from the iterator fields and compared
  against the deque max_size 0x7ffffffffffffff (a hit throws
  std::length_error with "cannot create std::deque larger than
  max_size()"), then a fresh chunk is installed in the map slot
  after finish.node -- growing or recentering the map first when
  no slot is free after finish.node (slots at-or-after finish <=
  1).  Map growth allocates a new map of 2 * (old size + 1) slots
  with (old size + 1) * 16 bytes (the old-size-0 case allocates 24
  bytes for 3 slots), with the library overflow discrimination:
  a new size whose bit 60 is set throws std::bad_alloc when bit 61
  is clear and std::bad_array_new_length when it is set.  The map
  is recentered without allocation when its size exceeds twice
  the needed node count (span + 2).  The pushed descriptor becomes
  the last element of the old finish node and finish moves to the
  fresh chunk.

* The notify callee 0x605e830 (window 0x605e830..0x605e859) is
  modelled as part of this packet: it reads the tracker head
  pointer at tracker + 0; when the head's first qword and its
  +0x20 qword are both zero the call is a no-op (counter
  untouched); otherwise it atomically adds the size to the
  counter at tracker + 8 and tail-jumps to the wake callee
  0x606a0c0 with the head pointer.  0x606a0c0 is by contract: it
  is injected as the ``wake`` hook.

* Exception behaviour follows the decoded LSDA of the main
  window: the producer call (0x605d030..0x605d035) has no landing
  pad; every call from 0x605d086 to the end of the body shares
  the landing pad at 0x605d395, which jumps to the shared cleanup
  block 0x605cfd6: destroy the descriptor slot at [r12], verify
  the stack canary, and _Unwind_Resume.  Observable effect: a
  throw out of the append machinery (operator new failures, the
  length_error and the two allocation-length throws) unmaps the
  produced region if it has not been moved into the deque yet
  and leaves the object unchanged; a throw out of the wake hook
  propagates after the append, the counter add and the notify
  counter add have all landed.

External effects are injected as hooks (mmap, munmap, operator
new, operator delete, wake); nothing else is reimplemented.
"""

U64 = 0xFFFFFFFFFFFFFFFF
DESCRIPTOR_BYTES = 16
NODE_BYTES = 0x200
DESCRIPTORS_PER_NODE = NODE_BYTES // DESCRIPTOR_BYTES  # 32
DEQUE_MAX_SIZE = 0x7FFFFFFFFFFFFFF
LENGTH_ERROR_MESSAGE = "cannot create std::deque larger than max_size()"

MMAP_PROT = 0x3
MMAP_FLAGS = 0x40022  # (flag byte 1 << 0x12) | 0x22: PRIVATE|ANON|HUGETLB
MAP_FAILED = U64  # -1 as an unsigned qword

# Field offsets within the arena object, as observed in the windows.
OFF_MAP = 0x868
OFF_MAP_SIZE = 0x870
OFF_START_CUR = 0x878
OFF_START_FIRST = 0x880
OFF_START_LAST = 0x888
OFF_START_NODE = 0x890
OFF_FINISH_CUR = 0x898
OFF_FINISH_FIRST = 0x8A0
OFF_FINISH_LAST = 0x8A8
OFF_FINISH_NODE = 0x8B0
OFF_USED = 0x8E0
OFF_NOTIFY = 0x8E8


class LengthError(Exception):
    """std::length_error thrown by the deque size guard."""


class BadAlloc(Exception):
    """std::bad_alloc (operator new failure or the size check)."""


class BadArrayNewLength(Exception):
    """std::bad_array_new_length from the map growth size check."""


def _u64(value):
    return value & U64


def _i64(value):
    value &= U64
    return value - (1 << 64) if value >= (1 << 63) else value


def _sar(value, shift):
    return _i64(value) >> shift


class Hooks:
    """Injected external effects (see the packet README)."""

    def __init__(self, mmap, munmap, operator_new, operator_delete, wake):
        # mmap(size, prot, flags) -> address, or MAP_FAILED
        self.mmap = mmap
        # munmap(address, length) -> None
        self.munmap = munmap
        # operator_new(nbytes) -> address (raises BadAlloc)
        self.operator_new = operator_new
        # operator_delete(address, nbytes) -> None
        self.operator_delete = operator_delete
        # wake(head) -> None (the by-contract callee 0x606a0c0)
        self.wake = wake


class NotifyTracker:
    """The tracker object pointed at by arena + 0x8e8.

    Memory image: +0 head pointer, +8 counter; the head's own
    first qword (+0) and +0x20 qword decide dormancy.
    """

    def __init__(self, head, counter=0, head_first=0, head_late=0):
        self.head = head
        self.counter = counter
        self.head_first = head_first
        self.head_late = head_late


class ArenaGrow:
    """Arena object state as the grow window observes it.

    The deque map is a list of node-chunk addresses (list index =
    map slot); node fields of the iterators are slot addresses
    (map_address + 8 * index).  Chunk contents are a dict of
    chunk address -> {byte offset: (address, length)}.
    """

    def __init__(self, hooks, map_address=0, map_slots=(),
                 start_node_index=0, start_cur=0, start_first=0,
                 start_last=0, finish_node_index=0, finish_cur=0,
                 finish_first=0, finish_last=0, start_node_addr=None,
                 finish_node_addr=None, used=0, notify=None,
                 map_size_field=None):
        self.hooks = hooks
        self.map_address = map_address
        self.map_slots = list(map_slots)
        # The +0x870 field itself; normally len(map_slots), but a
        # caller may state it independently to reproduce the
        # native arithmetic on fabricated field values.
        self.map_size = len(self.map_slots) if map_size_field is None \
            else map_size_field
        if start_node_addr is None:
            start_node_addr = map_address + 8 * start_node_index
        if finish_node_addr is None:
            finish_node_addr = map_address + 8 * finish_node_index
        self.start_node = start_node_addr
        self.start_cur = start_cur
        self.start_first = start_first
        self.start_last = start_last
        self.finish_node = finish_node_addr
        self.finish_cur = finish_cur
        self.finish_first = finish_first
        self.finish_last = finish_last
        self.used = used
        self.notify = notify
        self.chunks = {}

    # -- descriptor helpers (windows 0x60d5000/0x60d5050/0x60d4f70/
    #    0x60d4fa0/0x60d4fe0) -------------------------------------

    def _create_region(self, size):
        """0x60d5000 via the 0x60d5050 wrapper (flag byte 1)."""
        if size == 0:
            return (0, 0)
        addr = self.hooks.mmap(size, MMAP_PROT, MMAP_FLAGS)
        if addr == MAP_FAILED:
            addr = 0
        return (addr, size)

    def _destroy_region(self, descriptor):
        """0x60d4f70: munmap when the address qword is nonzero."""
        if descriptor[0] != 0:
            self.hooks.munmap(descriptor[0], descriptor[1])

    def _install(self, chunk_address, offset, slot):
        """0x60d4fe0 + 0x60d4fa0: zero the destination, move-assign.

        The zeroing makes the destination destroy a no-op, so any
        descriptor previously in the slot is dropped silently.
        Returns the source slot after the move (always (0, 0)).
        """
        self.chunks.setdefault(chunk_address, {})[offset] = slot
        return (0, 0)

    # -- notify callee (window 0x605e830) --------------------------

    def _notify(self, size):
        tracker = self.notify
        if tracker.head_first == 0 and tracker.head_late == 0:
            return
        tracker.counter = _u64(tracker.counter + size)
        self.hooks.wake(tracker.head)

    # -- deque append internals ------------------------------------

    def _node_index(self, node_address):
        return _sar(node_address - self.map_address, 3)

    def _deque_size(self):
        """Element count exactly as the auxiliary path computes it."""
        span = _i64(self.finish_node - self.start_node)
        count = _sar(span, 3)
        # cmp $1, finish.node / adc $-1: subtract 1, plus the
        # borrow, which is set only when finish.node is zero.
        if _u64(self.finish_node) >= 1:
            count -= 1
        total = _u64(count << 5)
        total = _u64(total + _sar(self.finish_cur - self.finish_first, 4))
        total = _u64(total + _sar(self.start_last - self.start_cur, 4))
        return total

    def _append_aux(self, slot):
        """push_back_aux: finish node has one free slot left.

        Returns (slot_after, new_finish_cur).  Raises LengthError,
        BadAlloc or BadArrayNewLength with the object unchanged.
        """
        if self._deque_size() == DEQUE_MAX_SIZE:
            raise LengthError(LENGTH_ERROR_MESSAGE)
        span_count = _sar(self.finish_node - self.start_node, 3)
        finish_index = _sar(self.finish_node - self.map_address, 3)
        slots_after = _i64(self.map_size) - finish_index
        if slots_after <= 1:
            slot = self._grow_map(slot, span_count)
        return self._install_chunk(slot)

    def _grow_map(self, slot, span_count):
        """The map-reallocation half of push_back_aux (0x605d1a0 on)."""
        new_num_nodes = _u64(span_count + 2)
        map_size = self.map_size
        if _u64(new_num_nodes * 2) < map_size:
            # Recenter inside the existing map (0x605d2b0).
            shift = _u64(map_size - new_num_nodes) >> 1
            new_start = self.map_address + 8 * shift
            self._move_nodes(new_start, span_count)
            self._refresh_iterators(new_start, span_count)
            return slot
        # Allocate a fresh map (0x605d1b5).
        if map_size == 0:
            alloc_bytes = 0x18
            new_map_size = 3
        else:
            new_map_size = _u64(2 * (map_size + 1))
            alloc_bytes = _u64((map_size + 1) << 4)
            if new_map_size >> 0x3C:
                if (new_map_size >> 0x3D) == 0:
                    raise BadAlloc("bad_alloc")
                raise BadArrayNewLength("bad_array_new_length")
        new_map = self.hooks.operator_new(alloc_bytes)
        new_slots = [0] * new_map_size
        start_off = _u64(new_map_size - new_num_nodes) >> 1
        span_incl = _i64(self.finish_node + 8 - self.start_node)
        old_start_index = self._node_index(self.start_node)
        if span_incl > 8:
            for k in range(span_incl // 8):
                new_slots[start_off + k] = self.map_slots[
                    old_start_index + k]
        elif span_incl == 8:
            new_slots[start_off] = self.map_slots[old_start_index]
        self.hooks.operator_delete(self.map_address,
                                   _u64(map_size * 8))
        self.map_address = new_map
        self.map_slots = new_slots
        self.map_size = new_map_size
        new_start = new_map + 8 * start_off
        self._refresh_iterators(new_start, span_count)
        return slot

    def _move_nodes(self, new_start, span_count):
        """memmove of the node span within the current map."""
        src = self._node_index(self.start_node)
        dst = self._node_index(new_start)
        span_incl = _i64(self.finish_node + 8 - self.start_node)
        if span_incl > 8:
            moved = [self.map_slots[src + k]
                     for k in range(span_incl // 8)]
            for k, value in enumerate(moved):
                self.map_slots[dst + k] = value
        elif span_incl == 8:
            self.map_slots[dst] = self.map_slots[src]

    def _refresh_iterators(self, new_start, span_count):
        """Node/first/last refresh shared by both map paths."""
        span_bytes = _i64(self.finish_node - self.start_node)
        self.start_node = new_start
        self.finish_node = new_start + span_bytes
        start_chunk = self.map_slots[self._node_index(self.start_node)]
        self.start_first = start_chunk
        self.start_last = start_chunk + NODE_BYTES
        finish_chunk = self.map_slots[self._node_index(self.finish_node)]
        self.finish_first = finish_chunk
        self.finish_last = finish_chunk + NODE_BYTES

    def _install_chunk(self, slot):
        """0x605d144: fresh chunk, append, advance finish (0x605d069
        stores the returned value into finish.cur afterwards)."""
        chunk = self.hooks.operator_new(NODE_BYTES)
        finish_index = self._node_index(self.finish_node)
        self.map_slots[finish_index + 1] = chunk
        self.chunks.setdefault(chunk, {})
        offset = self.finish_cur - self.finish_first
        slot = self._install(self.finish_first, offset, slot)
        self.finish_node = self.finish_node + 8
        installed = self.map_slots[self._node_index(self.finish_node)]
        self.finish_first = installed
        self.finish_last = installed + NODE_BYTES
        return slot, installed

    # -- the window itself ------------------------------------------

    def grow(self, size):
        """0x605d000: grow the arena by one region of ``size`` bytes.

        Returns the region address, or 0 when production failed.
        Throws LengthError / BadAlloc / BadArrayNewLength for the
        deque-append failures; the produced region is unmapped by
        the cleanup pad in that case and the object is unchanged.
        """
        slot = self._create_region(size)
        result = slot[0]
        if result == 0:
            self._destroy_region(slot)  # epilogue destroy: a no-op
            return 0
        try:
            if self.finish_cur != self.finish_last - DESCRIPTOR_BYTES:
                offset = self.finish_cur - self.finish_first
                slot = self._install(self.finish_first, offset, slot)
                new_finish_cur = _u64(self.finish_cur + DESCRIPTOR_BYTES)
            else:
                slot, new_finish_cur = self._append_aux(slot)
            self.used = _u64(self.used + size)
            self.finish_cur = new_finish_cur
            if self.notify is not None:
                self._notify(size)
        except BaseException:
            # LSDA landing pad (0x605d395 -> cleanup 0x605cfd6):
            # destroy the slot, then resume unwinding.
            self._destroy_region(slot)
            raise
        self._destroy_region(slot)  # epilogue destroy: moved-from
        return result

    def elements(self):
        """All descriptors currently in the deque, in order."""
        out = []
        first_index = self._node_index(self.start_node)
        last_index = self._node_index(self.finish_node)
        index = first_index
        while index <= last_index:
            chunk = self.map_slots[index]
            contents = self.chunks.get(chunk, {})
            lo = self.start_cur if index == first_index else chunk
            hi = self.finish_cur if index == last_index else \
                chunk + NODE_BYTES
            offset = lo - chunk
            while offset < hi - chunk:
                if offset in contents:
                    out.append(contents[offset])
                offset += DESCRIPTOR_BYTES
            index += 1
        return out
