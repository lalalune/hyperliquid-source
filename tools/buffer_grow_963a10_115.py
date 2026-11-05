"""Model of node #115 buffer growth routine 0x5963a10 (RE-001).

The routine is the shared grow step behind the node's byte-buffer
appends: callers whose buffer is full hand it the buffer descriptor
and it computes a new capacity, asks the allocator callee to move
the allocation, and stores the result back. Its own FDE is
0x5963a10..0x5963a9e (142 bytes); it is reached by 15,566 direct
calls in 3,647 caller FDEs and by nothing else (no tail jumps,
no stored pointers, no relocations naming it).

Pinned layout and contract (see
research/work-items/RE-001-buffer-grow-963a10-115/):

- rdi points at the buffer descriptor: +0x00 capacity in elements,
  +0x08 data pointer. The routine reads both and, on success only,
  stores the new data pointer at +0x08 and the new capacity at
  +0x00. The descriptor's +0x10 length field is neither read nor
  written here: the current length arrives as the rsi argument.
- rsi = current length in elements, rdx = additional elements
  requested. rcx is forwarded unchanged as the allocator callee's
  last argument. r8 is the element size in bytes: it drives the
  minimum-capacity table and the zero test below. (At the byte-wise
  JSON writer sites both rcx and r8 are 1.)

Pinned behavior, reproduced exactly:

- If the element size is 0, or length + additional overflows
  64 bits, the routine transfers through GOT slot 0x64df498 to
  the shared failure entry 0x141e264 with edi = 0 and does not
  return. The doubling itself is a bare lea: 2 * capacity wraps
  modulo 2**64 with no check.
- New capacity is max(2 * capacity, length + additional,
  minimum), all comparisons unsigned, where the minimum depends
  only on the element size: 8 for size 1, 4 for sizes 2..0x400,
  1 for sizes 0x401 and up.
- The allocator callee 0x5963650 (FDE 0x5963650..0x5963739) is
  called as alloc(&out, old_capacity, old_data_pointer,
  new_capacity, forwarded_rcx) and writes a 24-byte result:
  a tag dword at +0x00, a word at +0x08, a word at +0x10. Tag 1
  is the error case: the routine transfers through the same slot
  0x64df498 to 0x141e264 with (rdi, rsi) = (result word +0x08,
  result word +0x10) and does not return; the descriptor keeps
  its old capacity and data pointer. Any other tag is success:
  the +0x08 result word becomes the descriptor's data pointer.
- The routine has no LSDA (its FDE's augmentation length is 0
  and its CIE's augmentation is "zR", with no personality): a
  raise out of the allocator callee runs no cleanup in this
  frame, and the frame holds nothing to clean.

The allocator callee's body and the failure entry's body are
cited, not pinned; the model takes the allocator as a callable
returning the (tag, word1, word2) triple and raises for the two
non-returning transfers.
"""

MASK64 = (1 << 64) - 1

ROUTINE = 0x5963A10
ALLOCATOR_CALLEE = 0x5963650
FAILURE_SLOT = 0x64DF498
FAILURE_ENTRY = 0x141E264


class GrowthFailure(Exception):
    """The plain non-returning failure transfer: element size 0
    or length + additional overflow. The routine calls the shared
    failure entry 0x141e264 (through slot 0x64df498) with edi = 0.
    """


class AllocFailure(GrowthFailure):
    """The allocator-error transfer: same entry and slot, with
    (rdi, rsi) = the allocator result's +0x08 / +0x10 words."""

    def __init__(self, word1, word2):
        super().__init__(f"allocator error pair ({word1:#x}, {word2:#x})")
        self.word1 = word1
        self.word2 = word2


def min_capacity(elem_size):
    """The pinned minimum-capacity table, by element size in
    bytes. Only defined for nonzero sizes: size 0 never reaches
    the table (it takes the failure transfer first)."""
    if elem_size == 1:
        return 8
    if elem_size < 0x401:
        return 4
    return 1


def new_capacity(capacity, length, additional, elem_size):
    """The pinned capacity arithmetic, in instruction order.

    Raises GrowthFailure for a zero element size and for a
    length + additional sum that carries out of 64 bits. The
    doubling wraps modulo 2**64 (a bare lea, unchecked): a
    capacity of exactly 2**63 doubles to 0 and loses the max to
    the other two terms, while 2**64 - 1 doubles to 2**64 - 2
    and wins it.
    """
    if elem_size == 0:
        raise GrowthFailure("element size 0")
    needed = length + additional
    if needed > MASK64:
        raise GrowthFailure("length + additional overflow")
    doubled = (2 * capacity) & MASK64
    return max(doubled, needed, min_capacity(elem_size))



class Buffer:
    """The buffer descriptor as this routine sees it: capacity
    (+0x00) and data pointer (+0x08). A length field (+0x10) is
    included only so tests can show the routine leaves it alone:
    the current length is an argument, never read from here."""

    def __init__(self, capacity=0, data_ptr=0, length=0):
        self.capacity = capacity
        self.data_ptr = data_ptr
        self.length = length


def grow(buf, length, additional, forwarded, elem_size, allocator):
    """Grow buf's allocation; return the new capacity.

    allocator(old_capacity, old_data_ptr, new_capacity, forwarded)
    returns the callee's result triple (tag, word1, word2). On
    tag == 1 the model raises AllocFailure(word1, word2) and buf
    is unchanged, mirroring the routine: the descriptor stores
    happen only on the success path. On success buf.data_ptr
    becomes word1 and buf.capacity the new capacity; buf.length
    is never touched.
    """
    cap = new_capacity(buf.capacity, length, additional, elem_size)
    tag, word1, word2 = allocator(buf.capacity, buf.data_ptr, cap,
                                  forwarded)
    if tag == 1:
        raise AllocFailure(word1, word2)
    buf.data_ptr = word1
    buf.capacity = cap
    return cap
