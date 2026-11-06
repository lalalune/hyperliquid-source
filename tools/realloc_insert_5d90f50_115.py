"""Node #115 vector realloc-insert 0x5d90f50 (RE-001).

Maps the whole 389-byte helper from the digest-verified node #115
binary (work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The helper is std::vector::_M_realloc_insert: it inserts one qword
element at a position and always reallocates a fresh buffer. It is a
second, independently compiled copy of the same instantiation whose
other copy at 0x5d9ee20 is mapped by RE-001-qword-insert-grow-115:
the two bodies are 389 bytes each and differ in exactly 15 bytes,
all inside the rel32 fields of their seven call instructions, and
their FDE instruction programs are byte-identical. This copy's own
callers are a different set (see the packet census), headed by the
transfer 0x5f13e00 mapped by RE-001-predicate-drain-115, which left
this helper by contract only.

Container layout: begin at +0x00, end at +0x08, capacity end at +0x10,
8-byte elements. Arguments: rdi = container, rsi = insert position,
rdx = pointer to the qword value to insert (the stored value is the
qword loaded from that address, not the address itself). The helper
reads begin and end only; it never reads the capacity field except
to compute the freed byte count at the end (capacity end - begin).

Capacity rule, stated literally from the native code:

  * size = (end - begin) >> 3 (arithmetic shift on the wrapped
    64-bit difference).
  * size == 0x0fffffffffffffff -> __throw_length_error with the
    rodata string 'vector::_M_realloc_insert' at 0x43d55a, noreturn.
  * empty (end == begin): new capacity size + 1 (== 1), capped at
    the maximum; a wrapped size + 1 takes the max-bytes path.
  * otherwise: new capacity min(2 * size, 0x0fffffffffffffff).
  * doubling that wraps below size (unsigned) takes a max-bytes
    allocation path, operator new(0x7ffffffffffffff8); that path
    allocates exactly the same byte count and records exactly the
    same capacity end as the capped path, so the model returns the
    maximum capacity for it as well.

Copy order, stated literally: the inserted value is stored first,
then the prefix is memmove'd in, then the suffix is memcpy'd in,
then the old buffer is freed when non-null, then the three
container fields are stored. The prefix uses memmove and the suffix
memcpy (the sibling copy uses memmove for its prefix too; the two
copies agree instruction for instruction outside the call fields).

The native code reads memory without checks. The model raises
ReallocInsertError when the position is outside [begin, end] or
the span is not a multiple of 8 bytes, and LengthError on the
maximum-size arm; those are model guards, not native outcomes.
"""

MAX_ELEMENTS = 0x0FFFFFFFFFFFFFFF
QWORD_MASK = 0xFFFFFFFFFFFFFFFF


class ReallocInsertError(ValueError):
    """Model guard: input outside the native contract."""


class LengthError(Exception):
    """The native __throw_length_error arm (size == maximum)."""


def new_capacity_for_size(size):
    """New element capacity for a container of `size` elements.

    Pure arithmetic from the native arms; usable for sizes too large
    to build as a list.
    """
    if size < 0:
        raise ReallocInsertError("negative size")
    if size == MAX_ELEMENTS:
        raise LengthError("vector::_M_realloc_insert: size at maximum")
    if size == 0:
        return 1
    # Mathematical doubling, capped at the maximum: the native
    # capped arm and the doubling-wrap arm both end at the maximum
    # capacity (max-bytes allocation, 0x7ffffffffffffff8 bytes), so
    # wrapping changes nothing observable about the capacity.
    return min(2 * size, MAX_ELEMENTS)


def insert_grow(elements, index, value, old_begin_null=True):
    """Insert one qword at `index`, always reallocating.

    `elements` is the old element list, `index` is in [0, len],
    `value` is the qword to insert (truncated to 64 bits, as the
    native store of one qword does). `old_begin_null` records
    whether the old begin pointer was null; it matters only for an
    empty container, where a non-null old buffer is still freed.

    Returns (new_elements, new_capacity_elements, freed_old_buffer).
    """
    if not isinstance(index, int) or isinstance(index, bool):
        raise ReallocInsertError("index must be an integer")
    if index < 0 or index > len(elements):
        raise ReallocInsertError("insert position outside [begin, end]")
    size = len(elements)
    new_capacity = new_capacity_for_size(size)
    new_elements = (list(elements[:index])
                    + [value & QWORD_MASK]
                    + list(elements[index:]))
    freed = (not old_begin_null) if size == 0 else True
    return new_elements, new_capacity, freed


def allocation_bytes(new_capacity_elements):
    """Allocation byte count for a capacity (capacity * 8)."""
    return new_capacity_elements * 8
