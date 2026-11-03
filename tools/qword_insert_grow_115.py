"""Node #115 vector realloc-insert 0x5d9ee20 (RE-001).

Maps the whole 389-byte helper from the digest-verified node #115
binary (work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The helper is std::vector::_M_realloc_insert: it inserts one qword
element at a position and always reallocates a fresh buffer. Callers
invoke it on their full path (end == capacity end); the helper itself
never reads the capacity field.

Container layout: begin at +0x00, end at +0x08, capacity end at +0x10,
8-byte elements. Arguments: rdi = container, rsi = insert position,
rdx = pointer to the qword value to insert (the stored value is the
qword loaded from that address, not the address itself).

Capacity rule, stated literally from the native code:

  * size = (end - begin) >> 3 (arithmetic shift).
  * size == 0x0fffffffffffffff -> __throw_length_error, noreturn.
  * empty (end == begin): new capacity 1 element.
  * otherwise: new capacity min(2 * size, 0x0fffffffffffffff).
  * doubling that wraps below size (unsigned) takes a max-bytes
    allocation path, operator new(0x7ffffffffffffff8); that path
    allocates exactly the same byte count and records exactly the
    same capacity end as the capped path, so the model returns the
    maximum capacity for it as well.

The native code reads memory without checks. The model raises
QwordInsertGrowError when the position is outside [begin, end] or
the span is not a multiple of 8 bytes, and LengthError on the
maximum-size arm; those are model guards, not native outcomes.
"""

MAX_ELEMENTS = 0x0FFFFFFFFFFFFFFF
QWORD_MASK = 0xFFFFFFFFFFFFFFFF


class QwordInsertGrowError(ValueError):
    """Model guard: input outside the native contract."""


class LengthError(Exception):
    """The native __throw_length_error arm (size == maximum)."""


def new_capacity_for_size(size):
    """New element capacity for a container of `size` elements.

    Pure arithmetic from the native arms; usable for sizes too large
    to build as a list.
    """
    if size < 0:
        raise QwordInsertGrowError("negative size")
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
        raise QwordInsertGrowError("index must be an integer")
    if index < 0 or index > len(elements):
        raise QwordInsertGrowError("insert position outside [begin, end]")
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


def append_group_element(groups, capacities, index, value, refcounts):
    """Node-specific group append caller at 0x5f78060 (RE-001).

    `groups` is a list of element lists (one per 24-byte group entry),
    `capacities` the parallel element capacities, `index` the group
    index (sign-extended in the native code), `value` the element
    value pointer to append, and `refcounts` a dict mapping a value
    to its +0xb0 counter, incremented by 1 on both arms.

    Returns (arm, new_capacity_of_group) where arm is "inplace" when
    the group had spare capacity and "grow" when the realloc-insert
    helper ran. The helper's capacity rule applies on the grow arm.
    """
    if not isinstance(index, int) or isinstance(index, bool):
        raise QwordInsertGrowError("group index must be an integer")
    if index < 0 or index >= len(groups):
        raise QwordInsertGrowError("group index outside the entry array")
    elements = groups[index]
    capacity = capacities[index]
    if len(elements) < capacity:
        elements.append(value & QWORD_MASK)
        refcounts[value] = refcounts.get(value, 0) + 1
        return "inplace", capacity
    new_elements, new_capacity, _ = insert_grow(
        elements, len(elements), value, old_begin_null=(len(elements) == 0 and capacity == 0))
    groups[index] = new_elements
    capacities[index] = new_capacity
    refcounts[value] = refcounts.get(value, 0) + 1
    return "grow", new_capacity
