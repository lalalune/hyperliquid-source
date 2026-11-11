"""Node #115 arena allocate (window 0x605d930) — literal model.

The window is the third virtual (slot 0x64d1fc8) of the member
class whose vtable 0x64d1fb8 also holds the member destroy
0x605cc30, the virtual 0x605cf80 and AllocateAligned 0x605d7b0
(fourth virtual, slot 0x64d1fd0), mapped by the arena and
destructor-pair packets. The member is the arena embedded at
+ 0x60 in the outer object of the two allocate packets.
Arguments, as read: rdi = arena (this), rsi = size. The third
argument register is not read on the fast path and is forced to
zero on the slow path.

Fast path (the only path that touches memory): the remaining
field at this + 0x8d0 is compared against the size as an unsigned
64-bit value. When remaining >= size, both the remaining field
and the end field at this + 0x8c0 shrink by the size (64-bit
arithmetic, no saturation and no second check), and the window
returns the post-decrement end field. The carve therefore comes
off the end of the current block: the returned range is
[new end, new end + size), the exact complement of the main
window's cursor bump, and the cursor field at this + 0x8c8 is
never read or written here.

Slow path: when remaining < size the window tail-jumps to the
slow window 0x605d6c0 (the arena packet's slow window) with rdi
and rsi unchanged and rdx forced to 0, so the slow window's
return value becomes this window's return value and neither
field is written on this path.

The window reads and writes no other field, calls nothing else,
reads no GOT slot and has no landing pad: its FDE (offset
0x3676f4, CIE 0) carries no augmentation data.
"""

MASK64 = (1 << 64) - 1

END_OFF = 0x8C0
REMAINING_OFF = 0x8D0

WINDOW_START = 0x605D930
WINDOW_END = 0x605D967
SLOW_WINDOW = 0x605D6C0
VTABLE_SLOT = 0x64D1FC8


class Arena:
    """The two arena fields the window touches, as unsigned u64."""

    def __init__(self, end=0, remaining=0):
        self.end = end & MASK64
        self.remaining = remaining & MASK64


def arena_allocate(arena, size, slow):
    """Run the window against ``arena``.

    ``slow`` stands in for the tail-jumped slow window: it is
    called as slow(size, 0) only when the remaining field is
    short, and its return value is passed through untouched.
    On the fast path the arena is updated in place and the new
    end field is returned.
    """
    size &= MASK64
    if arena.remaining >= size:
        arena.remaining = (arena.remaining - size) & MASK64
        arena.end = (arena.end - size) & MASK64
        return arena.end
    return slow(size, 0)
