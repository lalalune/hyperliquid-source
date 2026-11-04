"""Model of node #115 routine 0x5fc9520: construct one shared
control block for a target object.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes two arguments: an out slot pointer in rdi and
a target pointer in rsi, and returns the out slot pointer.
End to end, in instruction order:

1. Atomically increment the 32-bit use count at target +0x00
   (lock addl $0x1, (%rsi)). The increment happens BEFORE the
   allocation, so a failing allocation would leave the count
   incremented; the routine has no landing pad, so an allocation
   failure propagates with the count already raised.
2. Allocate a 16-byte block (operator new with size 0x10, the
   direct call at 0x5fc9539 to the 0x63f0dd0 PLT entry).
3. Store the target pointer into the block's second qword
   (block +0x08).
4. Store the block pointer into the out slot (*out = block).
5. Store the vtable pointer 0x64cd880 into the block's first
   qword (block +0x00). The address is computed as the table
   base 0x64cd870 plus 0x10; its loaded slots are pinned by
   relocation: slot +0x00 (at 0x64cd880) is the reset routine
   0x5fc9460, slot +0x08 (at 0x64cd888) is the deleting
   destructor 0x5fc9480, and the slot at vptr - 0x08
   (0x64cd878) holds the typeinfo pointer 0x64cd828.
6. Return the out slot pointer (rax = rdi on entry).

The vtable pair is modelled too, from its own whole-function
excerpts, because it defines what the constructed block means:

* reset (0x5fc9460): rewrite the block's first qword to
  0x64cd880, load the target from block +0x08, and atomically
  decrement the 32-bit use count at target +0x00 (lock subl
  $0x1). No zero check and no delete: a zero count does not
  free anything here.
* deleting destructor (0x5fc9480): call reset, then delete the
  block with size 0x10 (tail jump to operator delete).

A sibling family exists at vtable 0x64cd8a0 (reset 0x5fc94a0,
deleting destructor 0x5fc94c0) whose count lives at target
+0x04 and is adjusted with a lock xadd; it is recorded in the
packet README as context only and is NOT modelled here.
"""

VTABLE_ADDRESS = 0x64CD880
VTABLE_TABLE_BASE = 0x64CD870
RESET_ROUTINE = 0x5FC9460
DELETING_ROUTINE = 0x5FC9480
TYPEINFO_SLOT = 0x64CD878
TYPEINFO_VALUE = 0x64CD828
BLOCK_SIZE = 0x10
USE_COUNT_OFFSET = 0x00
NEW_CALLEE = 0x63F0DD0
COUNT_MASK = 0xFFFFFFFF


class Target:
    """A target object carrying a 32-bit use count at +0x00."""

    def __init__(self, use_count=0):
        self.use_count = use_count & COUNT_MASK


class Block:
    """A 16-byte control block: vtable pointer plus target.

    The vptr starts unset: the binary writes block +0x08, then
    the out slot, and only then block +0x00, so the model sets
    the vptr at that step, not at allocation."""

    def __init__(self, target):
        self.vptr = None
        self.target = target
        self.freed = False


def make_control_block(out, target):
    """Construct a control block for target, store it in out[0],
    and return out. out is a one-element list standing in for
    the caller's stack slot; the binary writes the block pointer
    there and returns the slot address (rdi)."""
    if out is None or target is None:
        raise ValueError("null out slot or target")
    if not isinstance(out, list) or len(out) != 1:
        raise ValueError("out slot must be a one-element list")
    events = []
    target.use_count = (target.use_count + 1) & COUNT_MASK
    events.append("count_inc")
    block = Block(target)
    events.append("alloc16")
    block.target = target
    events.append("block_target")
    out[0] = block
    events.append("out_write")
    block.vptr = VTABLE_ADDRESS
    events.append("block_vptr")
    events.append("return")
    return out, events


def reset_control_block(block):
    """The vtable reset routine (0x5fc9460): rewrite the vptr,
    then decrement the target's use count. Returns the count
    after the decrement."""
    if block is None or block.target is None:
        raise ValueError("null block or target")
    block.vptr = VTABLE_ADDRESS
    target = block.target
    target.use_count = (target.use_count - 1) & COUNT_MASK
    return target.use_count


def delete_control_block(block):
    """The deleting destructor (0x5fc9480): reset, then delete
    the block with size 0x10. The model marks the block freed;
    a freed block cannot be reset again."""
    if block is None:
        raise ValueError("null block")
    reset_control_block(block)
    block.freed = True
    return BLOCK_SIZE
