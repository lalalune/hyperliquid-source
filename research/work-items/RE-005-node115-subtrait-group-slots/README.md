# RE-005 node115: what the Error-subtrait's K six-slot groups are

## Question

The accessor-parent packet (PR #3171) pinned the six
field-accessor parents of the shared-Debug census as vtables of
one Error-subtrait: a std::error::Error prefix, one own method
at +0x58, and K identical six-slot groups (K = 8, 4, 2, 4, 7, 15).
It identified only one slot of one group per vtable — the field
accessor whose returned vtable is the extended io vtable — and
left the rest of the group slots' identities open: what each of
the six slots in each group is. This packet answers that, slot
by slot, for every group of every member, and marks what the
binary cannot answer.

## Findings

### The family has eight members, not six

Scanning the whole binary for the same layout (Error prefix
with the +0x28 upcast cell, the 14-byte type-id writer at
+0x38 and the 1-byte provide() at +0x50; a method cell at
+0x58; a whole number of 0x30-stride groups whose first three
slots decode) finds two further members beyond PR #3171's six:
0x6408b48 (80-byte Self, K = 1) and 0x640a448 (64-byte Self,
K = 5). Together the eight members carry 46 groups. The six
parents of PR #3171 are exactly the members that contain an
io group (below); the two new members do not.

### Every group is one role, and roles recur across members

Each group is keyed by a 16-byte constant and bundles two
dyn Error vtables, identified by the TypeId constants their
+0x38 slots write:

- an **accessor type** A (the group's first vtable), and
- a **pair type** B (the group's second vtable).

The same (key, A, B) triple recurs across members with the
same key address in .rodata: there are 20 distinct roles.
Every member contains exactly one **self group**, whose pair
type is the member's own type. Six members contain exactly
one **io group**, whose accessor type is std::io::Error
(16-byte key and accessor TypeId both
f8dfacffdf56f26d91c0b01aa4986406) — those are the groups
PR #3171's census field accessors belong to, one per parent;
the io vtable instance returned differs per member CGU
(0x63f8f58 for 0x63fa140, 0x64445c0 for 0x6444b60, and so on),
each an extended io vtable of the same type.

### The six slots

In slot order, for group g with accessor type A and pair
type B:

1. **Accessor** (12 bytes:
   `lea rax,[rdi+0x38]; lea rdx,[A's vtable]; ret`). Returns
   the field at self+0x38 viewed as a dyn Error of type A.
   The returned field offset is +0x38 in all 46 groups.
2. **Pair return** (11 bytes:
   `mov rax,rdi; lea rdx,[B's vtable]; ret`). Returns self
   viewed as a dyn Error of type B. For the self group the
   returned vtable is the member's own (big) vtable; for
   other groups it is a plain Error vtable (extent 0x58) of
   type B from the same CGU.
3. **Keyed lookup** (33 bytes). Byte-compares the 16-byte
   key pointed to by the second argument against the
   group's constant (pcmpeqb/pmovmskb) and returns
   self+0x38 on equality, null otherwise. In 18 of the 20
   roles the constant is exactly the accessor type's own
   TypeId constant (the io role included). In the two
   remaining roles — the ones whose accessor types are 16
   and 24 bytes — the key is a distinct shared constant
   (at .rodata 0x4503e0 and 0x454c30) that is no vtable's
   TypeId in this binary.
4. **Drop shim for B**. A drop-in-place body over the
   shared node layout (a Once-guarded array field at
   +0x10 whose elements are 0x38 bytes; the state checks
   panic with std's Once unreachable message, file
   /rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/
   std/src/sys/sync/once/futex.rs:91) followed by a dealloc
   of B's size. The freed size equals B's vtable size in
   all 46 groups.
5. **Zero** (3 bytes: `xor eax,eax; ret`). One shared body
   per member; returns 0 for every group.
6. **Drop shim for the next group's pair type**. Same node
   layout, in several variants: array-only (72B), with the
   second-state check (141–170B), with the (size, ptr)
   buffer at +0x38/+0x40 freed (114B), with a drop call on
   the field at +0x38 (101B), with the (data, vtable) child
   at +0x38 dropped through its vtable and its 24-byte
   cell freed (248B), or a call-form (62B) that simply
   calls the next pair type's own vtable drop body. In all
   38 non-terminal cases the shim frees exactly the next
   pair type's size, or calls that type's drop (verified
   against the drop bodies of every vtable carrying that
   TypeId — e.g. group 9 of 0x63fa140 calls 0x14c5450, the
   drop of the plain Error vtable 0x63f9ba0 of the next
   pair type). The last group's sixth slot is not a body:
   it is the vtable's boundary cell (see Boundary).

The **+0x58 own method** is the same kind of shim as slot 3,
for the *first* group's pair type, in the fuller variant
where present (it frees the +0x38 buffer in the members
whose first pair type has one): its freed size equals the
first pair size in all eight members.

### Three accessor types carry a hand-written description()

All accessor and pair vtables use the shared default
description() body except three, whose +0x40 slots are
hand-written (bodies in description_variants.objdump.txt):

- vtable 0x63f96f0 (16-byte accessor type, group 13 of
  0x63fa140): selects on the object's first byte between
  the strings "invalid character" and "invalid length".
- vtable 0x63f97e0 (1-byte accessor type, group 14 of
  0x63fa140): returns "parser error, see to_string() for
  details".
- vtable 0x6408ad0 (24-byte accessor type, the only group
  of 0x6408b48): returns the (ptr, len) slice stored in the
  object itself at +0x08/+0x10 — a per-instance message.

## Boundary

- The subtrait's source-level name is not in the binary
  (PR #3171's boundary stands): no string or panic Location
  names it, and the group bodies are generic glue. What
  this packet adds is the per-slot semantics of its
  groups, not the name.
- Two of the recurring group keys (at .rodata 0x4503e0 and
  0x454c30) are not the TypeId constant of the group's
  accessor type, nor of any vtable in the binary: the type
  they name has no dyn vtable here, so the probe's target
  type for those two roles is identified only by its
  shared 16-byte key constant.
- The last group's sixth slot is the vtable's boundary
  cell: the measured extent ends there, and the cell holds
  the next header's drop pointer, a code address with no
  FDE record, or zero, depending on the member. It is
  recorded as a boundary cell, not classified as a group
  body.
- Virtual call sites of the group slots cannot be
  attributed by displacement alone: the offsets 0x60.. are
  used by hundreds of unrelated bodies calling through
  other vtables, so no caller census is claimed.

## Method

All vtables were re-derived from the materialised binary
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301)
by applying .rela.dyn RELATIVE relocations and scanning
.data.rel.ro for drop/size/align headers — the same
machinery as the census and accessor-parent packets.
`tools/subtrait_groups.py generate` rebuilds records.json
from the binary and `check` verifies the retained copy; the
generator asserts the accessor/pair/lookup body shapes, the
field offset, role consistency across members, the slot-3
and +0x58 size rules, the slot-5 size/call rule with zero
exceptions, and exactly one self group per member.
`tests/test_subtrait_groups.py` re-runs the full analysis
and compares it against the retained records. frames.txt
indexes the disassembly excerpts in this directory.
