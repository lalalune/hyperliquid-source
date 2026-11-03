# RE-001: map node #115 flag-selected slot replace 0x5d4cc80

Bounded question: what does the 490-byte routine at 0x5d4cc80
replace, how does the key object's flag byte change what it
builds, and where is it referenced from?

## Answer, end to end

The routine replaces the node held in one slot. It takes an
owner pointer in rdi (returned unchanged), a key object in
rsi, two values in rdx and rcx, and a slot pointer in r8 —
the address of a pointer variable, not the node itself. In
instruction order:

1. Null slot report: if r8 is null, the routine builds a
   32-byte stack block and calls the report callee 0x61cf670
   at 0x5d4ce43 with esi=4, edx=0, rcx pointing at the
   block, r8 pointing at the block + 0x10, and r9=0. The
   block's four qwords are the message pointer 0x960ee0
   with length 0x20, the path pointer 0x4376fd, and a zero
   qword. The message at 0x960ee0 reads, exactly,
   "stats_iterator not preallocated." (32 bytes). The byte
   at 0x4376fd itself is NUL; the path
   "/home/ubuntu/hl/code_Mainnet/z_vendor/futures-channel/src/oneshot.rs"
   begins at the next byte — recorded as observed, not
   smoothed over. On this path nothing is allocated, the
   slot is untouched, and the owner is returned unchanged
   after the stack-canary check.
2. Flag-selected construction: otherwise the flag byte at
   key +0x4c9 is read (there is no null check on the key
   object). If it is zero, the routine allocates a 0x70-byte
   node with operator new at 0x5d4cccc, sets its vtable
   pointer to 0x64d2c38 (base 0x64d2c28 plus 0x10), and
   calls the insert callee 0x606c680 at 0x5d4cd33. If it is
   nonzero, it allocates the same size at 0x5d4cd88, sets
   the vtable pointer to 0x64d2ca0 (base 0x64d2c90 plus
   0x10), and calls the insert callee 0x606ef50 at
   0x5d4cdf7. Both insert callees take (node, rdx value,
   rcx value). Both paths write the same remaining fields:
   +0x10 = rdx value, +0x18 = rcx value, +0x28 = 0,
   +0x30 = 0, +0x38 = the address of the node's own +0x28
   field, +0x40 = the same address, +0x48 = 0, +0x50 = 0,
   +0x54 = 0 as a 2-byte word, +0x58 = 0, +0x60 = 1, and
   +0x68 = the key object. The paths differ in exactly one
   field: only the flag-nonzero path zeroes +0x08; the
   flag-zero path leaves +0x08 untouched by this routine.
   Neither path writes +0x20.
3. Slot store, old release, notify: the old node is read
   from the slot, the slot is overwritten with the new
   node, and a non-null old node is then released through
   its vtable slot +0x8 at 0x5d4cd48 with the old node as
   argument. Finally the new node is announced through its
   vtable slot +0x38 at 0x5d4cd58 with (owner, new node).
   The owner pointer is returned in rax after the
   stack-canary check at rsp+0x28 (failure goes to
   __stack_chk_fail at 0x5d4ce4d).

The routine's own transfers are exactly six direct calls
(two operator news, two insert callees, the report callee,
__stack_chk_fail), two indirect calls (release, notify),
no indirect tail jumps, and two direct jumps at the end of
the FDE range that are landing-pad stubs, not normal-flow
exits: 0x5d4ce59 jumps to the shared cleanup block at
0x5d4cbfa and 0x5d4ce65 to the one at 0x5d4cc36, both
outside this routine in the preceding routine's cleanup
area. Their cleanup semantics are not claimed here.

## Consumers: no direct calls, four pointer-table slots

The census (reproduced by census.py, re-run inside
verify.py) finds exactly 0 direct calls and 0 tail jumps
for the routine address. It is reached through pointers:
four R_X86_64_RELATIVE slots in .data.rel.ro hold it as
their addend — 0x64c97c8, 0x64cb540, 0x64cba20 and
0x64cc020 — at the same slot position in four parallel
pointer tables (the same two preceding neighbours
0x5d49030, 0x5d44c50 and following neighbours 0x5d48980,
0x5d5b520, except the fourth table, whose following slot
is 0x5e84a80 instead of 0x5d48980). The file bytes at the
four slots are zero and are filled by the loader; the four
qwords a raw file scan finds are the addends inside the
corresponding .rela.dyn entries (file offsets 0x104ab8,
0x1090c0, 0x109f30, 0x10b0a0), not separate runtime
pointers. The owning classes of the four tables are not
named: RTTI/typeinfo was not parsed. The routine's vtable
bases (0x64d2c28, 0x64d2c90) likewise read as zeroes in
the file — they live in a writable segment and are filled
at runtime — so only the +0x10 offset bases are pinned.

## NOT claimed

- What the owner, the key object, or the rdx/rcx values
  denote.
- What the insert callees 0x606c680 and 0x606ef50 do
  beyond taking (node, rdx value, rcx value).
- What the release (vtable slot +0x8) and notify (vtable
  slot +0x38) callees do beyond their argument lists and
  order.
- What the report callee 0x61cf670 does with its stack
  block beyond taking it and returning.
- The classes owning the four pointer tables.
- The landing-pad cleanup semantics (see above).
- Behaviour on dangling pointers or a key object whose
  flag byte cannot be read (the model raises on a null
  key).
- Whether the flag-zero path's +0x08 slot is written by
  the insert callee 0x606c680, since this routine itself
  leaves it untouched.

## Evidence and verification

All extracted from the digest-verified node #115 work binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
work/hl-node-115.bin hashes exactly; provenance entry
artifacts/node/115/hl-node in provenance/artifacts.json).

Packet contents: semantic records.json only (no
per-instruction mnemonic list — instruction-level detail lives
only in the whole-function verbatim excerpt main.txt);
frames.txt with the routine FDE line; relocations.txt with
the four RELATIVE lines; callers.tsv with no direct-call
rows (there are none); pointer_slots.tsv with the four
slots and their neighbours; verify.py, export_excerpts.py,
and census.py in the packet. The mnemonics in the excerpt
are genuine instructions from the target binary, reproduced
verbatim by objdump, not placeholders: verify.py re-checks
every excerpt instruction byte-for-byte against the raw
binary and regenerates the excerpt from a fresh objdump run.

Reproduce from the repository root:

    python3 research/work-items/RE-001-slot-replace-4cc80-115/export_excerpts.py
    python3 research/work-items/RE-001-slot-replace-4cc80-115/census.py
    python3 research/work-items/RE-001-slot-replace-4cc80-115/verify.py
    python3 tests/test_slot_replace_4cc80_115.py

Tool versions: GNU objdump/readelf (Binutils 2.42),
Python 3.12.3. Repository-wide gates (make verify / make
test / catalogue-check) are NOT claimed: the baseline on
this VM is affected by missing LFS material and by the
absence of cargo/rustc, as recorded in earlier packets; the
checks claimed here are this packet's verify.py (ALL CHECKS
PASSED) and its model tests.

## Next step

Decompose the insert callees 0x606c680 and 0x606ef50
(what each one does with (node, rdx value, rcx value),
and whether the flag-zero callee writes the node's +0x08
slot); the 0x5d50470 routine and the 0x5d4dc00 routine
remain unbuilt candidates, as do the owning caller
functions 0x5d8479c..0x5d85475 and 0x5d878f0..0x5d887b0
(large, need decomposition).
