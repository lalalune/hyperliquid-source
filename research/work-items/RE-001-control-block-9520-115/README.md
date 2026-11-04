# RE-001: map node #115 shared control-block construction 0x5fc9520

Bounded question: what does the 62-byte routine at 0x5fc9520 build,
what does the block it allocates mean, and where is it used?

## Answer, end to end

The routine constructs one shared-ownership control block for a
target object and hands the block back through the caller's out
slot. In instruction order:

1. Atomically increment the 32-bit use count at target +0x00
   (`lock addl $0x1, (%rsi)`). The increment happens BEFORE the
   allocation.
2. Allocate a 16-byte block (operator new with size 0x10, the
   direct call at 0x5fc9539 to the 0x63f0dd0 PLT entry).
3. Store the target pointer into block +0x08.
4. Store the block pointer into the out slot (`*out = block`).
5. Store the vtable pointer 0x64cd880 into block +0x00. The
   address is computed as the table base 0x64cd870 plus 0x10.
6. Return the out slot pointer (rax = rdi on entry).

The routine has no landing pad: its FDE (0x5fc9520..0x5fc955e)
carries no LSDA, so an allocation failure would propagate with
the use count already incremented. That ordering is part of the
pinned behaviour, stated openly rather than smoothed over.

## What the block means: the vtable pair

The block's first qword is a vtable pointer, and both slots are
pinned by R_X86_64_RELATIVE records in relocations.txt:

- Slot +0x00, at 0x64cd880, resolves to 0x5fc9460, the reset
  routine: rewrite block +0x00 to 0x64cd880, load the target
  from block +0x08, and atomically decrement the 32-bit use
  count at target +0x00 (`lock subl $0x1`). There is no zero
  check and no delete in the reset: a count reaching zero
  frees nothing here.
- Slot +0x08, at 0x64cd888, resolves to 0x5fc9480, the
  deleting destructor: call the reset routine, then delete
  the block with size 0x10 (tail jump to operator delete).
- The slot at vptr - 0x08 (0x64cd878) holds 0x64cd828, whose
  own R_X86_64_64 relocation points at the __cxxabiv1 vtable
  plus 0x10: the standard typeinfo position for this vtable.

So the constructed block is a strong shared-ownership control
block: construction raises the use count, the reset lowers it,
and the deleting destructor lowers it and frees the block.
The model in tools/control_block_9520_115.py implements the
constructor plus this pair, with tests in
tests/test_control_block_9520_115.py.

## Consumers: four call sites, two callers

The census (reproduced by census.py, re-run inside verify.py)
finds exactly four direct calls and no tail jumps, stored
qwords, or RELATIVE addends for the routine address:

- 0x5d50d02 in the refresh routine 0x5d50a70..0x5d50dc5:
  rdi = the refresh stack temp (rsp), rsi = source +0x1100;
  after the call the refresh reads the out slot, installs
  the new pointer at source +0x1930, and disposes of the old
  one. This is the consumer the refresh packet left opaque.
- 0x5d8bf6f, 0x5d8c1e0 and 0x5d8c2c8, all in the single
  caller 0x5d8bea0..0x5d8c97a: each site sets rdi to a caller
  stack slot (lea 0x20(%rsp)) and rsi to the caller's r12
  object, and each reads the slot back immediately after the
  call. The caller's wider behaviour is not claimed here.

The routine's own transfers are exactly one direct call
(operator new), no tail jumps, and no indirect transfers.

## Sibling family, recorded as context only

A second control-block family sits at vtable 0x64cd8a0
(reset 0x5fc94a0, deleting destructor 0x5fc94c0). Its count
lives at target +0x04 and is adjusted with a lock xadd, and
its constructor at 0x5fc9560 uses that vtable. It is NOT
modelled in this packet; only its vptr and count offset are
recorded so the two families are not confused.

## NOT claimed

- What the target object or its use count denotes.
- What the vtable's owning type is beyond the typeinfo slot
  value.
- The caller functions' wider behaviour beyond sites, FDE
  ranges, and argument setup.
- Behaviour on dangling pointers, a null out slot, or a null
  target (the model raises on nulls, stated openly).
- Allocation failure (see the no-landing-pad note above).
- The sibling family beyond its vptr and count offset.

## Evidence and verification

All extracted from the digest-verified node #115 work binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
work/hl-node-115.bin hashes exactly; provenance entry
artifacts/node/115/hl-node in provenance/artifacts.json).

Packet contents: semantic records.json only (no
per-instruction mnemonic list — instruction-level detail lives
only in the whole-function verbatim excerpts main.txt,
reset.txt, and deleting.txt); frames.txt with the routine,
vtable-pair, and caller FDE lines; relocations.txt with the
vtable and typeinfo records; callers.tsv with all four sites;
verify.py, export_excerpts.py, and census.py in the packet.
The mnemonics in the excerpts are genuine instructions from
the target binary, reproduced verbatim by objdump, not
placeholders: verify.py re-checks every excerpt instruction
byte-for-byte against the raw binary and regenerates the
excerpts from a fresh objdump run.

Reproduce from the repository root:

    python3 research/work-items/RE-001-control-block-9520-115/export_excerpts.py
    python3 research/work-items/RE-001-control-block-9520-115/census.py
    python3 research/work-items/RE-001-control-block-9520-115/verify.py
    python3 tests/test_control_block_9520_115.py

Tool versions: GNU objdump/readelf (Binutils 2.42),
Python 3.12.3. Repository-wide gates (make verify / make
test / catalogue-check) are NOT claimed: the baseline on
this VM is affected by missing LFS material and by the
absence of cargo/rustc, as recorded in earlier packets; the
checks claimed here are this packet's verify.py (ALL CHECKS
PASSED) and its model tests.

## Next step

Decompose the shared caller 0x5d8bea0..0x5d8c97a around its
three control-block sites: what its r12 object is, and what
each site's freshly built block is used for after the call.
