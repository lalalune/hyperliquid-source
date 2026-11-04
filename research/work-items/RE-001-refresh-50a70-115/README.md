# RE-001: node #115 destination refresh 0x5d50a70

Task RE-001. Bounded question: what does the whole 853-byte
routine at `0x5d50a70` (FDE `0x5d50a70..0x5d50dc5`) do with
its destination and source arguments, end to end?

## Answer, pinned to the target binary

The routine takes a destination pointer in `rdi` and a source
pointer in `rsi`, and returns the destination pointer. In
order:

1. **Enter.** Call `0x606ca40` with source `+0x700`. The
   callee is opaque (554 bytes, not a stub); only its
   argument is pinned.
2. **Counter gate.** Read the dword at source `+0x1938`.
   If it is non-zero, increment it by 1 and skip the refresh
   sequence entirely (the fast path). If it is zero, run
   the refresh sequence below.
3. **Refresh sequence (slow path only).** Two 0x100-byte
   record temps are initialized on the stack (temp1 at
   `rsp +0x10`, temp2 at `rsp +0x110`). Each temp is written
   as: qword `+0x08 = 0x400000000`, qword `+0x50 = 0x100`,
   qword `+0x60 = 0x00ffffffffffffff`, and every other
   initialized slot zero. The range `+0x88..+0xef` of each
   temp is NOT written by the initializer. Then:
   - call `0x5fcbf90` with (source `+0xd40`, temp1,
     source `+0x700`);
   - if the byte at source `+0x17b0` is non-zero, also call
     `0x5fcbf90` with (source `+0xf50`, temp2,
     source `+0x700`);
   - re-read the counter: if it still reads 0, call
     `0x5fc9520` with (out slot, source `+0x1100`); the new
     pointer it writes into the out slot replaces source
     `+0x1930`, the out slot is zeroed, the old `+0x1930`
     pointer is disposed of (step 4), and the zeroed out
     slot is disposed of again, which is a no-op;
   - increment the counter by 1 (exactly once in either
     path);
   - if the `+0x17b0` byte is non-zero, call `0x5fcbda0`
     with (source `+0xf50`, temp2);
   - call `0x5fcbda0` with (source `+0xd40`, temp1);
   - call the record teardown `0x5d509c0` on temp2, then
     on temp1. A freshly initialized temp tears down to
     nothing: its `+0x50` flag byte is 0 (the low byte of
     `0x100`), so the condition-variable destroy is skipped,
     and its `+0x70`/`+0x80` pointers are null, so no delete
     runs. The teardown routine itself is shipped whole as
     `teardown.txt`; it was mapped in the `0x5d509c0`
     packet.
4. **Old-pointer disposal.** Given a non-null old pointer,
   read its vtable slot `+0x08` (the qword at `*(old) +
   0x08`). If that value equals the relocated global at
   `0x64ed2d8` (`0x5d486c0`, an `R_X86_64_RELATIVE` addend;
   the routine there, shipped whole as `global_target.txt`,
   is `endbr64; mov $0x10,%esi; jmp operator delete`),
   delete the old pointer with size `0x10` directly.
   Otherwise call the slot value with the old pointer.
   A null old pointer is skipped.
5. **Exit.** Call `0x60d52f0` with source `+0x700`. That
   callee calls `pthread_mutex_unlock` on its argument
   (its first call, with the argument register untouched
   by its prologue); only the argument and the call are
   pinned here.
6. **Virtual finish.** Call the source object's vtable slot
   `+0x300` with (destination, source, 0). If the
   destination's first byte is non-zero, call vtable slot
   `+0x318` with (stack temp, source) and, if the qword at
   temp `+0x08` is non-null, delete[] it. The third
   argument of the `+0x318` call is NOT pinned: `rdx` is
   set to 0 before the `+0x300` call but may be clobbered
   by it before the `+0x318` call.
7. **Return** the destination pointer.

## Transfers

The routine's own control transfers are exactly 13 direct
calls, 3 direct tail jumps out, 4 indirect calls, and 0
indirect tail jumps. The 3 direct tail jumps are the
landing-pad jumps (`0x5d50da8`, `0x5d50db4`,
`0x5d50dc0`) to the cleanup fragment below; every other
internal direct jump lands inside the routine. The stack
canary failure call (`0x5d50d9c`) is counted among the 13
direct calls. Bytes after the FDE range (`0x5d50dc5..
0x5d50dd0`) are `int3` padding, not part of the routine.

## The cleanup fragment

The routine's three landing-pad entries (`0x5d50da1`,
`0x5d50dad`, `0x5d50db9`, inside the FDE range) save the
incoming exception value in `rbx` and jump to the
separate-FDE cleanup fragment at `0x5d50a06..0x5d50a6c`
(shipped whole as `cleanup.txt`). Its three entry stages
are, in the fragment's own terms on the registers it
inherits from the throwing frame:

- `0x5d50a06`: delete[] the qword at inherited-`rbp`
  `+0x08` when non-null, then resume unwinding;
- `0x5d50a37`: tear down the inherited-`r13` temp, release
  the inherited-`r12` (`+0x700`) callee, then resume;
- `0x5d50a2f`: tear down the inherited-`r15` temp, tear
  down the inherited-`r13` temp, release the
  inherited-`r12` callee, then resume.

The fragment checks the same canary slot the routine uses
(`rsp +0x218`), which corroborates that it belongs to this
routine's frame. Which source-level object the fragment's
inherited-`rbp +0x08` denotes is NOT claimed: the normal
path's `+0x318` temp lives at `rsp +0x08`, not at
`rbp +0x08`.

## Consumers (site-only)

The census finds no direct call site and no tail-jump site
anywhere in the binary. The routine is reached only
through four `R_X86_64_RELATIVE` records whose addend is
the routine address (see `relocations.txt`): `0x64c9678`,
`0x64cb3f0`, `0x64cb8d0`, `0x64cbed0` — vtable slots, in
other words. The raw 8-byte scan's four qword hits inside
`.rela.dyn` are exactly the addends of those four records,
not separate stored pointers.

## NOT claimed

What the source, the destination, or any field denotes;
what the opaque callees compute; the third argument of the
`+0x318` call; which source-level object the cleanup
fragment's inherited-`rbp +0x08` denotes; the exact
call-range to landing-pad mapping in the LSDA (only the
three entries and their targets are pinned); caller
semantics (there are no direct call sites); behaviour on
dangling pointers or a null destination or source (the
model raises); or the exception path beyond the cleanup
fragment's staged actions. Instruction mnemonics such as
`endbr64` are genuine instructions present in the target
binary, not placeholders: every excerpt is verbatim
objdump output, checked byte-for-byte against the raw
binary by `verify.py`.

## Verification

Tool versions: GNU objdump/readelf (Binutils 2.42), Python
3.12.3. Reproduce from the repository root:

    python3 research/work-items/RE-001-refresh-50a70-115/export_excerpts.py
    python3 research/work-items/RE-001-refresh-50a70-115/census.py
    python3 research/work-items/RE-001-refresh-50a70-115/verify.py
    python3 tests/test_refresh_50a70_115.py

`verify.py` reports ALL CHECKS PASSED (digest, provenance,
manifest, excerpt regeneration byte-for-byte from a fresh
objdump run, every excerpt instruction byte-for-byte against
the raw binary, FDE ranges, the relocation records, census
consistency including the RELATIVE records and the
`.rela.dyn` addend positions, records, model tests). Three
extra spot instructions were also checked byte-for-byte
against a fresh objdump run and the raw binary (`0x5d50ae8`,
`0x5d50d02`, `0x5d50d7d`) beyond `verify.py`'s own spots.
Model `tools/refresh_50a70_115.py` with
`tests/test_refresh_50a70_115.py` (51 checks pass: the
fast/slow counter paths and single increment, the temp
initialization including the unwritten gap, the flag-gated
second build and merge order, the pointer refresh with both
disposal arms, the null skips, the literal counter re-read,
the virtual finish, and the input guards).
Repository-wide gates (`make verify`, `make test`,
`make catalogue-check`) are not claimed: their baseline is
affected by missing LFS material and by the absence of
cargo/rustc on this machine.

## Concrete next step

What the opaque callees do: the `0x5fcbf90` build, the
`0x5fcbda0` merge, and the `0x5fc9520` pointer refresh
(62–113 bytes each), and what the source object's vtable
slots `+0x300`/`+0x318` compute once the refresh has run.
