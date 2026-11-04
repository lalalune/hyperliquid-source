# RE-001: the node #115 lu slow deallocator — refused blocks go to the central pool or back to pages, never straight to the OS

This packet answers packet #202's explicitly stated next question:
**decode the deallocator's slow path `0x635c6d0`: where do blocks
refused by the fast path (oversized, aligned, page-aligned, or
list-full) actually go — central pool, page return, or OS release?**

## The answer

**Short version: mostly neither eviction nor OS release.** The slow
path is a re-classification machine first and a drain machine
second. Oversized-but-sane and aligned blocks are rounded up and
re-enter the mainline, where they are usually still cached in the
calling thread's list. Only genuinely uncacheable blocks leave the
thread: full class lists are flushed to the mutex-guarded central
pool, and page-owned blocks return to the page heap. No path in
this function — or in any of its 15 first-level helpers — reaches the
OS: the slow-path FDE contains no `syscall` opcode, and none of
the 15 first-level helper FDEs contains a `munmap`, `madvise`, or
`syscall` edge (the binary does import `munmap`/`madvise`, but no
edge from this function within one call level).

**1. The slow path and its single entry edge.** FDE
`0x635c6d0..0x635de25` (5973B / 1220 strict instrs) takes
`(ptr, size, align/flags)` like the fast path. Whole-`.text` census:
0 direct E8 calls, exactly 1 E9 tail jump, 0 rip-relative LEA
sites, and 0 GOT slots (no `.rela.dyn` RELATIVE addend equals
`0x635c6d0`). The single entry edge is the fast path's failure
stub at `0x635ded0` (`jmp 0x635c6d0`); all five fast-path guard
exits (size `> 0x1000`, third argument nonzero, pointer
page-aligned, budget exceeded, list full) jump to that stub.

**2. Refusal usually means re-classification, not eviction.**
Oversized blocks (`size > 0x1000`, branch at `0x635c73d` to
`0x635cc58`) are rounded up to a `bsr`-derived quantum
(`1 << max(bsr(2*size-1), 7) - 3` alignment) and re-enter the
mainline at `0x635c762`, provided the size is below
`0x7000000000000000`. Aligned blocks (third argument nonzero,
branch at `0x635c730` to `0x635c890`) are rounded up to the
requested alignment (`1 << third-arg`) the same way and re-enter
at `0x635c762` when the aligned size is `<= 0x1000` (larger
aligned sizes re-enter through the `0x635c8e3` class lookup).
Sizes at or above `0x7000000000000000` take the sentinel huge
class `0xe8` (232). The mainline then pushes the block onto the
calling thread's class list exactly as the fast path does (slot
`rbx+0x358 + class*24`, head at slot `+0x8`, bound at slot
`+0x1a` low-16 compare — the same cells #202 cited as
`+0x360`/`+0x372` against `TLS-0x10a8`), updates the budget at
`rbx+0x348`, and returns.

**3. Central pool: the list-full drain.** When a class list is
full, the slow path calls a flush helper and re-checks: if room
was made, the block is pushed to the thread list; if the list is
still full, the block was consumed by the helper and the function
only updates the budget and returns. Small classes flush through
`0x63ead50` (call at `0x635ce27`; `pthread_mutex_trylock` at
`0x63eaf51`, `memmove`, per-entry pushes via `0x63612b0`, then
`pthread_mutex_unlock`); large classes flush through `0x63eb870`
(call at `0x635c97e` / `0x635cc2d`; atomic `lock add` /
`lock addq` counters at `0x63eba30` / `0x63eba3b`, mutex
take/release, per-entry pushes via `0x63bd640`). A mutex plus
atomic counters around the move is the evidence the destination
is shared across threads — the central pool — not another
thread-local list. Segment-derived small-class blocks reach the
same drain through `0x6363260`, which itself calls `0x63eb870`.
The shared structure's exact layout is not decoded here (next
question). Budget-exceeded blocks are already in the thread list
when the budget helper `0x63eec80` runs (push precedes the budget
check at `0x635c851`), so that helper rebalances the cache
(`lock orq` atomics, per-class flush calls) rather than taking
the block anywhere.

**4. Page return: the page-owned paths.** Page-aligned blocks
(branch at `0x635c78d` to `0x635cce8`) and segment-derived
blocks resolve their owning segment and page and free through
the page's own accounting, not through a size-class list.
Segments are 1GB regions keyed at `TLS-0x10a8 + 0x1b0` slots
(`(ptr >> 0x1a) & 0xf0` selects the slot, key `ptr &
0xffffffffc0000000`); pages are 4KB with 8-byte entries
(`(ptr >> 9) & 0x1ffff8` offset into the segment's page base at
`+0x1b8`). A 1-entry cache at `TLS-0x10a8 + 0x2b0` (key) /
`+0x2b8` (page base) plus a scan of 8 slots backs the lookup; a
full miss calls `0x63d9700` to register the segment and the
path continues. The page sink itself is `0x63bd6c0` (call at
`0x635cd7a`: page-owner lookup, unlink via `0x6360b40` /
`0x63c0340`, thread counter decrement at `TLS + 0x98`) and the
`0x63be4d0` / `0x63c3330` pair (call at `0x635d0dd` /
`0x635d0f4`: page used-count, then release of emptied pages
under `pthread_mutex_trylock`, with `log` calls in `0x63c3330`).
The page-owning free `0x63637f0` (call at `0x635ce56`) likewise
takes the central mutex (`pthread_mutex_trylock` /
`pthread_mutex_unlock`) before its own page work. Pages return
to the allocator's page management; nothing here unmaps them.

**5. Side behaviors, not sinks.** When the runtime-initialized
`.bss` byte at `0x6511749` is set, the block is first poisoned
with `0x5a` bytes: the call at `0x635ce82` goes through GOT
slot `0x64ffb30`, whose RELATIVE addend is the stub `0x6349380`
(`mov %rsi,%rdx; mov $0x5a,%esi; jmp memset@plt`), then
re-dispatches at `0x635cbad`. When the thread-state flag at
`fs:0x330` is set, `0x63ef8e0` initializes thread state and the
function re-dispatches at `0x635c71e`. A segment-cache miss
registers via `0x63d9700` and continues. A lookup miss reaches
`0x63bf5b6` plus `abort@plt` (`0x635ce60`) — an internal-error
path, not a block sink. Class `<= 0x23` (35) always takes the
thread-list push; class `> 0x23` takes the segment/page pair
when the `.bss` selector byte at `0x6713606` is set, and the
slot-plus-central-flush path when it is clear — the byte is
runtime-initialized, so the live regime cannot be fixed from
the file alone.

## Census

- Slow path `0x635c6d0`: 0 direct E8 calls, 1 E9 tail jump
  (`0x635ded0`, the fast path's shared failure stub), 0 LEA
  sites, 0 GOT slots in the whole `.text`.
- Fast path `0x635de30`: 5 guard exits converge on `0x635ded0`
  (size, third argument, page alignment, budget, list full).
- Poison stub `0x6349380`: reached only through GOT slot
  `0x64ffb30` (RELATIVE addend `0x6349380`), 1 call site
  (`0x635ce82`).

## Corrections to earlier packets

None. #202's slow-path pointer (`0x635c6d0`), its fast-path
cells (`+0x360` head / `+0x372` bound against `TLS-0x10a8`),
and its guard list are all confirmed; the slot arithmetic here
(`0x358` base `+ 0x8` head, `+ 0x1a` bound) is the same cells
written from the slot base.

## Files

- `research/work-items/RE-001-node115-lu-slow-dealloc/README.md`
- `research/work-items/RE-001-node115-lu-slow-dealloc/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-slow-dealloc/records.json`
- `research/work-items/RE-001-node115-lu-slow-dealloc/dispatch.hex`
- `research/work-items/RE-001-node115-lu-slow-dealloc/dispatch.objdump.txt`
- `research/work-items/RE-001-node115-lu-slow-dealloc/full.hex`
- `research/work-items/RE-001-node115-lu-slow-dealloc/full.objdump.txt`
- `research/work-items/RE-001-node115-lu-slow-dealloc/page.hex`
- `research/work-items/RE-001-node115-lu-slow-dealloc/page.objdump.txt`
- `research/work-items/RE-001-node115-lu-slow-dealloc/MANIFEST.sha256`
- `tools/node115_lu_slow_dealloc.py`
- `tests/test_node115_lu_slow_dealloc.py`

## Verification

- Static verifier `tools/node115_lu_slow_dealloc.py`: exit 0
- Unit tests `tests/test_node115_lu_slow_dealloc.py`: 8/8 pass
- MANIFEST: 11/11 entries match
- `make doctor`: analysis_ready true
- `make verify`: exit 0
- `make catalogue-check`: exit 0
- `make test`: 77 files attempted, 1 failed — the single failure is
  the pre-existing test_node115_catalogue Errno 18
  cross-device-link error; this packet's file [36/77] passes 8/8

## Next question

Decode the central-flush helpers `0x63ead50` / `0x63eb870`:
what shared structure do they move full class lists into — its
layout, locking, and the per-entry pushes (`0x63612b0` /
`0x63bd640`)? (Behind it, still open: the drain helper
`0x51e8720`, the field-drop callees `0x5a50a10` / `0x5a4d200`,
and #200's delegates `0x51f3e20` / `0x57ec1b0` and unwind
callee `0x1680cab`.)
