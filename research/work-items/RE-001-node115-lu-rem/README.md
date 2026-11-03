# RE-001: the node #115 lu remainder helper — gate, slot, insert, account

## Question

Packet #217's next question: what does the `0x6369fe0` remainder helper
do with (pool, block, aligned, aligned, requested), how does it re-insert
the remainder into the free list, and when does it leave the remainder out?

## Answer

`0x6369fe0` (FDE `0x6369fe0..0x636a136`, 342B, single `ret` at
`0x636a0c9`) takes (pool, node, a, b, c) = (rdi, rsi, rdx, rcx, r8).
It reads the remainder size from `[node+0x10]`. If that word is zero it
skips insertion entirely and goes straight to pool accounting. Otherwise
it picks a pool slot from the remainder size, calls the insert helper
`0x63ac0d0(slot, node)` to put the node back into that slot's chain,
then updates three pool counters. It makes exactly one call.

The allocator call site (`0x636a9d0`, #216's carve) passes
(pool, block, padding, aligned, rounded): rdx is the aligned value minus
the node's old `+0x8` word (the `sub` at `0x636a9b7`), rcx is the
aligned value itself, r8 is the rounded requested size. This refines
#216's "(pool, block, aligned, aligned, requested)" gloss: the third
argument is the alignment padding, not a second copy of the aligned
value.

## How the slot is picked

- Remainder `r = [node+0x10]`; if `r == 0`, no insertion (`je 0x636a03a`).
- Small: `r + 1 <= 0x1000` — slot = `pool + 0xa8 + (table[(r + 8) >> 3] - 1) * 16`,
  where table is the `.bss` size-class table at `0x67277c0` (the same
  table #216's allocator worker reads).
- Large: `r + 1 > 0x1000` — a `bsr` formula on `2*r + 1` (clamped,
  masked, shifted) gives the slot index; slot = `pool + 0xa8 + (index << 4)`.
- Huge: `r + 1 > 0x7000000000000000` — the last slot, `pool + 0xf18`
  (the final 16B entry before `pool + 0xf28`).

## The insert

`call 0x63ac0d0` at `0x636a035` with rdi = slot, rsi = node unchanged.
The insert helper's entry (characterised only, not claimed here) zeroes
the node's `+0x28` pair and `+0x38` word and sorted-inserts it into the
slot's chain by the (`+0x20`, `+0x8`) key — the same comparison idiom
#217's slot-claim helper uses. The remainder helper does not test the
insert helper's return; it always proceeds to accounting.

## Pool accounting (always runs, even when the remainder is zero)

With a = rdx, b = rcx, c = r8:

- `pool + 0xf28 += c`.
- `pool + 0xf30 += page_ceil(c + b) - page_ceil(b - a)` (4K pages).
- `pool + 0xf40 += (round2M(c + b) - round2M(b - a)) >> 21`, gated:
  skipped when `.bss` byte `0x6711b34` is zero, when `.bss` word
  `0x6712374` is nonzero, or (unless the first flag equals 2) when
  `pool + 0x90` is zero. These are the same flag addresses #216 noted
  on the allocator worker's fresh path.

For the allocator call this reads: `+0xf28 += rounded`,
`+0xf30 += page_ceil(rounded + aligned) - page_ceil(node_start)`,
since `b - a` is exactly the node's old `+0x8` word.

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Remainder helper `0x6369fe0`: 2 direct E8, 0 E9,
0 LEA, 0 GOT. E8: `0x636a9d0` (allocator worker carve, #216),
`0x636b2b3` (FDE `0x636b0b0..0x636b300`, passing
(pool, obj+0x10, [rsp+0x18], pool, 0xf80); that caller's purpose is not
decoded here, cited by address only).

## Corrections to earlier packets

- **#216 refined.** The remainder call's third argument is the alignment
  padding (aligned minus the node's old `+0x8` word), not a second
  aligned value; the fourth is the aligned value, the fifth the rounded
  requested size.
- **#216 confirmed.** The carve stores the remainder size into
  `[block+0x10]` immediately before the call, and this helper reads
  exactly that word; the pool fields it updates (`+0xf28`, `+0xf30`,
  `+0xf40`) are the allocator worker's pool accounting.
- No bytes claimed by packets #183–#217 are re-claimed. All exhibits lie
  strictly inside the remainder FDE; the allocator carve, the insert
  helper, and the second caller are cited by address only.

## Unresolved, stated not inferred

Internals of the insert helper `0x63ac0d0` beyond its entry behaviour
(what its sorted-insert does on a key collision, and whether it ever
drops a node); the purpose of the second caller at `0x636b2b3`; what
populates the `.bss` size-class table at `0x67277c0`; the meanings of
the `.bss` flags `0x6711b34` / `0x6712374` and of `pool + 0x90`.

## Next question

Decode the `0x63ac0d0` slot-insert helper end to end: what it does with
(slot, node), how it sorted-inserts the node by its (`+0x20`, `+0x8`)
key, and when (if ever) it drops the node instead of inserting it.

## Verification

- Static verifier `tools/node115_lu_rem.py`: exit 0 (5 excerpts,
  216 bytes, 51 strict mnemonics, census 2 E8 sites, MANIFEST 15/15).
- Unit tests `tests/test_node115_lu_rem.py`: 9/9.
- `make verify`: exit 0 (29 manifests, 471 entries).
- `make catalogue-check`: exit 0.
- `make test`: 77 files attempted, 1 failed — the single failure is the
  pre-existing test_node115_catalogue Errno 18 cross-device-link error,
  identical on pristine checkouts, not a packet regression; this
  packet's file passes 9/9.
- Target: node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), upstream main `8fd8db6` (fetch-confirmed
  unmoved before analysis).
- No bytes claimed by packets #183–#217 are re-claimed; earlier bytes
  are cited by address only. No execution of the node binary at any
  point.

## Files (16)

- `research/work-items/RE-001-node115-lu-rem/README.md`
- `research/work-items/RE-001-node115-lu-rem/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-rem/records.json`
- `research/work-items/RE-001-node115-lu-rem/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-rem/rm_entry.hex`
- `research/work-items/RE-001-node115-lu-rem/rm_entry.objdump.txt`
- `research/work-items/RE-001-node115-lu-rem/rm_small.hex`
- `research/work-items/RE-001-node115-lu-rem/rm_small.objdump.txt`
- `research/work-items/RE-001-node115-lu-rem/rm_call.hex`
- `research/work-items/RE-001-node115-lu-rem/rm_call.objdump.txt`
- `research/work-items/RE-001-node115-lu-rem/rm_large.hex`
- `research/work-items/RE-001-node115-lu-rem/rm_large.objdump.txt`
- `research/work-items/RE-001-node115-lu-rem/rm_acct.hex`
- `research/work-items/RE-001-node115-lu-rem/rm_acct.objdump.txt`
- `tools/node115_lu_rem.py`
- `tests/test_node115_lu_rem.py`
