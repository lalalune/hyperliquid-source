# RE-001: the node #115 lu allocator — thunk, size class, then block

## Question

Packet #215's next question: decode the `0x636b370` allocator end to
end — what it does with (thread, pool, `0x200000`, `0x40`), what block
pointer it returns, when it returns NULL, and how the `0x40` argument
shapes the allocation.

## Answer in brief

`0x636b370` is not the allocator. It is a 12-byte thunk: it zeroes the
fifth argument and tail-jumps to the real worker `0x636a680`. The
worker is a size-class block allocator over a pool object. Given
(thread, pool, size, align-arg, mode-pointer) it locks the pool's
`+0x60` mutex (with the `0x63bf680` contention path), rounds the
align-arg up to a multiple of 16, rounds the size up to that
alignment, and looks for a reusable block in the pool's slot array
(`pool+0xa8..pool+0xf28`) at a size-class index — a `.bss` table byte
for small totals, an arithmetic `bsr` formula for large ones. On a
hit it carves the block, rewrites its header, hands the remainder to
the `0x6369fe0` helper for re-insertion, and returns the aligned
pointer. On a miss it asks the `0x636a140` helper for a fresh chunk
(NULL from there means NULL from the worker), links it into the
pool's chunk list, and applies the same carve. When the mode pointer
is nonzero the worker stores the block's `+0x20` word through it;
the thunk forces it to zero, so the miss-handler path never stores.

For the miss handler's call `(thread, *record, 0x200000, 0x40)`:
alignment `0x40`, rounded size `0x200000`, total `0x200040`, large
path (`total-16 = 0x200030 > 0x1000`), size-class index 65, scan
from `pool+0x4b8` to `pool+0xf28`.

## The thunk (FDE `0x636b370..0x636b37c`, 12B)

```
endbr64; xor %r8d,%r8d; jmp 0x636a680
```

The fifth argument is forced to 0. Every thunk caller therefore gets
the no-mode-store behaviour; only the worker's single direct caller
(`0x636b3a5`) can pass a live mode pointer.

## The worker (FDE `0x636a680..0x636aad8`, 1112B, single `ret`)

Args: `rdi` = thread, `rsi` = pool, `rdx` = size, `rcx` = align-arg,
`r8` = mode pointer. Saves: thread → `r14`, pool → `rbx`,
`pool+0x60` (mutex) → `r15`, align → `r12`, rounded size → `r13`.

- **Lock.** `pthread_mutex_trylock(pool+0x60)`. On failure: call
  the contention helper `0x63bf680(pool+0x20)`, set `[pool+0x88] = 1`,
  and proceed as if locked. On every hold: `[pool+0x58]++`; if the
  thread differs from `[pool+0x50]`, `[pool+0x48]++` and
  `[pool+0x50] = thread`. Every unlock is preceded by
  `[pool+0x88] = 0`.
- **Alignment math.** `align = (align-arg + 0xf) & ~0xf`;
  `rounded = (align + size - 1) & -align`;
  `total = align + rounded`. The initial limit word is
  `total - 0x10`.
- **Size class.** If `total - 0x10 > 0x1000`, the large path
  computes the index arithmetically (`bsr` on `2*(total-16) - 1`,
  masked/shifted, minus 23); otherwise the small path reads a byte
  from the `.bss` table at `0x67277c0` indexed by `(total-9) >> 3`.
  Index `> 0xe7` skips the scan and goes straight to the fresh path.
- **Scan.** The slot array is `pool+0xa8..pool+0xf28` (16B
  entries). The worker scans from `pool+0xa8 + index*16` to
  `pool+0xf28`, calling the slot-claim helper `0x63ac480` on each
  entry (unrolled by 8, Duff's-device dispatch on the remainder).
  Nonzero return = found block.
- **Fresh path.** Unlock, then call `0x636a140(thread, pool,
  pool+0x10, pool+0x94, pool+0x98, rounded, align)` (six register
  args plus a pushed align). Re-lock with the same contention
  protocol. NULL from the helper means: clear `[pool+0x88]`,
  unlock, return NULL. Otherwise link the chunk via `+0x8` into
  the `pool+0xa0` list, add `[chunk]` into `pool+0xf38`, update
  the `pool+0xf28` pair from `.rodata 0x450770`, and apply the
  flag-gated `pool+0xf40` counter.
- **Carve (shared).** At the block pointer: stamp word `+0x0`
  (low bits forced to `0xe80afff`, high bits kept), set word
  `+0x8 = requested-rounded + aligned`, set word `+0x10` to the
  computed remainder, call `0x6369fe0(pool, block, aligned,
  aligned, requested)` to return the remainder to the free list,
  then — only if the mode pointer is nonzero — store
  `[block+0x20]` through it. Unlock and return the aligned value
  derived from the block's `+0x8` word.

## Census

Whole-`.text` byte scan with rel32-target filter, per-site
disassembly spot checks; `.rela.dyn` for GOT (60,723 entries).
Thunk `0x636b370`: 19 direct E8, 0 LEA, 0 GOT. Worker
`0x636a680`: 1 direct E8 (`0x636b3a5`, the `0x80`/`0x80`
stack-out-pointer caller) plus the thunk's tail jump
(`0x636b377`, E9), 0 LEA, 0 GOT. The miss handler's call site is
`0x63d9803` (inside FDE `0x63d9700..0x63d987b`).

## Corrections to earlier packets

- **#215 extended.** The `0x636b370` call target is a 12B thunk,
  not the allocator body; it forces the worker's fifth argument
  to 0 and tail-jumps to `0x636a680`. The worker's fifth
  argument is a mode/out-pointer, not a second size: nonzero
  stores `[block+0x20]` through it.
- **#215 refined.** The allocator's pool object fields
  (`+0x20` contention arg, `+0x60` mutex, `+0x88` contended byte,
  `+0x48`/`+0x50`/`+0x58` accounting) differ from the
  miss-handler record's (`+0x30`/`+0x38`/`+0x40`); the allocator
  operates on the pool object (`*record`), not the record itself.
- **#215 confirmed.** The miss-handler call passes (thread,
  `*record`, `0x200000`, `0x40`); the worker returns a block
  pointer, which the miss handler stores into the directory slot.

## Unresolved, stated not inferred

Internals of the slot-claim helper `0x63ac480` (what its nonzero
return is, and how it detaches the block); internals of the fresh
helper `0x636a140`; internals of the remainder helper `0x6369fe0`
beyond its re-insertion call; the semantic identity of the block's
`+0x8` word (why aligning it yields the returned pointer); the
meaning of the block's `+0x20` mode-out word; what populates the
`.bss` size-class table at `0x67277c0`; the meaning of the
`.bss` counter flags `0x6711b34` / `0x6712374`; internals of the
contention helper `0x63bf680`.

## Next question

Decode the `0x63ac480` slot-claim helper end to end: what it does
with a pool slot pointer, what its nonzero return is, and how it
detaches the block it returns.
