# RE-001: the node #115 lu ctx feeder — gate, shard, generation, feed

## Question

Packet #220's next question, extended to this FDE's own callers: what does
the FDE `0x63e9cd0..0x63ead50` do end to end — what ctx object it passes to
the double slot-insert caller `0x6363660`, what drives its three call sites
(`0x63ea135`, `0x63ea495`, `0x63eaad3`), and how its nodes reach the
head/slot/anchor state machine?

## Answer

`0x63e9cd0` is a ctx feeder: it walks a buffer of items under a shard lock,
compacts the buffer by dropping every item whose key and shard tag match the
current item, and dispatches each dropped item by its generation field —
either to the collect sibling `0x6363560` or, when the generation becomes
exactly 1 and the item is not already the shard head, to the state machine
`0x6363660`. Items that match neither generation rule are dropped silently.
The loop repeats over the compacted buffer until it is empty, then a final
sweep finalizes every collected item.

Signature, as used here: `0x63e9cd0(ctx, src, obj, index, lock_flag)` =
(rdi, rsi, rdx, rcx, r8b). `ctx` (rdi) is saved at `-0x58(%rbp)` and passed
through unchanged as the first argument of every downstream call; it is also
the object whose `+0x98` field tracks the remaining item count. `obj`
(rdx) carries the range fields `+0x12`/`+0x14` and the `+0x8` drain word.
`index` (rcx) selects the per-index tables and the per-index struct.
`lock_flag` (r8b) selects the locked shard path versus the lock-free scan
path. The second argument's pointee contributes one word, `[pointee+0x28]`,
kept at `-0x88(%rbp)` as the drain-match value.

## Entry gate

- Entry `0x63e9cd0`: `endbr64`, pushes, `sub $0xd8, %rsp`.
- `0x63e9cf2`: `ecx = u16[obj+0x14]`, `ebx = u16[obj+0x12]`,
  `ebx -= ecx`; `r12 = table16[0x6728868 + index*2]`; `r10d = ebx +
  table16*8`; `shr $0x3, %r10w`; `jne 0x63e9d60` continues only when the
  shifted value is nonzero. When it is zero, control reaches the shared
  epilogue at `0x63e9d39` (stack check) and returns at `0x63e9d5a` —
  the FDE's single `ret` site.

## Setup

- `0x63e9d60`: `r13 = src`; `rsi = [obj]`; `r11 = 0x6727a00`;
  `rdx = table64[0x6727a00 + index*8]`; `call 0x63b6c50` at `0x63e9d9c`.
- `0x63e9da1`: `rax = [src]`; `rcx = [rax+0x28]` (the drain-match value);
  a stack buffer of `8*(count+1)+15` bytes is probed page by page, then
  `call 0x63e94a0` at `0x63e9e35` with (ctx, `&count`, ?, buffer) fills it.
- Loop head `0x63e9ef0`: `r14 = [r13]` (current item); `r12d =
  [item] & 0xfff` (the key); `rbx = table64[0x65096c0 + key*8]` (the obj
  value, kept at `-0x68(%rbp)`); the drain condition is
  `rbx == [pointee+0x28]` and flag byte `-0x69(%rbp) == 0`.
- The r8b flag byte at `-0x6a(%rbp)` selects the path: nonzero takes the
  shard-lock path, zero takes the lock-free scan path (`0x63ea160`).

## The shard ctx (lock path, r8b != 0)

- Shard index = `([item] >> 0x26) & 0x3f`, kept at `-0x80(%rbp)`.
- Mutex object = `table32[0x6511780 + index*4] + obj-value +
  shard*224`; `call pthread_mutex_trylock` at `0x63e9f72` on object
  `+0x40`. On failure, `call 0x63bf680` at `0x63ea9c0`, then flag byte
  `[shard+0x68] = 1` and execution continues as locked.
- On lock: `[shard+0x38]++`; if `[shard+0x30] != ctx` then
  `[shard+0x28]++` and `[shard+0x30] = ctx`.
- Drain, only when the drain condition holds: `[shard+0x98]++`,
  `[shard+0x80] += [obj+0x8]`, `[obj+0x8] = 0`, flag byte
  `-0x69(%rbp) = lock_flag`.
- This `r14` object is the ctx passed to `0x6363660`: its `+0xc0` field
  is the head `#220` documents (compared against the item at all three
  call sites), and its `+0xc8` slot and `+0xd8` anchor are `#220`'s
  state machine, cited here by layout, not re-decoded.

## The compaction scan and the generation dispatch

The first scan (`0x63e9fc7` setup) walks two parallel arrays — the stack
buffer at `r13` and the second array at `r15` — with write index `ebx`
and read offset `r8`. Non-matching items are compacted (stored at the
write index, kept); matching items are dropped from the buffer and
dispatched. A match requires both the key (`[item] & 0xfff == r12d`)
and the shard tag (`([item] >> 0x26) & 0x3f == [rbp-0x80]`).

For a matching item, in order:

- Bitmap flip: one bit in the item's `+0x40` bitmap is xored, with word
  and bit derived from `([item] - [item+0x8]) * table32[0x6511820 +
  index*4]` (`imul` at `0x63ea0a8`/`0x63ea0ac`, word via `>> 0x26`,
  bit via `<< (rax >> 0x20)`).
- `[item] += 0x10000000`; generation = `([item] >> 0x1c) & 0x3ff`
  (`0x63ea0e5` exhibit).
- Generation `== [per-index+0x10]`, where per-index = `40*index +
  [0x64ee138]`: collect path — `call 0x6363560` at `0x63eab9e`,
  `0x63eac11`, or `0x63eacf9` with (ctx, obj, item, shard-ctx), then
  append the item to the output array at `-0xc0(%rbp)`, count at
  `-0x70(%rbp)`.
- Generation `== 1` and item `!= [shard+0xc0]` (head): feed path —
  `call 0x6363660` with (ctx, obj, item, shard-ctx). The return is
  ignored at all three sites; saved registers are restored and the
  scan advances without storing the item.
- Any other generation, or item already head: the item is dropped
  silently (scan advances without storing it).

## The three feed sites

All three pass the identical tuple (rdi = ctx at `-0x58(%rbp)`,
rsi = obj value at `-0x68(%rbp)`, rdx = item, rcx = shard ctx `r14`)
and differ only in which scan path found the item:

- Site 1, `0x63ea135`: the general scan loop's match path
  (`0x63ea07c` loop, via the `0x63ea0ca` bit-flip block).
- Site 2, `0x63ea495`: the advance-loaded match path of the general
  scan (key checked at the `0x63ea03e` advance, tag checked at
  `0x63ea3f0`, then the same bit-flip/bump/dispatch sequence).
- Site 3, `0x63eaad3`: the odd-count first-item path (`0x63e9ff6`,
  via the `0x63eaa30` tag-check block), taken when the scan count is
  odd and the first item matches.

The obj passed is the `0x65096c0` table value for the item's key —
the same object whose `+0x13450` field gates `#220`'s block-1 rotation
and evict splice. That gate reappears here at `0x63ea4c9`
(`cmp %ebx, 0x13450(%rsi)` against the `.bss` word at `0x650969c`):
when it passes, the obj mutex at `+0x2968` is unlocked and flag byte
`+0x2990` cleared before the second scan.

## The lock-free path (r8b == 0)

- `0x63ea160`: a Duff's-device scan (remainder dispatch on count & 7,
  then an 8-wide block loop) over the same buffer. On a key match it
  calls `0x63bd5a0(ctx)` (15 sites in this FDE, all with rdi = ctx)
  and continues scanning; it never feeds the state machine.
- On exhaustion (`0x63ea4bb`): the obj gate above, then a second
  compaction scan whose key matches call `0x63bd640` (7 sites) with
  rdi = ctx and the matched pair in (rsi, rdx). Its internals are not
  decoded here.

## Loop latch and exit

- Latch `0x63ea398`: `[shard+0x78] += r10`, `[shard+0x88] -= r10`,
  byte `[shard+0x68] = 0`, `pthread_mutex_unlock` on the shard mutex.
  Then `ctx+0x98 -= consumed`; if negative, `call 0x63e9160` at
  `0x63ea9dd` on (ctx+0x70, ctx+0x98), and when that returns nonzero,
  `call 0x6360ed0` at `0x63ea9f6` with (ctx, obj, 0, 0).
- The loop repeats at `0x63e9ef0` while `ebx != 0` (ebx is the compacted
  write index, i.e. the new count). When it reaches zero, the exit
  path `0x63ea778` runs a final sweep over the output array, calling
  `0x63612b0` (7 sites) with (ctx, table value, item) per collected
  item (Duff's device, count & 3, then a 4-wide loop).
- Final drain `0x63ea904`: if flag `-0x69(%rbp) != 0`, skip to restore;
  else if `lock_flag == 0`, a lock-add drain moves `[obj+0x8]` into
  the `-0xa8(%rbp)` target and clears it (`0x63eac66`); else
  `call 0x6362130` at `0x63ea923` with (ctx, drain-match value, 0,
  count), then the same shard stats/drain/unlock sequence on the
  returned object (`+0x40` mutex, `+0x38`/`+0x30`/`+0x28`,
  `+0x98`/`+0x80`, `+0x68 = 0`).
- Restore `0x63ea986`: `[obj+0x12]` is rewritten from `[obj]`,
  `[obj+0x14]`, and the entry table value
  (`[obj+0x12] = (u16)([obj] + (u16)([obj+0x14] - [obj]) -
  table16*8)`), then `jmp 0x63e9d39` to the stack check and the
  shared `ret`.

## Census

Whole-`.text` byte scan + per-site objdump confirmation; `.rela.dyn`
for GOT (60,723 entries). This FDE `0x63e9cd0`: 56 direct E8 callers
across `.text`, 0 GOT. The FDE itself makes 50 direct E8 calls, 0 to
itself, with 39 `jmp` lines all targeting inside the FDE and a single
`ret` at `0x63e9d5a`. Outgoing breakdown: `0x6363660` x3 (the feed
sites), `0x6363560` x3 (collect), `0x63bd5a0` x15, `0x63bd640` x7,
`0x63612b0` x7, `pthread_mutex_trylock` x3, `pthread_mutex_unlock`
x3, `0x63bf680` x3, and one each of `0x63b6c50`, `0x63e94a0`,
`0x6362130`, `0x63e9160`, `0x6360ed0`, `__stack_chk_fail`.

## Corrections to earlier packets

- **#220 confirmed.** The three call sites pass (unused = outer rdi,
  obj = `0x65096c0` table value, node = scanned item, ctx = shard
  object) and ignore the return at all three sites; the shard object's
  `+0xc0` field is compared against the item before each call, matching
  `#220`'s head field.
- **#220 confirmed.** The obj gate operand `[obj+0x13450]` against
  `.bss 0x650969c` reappears at `0x63ea4c9` with the same direction
  (`jb` skips when below).
- **#219 confirmed, by address only.** The slot-insert helper is not
  called from this FDE; it is reached only through `#220`'s callee.
- No bytes claimed by packets #183–#220 are re-claimed. All exhibits
  lie strictly inside this FDE; caller FDEs, the collect sibling, and
  the state-machine callee are cited by address only.

## Unresolved, stated not inferred

Internals of the collect sibling `0x6363560`, the scan helpers
`0x63bd5a0` / `0x63bd640`, the finalizer `0x63612b0`, the resolver
`0x6362130`, the setup helpers `0x63b6c50` / `0x63e94a0`, the
negative-balance helper `0x63e9160`, and the fallback `0x6360ed0`;
the meaning of the second argument's pointee and of the per-index
struct fields other than `+0x10`; the meaning of the shard
`+0x78`/`+0x88` transfer pair; why generation 1 (freshly bumped from
0) is the feed rule while the expected generation is the collect rule;
the purposes of this FDE's 56 callers.

## Next question

Decode the collect sibling `0x6363560` end to end: what it does with
(unused, obj, item, ctx), how it differs from `0x6363660`'s
head/slot/anchor state machine, and what consumes the output array
this feeder appends to at `0x63eab9e` / `0x63eac11` / `0x63eacf9`.

## Verification

- Static verifier `tools/node115_lu_ctxfeed.py`: exit 0
  (5 excerpts, 205 bytes, 46 strict mnemonics, outgoing
  50 E8 sites, incoming 56 E8 callers, 0 GOT, MANIFEST 15/15).
- Unit tests `tests/test_node115_lu_ctxfeed.py`: 9/9.
- `make verify`: exit 0 (29 manifests, 471 entries).
- `make catalogue-check`: exit 0.
- `make test`: 77 files attempted, 1 failed — the single
  failure is the pre-existing test_node115_catalogue Errno 18
  cross-device-link error, identical on pristine checkouts,
  not a packet regression; this packet's file [36/77]
  passes 9/9.
- Target: node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis).
- No bytes claimed by packets #183–#220 are
  re-claimed; earlier bytes are cited by address
  only. No execution of the node binary at any
  point.

## Files (16)

- `research/work-items/RE-001-node115-lu-ctxfeed/README.md`
- `research/work-items/RE-001-node115-lu-ctxfeed/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-ctxfeed/records.json`
- `research/work-items/RE-001-node115-lu-ctxfeed/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-ctxfeed/ctx_entry.hex`
- `research/work-items/RE-001-node115-lu-ctxfeed/ctx_entry.objdump.txt`
- `research/work-items/RE-001-node115-lu-ctxfeed/ctx_gate.hex`
- `research/work-items/RE-001-node115-lu-ctxfeed/ctx_gate.objdump.txt`
- `research/work-items/RE-001-node115-lu-ctxfeed/ctx_gen.hex`
- `research/work-items/RE-001-node115-lu-ctxfeed/ctx_gen.objdump.txt`
- `research/work-items/RE-001-node115-lu-ctxfeed/ctx_site1.hex`
- `research/work-items/RE-001-node115-lu-ctxfeed/ctx_site1.objdump.txt`
- `research/work-items/RE-001-node115-lu-ctxfeed/ctx_site3.hex`
- `research/work-items/RE-001-node115-lu-ctxfeed/ctx_site3.objdump.txt`
- `tools/node115_lu_ctxfeed.py`
- `tests/test_node115_lu_ctxfeed.py`
