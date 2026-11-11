# RE-015 — node 115 map grow 0x4742aa0: it rehashes in place when the live items fit in half the usable capacity, and otherwise allocates a fresh 7/8-loaded table, rehashes every record into it, installs ctrl/mask/growth-left and frees the old block — and it never reads its map+0x20 argument

Question (carried by the map-insert packet
RE-015-node115-map-insert):

> What does the grow body `0x4742aa0` (2,215 bytes, reached
> only through slot `0x64eaf78`) do when growth left is 0 —
> how does it choose the new capacity from the mask and item
> count, how does it reallocate and rehash the bucket/control
> block, what does it read at its `map+0x20` argument, and
> which map words does it rewrite before the insert's probe
> reloads them?

Answer, in one line: **the body forms needed = additional +
items and splits on needed ≤ cap(old buckets)/2, where
cap(B) = (B & ~7) − (B >> 3) (or B−1 for B ≤ 8). Below the
split it rehashes in place: control bytes are flipped
through an 0x80-vector fixup (full → 0x80, empty/deleted →
0xff), the control head is mirrored with one memmove,
marked records are re-placed by pattern-write, move or
bucket swap, and only growth-left at map+0x10 is rewritten
(cap − items). Above the split it allocates a fresh block
for the smallest bucket count whose cap covers
max(cap+1, needed) (4/8/16 below a request of 15, else the
power of two above floor(8·request/7) − 1), fills the new
control block with 0xff, rehashes every stored record with
the same 0xff-terminated FNV-1a (pattern = hash >> 0x39,
slot plus mirror), installs the control pointer, mask and
growth-left at map+0x00/+0x08/+0x10 — never the item
count — and frees the old block when the old mask is
nonzero. The map+0x20 third argument is never read: rdx is
overwritten in every path before any load through it.**

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| map grow | `0x4742aa0..0x4743347` | 2215 | `dddec9130ff0171ebc861ae72351d0e4d846e76cbbd9811c5bed5d56d0ac4a67` |

The body hash is the same one the map-insert packet pins
for this body as a boundary.

## Boundaries

| Role | FDE | SHA-256 |
| --- | --- | --- |
| prev body | `0x4742850..0x4742958` | `19805cd457f128d16f1325f9b077f925f5dde1d5246cb6374881910ed5b03288` |
| displaced-record drop | `0x4742960..0x4742a93` | `1aae44edc7f846da821541c9455706506403ae72981926a7927dd0aa0a3069e1` |
| next body | `0x4743350..0x474398c` | `bc09ee782d62721d2cbc93cc2e52d6f447caebbf7ef36da19f5ae89cfef84ae4` |
| map insert (sole caller) | `0x474b620..0x474ba5d` | `f6d9ca4362a1a81c592c33e5e75d6522a738b71a143b4c6b9bcb0b1739cd6658` |

Slot bindings (`.rela.dyn` unless noted): alloc
`0x64df480` → `0x6355830`; alloc-error `0x64df490` →
`0x141e251`; dealloc `0x64df4a0` → `0x635de30`; panic
formatter `0x64df6b8` → `0x1680e80`; grow slot `0x64eaf78`
→ `0x4742aa0`. GLOB_DAT slots: `0x64df568` = `memmove`
(dynsym 8), `0x64df750` = `memset` (dynsym 10).

## Call sites and arguments

The whole-.text census for slot `0x64eaf78` is exactly one
site: the map insert's call at `0x474ba06`. There is no
direct (E8) call to `0x4742aa0` anywhere in .text. The
insert sets up (`0x474b9ee..0x474ba01`):

- `rdi` = the map pointer (`&S+0x20`);
- `rsi` = 1 (additional capacity requested);
- `rdx` = `map+0x20` — one word past the four map words;
- `ecx` = 1 (the fallibility byte in the low byte).

The body contains exactly six calls, all through slots
(alloc, memset, memmove, dealloc, panic formatter,
alloc-error), and no direct call. The insert caller
ignores the return registers and reloads the control
pointer and the mask from the map after the call.

## The capacity model

Old buckets B = mask + 1 (map+0x08 is the mask). The
usable capacity of a table, computed at entry and reused
for both growth-left stores, is

- cap(B) = (B & ~7) − (B >> 3), or B−1 when B−1 < 8:
  cap = 0, 1, 3, 7, 14, 28, 112, 224 for
  B = 1, 2, 4, 8, 16, 32, 128, 256.

Entry forms needed = additional + items (map+0x18) with a
checked add, and takes the in-place path when
needed ≤ cap(B)/2. Otherwise the requested capacity is
max(cap(B)+1, needed) and the new bucket count is:

- requested < 4 → 4; < 8 → 8; < 15 → 16;
- requested ≥ 15 → the smallest power of two strictly
  greater than floor(8·requested/7) − 1, computed with
  the `0x2492492492492493` divide-by-7 magic and a
  `bsr` round-up (15 → 32, 28 → 32, 29 → 64,
  100 → 128, 112 → 128, 113 → 256).

## Behaviour, phase by phase

1. **Split.** needed ≤ cap(B)/2 goes in place (phase 5);
   anything larger allocates (phases 2–4). From the
   insert this fires exactly when growth-left is 0, i.e.
   when items + deleted slots have consumed cap(B): a
   tombstone-heavy table with few live items rehashes in
   place, a genuinely full one grows.
2. **Allocation.** Total size = align16(new buckets ·
   0x58) + (new buckets + 16), checked at each step,
   allocated through the alloc slot. The new control
   pointer is base + align16(new buckets · 0x58). The
   new control block (new buckets + 16 bytes) is filled
   with 0xff through the memset slot; the bucket area
   is not initialised (empty buckets are never read —
   their control byte is 0xff).
3. **Rehash.** Old control groups are scanned in order.
   Each full slot's key (bucket+0x08 pointer, bucket+0x10
   length) is rehashed with the insert's 0xff-terminated
   FNV-1a (a zero length uses the constant
   `0xaf64724c8602eb6e`, that hash of `[0xff]`). The
   record's whole 0x58 bytes are copied into the new
   bucket at the first special byte of the probe run
   starting at hash & new mask, stepping one 16-byte
   group at a time (a full byte in that run falls back
   to the first special byte of the table's first
   group). The pattern byte (hash >> 0x39) is written
   at the slot and at its mirror `(index − 0x10) &
   new mask`. The loop ends when the item count is
   exhausted; items == 0 skips it entirely.
4. **Install and free.** map+0x00 = new control pointer,
   map+0x08 = new mask, map+0x10 = cap(new buckets) −
   items. The item word at map+0x18 is **not** stored.
   The old allocation (base = old control pointer −
   align16(old buckets · 0x58)) is freed through the
   dealloc slot with the old total size, but only when
   the old mask is nonzero — an empty map's control
   pointer is the static empty block, not heap.
5. **In-place fixup.** Every control byte is rewritten
   by a `pcmpgtb` against 0 ORed with the 16-byte 0x80
   vector at `0x454f80`: full (pattern) bytes become
   0x80, empty (0xff) and deleted (0x80) bytes become
   0xff. Tables of at most 16 buckets convert their
   single group directly; larger tables convert group
   pairs plus a possible tail group.
6. **In-place mirror and scan.** One memmove call
   copies the control head into the mirror area (16
   bytes from ctrl to ctrl + buckets when buckets ≥ 16,
   otherwise buckets bytes from ctrl to ctrl + 16).
   The scan visits indexes 0..mask; for each byte still
   0x80 it rehashes that record's key and probes the
   same table (16-byte groups from hash & mask). A
   destination in the same group takes only the pattern
   byte (slot plus mirror). A 0xff destination receives
   the whole 0x58-byte record and the source byte
   becomes 0xff. Any other destination swaps the two
   buckets qword by qword (0x00..0x50) and the scan
   retries the same index with the swapped-in record.
7. **In-place finish.** growth-left = cap(B) − items
   is stored at map+0x10 and the body returns. The
   control pointer, the mask and the item count are not
   stored on this path. (The degenerate mask == −1
   entry, where B wraps to 0, reaches only this
   recompute with a zero capacity word; it cannot arise
   from the S map, whose empty mask is 0.)
8. **The third argument.** No instruction loads through
   the incoming `rdx`. It is overwritten by the
   divide-by-7 magic (`0x4742b61`), by the group-count
   mask (`0x4742e96`), by the memmove length
   (`0x4742f30`), by the in-place bucket cursor
   (`0x47431e7`) and by the panic location
   (`0x474331d`) before any use; the `[rdx]` loads in
   the swap loop read through a bucket pointer the loop
   itself computes from the scan index. What the insert
   passes there (the word past the map) is therefore
   dead on arrival in every path.
9. **Failures.** A checked-add overflow, a requested
   capacity above `0x1fffffffffffffff`, a
   buckets · 0x58 overflow or a total-size overflow
   past `0x7fffffffffffffff − 15`, and a null
   allocation, all reach the stub at `0x4742bd1`. With
   the fallibility byte nonzero (the insert passes 1)
   the overflow path first calls the panic formatter
   through slot `0x64df6b8` with the string at
   `0x49bd80` ("Hash table capacity overflow", raw
   second argument 0x39) and the location record at
   `0x641cc98`, then the alloc-error slot `0x64df490`
   with (0x10, total size); the null-allocation path
   calls the alloc-error slot directly. With the byte
   0 the overflow path returns rax = 0 and the null
   path returns rax = 0x10, storing no map word.

## Map words rewritten — summary

| Path | +0x00 ctrl | +0x08 mask | +0x10 growth-left | +0x18 items |
| --- | --- | --- | --- | --- |
| allocation | new pointer | new mask | cap(new) − items | — |
| in place | — | — | cap(old) − items | — |
| failure return | — | — | — | — |

## Limits

- The bodies behind the alloc / alloc-error / dealloc
  slots and the panic formatter are pinned by slot
  binding only; their internal behaviour is not traced
  here.
- The panic call's raw second argument (0x39) is
  recorded mechanically; only the 29 bytes of the
  message text at `0x49bd80` are pinned as a string.
- The in-place probe's group-walk is recorded from the
  loop increments and the two pattern-store sites; the
  same-group test is recorded as the xor/distance
  comparison at `0x4743079..0x4743093` without a
  separate formal proof.
- Landing-pad / LSDA protection ranges are pinned by
  the frame records only.

## Next question

Which body consumes the table the grow leaves behind on
the removal side — when an entry is removed from the
S-rooted map, which body clears its control byte (to
0x80, or by the backward-shift deletion of the probe
family), and does anything ever call the grow body with
a fallibility byte of 0 or an additional other than 1
through a different slot referrer in a related binary
section?

## Verification

- `tools/map_grow_static.py` re-derives every pin above
  from the authenticated binary: FDE extents and body
  hashes for the owner and all four boundaries, the
  whole-.text slot census for `0x64eaf78` and the
  direct-call census for `0x4742aa0`, all slot bindings
  via `.rela.dyn` and `.dynsym`, the panic message and
  the 0x80 fixup vector, the capacity model tables
  (recomputed arithmetically), the empty-key FNV
  constant, and byte pins for the entry arithmetic, the
  capacity choice, both rehash loops, both install /
  growth stores, the fixup, the swap test and the
  failure stub.
- `tests/test_map_grow_static.py`: shape, slot bindings,
  census and capacity models, layouts, five one-byte
  counterfactuals (items load, divide-by-7 magic,
  install mask store, alloc call, new-table control
  store), a generate round-trip, and equality with the
  committed `records.json`.

Made via @slopdotcash
Authored with AI assistance (Meta Muse Spark)
