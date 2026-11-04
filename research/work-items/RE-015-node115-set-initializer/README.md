# RE-015 — node 115 set initializer: the .rodata template table is never copied; both merge-delegate sets start empty

Question (the first half of the recorded next question of the
merge-delegate packet, RE-015-node115-merge-delegate / #2615): what
does the set initializer `0x4743990` do with the `.rodata` template
table image at `0x450150` — copy it to the heap as the set's initial
contents, or start empty — and what strings, if any, does the initial
table hold?

Answer, in one line: **it starts empty.** The initializer is a
hashbrown-style reserve/rehash routine; on the delegate's first gate
use it allocates a fresh heap table, memsets its control bytes to
0xFF (EMPTY), moves zero records (the descriptor declares
items = 0), and never reads or copies any byte of the `.rodata`
image — which itself holds no strings, only a shared empty-control
static.

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| set initializer | `0x4743990..0x4743ff0` | 1632 | `eeac52dec8e29f0c1c3084ba80545a9b551b44c69b974a60f2220d564f961eef` |

## Boundaries

| Role | FDE | SHA-256 |
| --- | --- | --- |
| hash function | `0x4744490..0x47445fb` | `a63e8df74f90feb19a2edfb54c63f81974bac2b7c325c363bc7fe23f9c757f62` |
| merge delegate | `0x4748500..0x4749aa9` | `7b1d3b86c285b089e030cba72aa9fc2b71cba2009d2849c91ec06977ea9b2691` |

Slot bindings used: alloc `0x64df480` → `0x6355830`; memset
`0x64df750` → `memset@GLIBC`; memmove `0x64df568` →
`memmove@GLIBC`; dealloc `0x64df4a0` → `0x635de30`; panic entry
`0x64df6b8` → `0x1680e80`; initializer slot `0x64eaf88` →
`0x4743990` (all RELATIVE except the two GLIBC GLOB_DAT rows).

## Trace

### The descriptor the initializer actually sees

The gate (merge-delegate packet) calls the initializer through slot
`0x64eaf88` with (descriptor, 1, descriptor+0x20, 1) whenever the
descriptor word at +0x10 is 0. The descriptor has the hashbrown
RawTableInner shape: `+0x00` ctrl, `+0x08` bucket mask, `+0x10`
growth_left, `+0x18` items, `+0x20` seed (16 bytes, passed to the
hash function).

The delegate builds each frame descriptor by copying 32 template
bytes — two 16-byte loads from `0x64950f8` and `0x6495108`, pinned at
`0x47485a0`/`0x47485af` — and storing the saved TLS seed at frame
+0x20 (`0x47485c7`). The frame descriptor is therefore
{ctrl = `0x450150`, mask = 0, growth_left = 0, **items = 0**}: the
template word that lands at frame +0x18 is the one at `0x6495110`,
whose file value is 0 with no relocation. The template's name word
at `0x6495118` (→ `.rodata 0x4354fc`, the `/rustc/…` string) lies
outside both loads and never reaches the descriptor.

### The three arms

`needed = items + additional` (`0x47439a6`/`0x47439aa`) is compared
against the current capacity (buckets ≤ 8 → buckets − 1, else
buckets − buckets/8; the same formula recurs at `0x4743afe..`).

- **Grow arm** (needed above capacity): size a new power-of-two
  bucket count (bucket record = 24 bytes, `0x4743a85`); allocate
  (buckets·24 rounded up to 16) + (buckets + 16) bytes via the alloc
  slot; place the control base at alloc + bucket-bytes; **memset
  the control bytes to 0xFF (EMPTY)** — fill immediate pinned at
  `0x4743b1a`, memset call at `0x4743b22`. Then, only if items > 0,
  walk the old table's control bytes, rehash each live record with
  `0x4744490` and copy its 24-byte record into the new table
  (`0x4743b70..0x4743c67`; hash call sites `0x4743be4`,
  `0x4743d5d`). The items == 0 test at `0x4743b62`/`0x4743b65`
  skips that loop entirely.
- **Fits arm** (needed within capacity; unreachable on a first
  init): no allocation. Control bytes are normalized in place with
  the 0x80 DELETED vector at `0x454f80` (`0x4743ca9..`), the
  control mirror is refreshed via memmove (its only call site,
  `0x4743d1f`), live records are re-probed and swapped within the
  same table, vacated slots are reset to 0xFF, and growth_left is
  recomputed (`0x4743ef3..`).
- **Write-back** (`0x4743f3e..0x4743f49`): descriptor := {new ctrl,
  new mask, capacity − items, items}. The old table is freed via
  the dealloc slot **only when the old mask is non-zero**
  (`0x4743f4d`/`0x4743f50`) — a mask-0 static table is never freed.
  Success returns `0x8000000000000001` (`0x4743f80`). Capacity
  overflow branches on the caller's flag byte: panic via slot
  `0x64df6b8` (literal "Hash table capacity overflow" at
  `0x49bd80`) or a zero return.

No arm bulk-copies the old table. The body's complete slot-call
census is pinned in records.json; there is **no call through the
memcpy slot `0x64df508` anywhere in the function**, and the only
bulk writes are the 0xFF memset (grow arm) and the memmove mirror
refresh (fits arm).

### The live first-init trace (both delegate sets)

| Step | Value |
| --- | --- |
| input descriptor | ctrl `0x450150`, mask 0, growth_left 0, items 0, additional 1 |
| needed / capacity before | 1 / 0 → grow arm |
| new buckets | 4 |
| allocation | 116 bytes = 96 bucket bytes + 20 control bytes |
| control fill | 0xFF (EMPTY) via memset |
| records moved | 0 (move loop skipped, items == 0) |
| image bytes copied | 0 |
| write-back | {heap ctrl, mask 3, growth_left 3, items 0} |
| old table freed | no (old mask == 0; static is unowned) |
| return | `0x8000000000000001` |

### What the image at 0x450150 actually is

Not a populated table. It is the binary-wide shared empty-control
static: **62 RELATIVE relocations** across the binary use
`0x450150` as addend (this set's template slot `0x64950f8` is one).
Its first 32 bytes are 18 × 0xFF followed by the repeating
`00 00 ff ff` pattern of the adjacent statics; the mask-0
descriptor addresses exactly one bucket, whose control byte is
0xFF = EMPTY. The 24 bytes below the base — where bucket record 0
would sit — are unrelated `.rodata` constants (`0x14` filler and
two non-pointer words), and there is **no RELATIVE relocation
located anywhere in [0x450000, 0x450200)**: no record pointer, and
therefore no initial string, exists in the image. The initial
table holds exactly the zero items the descriptor declares.

## Limits

Static trace only. The hash function and the merge delegate are
hash-pinned boundaries, not re-traced. The fits/in-place arm is
traced at the level of its control-byte normalization, mirror
refresh and write-back; its exact trigger predicate (a
halved-capacity compare at `0x47439da..0x47439e0` and a small-table
special case at `0x4743a14..0x4743a35`) is recorded as observed
code, not reduced to a closed form — and that arm is unreachable
from the delegate's first-init path in any case. The
allocation-failure arm (slot `0x64df490` at `0x4743fb0`; return
constant 0x10 observed at `0x4743f2b` on the zero-flag path) is
pinned by site, not traced. No captured code executed, no runtime
value or reconstruction gate is claimed.

## Next question

What consumes the entry tags 0/1/2/3 downstream of the exit reader
(the 0x50-byte out struct versus the {6, ...} form, and the
destination object at `[rsp+0x278]`)? (Carried over unchanged from
the merge-delegate packet; the set-initializer half of its next
question is answered by this packet.)
