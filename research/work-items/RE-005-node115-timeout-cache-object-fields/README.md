# RE-005 node115 timeout-cache object fields: the +0x10..+0x108 payload of the SIGCHLD registry entry

## Question

The timeout-cache packet (#2947) identified the object cached
at `0x64fee08` as an Arc clone of the vendored tokio signal
registry's entry object for signal 17 (SIGCHLD), pinned the
Arc counts at `+0x00`/`+0x08`, the deferred sub-object at
`+0x110`/`+0x118`, the claim word at `+0x130` and the event
counter at `+0x138` with its orphan-reap consumer. It left
the payload range `+0x10..+0x108` unidentified: what fields
live there, and who reads or writes them?

## Answer

The payload is an array of **eight 0x20-byte cells** at
`obj+0x10, +0x30, +0x50, +0x70, +0x90, +0xb0, +0xd0, +0xf0`,
plus a ninth cell of identical shape at `obj+0x110` (the
sub-object #2947 saw). Each cell is one vendored-tokio
`sync::Notify` wait cell:

| cell offset | field | meaning |
|---|---|---|
| +0x00 | state word | low 2 bits are the Notify state tag; the runner advances it by 4 per run |
| +0x08 | claim byte | CAS 0→1 claims the cell before a run; the runner releases it 1→0; contention parks for 0x3b9aca00 ns |
| +0x10 | waiter head | head of the intrusive waiter list (tokio `util/linked_list.rs`) |
| +0x18 | waiter tail | tail of the same list |

The per-cell runner is body `0x5ce57c0`. Its panic Locations
resolve (through `.rela.dyn`) to
`z_vendor/tokio/src/sync/notify.rs:463`,
`z_vendor/tokio/src/util/wake_list.rs:35,36` and
`z_vendor/tokio/src/util/linked_list.rs:367,385,403`. Run on a
cell it: reads the state word snapshot; if the tag bit is
clear it only does `state += 4` and releases the claim byte;
if set it swaps in `(state & ~3) + 4`, detaches the waiter
list under the claim byte, moves up to 32 waiters into a
stack wake list and wakes each through `*0x8(vtable)`, then
drops the detached remainder through `*0x18(vtable)`.

### Who writes the range

* **Constructor** `0x5cfe910` (558 B; sole caller the Vec
  builder `0x5ce1320`, itself called only by the registry
  globals constructor `0x5cfcec0`): allocates 0x150 bytes,
  writes strong = 1, weak = 1, then
  `memset(obj+0x10, 0, 0x130)` — all eight cells, the ninth
  cell and the `+0x138` counter start zero — and stores 1 to
  `[obj+0x140]` and `[obj+0x148]`. The globals constructor
  builds the Vec for `__libc_current_sigrtmax()` entries, so
  every signal entry object has this identical layout.
* **Nobody else stores into `+0x10..+0x108`.** The only
  writes after construction are the runner's state-word
  updates and waiter-list detach operations, which happen
  inside the cells themselves.

### Who reads / runs the range

* **Per delivery** — the signal driver drain `0x5ce7380`
  (panic Locations `z_vendor/tokio/src/runtime/signal/mod.rs:118,121`)
  walks the entry Vec; for each entry whose pending byte
  (entry slot `+0x08`) was set and whose `[obj+0x140]` count
  is nonzero it claims `[obj+0x130]` (CAS 0→8), does
  `lock addq $2, [obj+0x138]`, releases the claim, then calls
  the drain callback `0x5cfcc50` (GOT slot `0x64ecba8`) with
  `rdi = obj+0x10`. The callback claims (CAS byte at payload
  `+0x08, +0x28, …, +0xe8`, park-retry on contention) and
  runs **all eight cells in order**.
* **Ninth cell (`obj+0x110`)** — run only from the release
  paths of the `[obj+0x140]` handle count: the pair-drop body
  `0x5cee390` and the cache-swap arm of the refresh
  `0x5cee650` (both claim the byte at `obj+0x118` first), and
  the constructor's inlined clone/drop sequence. When that
  count reaches zero the path runs the cell, then decrements
  the strong count; the weak release `0x5ce8860` frees the
  0x150-byte allocation when `[obj+0x08]` reaches zero.
* **`[obj+0x140]` provenance** — the getter `0x5cfcf90` is
  the only `lock inc` site for `+0x140` in `.text` (it also
  increments the strong count and returns
  `[obj+0x138] & ~1`); the only `lock dec` sites are
  `0x5cee390` and the refresh.
* **`[obj+0x148]`** — a second handle count with exactly one
  decrement site in `.text`: the pair-drop body `0x5cfc8f0`.
  On reaching zero it sets bit 0 of `[obj+0x138]` (the sticky
  flag the getter masks off), runs the eight-cell drain
  callback once with `rdi = obj+0x10`, and drops the strong
  count. Its only callers are two sites in the entry-Vec
  element drop glue reached from the registry constructor's
  unwind path.

### Provenance closure

RIP-relative census over the whole `.text`: the cache
globals `0x64fee00/0x64fee08/0x64fee10` are referenced only
by the refresh `0x5cee650`; the entry-Vec globals
`0x64fee28/0x64fee30` only by the lookup `0x5cde710` and the
drain. Every body that can receive the object pointer is
pinned in `records.json` by FDE range and sha256, and none
of them forms a cell pointer for waiter registration — the
generic vendored `Notify` register machinery exists
elsewhere in the binary but never receives one of this
object's cells. So for the SIGCHLD entry the eight waiter
lists stay empty in every reachable path: a delivery bumps
each cell's state word by 4 and wakes nobody, and the entry's
observable behaviour remains the `+0x138` counter that
#2947 pinned.

## Open gaps

* Which handle type owns the `[obj+0x148]` count on the
  registration side: no `lock inc` site for `+0x148` exists
  in `.text`, and its creation sits in the
  signal-hook-registry half of the vendored code.
* Whether the vendored tokio fork assigns distinct meanings
  to the eight cells: no per-cell divergence exists in the
  binary (the drain callback treats all eight identically),
  so the packet claims the shared layout only.
* The producer of the global signal fd at `0x64fee24` is a
  separate open edge (the globals constructor's UnixStream
  pair creation at `signal/unix.rs:71` is noted here only as
  context for the layout, not claimed).

## Verification

`tools/timeout_cache_object_fields_static.py` re-derives
every pin from the materialised artifact: PT_LOAD map, FDE
ranges and sha256 of 16 bodies, `.rela.dyn` resolution of
the five GOT slots, the nine panic Locations, 16 byte pins,
the globals RIP-reference census, the whole-`.text` lock
inc/dec census for `+0x138/+0x140/+0x148`, the cell-runner
call census (38 sites binary-wide, 11 inside the pinned
bodies), and the drain callback's eight claim offsets.
`tests/test_timeout_cache_object_fields_static.py` compares
its canonical output against `records.json`;
`MANIFEST.sha256` covers this folder.
