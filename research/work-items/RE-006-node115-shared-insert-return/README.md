# RE-006: node 115 shared book insert routine return contract

## Claim

The two 1,067-byte FDE bodies at `0x58df360` and `0x58df790` are the
shared insert routines the RE-006 ring-append twins call in both of
their arms. Each one returns, in `rax`, the head field `[rdi+0x20]` of
its first argument -- a slab collection of `0x110`-byte entries
(capacity `+0x0`, buffer `+0x8`, length `+0x10`, counter `+0x18`,
head `+0x20`) -- as that field stood before the insertion. The
returned value is the index of the slab slot that receives the order
copy:

- **Append (head == length).** The order copy lands in
  `buffer[head]` (growing the collection first when head equals the
  capacity field); length and head both become `head + 1`. The
  routine returns the pre-insert length.
- **Reuse (head < length).** The first dword of `buffer[head]` must
  equal `2` (vacant). Head becomes that slot's `+0x8` qword (the
  vacant-slot link), the order copy overwrites `buffer[head]`, and
  the routine returns the vacant slot index.
- **Panic (otherwise).** Head greater than length, or a non-vacant
  first dword in the reuse case, runs the vacant-entry panic block:
  the length-prefixed message `expected vacant entry ` at
  `0x4339b2`, location `l1/src/slab/slab.rs:78:21`, a call through
  slot `0x64df6b8`, and `ud2`. It never returns.

Before the decision the routine saturating-increments the slab
counter at `+0x18`. The two stack arguments never change the
returned index: the first is a mode selector and the second a link
index; the effective link mode holds iff the selector equals `1`,
the index is below the slab length, and the qword at that slab slot
does not equal `2`. They only choose the sources of the order
rewrite (below) and the target of the link writes.

## Scope

| Owner | FDE range | Bytes | SHA-256 | Role |
| --- | --- | ---: | --- | --- |
| `shared_a` | `0x58df360..0x58df78b` | 1,067 | `9885b0a31f873965b33690748e029b2539e0398c6e9d48f1eca3a5dc61f96e29` | shared insert routine A |
| `shared_b` | `0x58df790..0x58dfbbb` | 1,067 | `1c933868b0d8b192a97c7454766e2b0b3dfd17879d851ed5a0d58ab9c6a2d077` | shared insert routine B |

The measured denominator is the two complete owner FDEs: 2,134
bytes. The two ring-append twins are the boundary: each contains
exactly two direct `E8` call sites into its routine (registration
arm and append arm), a whole-`.text` census finds no other callers,
and no `R_X86_64_RELATIVE` relocation references any of the four
bodies, nor does either routine start appear as data anywhere in
the capture.

| Caller | FDE range | Bytes | Call sites | Calls |
| --- | --- | ---: | --- | --- |
| `twin_a` | `0x5911890..0x5911b27` | 663 | `0x59119d1`, `0x5911a3f` | `shared_a` |
| `twin_b` | `0x5911b30..0x5911dc7` | 663 | `0x5911c71`, `0x5911cdf` | `shared_b` |

## Method

`tools/shared_insert_return_static.py` authenticates the whole
node 115 capture by size and SHA-256 before generation. Analysis
derives both owner ranges and both caller ranges from the FDE
extents, re-derives every body hash, scans the whole `.text` for
direct `E8` callers, confirms no relative relocation reaches any
of the four bodies, parses all five `core::panic::Location`
records from their relative relocations, and pins every one of the
236 instructions per owner: 205 exact instruction byte strings
shared by both bodies, 31 per-twin sites checked by per-owner
bytes or by resolved branch/call/slot/lea target, and 27 intra-body
branch targets, each validated as a native instruction start
during generation.

## Trace

1. **Entry accumulator.** `*r8` (the fifth argument; the twins
   pass `book + 0x118`) becomes `*r8 + [order+0xe0]` as a checked
   add. On carry, the cold block calls the helper behind slot
   `0x64e4ea8` (bound to `0x4524e40`) with `edi = 0` and the
   Location record at `0x64b64b0`
   (`l1/src/qtys/mod.rs:831:1`), then stores the saturating sum.
   This runs before every other effect.
2. **Mode selection.** Link mode holds iff the first stack
   argument equals `1`, the second stack argument is below the
   slab length `[rdi+0x10]`, and the qword at that slab slot does
   not equal `2`; anything else falls back to fresh mode. (The
   twins' registration arm passes `0` as the first stack argument,
   so it always runs fresh; the append arm passes its flag qword
   and the cached result of the previous call.) The effective flag
   is stored into the event record and into the rewritten order.
3. **Event record.** One record is appended to the collection
   behind `rcx` (capacity `+0x0`, buffer `+0x8`, length `+0x10`),
   growing it through the per-twin slot when length equals
   capacity. The element is `0x2b8` bytes in `shared_a` and
   `0x2c8` in `shared_b`; this routine writes its first 77 bytes:
   constant `2`, the mode flag, a mode-dependent qword (link mode:
   `[slot+0xf0]` of the linked slab element; fresh: `[order+0xe0]`),
   `[order+0xe0]`, `[order+0xb0]`, the `rdx` argument,
   `[order+0xf0]`, the 16 bytes at `[order+0xf8]`, the dword at
   `[order+0x108]`, and the byte at `[order+0xd2]`. The remaining
   element bytes are not written by this routine.
4. **Order rewrite.** The order's first four qwords are replaced:
   `+0x0` and `+0x8` take the mode-dependent pair (link mode: the
   linked element's `+0x0`/`+0x8`; fresh: the level record's
   `+0x10`/`+0x18`), `+0x10` takes the mode flag, and `+0x18`
   takes the link index in link mode -- in fresh mode it takes a
   frame slot this routine writes only on the link path (recorded,
   not interpreted). The rewritten order is then copied to two
   frame scratch areas; neither copy is read on the return path.
5. **Return decision.** The slab counter `[rdi+0x18]` is
   saturating-incremented, the head `[rdi+0x20]` is loaded, and
   the append / reuse / panic split of the Claim runs on head
   against length `[rdi+0x10]`.
6. **Link writes.** With the flag set, the linked element is
   checked (assertion location `l1/src/book/book_orders.rs:81:40`,
   helper behind slot `0x64df830`) and receives `1` at `+0x0` and
   the returned index at `+0x8`; with the flag clear, the level
   record receives `1` at `+0x10` and the returned index at
   `+0x18`. In both cases, when the rewritten order's first dword
   equals `1`, a second element -- at the index held in the frame
   slot fed from the linked element's `+0x8` or the level's
   `+0x18` -- receives `1` at `+0x10` and the returned index at
   `+0x18` under assertion location
   `l1/src/book/book_orders.rs:89:40`; otherwise the level record
   receives `1` at `+0x0` and the returned index at `+0x8`.
7. **Level totals and return.** `[level+0x70]` gains
   `[order+0xe0]` through the same checked-add shape (its
   overflow arm uses the second Location record, also
   `l1/src/qtys/mod.rs:831:1`), `[level+0x78]` is
   saturating-incremented, and the routine returns the head value
   loaded in step 5 (`rax = r13`).

## Twin difference

Both routines hold 236 native instructions at identical relative
offsets; 205 are byte-identical and 57 bytes differ across the 31
remaining instructions. The differences are: the frame size
(`0x408` / `0x418`) and the stack-argument and scratch
displacements it shifts by `0x10`; the event element size
immediate (`0x2b8` / `0x2c8`, two sites); rip-relative
displacements that resolve to the same slot, record, message, or
callee; and three per-twin targets -- the event grow slots bind
to different functions (`0x59630a0` / `0x5962310`), the slab grow
slots differ but bind to the same function (`0x43bbd40`), and
the unwind destructor glue differs (`0x5947550` / `0x5948db0`).
The whole return path is byte-identical: the routines are the
same contract instantiated over two event record types.

## Boundary

The packet ends at the two owner bodies and their four pinned
call sites in the twins. The callees behind the copy slot
(`0x64df508`, not bound by a relative relocation in this capture),
the grow slots, the assertion and panic helpers, and the unwind
glue are recorded by address and slot binding only; their
internals are not established. The `rdx` argument and the event
record tail past byte 77 are recorded raw. What the returned
index means to the twins' callers above the twins is the parent
packet's boundary, not this one's.

## Next question

The returned index names a slab slot whose element the next call
can link against. What do the four insert-order callers above the
twins do with the value the twins forward to them -- is it stored
as a durable order handle, or consumed only inside the insert
path?

## Validation

```sh
python3 tools/shared_insert_return_static.py
python3 -m unittest tests.test_shared_insert_return_static
sha256sum -c MANIFEST.sha256  # run in this directory
```

The test regenerates the packet into a temporary directory and
requires byte identity with the retained files, checks the mode
rule, the slot decision cases (append, reuse, and both panic
conditions), and the saturating add, and mutates nine pinned bytes
or records -- the accumulator add, the mode immediate, the head
load displacement, the return move, one per-twin element size, a
grow slot displacement, the panic message, the panic location
line, and one caller `E8` opcode -- requiring `analyze` to reject
each mutation.
