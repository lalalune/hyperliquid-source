# RE-005 node 115: sibling dispatchers' JoinHandle ownership

## Question

The dispatcher-table packet (#3000) pinned eleven static-table
dispatchers whose threads store a result pair into a shared packet
cell, and the packet-cell packet (#3050) pinned the producer side of
one of them (entry `0x6400530`, dispatcher_v4): the cell's only
producer is that dispatcher itself. #3050 closed with the boundary
left open verbatim: "Sibling dispatchers' JoinHandle ownership and
whether their callers read the returned pair are not traced here."

For each of the eleven entries: which body spawns its thread, what
does the spawn's only caller do with the returned 0x18-byte
JoinHandle {thread Arc at +0x00, packet-cell Arc at +0x08,
pthread_t at +0x10} — keep it, store it, or drop it — and does any
body ever read the stored pair back through the matching join body?

Target: `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static analysis only; the artifact was disassembled, never executed
(`captured_code_executed: false`).

## Spawns and call sites (census)

Each entry base is loaded by exactly one `lea` in `.text`, and each
lea sits inside a different body — the per-entry spawn
monomorphisation. Each spawn body has exactly one direct call site
in `.text`. A spawn writes the handle through the caller's sret
pointer; on failure word 0 comes back zero and the caller panics
with the std message "failed to spawn thread".

| entry | family | spawn body | spawn's only caller |
|---|---|---|---|
| 0x64004d0 | L | 0x15b6d10 | 0x1534ed0 |
| 0x64004f0 | L | 0x15b73c0 | 0x15d63c0 |
| 0x6400510 | L | 0x15b7a80 | 0x15d5b00 |
| 0x6400530 | L | 0x15b80e0 | 0x150b310 |
| 0x6451280 | X1 | 0x2d46820 | 0x2d25620 |
| 0x64aa788 | X2 | 0x56141f0 | 0x5a07ec0 |
| 0x64aa7a8 | X2 | 0x5614960 | 0x5a6dd30 |
| 0x64aa7c8 | X2 | 0x56150d0 | 0x5a08720 |
| 0x64bdc50 | X3 | 0x5bc2c90 | 0x5bbea20 |
| 0x64c5330 | X4 | 0x5cd9470 | 0x5cd5ea0 |
| 0x64c6ac0 | X5 | 0x5cf6e80 | 0x5cf5100 |

The spawn body and join body of the 0x6400530 entry hash to exactly
the values #3050 published (spawn `967d4b0b…`, join `f57a1ff8…`);
`prev_packet_check` in records.json pins that agreement.

## Fates: nine drop in place, one is kept, one is stored

Nine call sites destroy the handle immediately after a successful
spawn, in one fixed idiom (byte-pinned per site in records.json):
`pthread_detach` on the fresh pthread word (GOT slot `0x64dfe50`,
dynsym-resolved to `pthread_detach`; 40 call/jump sites in the
binary), then release of the thread Arc (drop slot `0x64dfe58` →
body `0x5c98b40`), then release of the packet-cell Arc (family drop
slot: `0x64dfe60` → `0x5bc2a80` for type A; `0x64ecb50` →
`0x5cd86e0` for X4). No handle word is stored anywhere, so those
threads run detached and their stored pairs can never be read back
through a handle. The nine: **v1, v3, v4, x1, x2a, x2b, x2c, x3,
x4**.

Two call sites differ:

- **v2 is kept.** Caller `0x15d63c0` contains no `pthread_detach`
  site at all. The fresh handle is moved into an owned local, a
  second copy is built into a freshly allocated 0x50-byte worker
  record, the worker is registered through body `0x15c98c0`, a log
  call follows, and the caller returns. The handle value's
  outlined drop is body `0x15df8a0` — detach word 2, then release
  both Arcs — and it is wired into the caller's landing pads
  (direct call at `0x15d66f0`), i.e. the handle is an owned value
  released on unwind, not a value dropped at the spawn site. The
  caller itself has no direct callers; it is reached through
  RELATIVE slot `0x64e1750`.
- **x5 is stored.** Caller `0x5cf5100` is a loop body: it copies
  the fresh handle and passes it to insert body `0x5cf0700`,
  which stores it in the hash map inside the owner struct (map
  field at owner +0x68, bucket table at +0x88) under the caller's
  key. The insert writes the displaced previous value back into
  the spawn slot, and only that displaced handle is detached and
  dropped in place (detach at `0x5cf53d1`, cell drop through the
  X5 slot `0x64ecc48` → `0x5ce8390`). The stored handle's own
  outlined drop is body `0x5cf3570`, wired into the caller's
  landing pads for the stack copy.

## Readers: exactly two packet-cell join bodies

A take-idiom census over `.text` (`testb $1` and `movq $0` at cell
+0x18, pair loaded from +0x20/+0x28) finds exactly two bodies in
the whole binary: **join_a `0x15b8810`** for the shared type-A
cell of families L, X1, X2 and X3, and **join_x5 `0x5cf7550`** for
the X5 cell — the same 350-byte shape. The `pthread_join` census
agrees: two GOT slots are bound to `pthread_join`; slot
`0x64ee1f0` has no call sites, and slot `0x64e1590` is called from
exactly three bodies — join_a, join_x5, and `0x56467d0`. That
third body copies a 0x18-byte handle and joins its word 2, but
its cell is a different, larger object (it reads cell +0x58 at
`0x564685c`); it is reachable only through RELATIVE slot
`0x64e7388` and is not a reader of any of the eleven packet
cells. No join body exists for the X4 cell type at all, so an x4
thread's stored pair is never read by any body — consistent with
its call site dropping the handle in place.

- join_a has exactly one call site: `0x15ec467` in body
  `0x15ec360`, which loads a stored handle from its owner struct
  (words 0–1 from +0xa0, word 2 from +0xb0), calls join_a, and
  consumes the returned pair (null test at `0x15ec46c`,
  conversion call at `0x15ec480`, report call after). That body
  is called once from `0x15fe220`, itself called from two sites.
  No RELATIVE slot points at join_a. Of the nine type-A handles,
  v2's is the only one not destroyed at its call site.
- join_x5 has exactly three call sites: `0x5cf4186` and
  `0x5cf4321` in body `0x5cf3fe0`, and `0x5cf4d67` in body
  `0x5cf47f0`. Its callers dispatch the returned pair — the
  pair's first vtable slot is called on the pair's data
  (`0x5cf4196`/`0x5cf41a1`, `0x5cf4d77`/`0x5cf4d82`). The same two
  bodies also remove handles from the map and detach them
  (detach sites `0x5cf422b` / `0x5cf4c6b`), so a stored x5 handle
  is joined on some paths and abandoned on others.

## Boundaries

- The instruction-level data flow from v2's registered guard into
  the exact owner field the join consumer reads (+0xa0) is not
  traced; the v2 conclusion is the elimination form — it is the
  only type-A handle that survives its call site, and the only
  type-A join call site consumes a stored handle.
- Join-internal semantics of join_x5 (the CAS/take order inside
  the 350-byte body) and of the x5 detach path body `0x5cf3570`
  are the subject of open PR #3074 and are **not** re-derived or
  re-claimed here; both bodies are pinned only as census nodes
  (extents and hashes), which is what the ownership question
  needs. The pair (join_x5 350 bytes + `0x5cf3570` 113 bytes =
  463 bytes) is exactly the scope #3074 states.
- Two neighbouring packets touch single sites of this census
  without owning the question: #3012 pinned the caller_v3 ↔
  spawn_v3 pair and the std spawn-failure `Location`; #3043
  mentions spawn_v3's sret result shape in passing. Neither
  traces sibling ownership.
- Censuses cover direct (E8) calls and indirect calls through
  GOT slots; register-indirect calls cannot be enumerated
  statically and are out of scope.
- The X4 cell layout remains as #3050 left it (only its
  finish-store idiom classified); the no-join claim for X4 rests
  on the `pthread_join` caller census and the take-idiom census,
  not on the X4 layout.

## Validation

- `tools/sibling_join_ownership_static.py` re-derives every
  census (entry leas, spawn call sites, take idiom, pthread_join
  callers, per-body detach sites, join call chains) from the
  materialised artifact and checks `records.json`, `frames.txt`
  and the ten exported objdump ranges for exact agreement.
- `tests/test_sibling_join_ownership_static.py`: 17 tests, all
  passing with the artifact materialised, no skips — including a
  byte-mutation negative control on an owner body.
- All 32 pinned bodies are FDE extents with SHA-256 pins in
  `records.json`; the fate-decisive instructions at every call
  site are byte-pinned there as well.

## Files

- `records.json` — question, answer, 32 owner pins, byte pins,
  table records, GOT slot resolutions, all censuses, the fate
  table, the #3050 hash agreement, boundaries and limits.
- `frames.txt` — the `.eh_frame` FDE line of each pinned body.
- `*.objdump.txt` — disassembly of the ten bodies a reader needs
  to check the claims without re-running the census: spawn_v4
  (reference spawn), join_a, join_x5, both handle-drop bodies,
  caller_v2, caller_x5, join_consumer_a, other_join, insert_x5.
