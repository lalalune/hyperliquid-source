# RE-006 node 115 variant cursor searches (the 0x35bd660 / 0x35bd800 layouts)

## Scope

This packet answers the first open question of the cursor-search packet
(RE-006-node115-cursor-search): which set instances and node layouts the
two variant cursor searches at `0x35bd660` and `0x35bd800` serve. That
packet pinned the two byte-identical 143-byte clones and the three
variant call sites inside its own two callers, and claimed nothing about
the variants' other twenty-three call sites. This packet pins both
variant bodies in full, traces all twenty-six direct call sites in
eighteen caller FDEs, censuses what each caller reads from the returned
record — including whether any consumer reads the record's height field,
the cursor-search packet's third open question — and closes its second
open question with a census of the whole cursor-search family.

Static analysis only, against the authenticated node #115 ELF (SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
Function boundaries are the FDE ranges of the shared unwind index
(135,313 records, all starts unique). The packet retains:

- `records.json` — every claim below in machine-checkable form;
- `frames.txt` — the readelf frame lines for the two variant bodies,
  the eighteen caller FDEs and the sibling search `0x35bf460`;
- one full-body disassembly export per variant body (both are 146
  bytes);
- `tools/variant_cursor_static.py` and
  `tests/test_variant_cursor_static.py` — the checks that regenerate
  and verify all of it.

## Short answer

Both variants are the clones' search with a different node layout. The
record and the ABI are unchanged: `rdi` = record out (returned in
`rax`), `rsi` = root node, `rdx` = height, `rcx` = key pointer,
dereferenced once; the record is `{+0x00 flag (0 hit / 1 miss), +0x08
node, +0x10 height remaining, +0x18 position}`; a hit leaves the
equal-key index in the position field, a miss the insertion index;
descent follows child edges while height remains. Neither body calls
anything or stores anywhere except into the record.

- **Variant A, `0x35bd660..0x35bd6f2` (146 bytes, SHA-256
  `3da45a31…`):** u64 keys from node `+0x8` as in the clones, but up to
  **22 keys** per node — count word at `+0xba`, child edges from
  `+0xc0`.
- **Variant B, `0x35bd800..0x35bd892` (146 bytes, SHA-256
  `100afb1a…`):** up to **11 u64 keys** per node, but the key block sits
  behind a `0x160`-byte head — keys from node `+0x168`, count word at
  `+0x1c2`, child edges from `+0x1c8`.

Every one of the twenty-six call sites reaches its set through the
same handle shape: `{tag +0x0, root +0x8, height +0x10, bound +0x18}`,
with the tag compared against the `0x8000000000000000` sentinel — or,
in the three callers that embed the handle at record `+0x3fc8` /
`+0x4b38`, against a computed per-instance value — and the caller
extracts root and height and passes them as separate arguments. The
variant a caller uses is fixed per caller, as with the clones: no
caller FDE calls both variants.

The height question, answered for the variants' records: at none of
the twenty-six sites does a consumer use a variant record's height
field as a number in the traced code. Ten of the eighteen callers never
read the height slot at all; three copy the whole record region with
vector loads that span the field without interpreting it; three show
height-slot reads only in phases whose record was filled by a
different call reusing the same stack slot; and two do load the
variant record's height as a value — caller `0x3d987f0` loads it into
`rbp` in a follow-on phase, and caller `0x2a918f0` copies it
field-by-field into another struct after its scan loop. Their windows
are retained.

## Method

- The two variant bodies and all thirty-eight retained caller windows
  are decoded with the shared decoder, which requires the rows to tile
  the range exactly and reproduce its bytes; every cited instruction
  is pinned by address and exact bytes in `records.json`, and both
  variant bodies and all nineteen boundary FDEs are digest-pinned.
- Call sites are re-derived by scanning `.text` for direct `call`
  instructions and attributing each site to its containing FDE; the
  derived map must equal the retained map exactly. Tail calls
  (`jmp rel32`) and `R_X86_64_RELATIVE` addends naming either variant
  are censused the same way.
- Record consumption per caller is a full-FDE textual census of the
  four record slots — instructions naming the slot as a source,
  excluding `lea` and pure stores — the cursor-search packet's method,
  applied to all eighteen callers. On caller `0x23795c0` it reproduces
  that packet's retained census exactly.
- The family census scans `.text` for the fourteen-byte record-store
  epilogue sequence shared by every family member
  (`48897008 48895010 48897818 488908`) and attributes each hit to its
  containing FDE.

## Trace

### The variant bodies

The two bodies are instruction-for-instruction parallel to the clones:
load the key once from `[rcx]`, load the count word, scan the key array
with the `seta`/`sbb` three-way step, then either store the record at
the exhausted height (`flag = 0`, `position = count`), descend through
the child edge at the scan position, or store the hit/miss record
(`flag` 0/1 from the three-way result). Only the layout constants
differ, and variant A additionally widens every loop counter path for
its 22-key nodes. The child-index offsets (`+0xb8` / `+0x1c0`) are the
word below the count word in each layout, as in every family member;
the search bodies themselves never read them.

### Call sites

Variant A — 8 sites, 6 caller FDEs. All eight test the flag as a dword
against 1 and, on the consuming path, read node and position and form
`node + position * 8 + 0x60`, loading the qword there.

| call site | caller FDE | handle location |
|---|---|---|
| `0x2379742` | `0x23795c0` | caller record `+0xf0` |
| `0x23799c0` | `0x23795c0` | caller record `+0xf0` |
| `0x2c50127` | `0x2c4fe30` | frame record `+0x428` |
| `0x3d98859` | `0x3d987f0` | argument-derived record `+0xf0` |
| `0x55bdb07` | `0x55bd810` | frame record `+0x428` |
| `0x55be3c7` | `0x55be0d0` | frame record `+0x428` |
| `0x5b81281` | `0x5b810d0` | caller record `+0xf0` |
| `0x5b81533` | `0x5b810d0` | caller record `+0xf0` |

Variant B — 18 sites, 12 caller FDEs.

| call site | caller FDE | handle location | record use |
|---|---|---|---|
| `0x2667ac0` | `0x2667140` | caller record `+0x4b40` | flag only |
| `0x2a86860` | `0x2a84e60` | via pointer | flag; node + position × 32 |
| `0x2a89849` | `0x2a89500` | stack handle at `rsp+0x138` | none — overwritten at the join |
| `0x2a89a30` | `0x2a89500` | copied handle block | flag; node + position × 32 |
| `0x2a89d26` | `0x2a89500` | via pointer | flag; node + position × 32 |
| `0x2a920e2` | `0x2a918f0` | walked list of handles | flag only (existence scan) |
| `0x2c61e5f` | `0x2c61b30` | frame handle at `rbp+0x20` | flag; node + position × 32 |
| `0x2c6b54a` | `0x2c6b3b0` | caller record `+0x3fc8` | flag only |
| `0x558393c` | `0x5582180` | via pointer | flag; node + position × 32 |
| `0x5586a4c` | `0x5585290` | via pointer | flag; node + position × 32 |
| `0x55a0b29` | `0x55a07e0` | stack handle at `rsp+0x138` | none — overwritten at the join |
| `0x55a0d10` | `0x55a07e0` | copied handle block | flag; node + position × 32 |
| `0x55a1006` | `0x55a07e0` | via pointer | flag; node + position × 32 |
| `0x55a1629` | `0x55a12e0` | stack handle at `rsp+0x138` | none — overwritten at the join |
| `0x55a1810` | `0x55a12e0` | copied handle block | flag; node + position × 32 |
| `0x55a1b06` | `0x55a12e0` | via pointer | flag; node + position × 32 |
| `0x55f8d0a` | `0x55f8b70` | caller record `+0x4b38` | flag only |
| `0x55f942a` | `0x55f9290` | caller record `+0x3fc8` | flag only |

Three sites deserve a note. Caller `0x2a918f0` walks an array of
handles and calls variant B once per handle inside the loop, testing
only the flag byte — an existence scan over many set instances through
one site. The three "overwritten" sites are the first site of each
2816-byte caller (`0x2a89500` and its two clones `0x55a07e0`,
`0x55a12e0`): after the variant call, control jumps to a join that
first calls the sibling search `0x35bf460` into the very same record
slot, and only the sibling's record is then read — flag test, then
`position * 0xb0` against the node. Caller `0x2a89500`'s join is
retained as a window; both clone joins call the same sibling into the
same slot (calls at `0x55a0bf0` and `0x55a16f0`, recorded under
`deferred_flag_sites`). Where a caller's tag test fails, no search
runs at all: the fallback paths walk the set with 16-byte, 40-byte or
`0xb8`-byte stride arithmetic from the handle's fields instead.

### The family

Thirteen standalone bodies end in the shared epilogue — eleven
distinct byte strings — plus one inlined instance inside FDE
`0x4d38c10..0x4d38e67` (599 bytes; epilogue store block at `0x4d38e48`,
child edges at node `+0x1a38`; its key and count offsets are not pinned
by this packet). Key capacity is the number of key slots below the
child-index word.

| body | key kind | keys at | count at | edges from | capacity | call sites |
|---|---|---|---|---|---|---|
| `0x1d65920` (clone) | u64 | `+0x8` | `+0x62` | `+0x68` | 11 | 2 |
| `0x35bdd20` (clone) | u64 | `+0x8` | `+0x62` | `+0x68` | 11 | 1 |
| `0x35bd660` (variant A) | u64 | `+0x8` | `+0xba` | `+0xc0` | 22 | 8 |
| `0x35bd800` (variant B) | u64 | `+0x168` | `+0x1c2` | `+0x1c8` | 11 | 18 |
| `0x35bd8a0` | u64 | `+0x8` | `+0xe6` | `+0xe8` | 27 | 2 |
| `0x35bddb0` | u64 | `+0x218` | `+0x272` | `+0x278` | 11 | 1 |
| `0x35be3b0` | u32 | `+0xb8` | `+0xe6` | `+0xe8` | 11 | 2 |
| `0x35be560` | u64 | `+0x2c8` | `+0x322` | `+0x328` | 11 | 50 |
| `0x35bf3c0` | u64 | `+0x8` | `+0x13e` | `+0x140` | 38 | 2 |
| `0x35bf460` (sibling) | u64 | `+0x798` | `+0x7f2` | `+0x7f8` | 11 | 99 |
| `0x35bf500` | u32 | `+0x2c8` | `+0x2f6` | `+0x2f8` | 11 | 6 |
| `0x1d65b20` | u64 | `+0x8` | `+0x37a` | `+0x380` | 110 | 2 |
| `0x4d380a0` | u64 | `+0x8` | `+0x37a` | `+0x380` | 110 | 2 |

Two members (`0x35bd8a0`, `0x35bf3c0`) leave four spare bytes between
the last key slot and the child-index word; the offsets are reported as
read, not rounded to a capacity. The two u32 members keep the family's
scale-8 child edges; only their key array is dword-packed, with a
three-way compare built from `setl`/`setg` instead of `seta`/`sbb`.

## Consumption verdict

- **Flag:** tested at twenty-three of the twenty-six sites, as a dword
  against 1 (variant A callers and most variant B callers) or as a byte
  against 0 (the flag-only callers and the existence scan). The
  remaining three sites' records are overwritten by the sibling search
  before any field is read.
- **Node and position:** read at eighteen sites. Variant A callers
  form `node + position * 8 + 0x60` and load the qword stored there —
  the same slot arithmetic the cursor-search packet pinned. Variant B
  callers form `node + position * 32` and index 32-byte elements.
- **Height:** never read in ten callers (`0x23795c0`, `0x2667140`,
  `0x2a89500`, `0x2c4fe30`, `0x2c61b30`, `0x55a07e0`, `0x55a12e0`,
  `0x55bd810`, `0x55be0d0`, `0x5b810d0`) — in the 2816-byte callers not
  one instruction in the whole FDE names the height slot, even though
  their joins read the sibling's flag, node and position from the same
  record address. Copied wholesale, without interpretation, by vector
  record copies in `0x2c6b3b0`, `0x55f8b70` and `0x55f9290`. Read only
  in other phases — whose records are filled by other calls reusing
  the slot (`0x22b2450` in `0x2a84e60`, `0x5ac9df0` in `0x5582180`; both
  phases retained as windows) — in `0x2a84e60`, `0x5582180` and
  `0x5585290`. Loaded as a value from the variant's own record in
  exactly two callers: `0x3d987f0`, whose follow-on phase copies the
  node to a working slot and loads the height into `rbp`
  (`0x3d989b0`), and `0x2a918f0`, which copies flag, node and height
  into another struct after its scan loop (`0x2a92201`).

## Negative results

- No tail call (`jmp rel32`) anywhere in `.text` targets either
  variant, and neither variant appears as an `R_X86_64_RELATIVE`
  relocation addend — the twenty-six direct calls are the only static
  entries.
- Neither variant body contains a call, and neither stores anywhere
  except the four record fields.
- No caller FDE calls both variants, and no variant call site exists
  outside the eighteen caller FDEs.
- The epilogue scan finds no fourteenth standalone family body and no
  second inlined instance.

## Boundaries

- Caller internals beyond the retained windows are not traced; the
  slot census is a whole-FDE textual census of the record's four
  slots, but a slot reused by an unrelated phase with a different
  meaning would be indistinguishable except where a window attributes
  the phase, as done for the two retained other-phase windows and the
  two height loads.
- The other family members' callers are not traced — only their
  direct call-site counts are censused — and the inlined instance's
  key and count offsets are not pinned.
- Node allocation sizes are not established by the search bodies; the
  capacities are layout maxima from the count/edge geometry, and the
  child-index offsets follow the family layout pair without being
  read by any search body.
- What caller `0x3d987f0` does with the height value after loading it
  into `rbp`, and whether the vector record copies carry the variant's
  record or a later writer's, are not pinned.

## Next question

The sibling search `0x35bf460` — keys at node `+0x798`, eleven per
node — has ninety-nine direct call sites, more than the clones and
both variants combined, and it is the search whose records overwrite
the variant records at the 2816-byte callers' joins. Which set
instances does it serve, and who consumes its records at those joins
and at its other sites?

## Reproduction

Materialise the authenticated node #115 artifact at
`artifacts/node/115/hl-node`, then:

```
python3 tools/variant_cursor_static.py --generate   # regenerate this packet
python3 tools/variant_cursor_static.py --check      # re-derive and compare
python3 -m unittest tests.test_variant_cursor_static
```

The test suite additionally flips single bytes — a variant count
displacement, an uncited byte in each kind of pinned body, a family
signature displacement, the inlined epilogue byte — and requires the
matching check to fail for each.
