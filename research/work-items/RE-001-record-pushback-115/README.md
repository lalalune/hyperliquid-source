# RE-001: node #115 record-vector push-back 0x6099ce0

Task: RE-001. Bounded question: how does the table-options copy
(and the other factory constructors) populate the record vector
at owner+0x08 — what exactly does one append cost, when does it
grow, and what records do the three pinned call sites append?

Target: node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`work/hl-node-115.bin`, verified against
`provenance/artifacts.json`). All addresses below are node #115
virtual addresses; all excerpts are whole-function verbatim
objdump output. The mnemonics in the excerpts (`endbr64`
included) are genuine instructions present in the target binary,
not placeholders.

## What this pins (complete behaviour, not a fragment)

1. **The push-back helper `0x6099ce0`** (340 bytes,
   `0x6099ce0..0x6099e34`): appends exactly one 0x30-byte record
   `{key: std::string, a: u64, b: u64}` to the record vector at
   `owner+0x08` (`{begin +0x08, end +0x10, cap +0x18}`).
   It first builds the record value on the stack — the key is a
   copy of the caller's string (SSO-initialised empty, then
   `basic_string::_M_assign` from the `rsi` argument), the two
   u64 fields are the incoming `rdx`/`rcx`. When spare capacity
   exists it copies the record into the slot at `end` (SSO key
   copied inline, heap key copied via `_M_create` + `memcpy`,
   the two u64 fields by one `movdqa`), advances `end` by
   0x30, destroys the temporary string and returns. When
   `end == cap` it calls the growth path `0x6099790` with
   `(vector = owner+0x08, position = end, value = &stack record)`
   and returns.
2. **The growth path `0x6099790`** (1309 bytes,
   `0x6099790..0x6099cad`): `std::vector<Record>::_M_realloc_insert`.
   New capacity is 1 element for an empty vector, else
   `min(2 * size, MAX_SIZE)` with
   `MAX_SIZE = 0x2aaaaaaaaaaaaaa = 192153584101141162`
   (`(2**63 - 1) // 48`); the new buffer holds
   `new_capacity * 48` bytes. When `size == MAX_SIZE` it throws
   `length_error` with the literal `vector::_M_realloc_insert`
   (pinned at `0x43d55a`). It allocates the new buffer, constructs
   the new record at the new position (same string-copy branches
   as the fast path), moves the records before the position and
   then the records after it by string-move (a heap-backed key is
   stolen and the source is left an empty SSO string; an SSO key
   is copied byte for byte; the two u64 fields move with the
   record), frees the old buffer with its old byte size, and
   publishes the new triple (begin, new end, begin + new bytes).
   The landing pads dispose a half-built new record, free a
   half-built buffer and rethrow.
3. **Three registration call sites**, each a factory constructor
   that zeroes the vector triple, stores a vtable at owner+0x00,
   and appends exactly one record:
   - `table_init 0x60db710` (re-shipped byte-identical from PR
     #3254, SHA-256 `d496a0e3…`): key `"BlockTableOptions"`
     (17 chars, heap), `a = table_options+0x20`, `b = 0x6507540`
     (a `.bss` object address).
   - `0x6064440` (273 bytes): builds the key
     `"SkipListFactoryOptions"` (22 chars, heap) from a 16-byte
     literal chunk `"SkipListFactoryO"` (`0x452f70`) plus an
     8-byte `movabs` chunk `"yOptions"` stored at buffer+14,
     overwriting the first chunk's tail; `a = owner+0x20`,
     `b = 0x6505c40` (`.bss`). The object also stores its
     incoming `rsi` at `+0x20` and vtable `0x64d27b0` at `+0x00`.
   - `0x5fd0090` (232 bytes): appends the empty key `""`
     (SSO), `a = owner+0x20`, `b = 0x6504b80` (`.bss`). The
     object stores vtable `0x64cdd88` at `+0x00` and a
     shared-pointer copy at `+0x20/+0x28` (two qwords copied
     from the `rsi` argument; when the second qword is non-null
     its control block's refcount at `+0x08` is atomically
     incremented).

## Correction to PR #3254

PR #3254's README says the table-copy tail's tree "is populated
by the `0x6099ce0` call". That is not what the call does: the
call appends one record to the **vector at table-options+0x08**,
not to the tree rooted at heap `+0xb0`. The tail
(`0x60dba10..0x60dbd69`, a bound search for integer key 8 over
the tree, throwing `map::at` when the key is absent) reads a
different structure, and this packet does not claim to pin the
tree's population. The record the call appends is
`{"BlockTableOptions", table_options+0x20, 0x6507540}`.

## Census (one streamed objdump pass; see census.py)

- `0x6099ce0`: 37 direct calls, 0 tail jumps, no stored qwords,
  no RELATIVE records. The 37 call sites are the factory
  constructors that register one record each.
- `0x6099790`: 1 direct call (from the push-back helper at
  `0x6099e0a`), 0 tail jumps, no stored qwords, no RELATIVE
  records.
- `0x6064440`: 5 direct calls (`0x5d94ce8`, `0x5f10517`, `0x60b3dd2`
  — inside the base init `0x60b3c30` — `0x6193685`, `0x619371a`),
  0 tail jumps.
- `0x5fd0090`: 1 direct call (`0x60293b6`), 0 tail jumps.
- `0x60db710` (table_init): 3 direct calls, 0 tail jumps.
- The six direct callees (`_M_assign` 442 calls + 2 tail jumps,
  `_M_create` 1069, `memcpy` 1530 + 1, operator `delete`
  11706 + 898, operator `new` 1935, `_M_dispose` 5778 + 2) are
  counted in `callers.tsv` as well. No pinned routine is
  installed by a RELATIVE relocation (`relocations.txt` is
  empty).

## Model and tests

`tools/record_pushback_115.py` models the record, the vector
triple with its capacity, the fast/growth push-back, the growth
capacity rule, the SSO/heap key split and the three call-site
records. `tests/test_record_pushback_115.py` runs 47 checks
directly (pytest is not installed on this VM).

## Unknowns (not claimed)

- What populates the tree rooted at heap `+0xb0` that the
  table-copy tail searches, and what the integer key 8 selects.
- The contents of the `.bss` tag objects at `0x6507540`,
  `0x6505c40`, `0x6504b80` (file-unbacked; only their addresses
  are pinned).
- The keys and fields of the other 34 push-back call sites:
  they are listed with their enclosing functions in
  `callers.tsv` but were not individually analysed.
- The source-level class names behind the three constructors
  (only the vtable addresses `0x64d27b0`, `0x64cdd88` and the
  table-options layout from #3254 are pinned).

## How to check this packet

    python3 research/work-items/RE-001-record-pushback-115/verify.py

It prints ALL CHECKS PASSED on success: binary digest,
provenance entry, manifest, excerpt regeneration byte-for-byte,
every excerpt instruction byte-for-byte against the raw binary,
spot instructions, FDE ranges, the (empty) relocation set, the
literals, census consistency, semantic-record re-derivation
from the excerpts, and the model tests.
