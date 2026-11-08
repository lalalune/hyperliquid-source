# RE-001: pin node #115 the four TTL OptionTypeInfo map entries

## Task and bounded question

Task **RE-001** (the node #115 function map). Merged PR #4065
(`RE-001-register-ttl-objects-115`) pins the TTL library, the three
ctors and their RegisterOptions groups, recording the four option-map
globals (0x6509440, 0x65093c0, 0x6509400, 0x6509480) only as addresses;
merged PR #4087 pins the runtime methods and the three vtables. Neither
packet records what the maps **hold**. The bounded question: what entries
does the static initializer 0x6206ef0 insert into each of the four
maps -- keys, packs, flags, insert sites?

## What is pinned

The initializer 0x6206ef0 (FDE 0x6206ef0..0x620769f) builds four
`OptionTypeInfo` records and inserts exactly one entry into each map:

| map | key | pack (record+0xa8) | flags (record+0xb0) | insert | atexit |
|-----|-----|-------------------|---------------------|--------|--------|
| 0x6509480 | user_operator | 0x100000016 | 0x400 | 0x62070c2 | 0x62070f4 |
| 0x6509440 | ttl | 0x100000016 | 0x400 | 0x620726b | 0x62072d4 |
| 0x6509400 | user_filter_factory | 0x300000016 | 0x400 | 0x620740b | 0x620743b |
| 0x65093c0 | user_filter | 0x100000016 | 0x1200 | 0x6207575 | 0x62075be |

The pack's low 32 bits are the type (22) and its high 32 bits are the
verification: 0x100000016 = type 22 / verification 1, 0x300000016 =
type 22 / verification 3. All four entries carry type 22; only
`user_filter_factory` carries verification 3, and only `user_filter`
carries flags 0x1200 (the others 0x400).

The `ttl` entry is the odd one: its block sets no pack and no flags of
its own. The byte-scan in `census.py` finds no store to the record's
pack (-0x68(%rbp)) or flags (-0x60(%rbp)) slot between the end of the
`user_operator` block (0x62070f9) and the ttl insert (0x620726b), so the
ttl entry reuses the preceding block's pack (from GOT slot 0x458f68)
and flags 0x400. The ttl block instead stores a {ptr, size} name pair
and a 2 at aux +0xc8. The pack qwords are read directly from the
binary: GOT slot 0x458f68 holds 0x100000016, GOT slot 0x4594e8 holds
0x300000016.

A fifth map, 0x65094c0, is zeroed at the initializer entry (0x6206ef5)
and atexit-registered, but the initializer inserts nothing into it.

## What is NOT pinned here (already merged)

The three ctors (0x6202a10 / 0x6205790 / 0x6205560), their layouts and
vtables, the RegisterOptions groups (TTL, UserFilter, UserOptions,
TtlMergeOptions) and the maps' addresses, the runtime methods and the
slot-16 predicates are all pinned by merged PRs #4065 and #4087 and are
not re-claimed here. This PR pins only the maps' **contents**, which
neither packet records.

## How it was verified

- `census.py`: binary-wide lea census for the four maps and the four
  key literals, E8 callers of the insert helper 0x5d405b0 inside the
  initializer, FDEs, the pack GOT slots, and the ttl-block byte-scan
  above.
- `verify.py`: `ALL CHECKS PASSED (42)` -- artifact digest, manifest,
  excerpt regeneration, FDEs, raw-binary spot bytes, literals, lea/E8
  censuses, record packs, semantic-only records.json, and the model
  tests.
- The model `tools/ttl_option_maps_115.py` plus
  `tests/test_ttl_option_maps_115.py` (10 tests) assert the four entries
  and the ttl reuse finding.

## Open unknowns

- The OptionType enum name for type 22, and the meaning of
  verification 1 vs 3 across the four map entries.
- The ttl block's aux +0xc8 = 2 store (present only in that block) and
  the xmm callback pairs the initializer loads from GOT slots
  0x64eda98/0x64edaa0/0x64edae8/0x64edb58.
- The fifth map 0x65094c0: which code inserts entries into it, if any.
- The `ttl` literal's other lea sites 0x608a88c and 0x608da05 (both in
  0x6089b50..0x6091e5c).

## Assumptions

- The record pack sits at record+0xa8 and the flags at record+0xb0,
  calibrated against merged PR #4389's `block_size` record, which uses
  the same initializer pattern and the same GOT pack slot 0x458f68.

## Environment

- Bound to artifact `work/hl-node-115.bin`,
  sha256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (node #115, from `provenance/artifacts.json`).
- This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so
  `make verify`, `make test` and `make catalogue-check` could not be run
  in a tooled environment. The packet's own `verify.py` and the model
  tests were run instead (see above).
