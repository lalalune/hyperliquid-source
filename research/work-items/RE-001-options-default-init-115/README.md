# RE-001: node #115 options default-init 0x60b3fb0 with its small-limits preset 0x606ead0

## Bounded question

What does the options default-init `0x60b3fb0` (FDE
`0x60b3fb0..0x60b44c7`, 1303 bytes) write, what does the
small-limits preset `0x606ead0` (FDE `0x606ead0..0x606eb0c`,
60 bytes) override, and at which call sites is the pair
(init immediately followed by preset on the same object) used?

## Answer, pinned to the target

The pair initializes one options object (at least `0x2f8`
bytes) in two phases:

1. **Base init `0x60b3c30`** (751 bytes) writes the
   `+0x00..+0x1e8` fields: two packed i32 pairs at `+0x00`
   (2, 1) and `+0x88` (7, 20) from `.rodata`, `+0x20 =
   10000`, `+0x90 = 0x24`, `+0x98 = 0x4000000` (64 MiB),
   `+0xa0 = 1`, `+0xa4 = 0x100`, `+0xa8 = 10.0` (double),
   `+0xd8 = (64 GiB, 256 GiB)`, `+0xe8 = 0x300`, `+0xec`
   (two qwords), `+0xfc = 0x1ffffffff`, `+0x104 = 0`,
   `+0x108 = 0x40000000` (1 GiB), `+0x118` (16-byte
   constant), `+0x158 = 0x1000100`, `+0x160` (16-byte
   constant), `+0x198` (16-byte constant), `+0x1b0 =
   (0.25, 1.0)` (two doubles), the rest zeroes. It allocates
   a 0x1c-byte object (stored at `+0xb0`, with `+0xb8` and
   `+0xc0` pointing 0x1c into it), a 0x28-byte object
   (initialized by `0x6064440`, stored at `+0x128`), and a
   0x18-byte object (vtable `0x64d3780`, stored at `+0x130`).
2. **Main init `0x60b3fb0`** writes the `+0x1e8..+0x2f8`
   fields: `+0x1e8` is the singleton pointer returned by
   `0x61be810`, `+0x218 = 0x4000000` (64 MiB), `+0x220 =
   0xff01`, `+0x228 = 0x7ffffffffff2`, `+0x238 =
   0x100000000` (4 GiB), `+0x258 = 0x7ffffffffff2`,
   `+0x268 = 0x100000000`, `+0x280 = 1`, `+0x288 = 4`,
   `+0x2a0 = (256 MiB, 0)`, `+0x2b8` is the 0x260-byte
   table-options heap object, `+0x2c0` is a second 0x18-byte
   holder (vtable `0x64d37b8`), the rest zeroes. It builds a
   232-byte zeroed stack temp and calls the table-options
   copy `0x60db710` on it.
3. **Preset `0x606ead0`** overwrites exactly five fields:
   `+0x218` 64 MiB -> 2 MiB, `+0x98` 64 MiB -> 2 MiB,
   `+0x2a0` 256 MiB -> 10 MiB, `+0x220` low byte cleared
   (`0xff01` -> `0xff00`), `+0xd8` (64 GiB, 256 GiB) ->
   (256 MiB, 1 GiB).
4. **Table-options copy `0x60db710`** (1625 bytes) copies
   the stack temp into the 0x260-byte heap object: vtable
   `0x64d39b8`, `+0x30 = 0x01000100`, `+0x48 = 0.75`
   (double), `+0x50 = 4`, `+0x78 = 0x1000`, `+0x80 =
   0x100000000a`, `+0x88 = 1`, `+0x90 = 0x1000`, `+0x98 =
   2`, `+0xb0 = 0` (empty tree root), `+0xb8`/`+0xc0`
   self-pointers to `+0xa8`, `+0xd2`/`+0xe8`/`+0xf4`/`+0xf6
   `= 1`, `+0xf8 = 0x40000` (256 KiB), `+0x108` carries the
   `0x4506c0` constant. The temp's list head (`+0x90`) is
   null, so the list build is skipped. The copy's tail
   (`0x60dba10..0x60dbd69`) is a `map::at`-style lookup over
   the tree rooted at heap `+0xb0` (the `map::at` throw
   string is pinned at `0x4408a7`); the tree is populated by
   the `0x6099ce0` call in between, whose effect is not
   pinned here, so the lookup outcome is recorded, not
   simulated. The allocator wrapper `0x60dbd80` (59 bytes)
   allocates the 0x260 bytes and calls the copy directly;
   it has three callers of its own.
5. **Singleton `0x61be810`** (184 bytes) is a
   function-local static getter: guard acquire, allocate
   0x30 bytes on first use (vtable `0x64d7038`), return the
   pointer. It has 9 direct callers plus one tail jump from
   the 9-byte alias stub `0x61be8d0`.

## Call sites

The init has 13 direct call sites; the preset has exactly
3, each immediately following an init call on the same
object (8 bytes later: a 5-byte call plus the 3-byte
object-register move):

- `0x5e5a8c0` (init `0x5e5a9a1`, preset `0x5e5a9a9`):
  options on the stack at `rsp+0x20`; after the pair, a
  virtual slot `0x20` call, the acquire `0x606ca40`, then
  `0x5d35770` on the options.
- `0x5e61ad0` (init `0x5e61cd3`, preset `0x5e61cdb`):
  the column-family open routine (db_impl_open.cc:744);
  options in `r15`; after the pair, a virtual slot `0x20`
  call and `0x5d35770`. This is the same caller whose
  version-key fetches PR #3251 mapped.
- `0x5fa47e0` (init `0x5fa4a97`, preset `0x5fa4a9f`):
  options on the stack at `rsp+0x40`; the pair runs only on
  the exact-match path (memcmp name match with remainder
  0); after the pair, `0x5fa3330` then `0x5d35770`. Caller C
  is installed in two vtables (RELATIVE `0x64cd0b0`,
  `0x64cd110`).

The other 10 init sites use the default init without the
preset. Callers A and B are both called from the same
driver function `0x5e62c50..0x5e65462`.

## Verification

`verify.py` checks the work binary digest against the
provenance entry, the manifest, excerpt regeneration
byte-for-byte from fresh objdump runs, every excerpt
instruction byte-for-byte against the raw binary, spot
instructions, the FDE ranges in `frames.txt` against a
fresh frame dump, the relocation set (caller C's two
RELATIVE records; every other pinned routine appears in
none), the literals, census consistency (`callers.tsv`
against a fresh census run), the semantic records
(re-deriving the base/main/preset field tables from the
excerpts, including the pair-site adjacency), and the model
tests in `tests/test_options_default_init_115.py` (74
checks, all passing).

## Not claimed

- The RocksDB field names for the options offsets.
- The concrete dynamic type behind the singleton
  `0x61be810` (guard + 0x30-byte allocation, vtable
  `0x64d7038`).
- The 0x28-byte heap object init `0x6064440` and the
  0x18-byte holder objects beyond their size, vtable and
  pointer wiring.
- The table_init tail lookup outcome (see above).
- Bytes of the options object outside `+0x00..+0x2f8`.
- Which of the 10 init-only sites later apply a different
  preset.

The mnemonics in the excerpts (`endbr64` included) are genuine
instructions present in the target binary, not placeholders.

## Model

`tools/options_default_init_115.py` simulates the base init,
the main init, the preset, the stack temp and the
table-options copy prefix; `tests/test_options_default_init_115.py`
runs 74 checks against the pinned values.
