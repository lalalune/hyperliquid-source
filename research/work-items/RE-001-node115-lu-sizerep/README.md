# RE-001: the node #115 lu size representative helper — input, table, next class

## Question

Packet #226's next question: what representative value does the size
helper `0x63e8c80` return for its input, and how does it use the
`.bss` table at `0x6728180`? This decides what the class index and
the table check in packet #226 actually measure.

## Answer

`0x63e8c80(x)` takes one argument and is a pure function of that
argument, the `.bss` base `B = [0x6728140]`, and the `.bss` table
`T` at `0x6728180`. It makes no calls, performs no stores, and has
two `ret` sites (`0x63e8d4a`, `0x63e8d5f`). It returns either its
input unchanged, or `B + T[j]` for a class index `j` derived from
the table itself:

- Round 1: `d = x - B`. The `bsr` index idiom (same shape as #224's
  release index, #216's allocator index, #218's remainder index and
  #226's finder index) computes `i` from `d`: `edi =
  max(ceil_log2(d + 1), 14)`, `shift = 12` when `edi == 14` else
  `edi - 3`, `i = (edi - 14) * 4 + ((d >> shift) & 3) - 1`.
  The huge corner (`d + 1 > 0x7000000000000000`) hardcodes `i =
  198` (`0xc6`); the small corner (`d < 0x1000`) returns `x` at
  once without consulting the table.
- Cover check: candidate `C = B + T[i]`. If `C >= x`, return `x`.
- Round 2 (only when `C < x`): `j` is computed from `T[i]` with
  the same idiom but **without** the `-1` adjustment (`shift = 12`
  when the clamped value is 14, huge `T[i] + 1` hardcodes `j = 199`
  (`0xc7`)). Return `B + T[j]` unconditionally.

So the returned representative is either the input itself (when the
class-below representative already covers it) or the next class's
table value. The table contents are runtime-filled (`.bss`), so the
file proves the selection logic, not the numeric values: no table
entry is quoted here, because none can be read from the file.

## Relation to the sibling helper

`0x63e8bf0` (#224's size helper) shares the same base `B` and the
same table `T`, and performs exactly round 1's computation: it
returns `B + T[i]` unconditionally, with the same huge corner
(`i = 198`) and the same small-corner shape. In terms of that
sibling `S`:

- `0x63e8c80(x) = x` when `S(x) >= x`,
- otherwise `0x63e8c80(x) = B + T[class(S(x) - B + 1)]`, where
  `class` is the #226 index idiom (round 2's formula).

The two helpers are distinct functions, not two entry points of one
function: separate FDEs (`0x63e8bf0..0x63e8c77` vs
`0x63e8c80..0x63e8d87`), separate `ret` sites, and this helper's
cover check plus second round have no counterpart in the sibling.

## What this means for #226

The finder (#226) calls this helper on its threshold values
(`A + L - 0x1000` and `L`) and then computes its class index from
the return. That class index therefore measures the class of the
snapped value: the input's own class when the input already sits
at or below its class-below representative, otherwise the class of
the next table representative. The finder's table check
(`table[c] >> shift` against the threshold) compares the same
table's per-class values, which increase with class — so the
table is a per-class size scale, and the index is a position on
that scale, not a raw size.

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Helper `0x63e8c80`: 4 direct E8, 0 E9, 0 LEA,
0 GOT. E8: `0x63b09cb`, `0x63b0f62`, `0x63b0fbc` (all in #226's
finder FDE `0x63b0980..0x63b15e9`), `0x63d934b` (FDE starting
`0x63d9340`, which passes its second argument through to the
helper, then derives a class index from the return and clears
that class's bit in a bitmap at record `+0x400`).

## Corrections to earlier packets

- **#226 confirmed.** The three finder call sites (`0x63b09cb`,
  `0x63b0f62`, `0x63b0fbc`) are exactly this function's calls,
  and the `.bss` table at `0x6728180` is the table used here.
- **#226 refined.** The finder's class index is not the class of
  its raw threshold: it is the class of this helper's return,
  which may be the next table representative when the raw
  threshold exceeds its class-below representative.
- **#224 confirmed.** The sibling `0x63e8bf0` shares base
  `0x6728140` and table `0x6728180` with this helper; the two
  are distinct functions with different return contracts (the
  sibling always returns a table value, this helper may return
  its input unchanged).
- No bytes claimed by packets #183–#226 are re-claimed. All
  exhibits lie strictly inside the `0x63e8c80` FDE; the sibling,
  the table writer, and all caller FDEs are cited by address
  only.

## Unresolved, stated not inferred

The numeric contents of table `T` (runtime-filled `.bss`, not in
the file) and hence the actual representative for any given input;
what the base `B = [0x6728140]` is set from (the writer FDE at
`0x63e8d90` is cited by address only); the purpose of the fourth
caller FDE (starting `0x63d9340`) beyond its argument setup,
class-index computation, and bitmap-bit clear; whether the table
values are class maxima, class minima, or canonical sizes — the
cover check only proves they are compared against the input as
upper bounds in round 1.

## Next question

Decode the FDE starting at `0x63e8d90` end to end: what it writes
to the `.bss` base at `0x6728140` and how it fills the table at
`0x6728180` — this decides what the base and the per-class values
in this packet actually are.

## Verification

- Static verifier `tools/node115_lu_sizerep.py`: exit 0
  (5 excerpts, 180 bytes, 47 strict mnemonics, census
  4 E8 sites, MANIFEST 15/15).
- Unit tests `tests/test_node115_lu_sizerep.py`: 10/10.
- `make verify`: exit 0 (29 manifests, 471 entries).
- `make catalogue-check`: exit 0.
- `make test`: 77 files attempted, 1 failed — the single
  failure is the pre-existing test_node115_catalogue Errno 18
  cross-device-link error, identical on pristine checkouts,
  not a packet regression; this packet's file [36/77]
  passes 10/10.
- Target: node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis).
- No bytes claimed by packets #183–#226 are
  re-claimed; earlier bytes are cited by address
  only. No execution of the node binary at any
  point.
