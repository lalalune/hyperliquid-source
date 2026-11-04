# RE-001: the node #115 lu descriptor builder — thunk, constants, flat sub-blocks, header

## Question

Packet #228's next question: what descriptor `0x63da080` builds on
the caller's stack — where the 29 entries, the `+0x40` word, and the
sub-block fields come from — since that decides what packet #228's
inputs actually describe.

## Answer

`0x63da080` is a 9-byte thunk FDE (`endbr64`; `jmp 0x63d9ba0`).
The body is FDE `0x63d9ba0..0x63d9ed3` (819 bytes, single `ret`
site `0x63d9ed2`, zero `call` instructions). It takes one argument,
`rdi` = the descriptor base — the caller (FDE `0x634ece0..0x634f09d`)
zeroes `0x19b0` bytes at `rsp+0xf0` and passes that address — and
returns nothing its callers use. It writes the whole descriptor:
a header at `+0x00..+0x4f` and 232 sub-blocks at `+0x50`, stride
`0x1c` (`+0x50..+0x19af`), exactly the grid packet #228's table-fill
helper reads.

The one structural subtlety: the builder's records are written at
`+0x4c + n * 0x1c` (n = sub-block index), four bytes before the
reader's grid at `+0x50 + n * 0x1c`. Each record's first dword
therefore lands in the previous sub-block's `+0x18` tail (and equals
the next index), while the reader's `shift2`/`shift1`/`value`/`flag`
fields come from the record's bytes `+0x04..+0x10`. The 29-entry
grouping is the reader's view, not the writer's loop structure:
the builder writes one flat sequence of 232 sub-blocks.

## Sub-blocks 0..4: constants and the first loop

All four constants are `.rodata` file values: `[0x4595a0]` =
`0x100000003`, `[0x451510]` = dwords `[1, 3, 1, 3]`, `[0x452980]` =
dwords `[0, 3, 3, 0]`, `[0x96dc38]` u16 = `0x0100`. The entry stores
and the first loop (`r10 = 2, 3, 4`) produce:

| sub-block | shift2 | shift1 | value | flag | expanded |
|---|---|---|---|---|---|
| 0 | 3 | 3 | 0 | 0 | 8 |
| 1 | 3 | 3 | 1 | 0 | 16 |
| 2 | 4 | 4 | 1 | 0 | 32 |
| 3 | 4 | 4 | 2 | 0 | 48 |
| 4 | 4 | 4 | 3 | 0 | 64 |

Expanded value = `(value << shift1) + (1 << shift2)`, packet #228's
formula. The flag byte is the low byte of `0x0100`, i.e. `0`, so
all five are excluded from packet #228's filtered table `T` by
loop 1, while remaining present in the unfiltered array and the
byte table. Their unread tails: `+0x0d = 1`, `+0x10 = 1, 1, 1, 3, 1`
(the first loop's lcm page counts), `+0x14 = 3, 3, 4, 4, 4`,
`+0x18` tail = next index (`1, 2, 3, 4, 5`).

## Main loop: sub-blocks 5..231

57 outer iterations, `esi = 6..62`; inner counter `r8 = 1..4`
(`1..3` when `esi == 62`); 227 sub-blocks, indices `5..231`.
Per sub-block, with `s = (r8 + 1) << (esi - 2)`:

- `shift2 = esi`, `shift1 = r8`, `value = esi - 2`,
  `flag = ((s & 0xfff) == 0)`.
- Expanded value = `((esi - 2) << r8) + (1 << esi)`.
- Unread tails: `+0x0d = 1` iff `s <= 0x3fff` else `0`;
  `+0x10 = lcm(0x1000, s) / 0x1000` iff `s <= 0x3fff` else `0`
  (computed by the repeated-division loop);
  `+0x14 = esi - 2` iff `s <= 0x1000` else `0`;
  `+0x18` tail = next index (sub-block 231's tail stays `0`,
  caller-zeroed, never written).

Worked examples: sub-block 5 (`esi = 6, r8 = 1`) =
`{shift2 6, shift1 1, value 4, flag 0}`, expanded `72`;
sub-block 33 (`esi = 13, r8 = 1`) = `{13, 1, 11, flag 1}`,
expanded `(11 << 1) + (1 << 13) = 8214`;
sub-block 231 (`esi = 62, r8 = 3`) = `{62, 3, 60, flag 1}`,
expanded `(60 << 3) + (1 << 62)`.

## Final header block

Written after the `esi == 62` outer iteration, all values derived
from the loop counters (verified by arithmetic simulation of the
branch structure, not by executing the binary):

- `+0x00 = 1` (dword).
- `+0x04 = [34, 39, 232, 8]`: 34 = last small-path index + 1
  (sub-block 33, the last with `s <= 0x1000`); 39 = 5 + 34 counted
  iterations (`s <= 0x3fff`); 232 = final sub-block count;
  8 = `bsr(232) + 1`. Note the `and` producing 224 feeds only the
  carry into the `sbb`; the stored word is the un-ANDed 232.
- `+0x14 = 198`: flag-set count among main-loop sub-blocks.
- `+0x18 = 3` (dword).
- `+0x20 = 0x1000`: the last small-path slot (sub-block 33's
  `s = 4096` has zero low 12 bits, so the `0x1000` stand-in is
  stored instead of `s` itself).
- `+0x28 = 12288`: last counted `s` (`esi = 14, r8 = 2`).
- `+0x30 = 15`: next-`esi` of the last counted iteration.
- `+0x38 = 32768` (`1 << 15`).
- `+0x40 = 2^62`: the final `s` (`esi = 62, r8 = 3`: `4 << 60`).
  This is packet #228's tail-entry base: the guarded tail entry
  is `2^62 + 0x1000`.
- `+0x48 = 1` (byte).
- `+0x1c..+0x1f`, `+0x34..+0x37`, `+0x44..+0x47`, `+0x49..+0x4b`
  stay `0` (caller-zeroed, never written); `+0x4c..+0x4f = 0`
  (first dword of the `[0x452980]` constant).

## Consequence for #228

198 of the 232 sub-blocks are flag-set, but packet #228's loop 1
takes only the first 7 per entry: 172 flagged sub-blocks are
eligible, 26 flagged 8th-per-entry sub-blocks (indices
`31, 39, …, 231`) are skipped by loop 1. Since `172 <= 199`, the
tail entry is appended, so the filtered table `T` holds
`172 + 1 = 173` entries, ending with `2^62 + 0x1000`.

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Thunk `0x63da080`: 1 direct E8, 0 E9, 0 LEA,
0 GOT. E8: `0x634ed44` (FDE `0x634ece0..0x634f09d`, the
table-fill caller). Body `0x63d9ba0`: 1 direct E8, 1 E9, 0 LEA,
0 GOT. E8: `0x634c2a5` (FDE `0x6349be0..0x634eb7c`, passing
`[rsp+0x30]` as the descriptor); E9: `0x63da084` (the thunk
jump). The second caller's purpose beyond its argument setup is
cited by address only, not decoded here.

## Corrections to earlier packets

- **#228 confirmed.** The descriptor layout (29 entries at
  `+0x50`, stride `0xe0`; sub-blocks stride `0x1c`; fields
  `+0x00` shift2, `+0x04` shift1, `+0x08` value, `+0x0c` flag
  byte) matches exactly, and the `+0x40` word is the final loop
  `s = 2^62`, not an independent input.
- **#228 refined.** The "builder" is a thunk plus an 819-byte
  body, not one FDE; its records sit 4 bytes before the reader's
  sub-block grid; sub-blocks 0..4 are all flag `0`, so the
  filtered table starts at sub-block 5's successors, not at
  index 0; the filtered table holds 173 entries (172 flagged
  eligible + tail), not 199.
- **#227 confirmed.** The `.bss` base/table writer's inputs are
  fully accounted for: every sub-block field the writer reads
  is written here, and no other writer of the descriptor is
  known (the only other body caller passes a descriptor pointer
  but is not decoded here).
- No bytes claimed by packets #183–#228 are re-claimed. All
  exhibits lie strictly inside the thunk and body FDEs; the
  caller FDEs, the `.rodata` constants' neighbours, and all
  tables are cited by address only.

## Unresolved, stated not inferred

The semantic identity of the header words (`+0x00 = 1`,
`+0x04 = [34, 39, 232, 8]`, `+0x14 = 198`, `+0x18 = 3`,
`+0x20`, `+0x28`, `+0x30`, `+0x38`, `+0x48 = 1`) beyond the
counter derivations shown; the purpose of the second body
caller (FDE `0x6349be0..0x634eb7c`); the consumers of the
unread sub-block tails (`+0x0d..+0x1b`); why the builder's
records sit 4 bytes before the reader's grid; what the
`+0x40` tail value `2^62` represents in the allocator's
address space.

## Next question

Decode the FDE starting at `0x63d9340` end to end: what it does
with the size helper's return, why it derives a class index from
it, and why it clears that class's bit in a bitmap at record
`+0x400` — this is packet #227's unresolved fourth caller, and
it decides how the size-class index machinery is consumed.

## Verification

- Static verifier `tools/node115_lu_descbuild.py`: exit 0
  (5 excerpts, 429 bytes, 98 strict mnemonics, thunk census
  1 E8, body census 1 E8 + 1 E9, MANIFEST 15/15).
- Unit tests `tests/test_node115_lu_descbuild.py`: 10/10.
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
- No bytes claimed by packets #183–#228 are
  re-claimed; earlier bytes are cited by address
  only. No execution of the node binary at any
  point.
