# RE-001: the node #115 lu table-fill helper — base, table, class bytes

## Question

Packet #227's next question: what the FDE starting at `0x63e8d90`
writes to the `.bss` base at `0x6728140` and how it fills the table
at `0x6728180` — this decides what the base and the per-class values
in packet #227 actually are.

## Answer

`0x63e8d90(record, byte)` = (rdi, rsi low byte) is the single
initialiser for three `.bss` structures used by the size-class
machinery. It takes a 29-entry descriptor on its first argument and
a byte on its second, makes no calls, has one `ret` site
(`0x63e913c`), and returns nothing its caller uses. It runs three
passes over the descriptor:

1. **Base.** `[0x6728140] := byte << 12` — the base `B` of #227's
   size helpers is the argument byte times one page.
2. **Filtered table `T` at `0x6728180`.** Loop 1 walks the 29
   entries (record `+0x50`, stride `0xe0`, end record `+0x19b0`)
   and appends, for each of the first 7 sub-blocks per entry whose
   flag byte is nonzero, the expanded value
   `(value << shift1) + (1 << shift2)`. If the appended count is
   at most 199, one final entry `T[count] = [record+0x40] + 0x1000`
   is appended. The 8th sub-block per entry (`+0xc4`) is not
   processed by this loop.
3. **Unfiltered array at `0x6727a00`.** Loop 2 expands all 8
   sub-blocks of all 29 entries with the same formula and stores
   the 232 values consecutively (`0x740` bytes), ending exactly at
   `B`'s address.
4. **Class-byte table at `0x67277c0`.** Loop 3 walks all 232
   sub-blocks in order and, for each, computes
   `end = min(512, ceil(expanded / 8))`; if `end` is below the
   current fill position it contributes nothing, otherwise it
   fills table bytes `[pos..end]` with its own sub-block index
   and advances `pos` to `end + 1`. The walk stops after
   sub-block 231 or when the position passes 512.

## Descriptor layout

Each entry is `0xe0` bytes; each sub-block is `0x1c` bytes:

- `+0x00`: shift2 (u32) — the `1 << shift2` term.
- `+0x04`: shift1 (u32) — the value shift.
- `+0x08`: value (i32, sign-extended).
- `+0x0c`: flag byte — loop 1 includes the sub-block only if
  nonzero.
- `+0x0d..+0x1b`: never read by any of the three loops
  (identity unresolved).

Expanded value of a sub-block: `(value << shift1) + (1 << shift2)`.

## The three outputs, and how they differ

- `T` (`0x6728180`) is the flag-filtered table #227's size
  helpers read: its positions are filtered order, not sub-block
  order, and its count is data-dependent (at most 203 appended
  values from loop 1, plus the guarded tail entry).
- The `0x6727a00` array is the unfiltered expansion in raw
  sub-block order (232 values). Its consumer is not identified
  here.
- The `0x67277c0` byte table maps size buckets to sub-block
  indices: table byte `i` is the index of the first sub-block
  whose `ceil(expanded / 8)` reaches `i`. Its values are raw
  sub-block positions (0..231), distinct from `T` positions —
  how a sub-block index becomes a class index is not shown here.

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Writer `0x63e8d90`: 1 direct E8, 0 E9, 0 LEA,
0 GOT. E8: `0x634edce` (FDE `0x634ece0..0x634f09d`), which passes
a stack descriptor (0x19b0 bytes at `rsp+0xf0`, zeroed then filled
by `0x63da080`) and a byte loaded from `.data` (`0x64ffb5c`),
and ignores the return value. The caller's purpose beyond that
setup is cited by address only, not decoded here.

## Corrections to earlier packets

- **#227 confirmed and resolved.** The writer FDE is
  `0x63e8d90..0x63e9152`, it shares base `0x6728140` and table
  `0x6728180` with the size helpers, and it fills `T` exactly as
  loop 1 above describes: base is the caller byte shifted left
  12, table values are the expanded sub-block values, and the
  tail entry is `[record+0x40] + 0x1000` when the count allows.
- **#216 / #218 refined.** The `.bss` size-class byte table at
  `0x67277c0` is filled by this function (loop 3), not by an
  unknown writer: its bytes are sub-block indices keyed by
  `ceil(expanded / 8)` buckets, filled monotonically.
- **#226 confirmed.** The finder's table check reads the same
  `T` at `0x6728180` this function fills.
- No bytes claimed by packets #183–#227 are re-claimed. All
  exhibits lie strictly inside the writer FDE; the descriptor
  builder, the caller FDE, and all tables are cited by address
  only.

## Unresolved, stated not inferred

The 15 unread bytes per sub-block (`+0x0d..+0x1b`); why loop 1
skips the 8th sub-block per entry while loops 2 and 3 process all
8; the consumer of the `0x6727a00` unfiltered array; the identity
of `[record+0x40]` (the tail entry's base); the meaning of the
caller's byte at `0x64ffb5c`; what builds the descriptor
(`0x63da080`, cited by address only); the contents of the
`0x67277c0` table beyond the final fill position; how a
sub-block index from that table becomes a class index.

## Next question

Decode `0x63da080` end to end: what descriptor it builds on the
caller's stack — where the 29 entries, the `+0x40` word, and the
sub-block fields come from — since that decides what this
packet's inputs actually describe.

## Verification

- Static verifier `tools/node115_lu_tablefill.py`: exit 0
  (5 excerpts, 192 bytes, 50 strict mnemonics, census
  1 E8 site, MANIFEST 15/15).
- Unit tests `tests/test_node115_lu_tablefill.py`: 10/10.
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
- No bytes claimed by packets #183–#227 are
  re-claimed; earlier bytes are cited by address
  only. No execution of the node binary at any
  point.
