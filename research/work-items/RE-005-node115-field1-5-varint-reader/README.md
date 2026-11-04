# RE-005 node115 field1-5 varint reader

Status: static evidence packet for one bounded RE-005 question. The
companion verifier is `tools/field1_5_varint_reader_static.py`;
retained exports sit beside this file and are hash-bound by
`MANIFEST.sha256`.

## Question

How does the pinned node #115 binary's bincode-fork scalar varint
reader family whose error results carry **field1 5** behave: what
does it charge, which payload markers does it accept or reject,
what does it consume on each outcome, and what does its short-input
path report?

## Result

One logical reader, present as two codegen copies with identical
relative layout and semantics — `0x2cd7bb0..0x2cd7c95` and
`0x5821340..0x5821425` (229 bytes each) — sharing one slow-path
reader `0x5822710..0x582284c` (316 bytes), reached only through GOT
slot `0x64e7f80`, and the shared raw error constructor `0x5822700`
(a boundary, see below). The u32 packet (#2412) identified this
family by its constructor field1 and excluded it; this packet
traces it.

Reader state: mode dword at `+0x0`, limit at `+0x8`, cursor at
`+0x10`, remaining at `+0x18`, charged count at `+0x20`. Result:
rawtag byte at `+0x0`, u64 value at `+0x8` on success (rawtag
`0x12`), additional-needed u64 at `+0x8` on slow shortfall (rawtag
`0x00` — the value and the additional count share offset `+0x8`
and are distinguished by the rawtag), error fields at `+0x1/+0x2`
via the constructor (rawtag `0x03`).

- **Charge (mode 1 only):** the reader adds **8** to the charged
  count and stores the new count *before* comparing it with the
  limit. Overflow past `u64::MAX - 8` returns rawtag 2 with the
  count unchanged; exceeding the limit returns rawtag 2 with the
  +8 retained and no input consumed. Every other mode value takes
  the uncharged route in these bytes.
- **Fast route** requires `remaining > 8`; at or below that it
  delegates to the slow reader with the `(cursor, remaining)` pair
  and a little-endian flag of 0.
- **Fast markers:** `0..250` are the value (consume 1); `251`
  reads a u16 LE payload (consume 3); `252` reads a u32 LE payload
  (consume 5); `253` reads a u64 LE payload (consume 9); **`254`
  is an error** (field1 5, field2 4, consume 0); `255` errors with
  field2 12. No minimality check exists: non-minimal `251`/`252`/
  `253` encodings of small values are accepted.
- **Slow path:** an empty input returns rawtag 0 with additional
  1 and consumes nothing. Otherwise the marker is consumed *before*
  classification; a short `251` reports additional `3 - total`, a
  short `252` reports `5 - total`, a short `253` reports
  `9 - total`, each consuming only the marker; marker errors
  (`254`/`255`) consume the marker, unlike the fast route, and
  also carry field1 5. Payload loads honour the endianness flag
  (rol/bswap selects); both copies pass 0.

## Trace

1. Authenticated the pinned distribution by size and SHA-256 and
   re-derived all three owner extents from `.eh_frame` FDE records
   (CIE `0xca6ed8` for all three); body hashes are in
   `records.json` and the native readelf lines in `frames.txt`.
2. Read the mode/charge prologue bytes: mode `== 1` test, charge
   increment 8, store-before-compare, rawtag 2 refusal arms.
3. Read the fast marker dispatch: boundary compare 251, relative
   dispatch tables (`0x60be9c` / `0x935bec`), and validated every
   table target as an instruction start inside the retained
   objdump exports (`decode_export`).
4. Read the slow delegation (slot `0x64e7f80`, endianness 0) and
   the slow reader itself: consume-before-classify stores, total
   widths 3/5/9, shortfall arithmetic, endianness selects, error
   arms through slot `0x64e7f78`.
5. Resolved `.rela.dyn`: slot `0x64e7f80` → the slow reader,
   `0x64e7f78` → the raw constructor `0x5822700` (14 bytes: writes
   rawtag 3, field1 from `esi`, field2 from `edx`), and a second
   constructor slot `0x64e7f88` → the same constructor, used by
   copy A only. The copies share the slow slot but reach the
   constructor through different slots.
6. Censused the full `.text`: 3 direct call sites for each copy
   (in 2 FDEs each; per-FDE multiplicity at most 2, so no caller
   calls either copy four times), **zero** direct call sites for
   the slow reader, and exactly two rip-relative references to
   its slot — the two copies' slow calls.

## Boundaries

- The raw error constructor `0x5822700` is a component of the
  open u64-reader packet (#2300); it is recorded here only as the
  called boundary that writes the error result layout.
- The u64 scalar reader family (copies `0x2cd7ac0`/`0x5821250`,
  slow reader `0x58225c0` via slot `0x64e6c38`, 4× aggregate
  callers `0x2cd7d90`/`0x5821540`) is #2300's scope. Charge (8),
  fast threshold (`remaining > 8`) and the payload ladder
  (251/252/253 consuming 3/5/9; slow widths 3/5/9) **agree** with
  this family; the families are separated by the error results on
  identical inputs — markers `254`/`255` return field1 **2** on
  #2300's fast route and field1 **3** on its slow route, against
  field1 **5** on both routes here — and by the disjoint
  slow-reader wiring. Neither family's behaviour record covers
  the other's error bytes.
- The u32 scalar reader family (copies `0x2cd79c0`/`0x5821150`,
  slow reader `0x5822490`) is our open PR #2412. It disagrees on
  the same inputs: charge 4 against 8, threshold `remaining > 4`
  against `> 8`, marker `253` is an error (field1 2, field2 3)
  there and a u64 payload read here, its value is a dword at
  result `+0x4` against a qword at `+0x8` here, its slow widths
  are 3/5 against 3/5/9 here, and its error field1 is 2 on both
  routes against 5 here.
- The encode-side varint size functions are open PR #2257; the
  `rmp_signable` `.rodata` window is open PR #2311. Neither
  records this reader.
- No Rust reconstruction is included or claimed. Rawtag and
  error-field values are reported as raw bytes; which Rust enum
  variants they name is not established from these bytes.

## Files

- `records.json` — authenticated owners, frame records, charge
  and route facts, fast marker classes, the 77-row slow grid,
  call-site census, relocations, boundaries and limits.
- `copy_a.objdump.txt`, `copy_b.objdump.txt`,
  `slow_path.objdump.txt` — retained disassembly of the owners.
- `frames.txt` — native readelf FDE lines for the owners.
- `../../tools/field1_5_varint_reader_static.py` — regenerator
  and verifier; `../../tests/test_field1_5_varint_reader_static.py`
  — regeneration, table and counterfactual tests.

## Next question

Which per-type decode wrappers (the 6 direct callers) pass which
mode and limit values into this reader — and does any caller pair
it with the u64 reader of #2300 on the same buffer, which would
make the field1 difference observable as two different error
results for one input?
