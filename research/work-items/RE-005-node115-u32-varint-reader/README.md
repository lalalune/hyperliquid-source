# RE-005 node115 u32 varint reader

Status: static evidence packet for one bounded RE-005 question. The
companion verifier is `tools/u32_varint_reader_static.py`; retained
exports sit beside this file and are hash-bound by `MANIFEST.sha256`.

## Question

How does the pinned node #115 binary's bincode-fork scalar varint
reader behave at the **u32 width**: what does it charge, which
payload markers does it accept or reject, what does it consume on
each outcome, and what does its short-input path report?

## Result

One logical reader, present as two codegen copies with identical
relative layout and semantics — `0x2cd79c0..0x2cd7ab3` and
`0x5821150..0x5821243` (243 bytes each) — sharing one slow-path
reader `0x5822490..0x58225b5` (293 bytes), reached only through GOT
slot `0x64e7f70`, and one raw error constructor `0x5822700` (a
boundary, see below).

Reader state: mode dword at `+0x0`, limit at `+0x8`, cursor at
`+0x10`, remaining at `+0x18`, charged count at `+0x20`. Result:
rawtag byte at `+0x0`, u32 value at `+0x4` on success (rawtag
`0x12`), additional-needed u64 at `+0x8` on slow shortfall (rawtag
`0x00`), error fields at `+0x1/+0x2` via the constructor (rawtag
`0x03`).

- **Charge (mode 1 only):** the reader adds **4** to the charged
  count and stores the new count *before* comparing it with the
  limit. Overflow past `u64::MAX - 4` returns rawtag 2 with the
  count unchanged; exceeding the limit returns rawtag 2 with the
  +4 retained and no input consumed. Every other mode value takes
  the uncharged route in these bytes.
- **Fast route** requires `remaining > 4`; at or below that it
  delegates to the slow reader with the `(cursor, remaining)` pair
  and a little-endian flag of 0.
- **Fast markers:** `0..250` are the value (consume 1); `251`
  reads a u16 LE payload (consume 3); `252` reads a u32 LE payload
  (consume 5); **`253` is an error** (field1 2, field2 3, consume
  0); `254` errors with field2 4; `255` with field2 12. No
  minimality check exists: non-minimal `251`/`252` encodings of
  small values are accepted.
- **Slow path:** an empty input returns rawtag 0 with additional
  1 and consumes nothing. Otherwise the marker is consumed *before*
  classification; a short `251` reports additional `3 - total`,
  a short `252` reports `5 - total`, each consuming only the
  marker; marker errors (`253`/`254`/`255`) consume the marker,
  unlike the fast route. Payload loads honour the endianness flag
  (rol/bswap selects); both copies pass 0.

## Trace

1. Authenticated the pinned distribution by size and SHA-256 and
   re-derived all three owner extents from `.eh_frame` FDE records
   (CIE `0xca6ed8` for all three); body hashes are in
   `records.json` and the native readelf lines in `frames.txt`.
2. Read the mode/charge prologue bytes: mode `== 1` test, charge
   increment 4, store-before-compare, rawtag 2 refusal arms.
3. Read the fast marker dispatch: boundary compare 251, relative
   dispatch tables (`0x60be7c` / `0x935bcc`), and validated every
   table target as an instruction start inside the retained
   objdump exports (`decode_export`).
4. Read the slow delegation (slot `0x64e7f70`, endianness 0) and
   the slow reader itself: consume-before-classify stores, total
   widths 3/5, shortfall arithmetic, endianness selects, error
   arms through slot `0x64e7f78`.
5. Resolved `.rela.dyn`: slot `0x64e7f70` → the slow reader,
   `0x64e7f78` → the raw constructor `0x5822700` (14 bytes: writes
   rawtag 3, field1 from `esi`, field2 from `edx`), `0x64e7f80` →
   the sibling family's slow reader (boundary).
6. Censused the full `.text`: 16 direct call sites for copy A in
   12 FDEs, 11 for copy B in 9 FDEs, **zero** direct call sites
   for the slow reader, and exactly two rip-relative references
   to its slot — the two copies' slow calls. No caller calls
   either copy four times (no 4×u32 aggregate among direct
   callers).

## Boundaries

- The raw error constructor `0x5822700` is a component of the
  open u64-reader packet (#2300); it is recorded here only as the
  called boundary that writes the error result layout.
- The u64 scalar reader family (copies `0x2cd7ac0`/`0x5821250`,
  slow reader `0x58225c0`, 4× aggregates) is #2300's scope. The
  two widths observably disagree on marker `253`: the u64 copies
  read an 8-byte payload (consume 9); this reader errors with
  field2 3. Charge (8 vs 4) and fast threshold (`remaining > 8`
  vs `> 4`) also differ, so this packet records behaviour no open
  packet records.
- A sibling scalar-reader family uses constructor field1 5
  (copies include `0x5821340`; slow reader `0x5822710` via slot
  `0x64e7f80`). Same payload widths, different result-enum
  family; excluded and not traced.
- The encode-side varint size functions are open PR #2257; the
  `rmp_signable` `.rodata` window is open PR #2311. Neither
  records this reader.
- No Rust reconstruction is included or claimed. Rawtag and
  error-field values are reported as raw bytes; which Rust enum
  variants they name is not established from these bytes.

## Files

- `records.json` — authenticated owners, frame records, charge
  and route facts, fast marker classes, the 49-row slow grid,
  call-site census, relocations, boundaries and limits.
- `copy_a.objdump.txt`, `copy_b.objdump.txt`,
  `slow_path.objdump.txt` — retained disassembly of the owners.
- `frames.txt` — native readelf FDE lines for the owners.
- `../../tools/u32_varint_reader_static.py` — regenerator and
  verifier; `../../tests/test_u32_varint_reader_static.py` —
  regeneration, table and counterfactual tests.

## Next question

Which per-type decode wrappers (the 27 direct callers) pass which
mode and limit values into this reader — i.e. which serialized
u32 fields are charged against a limit and which are not?
