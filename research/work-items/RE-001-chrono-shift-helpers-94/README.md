# RE-001: bind the node #94 chrono datetime-shift helpers at 0x15206e0 / 0x151f870

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations; the "NaiveTime shift" and
  "NaiveDate day shift" labels are inferred from the arithmetic and the
  chrono anchors; no reconstruction, no gate request.
- Scope included: both FDE-bounded bodies (`0x15206e0..0x1520842`, 354
  bytes; `0x151f870..0x151fa9c`, 556 bytes), their FDE records, all
  twenty-seven verified branch destinations, the nanosecond normalization
  constants (1e9, 1e9-1, 2e9, ±1e9 renormalization adds), the four magic
  divisions (86400, 146097, 400, 365) with exact-division grid proofs,
  the eleven panic Locations across `naive/time/mod.rs` (623–639),
  `naive/date/mod.rs` (2325/2326/2334) and `naive/internals.rs` (80), both
  MDL table lookups (the 400-entry table at `0x250354` already anchored to
  the datediff core `0x151d1b0`, plus the second base at `0x2504e5` =
  `0x250354 + 401`), the packed-date field masks (`0x1ff`, `0xffffe00f`,
  `0x1ff8`, bound `0x16e1`), the three panic GOT slots, and the
  GOT-mediated call census. Scope excluded: the containing statistics
  function `0x4898810..0x489a550`, the ema update body, the ema window
  guard (bound separately), #115, visor.

## Question

The ema window-guard packet left both chrono callees unbound: what are
`0x15206e0` and `0x151f870`, and which dependency evidence do they carry?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/chrono_shift_static.py --output work/shift-record.json
diff work/shift-record.json research/work-items/RE-001-chrono-shift-helpers-94/observed/records.json
python3 -m unittest discover -s tests -p test_chrono_shift_static.py -v
```

The tool authenticates size and SHA-256, then checks both exact FDE records
and body bytes, every branch destination, the nanosecond constant encodings,
the magic-division sequences, both MDL table leas and the 400-entry table
bytes, five GOT relocations against `.rela.dyn`, the eleven Location
structs (file, line, column) through their relocations, and the whole-
`.text` census for `e8`, `ff 15` and `48 8d` encodings. Disassembly text in
`observed/` was rendered with capstone 5.0.7 and labeled as such; byte
records are authoritative. Platform: Windows 10 22H2, Python 3.11.9.

## Observations

Both bodies are chrono-0.4.38 helpers reached only through GOT slots
`0x576e8a8` / `0x576e8b0` — 133 and 150 `ff 15` sites across the complete
`.text`, zero direct `e8` calls, zero `lea` references.

`0x15206e0` (354 bytes, FDE `0xcf67f0`): normalizes a fraction against
1e9 (compare bound 1e9-1, pair limit 2e9, three ±1e9 renormalization
adds, sign-corrected second carry), splits whole seconds through the same
86400 magic multiplier as the window guard (`0x1845c8a0ce512957`, shifts
13 + sign, correction multiplier 86400), and stores a 12-byte result
(fraction, seconds-within-day, day count). Six overflow panics whose
Locations all resolve to `chrono-0.4.38/src/naive/time/mod.rs` lines
623, 627, 628, 632, 635 and 639 — the `NaiveTime` shift arithmetic. The
label "NaiveTime shift with nanosecond normalization and day carry" is
inferred from these cascades, not a claim about the Rust source symbol.

`0x151f870` (556 bytes, FDE `0xcf65ac`): extracts a 9-bit ordinal field
(`shr 4; and 0x1ff`), walks the 400-year cycle (146097-day magic
`0x396b06bd` / multiplier `0x23ab1`, 400 magic `0x51eb851f` /
multiplier `0x190`, 365 magic `0x6719f361`), reads the shared MDL table
at `0x250354` (400 entries, sha256
`299e3736...`, the same table the datediff core `0x151d1b0` binds) and a
second base at `0x2504e5` = `0x250354 + 401`, applies the packed-date
field operations (clear mask `0xffffe00f`, insert shift 4, repack shift
13, frob shift 4, validation mask `0x1ff8` against bound `0x16e1`), and
validates the year range (bias add `0xfffc0001`, compare `0xfff80002`).
Five panics: `naive/date/mod.rs` 2325:9, 2326:9, 2326:27, 2334:5 — the
last Location is the exact one the datediff core carries — plus
`naive/internals.rs` 80:9, whose call sites pass the integer operands 400
and 401 alongside the Location. The label "NaiveDate day shift over the
400-year cycle" is inferred from this arithmetic.

The ema window-guard body reaches both helpers through exactly the two
GOT slots bound here (`0x474fbf3`, `0x474fc46`), closing the cross-packet
edge left open by the window-guard packet.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no two-build comparison. The
four magic-division identities are Python validations of decoded
arithmetic over grids (signed trunc division for 86400 / 146097 / 400,
unsigned variant for 365), not target equivalence.

## Results and limitations

- 2 helper bodies bound to the digest (354 + 556 bytes), 2 FDE records,
  27 branch destinations, 6 nanosecond constant encodings, 4 magic
  divisions with grid proofs, 11 chrono panic Locations, 2 MDL table
  lookups with the 400-entry table hash, 4 packed-date field constants,
  5 GOT relocations; census denominators are the complete `.text` for
  `e8`, `ff 15` and `48 8d` encodings.
- 10 tests pass (retained record, FDE/body identity, chrono Locations,
  four division grids, MDL shared anchor, size/SHA rejection, body/FDE
  mutation controls, Location mutation controls, GOT mutation controls,
  census with the window-guard edge). Author rerun, not independent peer
  review.
- Unknowns: the exact chrono source symbols behind both labels, what the
  constant 30 selects at the window-guard call site (still open from that
  packet), and the semantics of the second MDL base. No execution, Rust
  build, hosted CI, or gate.

Next question: bind the containing statistics body
`0x4898810..0x489a550`, which consumes both helpers bound here.
