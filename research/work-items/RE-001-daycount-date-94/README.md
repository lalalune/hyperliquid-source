# RE-001: bind the node #94 day-count date constructor 0x151f6f0 and the epoch identity

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations plus two decoded-arithmetic
  identities; the NaiveDate-style constructor label is inferred from the
  shared machinery; no reconstruction, no gate request.
- Scope included: the 378-byte body `0x151f6f0..0x151f86a` (FDE `0xcf6588`),
  thirteen immediate anchors, four panic Locations with their callees and
  length operands, both shared tables re-validated entry-by-entry with the
  sentinel, the exhaustive 146097-day cycle identity, the epoch identity
  resolving the lock-cell accessor's constant, and the whole-`.text` census.
- Scope excluded: the NaiveDate day-shift body `0x151f870` (bound in
  `RE-001-chrono-callees-94`), the datediff core (`RE-001-datediff-chrono-94`),
  the lock cell and accessor (`RE-001-lock-descriptor-94`), the 324 caller
  families, #115, visor.

## Question

The lock-guard cell packet left its accessor's lookup unbound: what does
`0x151f6f0` compute, and what does the constant index `0xaf93b` select?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/daycount_date_static.py --output work/daycount-record.json
diff work/daycount-record.json research/work-items/RE-001-daycount-date-94/observed/records.json
python3 -m unittest discover -s tests -p test_daycount_date_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact body and FDE,
thirteen anchors (the +365 immediate, both magics, both table lea
displacements, the bound checks, the year gate, the packing shifts and
masks), the four panic Locations and their GOT callees with the 400/401
length operands, both tables against the Gregorian models with the sentinel,
the exhaustive day cycle, the epoch identity, and the census. Disassembly
text in `observed/` was rendered with capstone 5.0.7 and labeled as such;
byte records are authoritative. Platform: Windows 10 22H2, Python 3.11.9.

## Observations

The body takes a raw day count in `edi`, adds the immediate `0x16d` (365)
under an overflow check that returns 0, and then runs the same chrono day
machinery as the NaiveDate day-shift body bound separately: the
`0x396b06bd` divide-by-146097 sequence, the `0x6719f361`
year-in-cycle estimate, the 400-entry cumulative leap table at `0x250354`
(with its 401st sentinel byte 97 on the estimate-overflow path), the borrow
correction, the year gate `0xfffc0001`/`0xfff80002` admitting years
[-262143, 262142], the flag read from the 400-entry table at `0x2504e5`,
and the `year << 13 | ordinal << 4 | flags` repack with the `0x16e1`
ordinal limit — returning the packed date or 0. Four panic paths reuse the
Locations `date/mod.rs:2325:9`, `date/mod.rs:2326:27`, `date/mod.rs:2326:9`
and `internals.rs:80:9` shared with the callees packet.

The epoch identity: the lock-cell accessor calls this constructor with the
constant `0xaf93b` (719163); the constructor's immediate adds 365, and
719163 + 365 = 719528, exactly the number of days from `0000-01-01` to
`1970-01-01` in the proleptic Gregorian calendar (the standard
`days_from_civil` epoch constant). The decoded machinery maps 719528 to
year 1970, ordinal 1, flag 10, packed `0xf6401a` — the Unix epoch date,
independently confirmed by Python's calendar. The cell the read-lock guards
publish therefore materializes 1970-01-01 lazily.

Census over the complete `.text`: GOT slot `0x576e890` receives 324 `ff 15`
call sites with zero direct `e8` and zero `lea` references — by site count
the most-shared helper measured in this series (the read-lock helper has
952, this constructor 324, the NaiveTime/NaiveDate pair 133/150). The
accessor's call site `0x3790ff0` is among them.

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison. The
identities are Python validations of decoded arithmetic against independent
calendar oracles, not target equivalence.

## Results and limitations

- 1 body (378 bytes) + FDE, 13 anchors, 4 panic Locations with callees and
  length operands, 2 tables (400 + 400 + sentinel bytes) re-validated, 1
  exhaustive 146097-day cycle, 1 epoch identity; census denominator is the
  complete `.text` for `e8` / `ff 15` / `lea` encodings.
- 8 tests pass (record match, epoch identity with oracle, shared tables,
  exhaustive day cycle, panic locations, census, body and epoch-constant
  mutation controls). Author rerun, not independent peer review.
- Unknowns: what the other 323 caller families compute, and why the epoch
  is materialized through a guarded cell rather than a constant. The
  constructor label stays inferred. No execution, Rust build, hosted CI, or
  gate.

Next question: the once machinery `0x4ee3b20` shared by both read-lock
guards, and a census-driven sample of the 324 constructor callers.
