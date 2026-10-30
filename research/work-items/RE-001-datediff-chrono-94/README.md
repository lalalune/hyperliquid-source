# RE-001: bind the node #94 chrono-style date difference core at 0x151d1b0

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations; the packed-date labels are inferred
  from the constant structure; no reconstruction, no gate request.
- Scope included: the core body `0x151d1b0..0x151d33f` (399 bytes), its FDE
  record, the 400-entry leap-day table with entry-by-entry independent
  validation, the era arithmetic constants, the year-0 panic anchored to a
  chrono-0.4.38 source Location, and the three-caller census. Scope excluded:
  the "Time Sub" wrapper's semantics (separate packet), the two other callers'
  logic, the panic callee's internals, #115, and visor.

## Question

What does the inner callee of the shared "Time Sub" helper compute, and is
its calendar table genuine Gregorian arithmetic rather than an invented
label?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/datediff_static.py --output work/datediff-record.json
diff work/datediff-record.json research/work-items/RE-001-datediff-chrono-94/observed/records.json
python3 -m unittest discover -s tests -p test_datediff_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact FDE record and
body bytes, fifteen immediate constants, both panic branches, the leap table
bytes against a freshly computed proleptic-Gregorian model, the table's
in-body `lea`, the chrono panic Location through its RELATIVE relocation, two
GOT slots, the whole-`.text` call census, and a day-count identity against
Python's own calendar. Disassembly text in `observed/` was rendered with
capstone 5.0.7 and labeled as such; byte records are authoritative. Platform:
Windows 10 22H2, Python 3.11.9.

## Observations

Body `0x151d1b0..0x151d33f` (399 bytes, FDE at `.eh_frame` VA `0xcf630c`,
sha256 `7d783da6...`), reached only through GOT slot `0x576eaa0` by exactly
three `ff 15` sites — `0x13cfdc1`, `0x1447166` (the shared Time Sub helper)
and `0x1450a61` — with zero direct `e8` or `lea` references.

Each 12-byte operand's leading dword decomposes as a packed date:
`year = dword >>a 13` and a 9-bit field `(dword >> 4) & 0x1ff`. The era math
is textbook proleptic Gregorian: `q400 = year / 400` via the `0x51eb851f`
magic, euclidean remainder `r` in `0..399`, `365*r` plus a 400-entry leap-day
table at `0x250354` indexed by `r`, and the full cycle worth `146097` days
(`0x23ab1`) scaled at the tail with `86400` seconds per day (`0x15180`).

The leap table was validated entry-by-entry against an independently computed
model (cumulative count of leap years before each cycle year, with cycle year
0 = 1 BC leap under astronomical numbering): all 400 entries match. A
day-count identity then checks `146097*q + 365*r + table[r] + ord0` against
Python's calendar as day differences for years 1..2400 and offsets 0..365 —
the stored 9-bit field behaves as a zero-based day offset, consistent with
chrono's internal `NaiveDate` packing.

Both operands' day sums branch to a panic at `0x151d332` when zero (the
year-0, day-0 invalid date). That panic carries Location `0x5672188`:
`/home/ubuntu/.cargo/registry/src/index.crates.io-.../chrono-0.4.38/src/naive/date/mod.rs`
line 2334, column 5 — binding this body to the vendored chrono 0.4.38
dependency, with the panic callee at GOT `0x576e150 -> 0x157b520`.

The seconds/nanoseconds tail subtracts the operand day/second/nanosecond
fields with `1e9` (`0x3b9aca00`) normalization via the
`0x112e0be826d694b3` magic divisor and borrow `cmov`s (recorded
structurally), returning `(i64 total seconds in rax, i32 nanosecond
remainder in edx)` — exactly the pair the Time Sub wrapper consumes.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no two-build comparison. The
leap table and day-count identities are Python validations of decoded
arithmetic against an independent calendar oracle, not target equivalence.

## Results and limitations

- 1 core body bound to digest (399 bytes), 1 FDE record, 400/400 leap-table
  entries validated against the independent model, 15 immediates, 2 panic
  branches, 1 chrono Location, 2 GOT slots; census denominator is the
  complete `.text` for `e8` / slot-`ff15` / `lea` encodings.
- 9 tests pass (identity, FDE bounds, leap-model spot checks, day-count
  identity, body/FDE/table/Location/relocation mutation controls, census).
  Author rerun, not independent peer review.
- Unknowns: the exact chrono function identity (the Location proves the file
  and line, not the symbol), the borrow `cmov` corner semantics, and the two
  non-Time-Sub callers. No execution, Rust build, hosted CI, or gate.

Next question: bind the remaining two callers (`0x13cfdc1`, `0x1450a61`) and
the Time Sub wrapper's descriptor/flag plumbing.
