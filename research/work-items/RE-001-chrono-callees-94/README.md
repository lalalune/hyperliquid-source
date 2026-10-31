# RE-001: bind the node #94 chrono callee pair 0x15206e0 / 0x151f870

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations plus decoded-arithmetic identities;
  the NaiveTime/NaiveDate labels are inferred from the panic Locations, the
  table models and the structure; no reconstruction, no gate request.
- Scope included: callee 1 `0x15206e0..0x1520842` (354 bytes, FDE `0xcf67f0`),
  callee 2 `0x151f870..0x151fa9c` (556 bytes, FDE `0xcf65ac`), both FDE
  records, twenty-nine immediate anchors, eleven panic Locations, three panic
  callees via relocations, both chrono tables (400-entry cumulative leap table
  with its 401st sentinel byte, 400-entry year flag table), the day/era
  division chain, the year-range gate, and the whole-`.text` census.
- Scope excluded: the calling statistics body `0x4898810..0x489a550`, the ema
  update body, the guard body itself (bound in
  `RE-001-ema-window-guard-94`), the datediff core (bound in
  `RE-001-datediff-chrono-94`), #115, visor.

## Question

The ema window guard packet left its two chrono callees unbound. What are
`0x15206e0` and `0x151f870`, and what dependency evidence do they carry?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/chrono_callees_static.py --output work/callees-record.json
diff work/callees-record.json research/work-items/RE-001-chrono-callees-94/observed/records.json
python3 -m unittest discover -s tests -p test_chrono_callees_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact FDE records
and body bytes of both functions, the immediate anchors, all eleven panic
Locations (six in `chrono-0.4.38/src/naive/time/mod.rs` lines 623-639, four
in `naive/date/mod.rs` lines 2325-2334 reusing the datediff packet's 2334:5
Location, one in `naive/internals.rs:80:9` with table lengths 400 and 401),
the three panic callees against relocations, both tables entry-by-entry, and
the census. Disassembly text in `observed/` was rendered with capstone 5.0.7
and labeled as such; byte records are authoritative. Platform: Windows 10
22H2, Python 3.11.9.

## Observations

Callee 1 `0x15206e0..0x1520842`: takes an out pointer, a 12-byte result
written as `{u32 secs, u32 frac, i64 day-carry seconds}`. The input
`{secs, frac}` pair and a `(seconds, nanos)` delta are normalized with the
constants 1e9, 2e9 and -1e9 (five sites), six arithmetic-overflow `jo`
branches route to six panic Locations in `naive/time/mod.rs`, and the tail
divides the signed second total by 86400 through the same magic
`0x1845c8a0ce512957` the window guard carries, with an explicit euclidean
remainder fixup (`sar`/`and`/`add`). Called through GOT slot `0x576e8a8`
from 133 `ff 15` sites across `.text`, with zero direct `e8` references;
the window guard site `0x474fbf3` falls inside `0x474fb90..0x474fce5`.

Callee 2 `0x151f870..0x151fa9c`: takes a packed date
(`year >>a 13`, ordinal `(dword >> 4) & 0x1ff`, flags `dword & 0xf` where
bit 3 marks a common year and bits 0-2 carry the Jan-1 weekday class) and a
signed day offset, returning a repacked date or 0 (observed None marker)
when the ordinal or year-range check fails. The fast path stays inside the
current year (366 minus the common flag); the slow path decomposes through
the 400/146097/365.2425 magic chain — `0x51eb851f`, `0x396b06bd`,
`0x6719f361` — reads the 400-entry cumulative leap table at `0x250354`
(shared with the datediff core) plus its 401st sentinel byte 97 when the
year estimate reaches 400, borrows into the previous year through the
correction at `0x151f951..0x151f9b2`, and rejoins with the year gate
constants `0xfffc0001`/`0xfff80002`, which admit exactly years
`[-262143, 262142]`. The final flag comes from the 400-entry year flag
table at `0x2504e5`. Five panic paths cover the invalid-date and table
bound cases. Called through GOT slot `0x576e8b0` from 150 `ff 15` sites,
zero direct references; the window guard site `0x474fc46` falls inside the
guard body.

## Identities

- Day division (callee 1): euclidean decomposition validated on a signed
  grid including negatives; the magic quotient is trunc-style and the
  remainder is explicitly normalized.
- Div-400 and div-146097 (callee 2): same decomposition property on the
  year and day-index domains.
- Year-in-cycle plus ordinal: the decoded estimate and borrow correction
  resolve every one of the 146097 days of a 400-year cycle to the exact
  `(year, ordinal)` pair implied by the leap table.
- Year flag table: all 400 entries equal
  `(8 if common else 0) | ((dow(Jan 1) + 1) % 7 + 1)` under the proleptic
  Gregorian model with astronomical year numbering; 97 entries below 8.
- Leap table: all 400 entries equal the cumulative Gregorian leap-day
  model; the 401st byte is 97.
- Fast path: 366 minus the flag's bit 3 equals 366 on leap and 365 on
  common cycle years.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no two-build comparison. The
identities are Python validations of decoded arithmetic, not target
equivalence.

## Results and limitations

- 2 bodies bound to digest (354 + 556 bytes), 2 FDE records, 29 immediate
  anchors, 11 panic Locations, 3 panic callees via relocations, 2 tables
  validated entry-by-entry (400 + 401 bytes), 3 division identities, 1
  exhaustive 146097-day cycle check; census denominator is the complete
  `.text` for `e8` / `ff 15` encodings.
- 9 tests pass (record match, both table models, exhaustive day cycle,
  division sequences, panic anchors, body/FDE/Location/relocation mutation
  controls, census and guard cross-link). Author rerun, not independent
  peer review.
- Unknowns: the weekday-class encoding beyond the validated alignment, the
  containing statistics body, and what selects the `(30, 0)` delta at the
  guard's call site. The NaiveTime/NaiveDate labels stay inferred. No
  execution, Rust build, hosted CI, or gate.

Next question: bind the containing statistics body `0x4898810..0x489a550`
that calls the guard, then the remaining shared chrono helpers reachable
from the 133/150-site censuses.
