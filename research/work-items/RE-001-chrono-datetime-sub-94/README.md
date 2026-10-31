# RE-001: bind the node #94 chrono datetime-Sub wrapper at 0x151d080

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations; the "NaiveDateTime Sub wrapper"
  label is inferred from the negation complement, the helper calls and the
  chrono anchors; no reconstruction, no gate request.
- Scope included: the FDE-bounded body `0x151d080..0x151d1a4` (292 bytes),
  its FDE record, all nine verified branch destinations, the TimeDelta
  negation complement (1e9-nanos with a -1 secs borrow when nanos are
  nonzero, plain negation otherwise), the i64::MIN day-carry sentinel
  check, both day-carry range gates (the second pair byte-identical to the
  ema window-guard packet's constants), the unsigned 86400 magic variant
  (`shr 63` / `shr 13`, unlike the signed variant inside the callee), both
  helper GOT slots with their call sites, three panic Locations across
  `time_delta.rs` (473:26, 475:27) and `naive/time/mod.rs` (670:16), and
  the four-site GOT-mediated call census. Scope excluded: both shift
  helpers (bound in the chrono-shift packet), the datediff core
  `0x151d1b0` (bound separately), the ema window guard, the containing
  statistics body `0x4898810..0x489a550`, #115, visor.

## Question

The chrono-shift packet bound both datetime-shift helpers; what does the
small 292-byte body that calls both of them back-to-back — right before
the datediff core — actually do?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/chrono_dtsub_static.py --output work/dtsub-record.json
diff work/dtsub-record.json research/work-items/RE-001-chrono-datetime-sub-94/observed/records.json
python3 -m unittest discover -s tests -p test_chrono_dtsub_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact FDE record
and body bytes, nine branch destinations, the negation complement and
sentinel encodings, all four range-gate constants, the unsigned
day-division shifts, five GOT relocations against `.rela.dyn`, the three
Location structs (file, line, column) through their relocations, and the
whole-`.text` census for `e8`, `ff 15` and `48 8d` encodings. Disassembly
text in `observed/` was rendered with capstone 5.0.7 and labeled as such;
byte records are authoritative. Platform: Windows 10 22H2, Python 3.11.9.

## Observations

Reached only through its own GOT slot `0x576f748` — four `ff 15` sites
(`0x151c698`, `0x2229fd4`, `0x470f1b4`, `0x4717007`), zero direct `e8`
calls, zero `lea` references.

The body negates its `(secs, nanos)` operand before the first helper
call: when nanos are nonzero it passes `(-1 - secs, 1e9 - nanos)` — the
complement form of chrono's `impl Neg for TimeDelta` — and plain
`(-secs, 0)` otherwise; the two `time_delta.rs` Locations (473:26,
475:27) sit exactly on those overflow checks. It calls the NaiveTime
shift helper (`0x576e8a8` → `0x15206e0`, the slot the chrono-shift
packet binds) on the time half, takes the day carry, rejects the
`i64::MIN` sentinel (panic at `naive/time/mod.rs:670:16`), range-gates
the carry twice — the second gate uses the constants
`0xffff574000000000` / `0xfffeae7ffffeae81`, byte-identical to the ema
window-guard packet's datetime bounds — divides the carry by 86400 with
the same magic `0x1845c8a0ce512957` but the **unsigned** shift variant
(`shr 63` / `shr 13`), and feeds the whole days into the NaiveDate shift
helper (`0x576e8b0` → `0x151f870`). A zero return from the date helper
produces the null output; otherwise the new packed date and the shifted
12-byte time are stored.

The label "NaiveDateTime Sub wrapper" is inferred from this shape
(`datetime - delta` as `datetime + (-delta)`); no Rust symbol is claimed.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no two-build comparison. The
unsigned 86400 identity is a Python validation of decoded arithmetic for
non-negative operands, not target equivalence.

## Results and limitations

- 1 wrapper body bound to the digest (292 bytes), 1 FDE record, 9 branch
  destinations, 3 negation/sentinel encodings, 2 range gates (one shared
  byte-identical with the guard packet), 1 unsigned magic division with
  identity grid, 3 chrono panic Locations, 5 GOT relocations; census
  denominators are the complete `.text` for `e8`, `ff 15` and `48 8d`
  encodings.
- 10 tests pass (retained record, FDE/body identity, Location anchors,
  negation and range anchors, unsigned division grid, size/SHA rejection,
  body/FDE mutation controls, Location mutation controls, GOT mutation
  controls, census). Author rerun, not independent peer review.
- Unknowns: the exact chrono source symbol, the first range gate's
  provenance (observed constants, wider than the datetime pair), and the
  four callers' identities. No execution, Rust build, hosted CI, or gate.

Next question: bind the containing statistics body
`0x4898810..0x489a550`, which consumes the guard and, through it, this
wrapper family.
