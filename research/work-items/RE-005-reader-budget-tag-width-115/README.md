# RE-005: preserve asymmetric raw-tag comparison widths

The retained limit-writers summary identifies the source's first qword as a
tag and describes cases2/1 before the arithmetic fallback. It omits that the
second comparison uses only the low32 bits. A reconstruction following a
full-qword equality interpretation therefore selects a different budget for
some raw source words. This corrects an actual interpretation gap blocking
faithful RE-005 reconstruction, rather than changing live node policy.

Sole target node115,105896032bytes,SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base05bc2de303c05525b71e7e257426e741bc66a390; unrebased ELF VAs.
Merged #2527 introduced the retained contract. Merged #2531 traces input
writers but proves no upper32-zero invariant and does not repair this width
qualification. Original types, enum validity and live reachability remain open;
the counterexamples are raw-word observations, not a deployed-node defect.
All-state reader/limit/tag-width, low32 and ECX searches found no competing
correction within indexing/unpublished-work limits. Open reader/limit issue
search found no assigned work.

## Before and after on the same original instructions

The explicit reproducer ran before correction: raw source word0x100000001,
start0,end9 in both twins. Actual budget10000; the retained qword-tag summary
predicts100000000. The before run failed in4.389s with both numeric values,
not because a new schema field was absent. After correction the unchanged
reproducer passes in4.931s with actual/predicted10000. Original producer,
records and README were preserved externally and in the base Git revision;
before-after.json retains their hashes and the exact old declared-contract
subset. It distinguishes this descriptive-contract prediction from an old
runtime numerical API: the old tool emitted a summary, not a budget function.

The actual ordered comparisons are:

| Case | Operand/mask | Twin A CMP | Twin B CMP | Budget |
| --- | --- | --- | --- | --- |
|2|RCX,64bits /0xffffffffffffffff|0x2b6a7d9|0x5a6b62a|120|
|1|ECX,32bits /0xffffffff|0x2b6a7e5|0x5a6b636|10000|

Thus raw0x100000001 takes the second case, while raw0x100000002 does not take
the first. The generator now derives the ordered masks, registers, widths,
immediates and actual VAs from the pinned CMP encodings, and emits them as
tag_conditions for each twin. Existing case-value labels remain compatible.
The record/README's raw condition is corrected. A private width-byte mutation
also changes both the decoded certificate and actual computed value, so this
is not a test asserting newly hardcoded labels.

The existing range/scale/saturation rules are preserved and covered, including
borrow, inclusive increment wrapping through the MAX fallback, multiplication
overflow and the cap. No unrelated parser, performance or architecture change
is included. Original byte pins, native captures, frame text and the existing
record-helper export are byte-identical; no import or artifact pin changes.

## Qualified differential scope

The two fresh readonly compute points are0x2b6a7d2..0x2b6a834 and
0x5a6b620..0x5a6b685. They read the actual source pointer from dispatcher+0x78
or+0x958, then its tag/start/end words. Valid disjoint synthetic storage is a
premise; other registers/flags start unknown. Observe the actual R13/R15 budget
at the following continuation. No store or call is allowed. No constructor,
later flag trace, native RET/public ABI or whole dispatcher is asserted.

Selected199 bytes/50 instructions are all visited by302 distinct input tuples;
the two aliases are one family and agree on all151 shared tuples. Sixteen
actual private byte-COW changes alter width/immediate/case values, borrow,
scale and clamps. Wrong register extensions reject in the certificate parser.
Original target SHA is checked before/after. Full containing bodies total10985
bytes; actual FDE/CIE and agreeing full GNU/Capstone exports are retained as
static context, without full-body source-equivalence credit.

proof.py completed in10.183s and matches the corrected declaration to every
original corpus observation. The broader regression corpus was collected after
the correction; only the explicit initial counterexample predates it. No
pre-Rust seal, Rust reconstruction or compiled-byte equivalence is claimed.

## Reproduce and review

From the repository root with Python/Capstone5.0.6 and GNU binutils:

```sh
python3 research/work-items/RE-005-reader-budget-tag-width-115/native.py
python3 research/work-items/RE-005-reader-budget-tag-width-115/proof.py --objdump /absolute/path/to/objdump
python3 -m unittest discover -s tests -p test_reader_budget_tag_width115.py -v
python3 -m unittest discover -s tests -p test_limit_writers_static.py -v
```

The actual full producer completed in116.753s, preserving native exports.
Seven new focused tests passed in10.864s and all12 unchanged existing tests
passed in449.060s, including fresh full-producer/native-export regeneration.
Complete focused run460.476sPASS. Repository checks and exact final receipts
are recorded after completion. Raw before/after,
generator/proof/test logs are retained externally; durable evidence is here.
Run MANIFEST.sha256 checks from the repository root; entries are root-relative.

All92 gates remain false. No real caller-validity, original enum/type layout,
complete reader-state behavior, source-built node or hosted CI result is
inferred from these point observations. New analysis/fix MIT; existing native
exports retain their upstream rights. Mmap scaffold reuse is credited to the
stake/quantity/source-fix packets. No unlicensed inferred source copied. No
captured ELF process/Unicorn, service, chain/signing or wallet action runs.
Slop opened/OAuth remains deferred by the operator.

Final repository checks: twelve packet-integrity tests, doctor, verify, staged catalogue/check and actual inventory reproduction PASS; scoped368.670s. Only catalogue steps use the exact already-submitted2655immutable-snapshot helper for its measured repeated-read blocker. Hashes/scope in validation-overlay.json, baseline restored before reproduce/commit; no helper duplicated, no unmodified-head catalogue or local full-suite pass. Own fullCI pending.
