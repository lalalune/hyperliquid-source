# Stake predicate pre-source corpus specification

This describes the unexecuted generator draft. The reference has separately
passed the parent's actual 40-case manual qualification; no generator result,
retained count, output hash or Rust result is claimed here.

## Inputs, outputs and provenance

The scalar value reference accepts actual physical `(bytes20, u64)` rows,
canonical host head/live metadata and the complete selected key sequence. It
uses linear counts of keys less than/equal to each query, with the explicit
wrapped seam equality override. Its unbounded mathematical sums are clamped
once at the end, then compared with exact wider products. It has no imports,
I/O, source algorithm, native decoder or behavioral-model dependency.

The generator emits the final HOST-CONTRACT's six input fields, without any
expected fields:

`id<TAB>capacity<TAB>head<TAB>live<TAB>physical_rows<TAB>selected_keys<LF>`

Physical rows are comma-separated `lowercase_key_hex:canonical_u64_weight`, or
`-`; selected keys are comma-separated lowercase forty-character hex strings,
or `-`. Capacity equals physical row count. IDs contain only allowed characters
and are unique. Expected output is in a separate parent-side `expected.tsv`:
`id<TAB>ok<TAB>B<TAB>S<TAB>0_or_1<LF>`, `id<TAB>bounds<LF>` or
`id<TAB>order<LF>`. Every generated record is valid transport; some exercise
the library's chosen bounds/order refusal. Malformed transport tests belong to
a separate control stream because one such input would reject the whole batch.

The first forty records and corresponding expectations must be byte-for-byte
equal to the previously sealed manual inputs/expected files. Manual cases and
derivations are also copied byte-for-byte into the bundle. The generator checks
the reference result against each literal expectation and stops on disagreement;
it never rewrites the manual expected value to fit the reference. Their native
anchors are semantic evidence context, not visited-instruction traces. In H28,
the first weight reaches MAX exactly, without arithmetic overflow; late misses
leave that value unchanged and cannot prove an equivalent early stop was killed.

## Deterministic requested families

| Family | Requested records | Construction and purpose |
|---|---:|---|
| Manual literals | 40 | Frozen actual inputs and independent derivations, including seam weights and near-MAX equality. |
| Complete small geometry | 7,063 | Capacities0..6, every canonical head, every live length, every nondecreasing multiset over keys1/2/3; logical weights1..live distinguish equal-key choices. Each view gets empty selection, five individual queries0..4, and the mixed repeated sequence3/0/1/2/1/4. Inactive rows alternate zero/all-ff keys with MAX weights. |
| Search-length boundaries | 118 | Live lengths7/8/9,15/16/17,31/32/33,63/64/65,127/128/129,255/256/257,4095/4096. Each has contiguous and wrapped full views, plus a partial wrapped view when capacity+1 remains <=4096. Each layout gets a middle query and a six-query first/last/missing/repeated combination. |
| Selected-length boundaries | 28 | Lengths0/1/2/7/8/9/63/64/65/255/256/257/4095/4096, each with repeated key1 and a key1/key2/miss/key1 pattern on weights2^63/1. These exercise long input sequences; values do not certify continued effects after saturation. |
| Every key byte | 80 | Each of twenty positions independently uses unsigned7f/80/ff, with all other bytes zero; contiguous and wrapped views, single and mixed/repeated/missing selections. |
| Arithmetic interactions | 600 | Every pair from ten weights0/1/2/MAX÷3/2(MAX÷3)/2(MAX÷3)+1/2^63-1/2^63/MAX-1/MAX, with six empty/single/repeated/two-key selections. This separates selected/total saturation and comparison domains. |
| Bounds-before-order | 28 | Capacities0..6, descending physical keys and four invalid head/live choices, including u64::MAX. These remain lexically valid TSV inputs. |
| Order refusals | 5 | Capacities2..6, canonical full descending views. |
| Seeded bit patterns | 64 | Seed `0x5354414B455F3230`, stdlib `random.Random`, capacities1..31, arbitrary160-bit keys and64-bit weights, duplicate key pools, variable live/head and sixteen selected occurrences/misses. |
| **Total requested** | **8,026** | A coverage-driven sum of explicit families, before exact-input deduplication. |

The small-geometry view count is
`1 + sum(c * sum(comb(n+2,2), n=0..c), c=1..6) = 1,009`;
each has seven selected sequences. The search-length family has nineteen
lengths with three layouts and one with two, all with two selections. These
counts are source-level plans, not claimed executed coverage.

The deterministic seed and its exact stdlib use are recorded in provenance.
Two runs under the parent's pinned interpreter must produce all eight output
files identically. No time, environment, process ID, machine path or filesystem
enumeration order is included in output bytes.

## Deduplication, limits and artifacts

Deduplication uses exact encoded input fields2..6, including all physical
inactive rows and metadata. It does not normalize ring rotations, keys, ignored
fields or expected results. The first request remains canonical. Every later
identical request receives an alias with original ID/family, canonical ID and
input-body hash. A manual fixture may never be dropped as an alias. Retained
count plus aliases must equal8,026, and family requested/retained counts are
reported separately.

The planned request count is below the driver's8,192-record limit even before
deduplication. All physical/selected lengths are <=4,096. A conservative bound
on input bytes is below10MiB: small geometry <4,944,100B; search-length rows
total50,064 plus118 headers/query lists <3,135,710B; the28 selected-length
records <758,000B; all other families together <410,000B. Actual retained bytes
must still be measured. The code refuses any >16,777,216B or >8,192 retained
stream; it never truncates or silently drops a family to fit.

Eight files are written to a newly created output directory:

* `inputs.tsv` and separate `expected.tsv`;
* `index.jsonl` with ID, family, expectation provenance and per-line hashes;
* `aliases.json` with every exact-input duplicate request;
* exact `manual-cases.json` and `manual-derivations.md` copies;
* `PROVENANCE.json` with reference/generator/manual/qualification/host hashes,
  seed and limitations;
* `SUMMARY.json` with actual counts, bytes, classes and hashes of the seven
  preceding files.

No gzip normalization or captured data is involved. Future Rust receives only
the frozen input TSV; expected output, models and manual derivations remain in
the parent process, outside the child source/arguments/environment/cwd.

## Candidate mutation obligations after separate source admission

Meaningful faults include removing seam override, choosing first equal instead
of last within a segment, comparing a key prefix or signed bytes, deduplicating
selected occurrences, adding a default weight for misses, counting inactive
rows, omitting/doubling the second span, wrapping either sum, comparing raw
unclamped totals, dropping high product limbs, and using non-strict comparison.
Each actual compiled mutation must later build, exit zero, emit complete valid
output and change an identified witness. These are proposed fault classes, not
already measured mutation kills. No value-only control is promised to detect
every observationally equivalent early stop.

## EXPAND

Parent reads the exact generator/effect plan before its first execution, then
checks two actual output trees, manual prefixes, alias accounting and resource
measurements. Freeze successful inputs/expectations and provenance before the
separate Rust authorship gate. Static native controls, strict comparator and
transport tests remain separately qualified work, not results of this builder.
