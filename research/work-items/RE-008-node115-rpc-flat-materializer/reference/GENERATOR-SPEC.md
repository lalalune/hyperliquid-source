# RPC supplied-value reference and corpus authoring specification

This is an unexecuted authoring-stage specification. Root admitted draft
authorship only in `PRECODE-AUTHORING-ADMISSION.json`. No generator/reference
import, qualification run, corpus generation, Rust, test or native execution
was performed by this author. Parent execution and later source admission are
separate gates. Preserve the sealed `REFERENCE-AUTHORING-FREEZE.json` and the
original independent fixtures; do not adjust their expectations to fit code.

## Contract and chosen interface

The native conditional contract is `ROOT-RPC-CONTRACT.v3.md`, SHA256
`2919fdb8323d4826063e8ffc70c89286f6e11566c6b8f0f1f9cff4d9a9bc325d`.
This continues credited lookup/collector/materializer work and does not claim
first native byte coverage, a new native oracle, matching compiled bytes,
native ABI or runtime equivalence. Every native layout, stability, import,
per-acquisition reference-word and normally returning helper premise remains.

`reference_math.py` accepts actual supplied 32-byte strings and integer opaque
values. A physical tuple of Rows defines capacity; head/live length select the
logical live sequence by modular indexing. Only live values must be nonzero,
and only live keys must be nondecreasing. Inactive rows still have typed 32-byte
keys/u64 values, but their zero values and ordering do not affect admission.

Search enumerates matching logical keys. Wrapped seam equality selects the
seam index; otherwise it selects the last equal key. Absence counts live keys
strictly below the query. This is an order-statistics definition, with no binary
reduction, instruction dispatcher, machine state or captured helper oracle.
Materialization is the all-hit value predicate, preserving query order and
duplicates. Its evaluation of all search values is not a native callback/read-
count claim. Empty queries produce an empty successful tuple; any miss gives
None, never a partial successful prefix.

The reference's host DomainError rejects malformed host values/headers,
unsorted live keys and zero live values. It does not reproduce native errors,
allocation failures, lifetime/drop or undefined pointer behavior. No source
allocation-failure case is synthesized. All eventual success comparisons
require successful necessary host allocation as well as native premises.

## Transport review and exact file schemas

The initially ambiguous CRLF/canonical-decimal/byte-bound details were reported
to the parent, not silently chosen. The parent resolved them in
`RPC-HOST-TRANSPORT.v1.md`, SHA256
`2838931cd554744a81bb88d58beefb7646db829b1a5d633007132c6816098e52`:
LF only, no CRLF, blank rows or non-ASCII; canonical unsigned decimal with no
sign, leading zero except literal 0, or whitespace; raw stdin limit exactly
16,777,216 bytes. No further transport-policy clarification is needed for these
drafts. The reference and generator do not implement or qualify an stdin parser.

`inputs.tsv` is ASCII, LF terminated, seven fields per row:

```
case_id<TAB>operation<TAB>capacity<TAB>head<TAB>live_length<TAB>physical_rows<TAB>queries<LF>
```

IDs are unique 1..64 ASCII alphanumeric/underscore/hyphen. S has one query;
M has 0..32. Capacity is 0..256. Physical rows are `-` for capacity zero or
exactly capacity comma-separated records: 64 lowercase hex key characters
followed by 16 lowercase hex value characters. Values are conventional
most-significant-hex-first integers, not native object memory. Queries are `-`
or comma-separated 64-character lowercase hex keys. Headers are canonical
unsigned decimal. All generated frames are valid host-domain inputs.

`expected.tsv` is a separate file, unavailable to the future Rust client:

```
id<TAB>H<TAB>logical_index<TAB>physical_index<TAB>value16hex<LF>
id<TAB>N<TAB>insertion_index<LF>
id<TAB>V<TAB>comma-separated-value16hex-or-minus<LF>
id<TAB>F<LF>
```

Expected rows match input order and ID. Manual expectations are rendered from
the immutable literal fixture and compared against the reference; a mismatch
raises an error instead of replacing the literal. Other expectations are
explicitly labeled reference-derived. No output expectation is embedded in
the input stream. Neither reached-query counts nor temporary prefixes are
driver output fields or required comparison results.

## Deterministic enumeration and bounds

No PRNG, time input, filesystem enumeration order or seed is used. All loops,
fixed key bytes and orderings below are normative. A source/header edit must
produce a new recorded draft identity; never overwrite an executed/frozen
corpus to conceal a mismatch.

1. **Manual, first:** all 24 sealed cases and their 64 separate searches produce
   88 requested frames: 64 S, 24 M. Original `handcases.json` bytes are copied
   unchanged into the output. `reached_queries`/`temporary_prefix` remain
   explanatory fixture metadata only. The seven invalid examples are copied
   separately and excluded from the valid stdin stream.
2. **Exhaustive small domain:** capacities 0..6; all valid heads; lengths 0..c;
   every sorted sequence from three complete 32-byte keys representing
   integers 0x40,0x80,0xc0 in unsigned big-endian text. There are
   `1 + sum(c*C(c+3,3), c=1..6) = 1,009` geometry/key states. Every state gets
   seven S queries for 0,0x40,0x60,0x80,0xa0,0xc0,0xff and five M families:
   empty; ordered repeated all-hit keys; first miss; middle miss; last miss.
   Empty live states have the explicitly coded degeneracies, retained as
   dedup aliases where identical. Total requested: 7,063 S + 5,045 M = 12,108.
3. **Depth boundaries:** lengths 7,8,9,15,16,17,31,32,33,63,64,65,127,128,129,
   255,256. For each, three geometries (full contiguous, full head1, and
   capacity min(256,n+3)/head c-2) and three key patterns (strictly increasing
   even integers, groups of three duplicates, all equal). Five S queries cover
   below, first, seam, middle and above. Two M frames use 32 queries: ordered
   repeated last/first/middle/seam hits, and a final miss after 31 hits.
   Requested: 17*3*3*7 = 1,071.
4. **Every key byte:** positions 0..31, all other bytes 0x55. Live differing
   bytes are 00,01,7f,80,80,fe,ff, with distinct opaque physical-slot values
   including high u64 words. Capacity9 and heads0,6,8 cover contiguous and
   two wrapped geometries. Seven S queries include an absent02, plus M hit32
   and middle-miss batches. Requested: 32*3*9 = 864. This reaches the last
   key byte, unsigned boundaries and seam duplicate selection.
5. **Endian distinction:** eight sorted complete keys formed from integers
   1,256,65536,0x01020304 encoded as both 32-byte big- and little-endian strings.
   Capacity10, heads0,3,9. Ten searches (all eight hits and two outer misses)
   plus hit32/middle-miss batches. Requested: 36.

Total requested frames before deduplication: **14,167**, below 16,384. Actual
retained/alias counts are deliberately not asserted until execution. A draft
arithmetic typo of 14,267 was caught by manual addition and corrected before
any execution or generator freeze; no output existed for that draft.

Inactive generated slots use key ff repeated32 and value0; active ordinary
values are 0x1000+physical_index. Comparison families cycle explicit high
values. These are supplied values, never dereferenced pointers or counts.
The exhaustive claim concerns this stated small geometry/key alphabet with
one fixed payload assignment, not every possible inactive allocation or u64.

A conservative raw-input size bound, before dedup, is **15,711,944 bytes**:
7,356,642 small + 7,255,467 depth + 961,920 byte-position + 40,851 endian +
97,064 manual. This uses at most81 bytes of ID/header/separators per frame,
physical text at most81*c+1, query text at most65*k-1 (or1 for empty), and the
actual family's maximum query lengths. For depth geometries the summed
capacities before the three key patterns are3,811. The manual bound uses its
pinned maxima capacity7/query count7. This is an upper bound, not measured
output size. The generator checks each retained addition against both whole-
stream limits and fails if either is exceeded; it never truncates to fit.

Deduplication uses the complete six input fields after the ID, including
operation, full physical rows and full query order. Candidate IDs remain
unique. A duplicate must have identical expected fields; contradictory
expectations fail. The first row is retained, later candidate IDs map through
`aliases.jsonl` to that canonical ID, with family and expected provenance.
Every requested candidate is therefore retained or explicitly aliased.

## Files, effects and future qualification

`qualify_handcases.py` takes `--handcases`, `--host-invalid`, `--manual-freeze`,
and `--output`. It verifies exact immutable input hashes and checks 64 searches
and 24 materializer values. Its seven host negatives are classified separately:
X05 is a **record-loader** capacity/row-count mismatch, unrepresentable as a
Ring whose capacity is slice length; the other six are Ring constructor
domain refusals. It writes `result.json` under a fresh output directory,
preserving mismatches and returning exit1 when any mismatch exists. A reported
match is not a native differential test. No code has been run by this author.

`generate_corpus.py` takes the same three manual input paths, a required
`--qualification` path and a fresh `--output`. The qualification is the actual
parent-run `rpc-reference-qualification/actual/result.json`, SHA256
`cc4680b2c319ca6dd885de9b046271db361fd0d610375fe557fb75abf77fdb9e`.
Its parent command receipt is SHA256
`4d9012abfac6776c4cf10bf3517ef8072fb299adc54fdb5a2328fe6c9a3e2f4a`.
The parent actually ran Python3.14.3 `-B -S` in a clean environment and recorded
exit0, 24 cases / 64 full search tuples / 24 materializer values / seven host
refusals, zero mismatches and unchanged source/input identities. This author
read those receipts as data and did not rerun qualification. The generator
checks the exact result hash, successful status/counts and frozen source pins.

It reads only these four pinned JSON files and four sibling authoring files
for source hashes. It uses only stdlib and the reviewed sibling reference. It
creates the output directory only after computing/validating the in-memory
corpus and writes ten files with exclusive creation:

- `inputs.tsv`, `expected.tsv`, `case-metadata.jsonl`, `aliases.jsonl`;
- byte-identical `manual-handcases.json`, `manual-host-invalid.json`,
  `manual-freeze.json` copies;
- byte-identical `reference-qualification.json` (no private command paths);
- `coverage.json` with measured counts/bytes and bounded claim labels;
- `manifest.json` binding source/input/output hashes (excluding its own hash).

Outputs contain no local absolute paths, timestamps or secrets. No gzip is
used, avoiding compression-header variability. A second admitted generation
must use a different fresh directory and compare every file byte-for-byte.
No partial I/O output is silently deleted; an I/O failure exits unsuccessfully
and leaves evidence for parent inspection. No subprocess, network, installation,
service, native file reader or unlicensed binary/helper import is present.

The parent must verify source identities **before** interpreter import, then
use a pinned installed Python with `-B -S` and an explicit minimal environment,
for example PATH=/usr/bin:/bin and LANG=LC_ALL=C. Do not use `-I`: the intentional
sibling module import requires the script directory. Post-import source hashes
in output are provenance, not a substitute for the parent's pre-import gate.

The reference qualifier has actually passed its immutable manual expectations
under the parent's separate gate; the generator remains unexecuted. Its
sources/effects still require parent and independent review. After admitted
deterministic generation and review, freeze generator,
reference, manual fixtures, actual qualification receipts, input/expectation
separation and corpus bytes before any Rust source is authored. Rust authors
need the contract and input/output protocol, not this reference implementation.

## Prospective semantic control obligations

These are independently specified behavior changes to be mapped onto exact
source edits only after an implementation exists. They are not executed or
claimed detections now. Expected observations already have literal witnesses:

| Changed behavior | Literal witness / necessary observation |
| --- | --- |
| Pick first equal instead of last outside seam equality | H07/H10 selected logical index/value changes |
| Ignore wrapped seam equality and always pick final duplicate | H09/H11 selected index/value changes |
| Return physical index as logical, or omit head in slot mapping | H08/H17 exact two-index/value tuple changes |
| Return predecessor rank instead of insertion rank on an interior miss | H06 K02 expects insertion1 |
| Ignore the last key byte | H23 distinguishes P7f/P80/Pff and duplicate value selection |
| Compare signed bytes or little-endian integer keys in search | H22 exact indices/values change; keep host validation unchanged |
| Return the collected prefix as success after a miss | H19/H20 must remain F |
| Deduplicate or sort materialized handles | H21 ordered repeated output changes |
| Truncate or sign-filter opaque u64 payloads | H23 full16hex words must survive |

Every later counted control needs an actual successful build, ordinary child
exit, complete valid output and a named semantic mismatch; a compiler error,
parser refusal, crash or incomplete output does not count. No final-value
control can prove whether extra reads occur after a miss. Constructor/transport
refusal checks are separate host-policy controls, and no allocator-failure,
reference-count, lifetime, native/Linux execution or whole-RPC claim follows.

## EXPAND

After source/effects review, the parent can qualify the sealed mathematical
reference against the independent literals and then generate/freeze this
bounded corpus twice. Only a later gate may admit authored Rust and compiled
semantic controls. Further native helper closure is a separate research scope.
