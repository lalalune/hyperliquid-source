# Host operation and transport contract v1 — pre-source specification

This is a chosen safe interface for the reviewed conditional value relation,
not a reconstruction of native ABI or native error tags. Root settled the
parser-policy clarifications below after separate review; executable source
authorship and execution remain separate qualifications.
No expected output, reference file or native artifact is available to the driver.

Library proposal:
- Row = key [u8;32] and opaque value u64.
- Immutable RingView borrows a physical row slice; capacity is the slice length.
  Constructor takes head and live length. It rejects an invalid header, a zero
  live value, or live keys that are not nondecreasing. Unused rows do not affect admissibility.
  Errors are host policy, not captured failure behavior.
- search(query) returns Found(logical index, physical index, stored value) or
  Missing(insertion index), using the exact wrapped-seam exception and
  right-biased segment search. Never dereference stored values.
- materialize(queries) uses actual search on the supplied ring for each query.
  Return Some(all selected values in query order) only if every query hits,
  otherwise None. Empty query sequence yields Some(empty).
- Chosen Option/Result types do not represent the captured vector/tag layout.
  The source does not reconstruct reference counts, locks, drops or allocation
  failure. The contract's per-acquisition normal-return premise remains required.

Input-only line protocol, ASCII TSV, seven fields:
case_id<TAB>operation<TAB>capacity<TAB>head<TAB>live_length<TAB>physical_rows<TAB>queries

operation is S (one search) or M (materialization).
case_id: 1..64 ASCII alphanumeric/underscore/hyphen, unique in one invocation.
capacity/head/live_length: canonical unsigned decimal: zero is literal 0; otherwise the first digit
is1..9 followed only by0..9. No leading zeros, leading+, sign or whitespace.
capacity <=256, queries <=32; these are chosen driver resource limits.
physical_rows: '-' for capacity0; otherwise exactly capacity comma-separated
80-character lowercase hex records: key32bytes (64hex) then valueu64 (16hex).
The value is an integer encoded as conventional most-significant-hex-first
text; it is not native-endian object memory or a live pointer.
queries: '-' for empty, or comma-separated 64-character lowercase hex keys.
S requires exactly one query. M accepts0..32.

Output one LF-terminated row per input, in identical order:
S hit:    case_id<TAB>H<TAB>logical_index<TAB>physical_index<TAB>value16hex
S miss:   case_id<TAB>N<TAB>insertion_index
M success:case_id<TAB>V<TAB>comma-separated value16hex (or '-' when empty)
M failure:case_id<TAB>F

The driver takes stdin only/no arguments, at most16,777,216 raw stdin bytes (16MiB) and1..16384 records,
requires LF-only row endings and a finalLF, rejects CR/CRLF, empty rows and
non-ASCII bytes anywhere, validates ALL rows before its first stdout write, and
returns exit2 with emptystdout for malformed/host-domain input. I/O failure
after writes begin may leave partial output and is not a malformed-input proof.
No filesystem/network/native-ABI access or source-derived expected answers.

Validation design before Rust:
- Independent expectation: linear sorted-order relation plus explicit seam
  equality; direct all-hit predicate for materialization. Do not replay native
  instructions or mirror the binary-search loop.
- Handcases independently fix physical/logical mapping, seam duplicates,
  unsigned lexicographic comparisons, inactive rows, first/middle/last miss,
  repeated queries, and chosen host-domain refusals separately.
- Corpus should exhaust small admitted ring geometries and small sorted
  duplicate-key alphabets, then add binary-depth and32-byte comparison boundaries.
  Record dedup aliases; freeze inputs and expectations before implementation.
- Semantic mutations should alter choosing first/last/seam hit, segment routing,
  logical/physical mapping,32-byte comparison, absent insertion, all-or-nothing
  failure and ordered duplicate materialization. Every claimed detection must
  have a valid compiled/run/output result, not a compiler or parser failure.
- The value-only interface does not expose lookup callback/call-count effects.
  Do not claim detection of extra reads after a miss merely from identical
  final failure values. Short-circuit code can be reviewed without overstating
  observable differential evidence.

No library, driver or executable oracle has yet been written/admitted.

