# RE-005: nested three-record decode and array-first result

The nested hash tag2 helper21cca20 decodes exactly three records, each as
two variable-width64bit words followed by2048raw bytes. It writes each result
as(array,firstWord,secondWord), with2064byte record stride after an outer8byte
tag. Physical wire size6150..6198, logical payload6192 and full selected success
projection6200bytes are separate observations. No field count or array length
prefix appears. No source nominal/cryptographic type is inferred.

Mode QWORD exactly1 admits arbitrary u64 initial chargeC and limitL. Each
word charges8, and each raw array charges2048 before availability. Overflow
keeps the old charge without a store; limit failure keeps the increment.
Errors retain all preceding charge stores and cursor effects. A short array
consumes none of its bytes. A short scalar extension consumes only its marker.
FE/FF use expected5 in BOTH fast and Reader paths; only the fast invalid marker
remains unconsumed. Importing the other u64 family's expected2/3 behavior is wrong.
The raw arrays accept every byte value and preserve their full2048bytes.

The compiler's2025/2016byte temporary memcpy lengths do not truncate payloads.
The manual field map proves each final array consists of byte0, bytes1..6,
byte7, word8..15, block16..31 and tail32..2047, in original order. All three
arrays precede their corresponding scalar pair in output. Errors forward
outerQWORD1 plus active kind at+8, needed at+16 or expected/found at+9/+10;
inactive wide-copy cells are excluded. No partial prior records are returned.
No heap allocation/free occurs in this selected stack-only aggregate.

Full success charges C+6192 when it fits and is<=L, with complete valid fields.
For L1000, after two successful leading words Cprime is in[16,1000]; the first
array charge storesCprime+2048, then necessarily fails before reading array
bytes. Actual runtime caller configuration, the surrounding hash output
allocation and full greeting/connection remain outside this helper theorem.

Basee5c9b6436876b2a4a39daef813171f9879317699. Node94 is91774280bytes,
SHA2563b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Primary21cca20..21cd350 is2352bytes/432GNUrows. Four credited dependencies
2558d80,2559410,466dad0,466dac0 make the complete static identity denominator
fiveFDEs/3052bytes/**642GNUrows**, fourinitialRELA, nine directcalls and two
16byte dispatch tables. Initial slots bind memcpy and the actual Reader/error
helpers; file addends are not loaded pointers or callee implementation proof.
Raw GNU2.42/LLVM18.1.3 exports, complete FDE/CIE, all selected bytes and table
targets are retained without masks or omission. Static identity is not semantic
coverage, new recovered-byte credit or a compiler-equivalence claim.

The unchanged pre-checker PROOF.md records the earlier4charge hypothesis
being disproved before freezing. Its provisional645row estimate is corrected
to measured642 in the pre-checker PROOF-ADDENDUM.md: the14byte error helper
has five rows rather than eight. FROZEN-ADDENDUM.json binds that correction.
This changes no protocol expectation. Both normal/optimized runs sealed
12136distinct mathematical inputs BEFORE the independent byte parser/checker:
all2048array coordinates with distinct record markers, individual boundary
bits, all256raw-byte values, word basis/thresholds, record permutations, every
cut of a maximum-width message, nonminimal widths, suffixes and reached
budget/overflow/invalid-marker stages. Known values and chosen field widths
construct expectations. Twenty wrong protocol/layout/accounting rules must
disagree. These are mathematical predictions, never captured native outputs.

The current444open-PR-body screen has no focused helper/aggregate match;
broad hash/2048wording matched unrelated1397mask-rounding. This is a non-atomic
ownership screen, not exhaustive absence. CanonicalRE-005varint/slow-width,
peer1365scalar families and fixed-byte leaf families/peer1535 are credited.
Canonicalstream-msg-codecs-94 retains generic schema ownership. Author1723
owns the response envelope and author1742/1779 the separate value/map work.
The actual caller255eba0 uses this helper for its nested tag2 arm; full caller
tag handling/heap-result formation is excluded. Generic MIT static tools reuse
author1607/1723/1742, self-contained here. No unlicensed inferred source or
another open PR's implementation is copied.

VALIDATION.json records only observed qualification, exact commands, normal/
optimized receipts, Linux replay and rootdoctor/verify/catalogue-check/reproduce.
Fullmake test is NOT RUN because flat discovery includes captured-instruction
evaluators outside static authorization. No target execution/instruction
evaluator/symbolic CPU, compiler/Rust/native build, hosted CI, other raw modes,
original types/ABI, faults/aliases/races, full caller/greeting/connection or
component gate is claimed. Stable disjoint valid input/state/output/stack,
ordinary preserving helpers and exact memcpy request behavior are premises.
New code/docs are MIT; captured artifact excerpts retain their original rights.

Reproduce with an authenticated non-executable node94 and fresh outputs:

```sh
python3 -B survey.py --binary /absolute/node94.elf --output /fresh/observed
python3 -B verify.py --binary /absolute/node94.elf --receipt /fresh/integrity.json
python3 -B check_bindings.py --binary /absolute/node94.elf --receipt /fresh/bindings.json
python3 -B crosscheck_llvm.py --binary /absolute/node94.elf --output /fresh/llvm
python3 -B regenerate_expectations.py /fresh/expectations
python3 -B check_relation.py /fresh/relation.json
```

Repeat optimized Python and compare exact receipts. Global registries, source
pins and component acceptance gates remain unchanged.
