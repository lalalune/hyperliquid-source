# Nested three-record decoder: manual proof before an oracle/checker

This private draft concerns21cca20..21cd350 on node94,
91774280bytes/SHA2563b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f,
basee5c9b6436876b2a4a39daef813171f9879317699. All coordinates are ELF VAs.
The function is the tag2 arm called by255eba0 at255ec5c; calling it a
selector0 decoder directly was only preliminary surrounding-greeting context.
No complete caller, greeting, connection or component gate is claimed.

The earlier private intake hypothesized two4charged scalar reads. Inspecting
the exact dependency disproves that hypothesis before any frozen expectation
or model:2558d80 charges8 and returns a64bit word. It is not the4charged
scalar2973aa0 used to select the surrounding hash arm. Preserve the earlier
intake as a rejected hypothesis, not an earlier validated result.

## Domain and credited helpers

Admit stable modeQWORD exactly1, arbitrary u64 initial chargeC and limitL,
valid immutable nonwrapping input of at mostisize::MAX, and disjoint valid
input/state/output/stack. All helper returns are ordinary and preserve
unrelated caller state. memcpy copies exactly its requested bytes without
changing source or disjoint state. Invalid pointers, faults, aliases, races,
unwind and native source types/ABI are excluded. No captured instruction
evaluator, symbolic CPU execution, compiler or captured binary is used.

Canonical scalar varint/slow-width work and peer1365 own primitive grammar
and wrapper families. Fixed-byte families and peer1535 remain credited;
2559410's2048byte copy is dependency closure, not a new primitive contribution.
The canonical stream schema remains credited. The new bounded question is
the complete three-record composition and its actual active output mapping.

The primary2352byte/432GNUrow FDE invokes2558d80 six times,2559410 three
times, in the exact order(wordA,wordB,array2048) repeated three times.
2558d80 is229bytes/69rows;2559410 is141/41. Its actual scalar slow Reader
slot57745d0 initially relocates to466dad0..466dc0c (316bytes/95rows), not
the nearby4byte Reader466d850. Error slot57745d8 initially points to466dac0;
that14byte helper forwards kind3/expected/found. Complete identity is therefore
five FDEs/3052bytes/645GNUrows, including credited context; qualification
must independently confirm that denominator and all call/table/RELA bindings.

## Scalar and array sequencing

2558d80 tests modeDWORD1, checks C<=MAX-8, then stores C+8 BEFORE testing
the limit. Overflow leavesC unchanged/no new store; an exceeded limit retains
the increment. Only admitted charges read the scalar. The fast path applies
when actual remaining>8; nonminimal FB/FC/FD encode2/4/8byte little-endian
payloads and consume3/5/9bytes, while0..250 consume1byte. FE/FF are kind3,
expected5/found4or12, without consuming the fast marker. The actual
466dad0 Reader consumes its marker before dispatch and also uses expected5
for FE/FF. It does NOT inherit the other u64 family's expected2/3 distinction.
An empty scalar reports needed1 with no consume. A short extended value
consumes only its marker and reports missing payload bytes. Prior words,
arrays and reached stores remain consumed/stored after later errors.

2559410 first charges2048 with the same overflow-before-store and
limit-after-store order. Only then does it test remaining>=2048. A shortage
reports needed2048-remaining and consumes none of that array. Success advances
the input by2048, writes the2048raw bytes starting at its result+1 using
memcpy, and sets resultBYTE0. Error sets resultBYTE1 with nested kind at+8
and kind0needed at+16; no array content validation is performed.

There is no decoded row count, array-length prefix, loop, heap allocation,
drop or release in21cca20. Its nine logical stages are unrolled. Each complete
record charges8+8+2048=2064, so full success charges6192, with no refund.
The maximum reached stores are monotone; all successful earlier stages remain
charged. Full success requires all nine charge admissions and all input fields;
equivalently C+6192 fits u64 and is<=L, plus valid complete field encodings.
Its wire size is6150..6198bytes, independently of its6192logical payload bytes.
An arbitrary suffix remains unconsumed.

For L1000, if the two leading scalar reads succeed, their chargeCprime=C+16
is in[16,1000]. The first array charge cannot overflow, storesCprime+2048,
then necessarily exceeds1000 before testing or reading array bytes. Hence the
function has no success in this domain; earlier scalar/budget failures still
take precedence. This is a conditional helper theorem, not proof of which
runtime caller configuration or connection path actually occurs.

## Active success projection and temporary copies

The function's success output is outerQWORD0 followed by three records.
For recordj=0,1,2, let base=8+2064*j. It places the raw2048byte array at
base, then the first decoded word atbase+2048, and the second atbase+2056.
Thus wire order(wordA,wordB,array) differs from output order(array,wordA,wordB).
The three array ranges are8..807,818..1017,1028..1827 (hex inclusive), with
the corresponding words at808/810,1018/1020,1828/1830. The complete selected
success projection spans6200defined bytes including the outer tag. This
observation does not identify original source nominal types or certify an ABI.

The compiler's2025byte and2016byte temporary memcpy lengths do not truncate
an array. Write each source array as bytesa[0..2047]. The manual field map is:
a0 is saved individually; a1..6 are saved as overlapping4/2byte pieces;
a7 individually; a8..15 as a saved8byte word; a16..31 as a16byte block;
a32..2047 as the final2016byte copy. The intermediate2025byte copies start
at sourcea23; their first9bytes join the earlier pieces intoa16..31, leaving
the2016byte tail. These intervals are disjoint in the final destination and
their union is all2048array bytes, in original order. No bytes are invented.

For record0, the final writes are21cd232..21cd25f plus21cd29c..21cd2c7:
array0 at+8, wordA0 retainedr13 at+808, wordB0 savedstack+d0 at+810.
For record1,21cd261..21cd29a plus21cd2ce..21cd302 writearray1 at+818,
wordA1 savedstack+b8 at+1018 and wordB1 savedstack+c8 at+1020.
For record2,21cd1e7..21cd22b plus21cd309..21cd33d writearray2 at+1028,
wordA2 savedstack+a8 at+1828 and wordB2 savedstack+b0 at+1830.
Record0's a8..15 word is savedstack+c0 before reuse; record1's equivalent
is retainedr12 after its earlier scalar was saved; record2's is retainedr14
after the last input helper returns. These are manual field correspondences,
not a program that interprets registers/instructions. All native rows remain
raw evidence. The multiple memcpy requests are ordinary exact-copy premises;
no full physical write/call trace is claimed by the logical comparator.

## Active failure projection

Any failed scalar is forwarded by the record's early error block. Any failed
fixed-byte wrapper removes its BYTEouter1 and forwards the nested error.
All converge on outerQWORD1 at result0, BYTEkind at+8, neededQWORD at+16
only for kind0, expected/foundBYTE at+9/+10 only for kind3. Kind2 has no
active payload. Wide copies of other inactive cells do not define padding.
No partial record or prior array is returned, no input/counter rollback occurs,
and no heap/allocator cleanup is needed on this selected stack-only relation.

## Remaining work

Refresh actual canonical/current peer ownership before selecting/publication.
Bind full five FDEs, both dispatch tables3e5974/6f6ee8, actual Reader/error
and memcpy initial RELA, and all nine direct call sites. Freeze constructive
values/field-width/array-boundary expectations before an independent protocol
checker; those are mathematical predictions, not captured target outputs.
Require effective controls, normal/optimized replay and allowed root checks.
Other raw modes, surrounding hash tag dispatch/output allocation, full greeting
and connection, compiler/native equivalence and full-scope gates stay excluded.
