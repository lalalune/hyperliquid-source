# RE-005: bounded greeting-map attempts and single-leaf state

The map decoder2890b60 reserves96per decoded attempt before reading rows.
For mode QWORD exactly1 and logical limit1000, the preceding count8charge
proves at most10attempts. That bound closes a produced nonfull single-leaf
domain: every insertion has at most9prior distinct keys, below the11key
capacity. The full retained split/ancestor code is not semantically claimed.

This packet addresses a new aggregate question after author1742's paired
value decoding: reservation/refund ordering, duplicate replacement, sorted
last-value associations, active empty/nonempty headers and error cleanup.
The count is the original row-attempt count, including duplicates. Each full
row refunds96 then charges20/32/32/1, leaving R-11per completed attempt.
The invariant R-11*j=Cprime+96*(M-j)+85*j proves every admitted refund and
later entry charge valid. Data failures preserve reached stores and cursor.
No bound based on distinct keys or the unclosed outer9attempt hypothesis is used.

Count multiplication/addition overflow precedes the reservation store; an
exceeded limit retains the store. Empty M0 still stores its unchanged counter.
A failed20byte key read consumes none. Value errors forward the credited
scalar/paired active error cells. Map success is BYTE18 plus root/height/len;
the empty root0/len0 has no active height. Nonempty root is a symbolic fresh
leaf of height0, not a native pointer claim. Error output returns no partial map.

Keys compare as unsigned20byte strings. Replacement keeps one distinct key
with its last value and consumes/charges the whole row. Missing middle keys
request overlapping20byte-key and72byte-value-stride movements. Values have
only65defined payload bytes; seven physical padding bytes remain excluded.
The first fully decoded row requests one0x400leaf. A later input failure
requests exactly one0x400/flags0release; first-row failure has no leaf to free.
Helper allocator/memcmp/memmove/free behavior is an explicit ordinary-return
premise. No allocator implementation or loaded pointer values are inferred.

Base e5c9b6436876b2a4a39daef813171f9879317699. Original manual proof used
966865; the only intervening1747merge updates RE-001 validation records.
Target node94 is91774280bytes, SHA256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Four primary context FDEs total6260bytes/1326GNUrows. Including the seven
credited key/value/scalar helpers, retained identity is11completeFDEs,
8764bytes/2003GNUrows,26selectedinitialRELA,12directcalls/tails and28data
extents953bytes. Six dispatch tables and13diagnosticLocations/five paths
are bound separately. Initial file identities do not establish runtime values.
Raw GNU2.42/LLVM18.1.3 exports include all excluded split/terminal/unwind
blocks, complete FDE/CIE records and original bytes. No masks or omissions.

PROOF.md and PROOF-ADDENDUM.md preceded a new independent checker. Known
values and encoded-field lengths constructed14891distinct mathematical inputs
before the checker existed. The earlier14511case authority was retained;
V2adds380cross-position lexicographic witnesses before checker creation,
without repairing expectations from a checker failure. FROZEN-HISTORY.json
records that provenance. The checker separately parses bytes and updates a
logical sorted leaf. Twenty-four wrong rules must disagree, covering
reservation/refunds, overflow-store order, duplicate values/count, signed/
little-endian keys, movement stride, allocation/release, empty height,
error-layout forwarding, rollback and partial cursor behavior.
These are mathematical predictions, never captured target outputs.

CanonicalRE-005-bincode-varint/slow-widths and peer1365 own primitive scalar
grammar/wrapper sites; peer1535owns fixed20/fixed32 leaves; author1742owns
paired values. Canonicalstream-msg-codecs-94owns generic schema. Peer1454byte
and1497owned-byte collection remain credited. Author1723covers the response
envelope and excludes this selector0map. The current396open-PR-body inventory
finds only author1742context, with no independent focused map match; it is a
non-atomic ownership screen, not an exhaustive absence proof. Generic MIT
static tools reuse author1607/1723/1742, with no dependency on open PR code at
reproduction time. No unlicensed inferred implementation is copied.

Normal/optimized replay, relation, native integrity, binding and LLVM receipts,
root doctor/verify/catalogue-check/reproduce and exact commands are recorded
only after actual qualification in VALIDATION.json. Fullmake test includes
captured-instruction evaluators outside static authorization and is NOT RUN.
No captured execution, compiler/native Rust build, hosted CI, arbitrary raw
modes, all-limit/full trees, preexisting supplied maps, allocator internals,
faults/aliases/races, original source types/ABI, whole greeting/connection,
recovered-byte credit or component gate is claimed. Stable disjoint valid
input/state/output and ordinary preserving helper returns are premises.
New code/docs are MIT; artifact excerpts retain their original rights.

Reproduce against a non-executable authenticated node94, with fresh outputs:

```sh
python3 -B survey.py --binary /absolute/node94.elf --output /fresh/observed
python3 -B verify.py --binary /absolute/node94.elf --receipt /fresh/integrity.json
python3 -B check_bindings.py --binary /absolute/node94.elf --receipt /fresh/bindings.json
python3 -B crosscheck_llvm.py --binary /absolute/node94.elf --output /fresh/llvm
python3 -B regenerate_expectations.py /fresh/expectations
python3 -B check_relation.py /fresh/relation.json
```

Repeat optimized Python and compare exact receipts. Global registries/gates
remain unchanged; a partial packet cannot satisfy full component acceptance.

## Control-label clarification

One wrong-control label was corrected from input-order-associations to reverse-association-order, matching its actual reverse-sorted-output operation. Only that label changes; default relation and frozen expectations are unchanged. Original relation-normal/optimized receipts and initial archive are retained. Both Python modes were rerun as relation-final-normal/optimized; compare these final receipts when reproducing the current checker. No native/static inputs or binding logic changed, so their passing checks were not repeated.
