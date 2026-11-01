# Native argument and qualified final-state relation

This proof concerns only node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Names D (decoder state), G (group result), P (input pointer), N (remaining),
C (charge) and L (limit) label observed memory operations, not recovered source
types. Pointers, ranges and little-endian words are interpreted at native entry.

## Preconditions

Mode dword `u32(D+0)=1`; `C=u64(D+0x20)` and `L=u64(D+8)` satisfy
`C<=MAX-32` and `C+32<=L`. Input begins with four `FD` markers at offsets
0,9,18,27, each followed by eight readable payload bytes; `N>=36`. P+N and
all observed address arithmetic do not wrap. D, input and G are valid,
nonoverlapping, stable memory regions with no alias into the group or wrapper's
active stack frames. G has 40 writable bytes. Calls obey the ordinary preserved
register/stack convention and return normally. These are premises, not recovered
constructor/lifetime guarantees.

At row `0x4c7e41a..0x4c7e427`, RDI becomes row-RSP+0x28, RSI is saved R14,
and `CALL` at `0x4c7e422` targets `0x466bf60`. After the call the row stages the
payload and tests byte G+0 at `0x4c7e44b`; zero branches to `0x4c7e4f3`.
Earlier successful row fields and the later recovery byte are premises/context.
The helper's qualified relation also applies at other callers satisfying these
premises; no other caller's reachability is established here.

## Complete body identities

| Body | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `0x466bf60..0x466c13f` | `0xef1f28` |479|`aa484554c9abb65bea26e5450e6cda287fc037cc7c53a47ed5e04e2069ab44a0`|
| `0x466bd10..0x466bdf5` | `0xef1eac` |229|`fca33a99b93d22ee7cde15b995c1faf05b6fc7f4967c1489ecaf77030d0f6f5e`|
| `0x4c7e340..0x4c7e60d` | `0xf443ac` |717|`691aada3f78a0a84acaa2b4e75ce3c58fe68b1e852aa29a98e464287e1ebf512`|

All three FDEs use CIE `0xce1518` and have no LSDA. The verifier checks complete
FDE bytes, unique matching unwind-index records, file-backed mappings and body
hashes. This establishes these extents, not all functions or component coverage.

## Four primitive successes

`0x466bf6e/71` save RSI/RDI as D/G. The four direct calls at
`0x466bfbe`, `0x466c001`, `0x466c044`, `0x466c083` all pass D and the same
temporary result at group-RSP+8 to `0x466bd10`. Each has a tag 0x13 panic check
and a tag 0x12 success check. The non-0x12 branches stop the success corridor at
`0x466c0ac/0b3/0bd/0c7`; no failure semantics are inferred here. The four
payload qwords from temporary+8 are held in R15,R13,RBP,RCX respectively.

The selected primitive behavior credits #1365 and is independently bound here:

1. Under mode 1, `0x466bd16..2f` adds 8, stores charge, then admits charge<=L.
2. Remaining N is compared with 8 at `0x466bd3d`. Before call i, N is at least
   36-9i, hence at least9 even at the last call; all four choose the fast path.
3. Marker FD yields index2 after subtracting 251 at `0x466bd5b`. The signed
   relative entry at table `0x6f6ea8+8` targets `0x466bd82`: load qword P+1,
   choose total width 9. No minimal-value test occurs on that arm.
4. `0x466bd97..a9` advances P by 9, decreases N by 9, writes payload at temp+8
   and tag 0x12 at temp+0. The ordinary return ends at `0x466bdb0`.

Thus no Reader, error-builder, allocator or unresolved indirect call is visited
on this domain. The table dispatch is authenticated data, not a guessed target.
Other table entries are context only.

## Charge composition and exact bounds

`0x466bf7d/81` rejects unsigned C>MAX-32 before addition. The selected admitted
path computes/stores C+32 at `0x466bf8b/8f`, then compares it with L at
`0x466bf93/96`. At `0x466bfae/b2` it stores C+24 before the first primitive.
After each of the first three successes, the full qword at D+0 is tested for
zero. Its low dword1 makes it nonzero regardless of upper bytes, so each
refund arm is selected. The charge>=8 checks cannot fail: before each refund
the charge is C+32. Refund stores are at `0x466bff5`, `0x466c038`, `0x466c077`.

The exact relative charge-write sequence is:

`+32,+24,+32,+24,+32,+24,+32,+24,+32`.

Every primitive charge is therefore C+32, representable and admitted by the
entry premise. Equality at C=MAX-32 and L=C+32 succeeds on this branch. Final
charge is C+32; final pointer/remaining are P+36/N-36. Rust compares this final
state only; its single final charge assignment does not reproduce those nine
stores. Changing the second refund from 8 to 16 still permits all four original
domain successes but leaves C+24, providing a genuine native-state distinction.

## Constructor and output widths

`0x466c09e..aa` selects zero tag and the successful values. For word0 w,
`RSI=w>>8`, `EAX=low32(w)`, then `0x466c0fc..103` computes
`((w>>8)<<8)|(w&255)=w`. All 64 bits survive. Success writes are:

| Native site | Width | Destination | Value |
| --- | --- | --- | --- |
|`0x466c0f9`|qword|G+0|0|
|`0x466c106`|qword|G+8|word0|
|`0x466c10a`|qword|G+0x10|word1|
|`0x466c10e`|qword|G+0x18|word2|
|`0x466c112`|qword|G+0x20|word3|

These five stores cover all 40 result bytes, with no result padding in this
selected view. The wrapper temporary's inactive bytes are not exposed. The
group epilogue returns at `0x466c124`; no original return-register ABI is claimed
by the safe bool-returning interface.

Six frozen byte edits modify word0's right shift, three destination
displacements, the second refund immediate, or the final store's source
register. `verify.py` bypasses identity checks only for those byte overlays,
reconstructs their altered operands and compares the qualified algebraic result
against the same eight frozen rows. These are static semantic counterexamples,
not executed patched binaries or a general instruction emulator. Matching Rust
source mutants are compiled/run and must disagree on the same row counts.

## Inferences and unknowns

The direct QC-row caller establishes the consensus route. Calling these words
signature words or C a resource charge is descriptive inference; no field's cryptographic interpretation is proved.
No native error union, ABI, source enum/struct, allocator, short-input outcome,
other mode/marker, canonical encoding rule, full decoder, runtime equivalence
or completed gate follows from this successful path.
