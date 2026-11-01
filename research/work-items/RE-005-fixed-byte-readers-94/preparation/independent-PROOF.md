# Complete paired fixed-byte reader relation, before new Rust

This proof is derived from the authenticated node94 bytes and every instruction in two complete no-call leaves. It is not an instruction evaluator or a claim about an inferred source implementation. The image is 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Independent native admission is `NATIVE-REVIEW.json`: 20-byte reader `[0x466c140,0x466c1a6)` is 102 bytes/32 instructions, SHA `bb3c6ab56de3c09eb51017ac988e6a43a4d06286835baa5d3f27e19a5064015a`; 32-byte reader `[0x466c1b0,0x466c223)` is 115 bytes/37 instructions, SHA `14f7a11f50bba370abd61ae08c76346b828217584ce9a296bcce3df0040cd7a5`. Thus the primary family is 217 bytes/69 instructions. Both FDEs/CIEs and executable mappings, all eight local conditional branches, three returns per body, and the absence of calls or external code/data references are bound. All 80,300 actual eight-byte RELA writers have no interval overlap with either body or either retained caller.

## Normal domain and observation

Choose N=20 or N=32. The reader's native observed fields are mode low32 at +0, unsigned limit at +8, valid nonwrapping slice pointer/length at +16/+24, and unsigned charged count at +32. The input is immutable and contains L initialized bytes, with 0<=L<=isize::MAX; the cursor, native reader fields, initialized result storage, code/data and control storage have separated valid roles. All fields and every byte of the selected result projection are initialized: 21 bytes for N20, 33 for N32. No arbitrary or partial aliases, overlapping copies, faults, uninitialized-byte observations, asynchronous/concurrent changes, or wrapping address formations are admitted. Normal return is assumed. These are mathematical memory premises, not recovered source Rust types or nominal ABI.

Mode is an arbitrary u32 machine-state control, not an asserted valid source enum. Only raw value exactly 1 enables charging. Higher bits in that u32 remain material to that equality. Limit B and count C are arbitrary u64 values; an initially over-limit count is admitted. The safe projection need not expose original addresses. The source proof will cover valid slice lengths symbolically; finite serialized cases use small allocated slices.

Observe unchanged mode/limit and immutable input bytes, the final charged count, cursor/residual slice, and all bytes of the chosen initialized result window. Logical names value/end/charge are independent descriptions of the three native routes, not original enum declarations. The caller chooses initial result bytes, so preservation means preservation of those supplied bytes. It does not assert that a real caller's padding was initialized. Neither original stack padding nor enclosing caller outputs are thereby qualified.

## All-domain charge theorem

Let U=2^64-1. If mode!=1, the charge gate is skipped: C'=C and the length decision follows. In particular this is not a nonzero-boolean test. For mode=1:

1. If C>U-N, return charge with C'=C. The native unsigned JA follows CMP against U-N before either ADD or counter store, so overflow never wraps into a stored count.
2. Otherwise set C'=C+N, in the mathematical interval [N,U]. The native store precedes the unsigned comparison with B. If C'>B, return charge, retaining that increment even if the slice is short.
3. If C'<=B, the length decision follows with that increment retained.

These three cases partition every (mode,B,C). They require no relation between count and input length. Mode/limit never change. The gate's exact instruction ranges are 0x466c143..0x466c166 and 0x466c1b3..0x466c1db. Counter loads occur only on enabled mode; the limit load occurs only after the overflow guard succeeds. Charge returns do not inspect input length or payload and leave the cursor/residual slice unchanged.

## All-domain length/copy theorem

On a permitted length decision, if L<N, return end with additional=N-L in [1,N]. No input byte is read, no cursor/length store occurs, and any successful prior charge remains. Exact unsigned predicates are L>19 and L>31 for the successful routes; hence these two cases partition every admitted L without signed reinterpretation.

If L>=N, snapshot prefix P=input[0:N], then advance cursor by N and reduce remaining length to L-N. Every loaded byte lies in P. No arithmetic can wrap under the valid slice premise. The result payload is precisely P in original byte order: N20 uses the final four bytes plus the first sixteen; N32 uses two sixteen-byte chunks. The native stores precede/follow each other as listed, but separated initialized roles make their final-byte sets disjoint and their final result independent of that ordering. There are no callbacks or hidden paths.

For repeated calls, apply this same relation to the residual slice and current count/result bytes. Every value route consumes exactly N. Every end or charge route consumes zero. An end can change to charge on later enabled-mode calls because unsuccessful reads still charge; overflowing counts then remain fixed. No implicit retry reset, rollback, sticky error or cursor resurrection is present.

## Complete result write sets

All positions not assigned below retain their supplied initialized value. The integer encodings are eight little-endian bytes, as fixed by the actual x86-64 stores; copying does not perform endian conversion.

| Width | Logical route | Exact assignments |
|---|---|---|
|20|charge|out[0]=2|
|20|end|out[0]=0; out[8:16]=LE64(N-L)|
|20|value|out[0]=18; out[1:21]=P|
|32|charge|out[0]=1; out[8]=2|
|32|end|out[0]=1; out[8]=0; out[16:24]=LE64(N-L)|
|32|value|out[0]=0; out[1:33]=P|

N20's stores are at 0x466c163, 0x466c179/17c and 0x466c198/19e/1a2. N32's are at 0x466c1d3/1d9, 0x466c1ee/1f2/1f8 and 0x466c216/21a/220. This accounts for every result write in all 69 rows. In particular N32's leading 1 is an error route and its successful leading byte is 0; importing the N20 rawtag18 layout would be wrong. The native initial MOV RAX,RDI is preserved to every return, but the chosen portable projection does not claim original pointer ABI or other registers.

## Actual use, prior scope and limits

Two complete actual callers establish that these are real node uses. At 0x4c80b0b in `[0x4c80b00,0x4c80b5d)`, a real direct CALL reaches N20; the caller tests the returned first byte against 18 and copies the twenty-byte region. At 0x4779f20 in `[0x4779eb0,0x477a064)`, a real direct CALL reaches N32; the caller tests its first byte against 1, reading the success region from +1 on the other route and its error region from +8 on the 1 route. No purpose, nominal schema, full caller return, unknown padding or other callee semantics is inferred. Old stream-message static observations and the existing kind5 charged varint reader are credited as prior context, not newly discovered addresses or a generic fixed-byte implementation. Existing current Rust has no fixed20/fixed32 decoder preserving this distinct result relation.

All eight conditional branch predicates and six return routes are covered by the charge/length partitions above. There are no exceptional callees to leave opaque. The theorem is all-domain under its stated normal memory premises; the finite corpus is an independent arithmetic/immutable-byte witness, not captured execution or exhaustive execution of u32/u64 domains. New Rust byte identity, original source/compiler/nominal ABI, aliases, faults/unwind, allocation, whole codec/caller/node and all component gates remain open. Captured execution, new instruction evaluators, full/expanded suite and hosted CI remain NOT_RUN.
