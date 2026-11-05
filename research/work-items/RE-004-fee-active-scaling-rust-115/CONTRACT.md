# Frozen raw checked-scaling relation, RE-004 / fees

Sole target node115 SHA256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
105896032 bytes, base05bc2de303c05525b71e7e257426e741bc66a390.
Complete FDE46a6860..46a69cf is367B100instructions. Selection is the entire
real-entry CFG through normalRET or before the first diagnostic CALL at
46a6973(A),46a6982(L),46a6991(I). Unwind-only cleanup, postdiagnostic UD2
and the diagnostic callee itself are context, not helper closure.

Input: one raw120byte representation, output initialized to one raw canary byte
repeated120times. Valid stable disjoint readable input120, writable output120
and stack88+returnword; all arithmetic addresses nonwrapping. No overlapping
input/output, concurrency, fault/unwind, original allocation or public ABI claim.
Only output and local stack writes are admitted. Unknown incoming registers and
uninitialized stack stayunknown, not assigned fabricated values.

Read raw outerword+0 and innerword+0x28. Multiply rawu64+0x60, then+0x68 by100.
If outer==1, multiply+8 by100 and copy20bytes+0x10. If inner!=2^63, multiply+0x40
by100 and copy word+0x38 plus20bytes+0x48. Finally multiply+0x70 by100. Every
MUL checks highword via overflow; values<=floor(u64MAX/100) fit, the next fails.
The first three failures select A, inner selects I and last selects L. A/L/I
are actual first-call coordinates, not native returned errors. They pass the
same authenticated compute.rs:45:42 Location to the unclosed diagnostic helper
and have not written any output bytes. No helper returns/side effects are supplied.

On normalRET, output+0 is0/1 from exact outer equality. Output+0x28/+0x30 preserve
raw input words. Active transformed/copy fields above occupy their same offsets.
Padding+0x24..0x28 and+0x5c..0x60 remains canary. All120output bytes are observed
EXCEPT inactive payload8..36 when outer!=1 and56..92 when inner==2^63 (half-open
byte coordinates in decimal). These excluded bytes are rendered ??, never zero
filled. Exclusion covers actual uninitialized spills and inactive pointer/raw
values; it is a semantic active-field projection, NOT a complete raw120byte match.
The actual instructions still perform all their original loads/stores and bounded
footprint checks. RET restores stack and returns original output pointer RAX.
Normal kindR and actualcallfrontiers A/L/I remain different outcomes.

The threshold, equality and sentinel come from original instructions, not a prior
narrative oracle. Source identities and failure/copy controls are independently
bound in proof.py and native-controls.json. Existing static #2092 and its original
packet are credited, untouched context. New code uses project MIT. This relation
establishes no economic units, original enum validity, fees policy, owning/drop
ABI, diagnostic/panic/unwind behavior, original compiler flags, code-byte match,
integrated node or acceptance gate. All92gates/registeredbytewindows stayfalse.
