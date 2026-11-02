# Pre-source successful-domain value contract

No production Rust or validation driver exists when this contract and its
oracle/corpus are frozen. The native proof is `../PROOF.md`. This contract
selects its successful bounded values; refusal variants are new safe API
results, not recovered panic/ABI results or a transactional rollback promise.

Proposed component: `src/node94-funding-worker-values`, a real dependency-free
Rust library with its own manifest and lockfile. It accepts immutable supplied
state and returns values. Inputs are a 20-byte address, raw bypass byte,
membership set of 20-byte addresses, raw time12, metadata's selected signed
first words in index order, rate map u64 asset -> raw binary64 u64, user signed
balance, and a BTreeMap of positions. A position has raw u32 tag, signed local
balance, signed size, and three signed accumulators. The remaining native
position bytes have a frame-preservation theorem but are not represented.

The operation returns one of: excluded eligibility with unchanged modeled
state; accepted with updated modeled state, ordered fully active rows, summary
and ordered saturation requests; or safe domain refusal with offending asset
and category. It never sends diagnostics or invokes an allocator from the
captured program. Rust standard collections allocate normally; successful
finite storage is a condition. No fallible-allocation recovery, native pointer,
capacity identity, ownership destructor, SSE status or machine ABI is promised.

Eligibility uses bypass!=0 OR exact address-set membership. Exclusion precedes
all position/rate checks. Position and rate keys are unique and ascending under
u64 ordering; Rust BTreeMap supplies this abstract invariant. Addresses use
unsigned-byte lexicographic order, matching the proved comparator premise.

For each position in that order:

1. Missing rate or raw ±0 rate skips it.
2. Asset%10000 must index the supplied metadata slice, even for size0.
3. Size0 skips the metadata word's sign/product checks.
4. Metadata word must be nonnegative and its mathematical product with size
   must fit signed64.
5. Convert that checked product to binary64 RN-even, then multiply with the
   raw rate and round RN-even again, with gradual underflow. Nonfinite result
   gives amount0; finite x>=2^63 gives MAX; finite x<=-2^63 gives MIN;
   other finite values truncate toward zero. MIN refuses.
6. Raw time DWORD0 skips state updates and row emission, after all these checks.
7. Tag exactly1 selects local balance; other raw u32 tags select shared balance.
   Saturating subtraction of amount precedes three saturating additions to
   accumulators, in field order. Each overflow adds one request before the
   corresponding conceptual store. Append the exact active row from PROOF.

On success, sum row payments in order with signed saturation; each sum overflow
adds its request after all position-update requests. First maximum unsigned
absolute checked product selects asset/magnitude/address; ties stay first.
Product MIN has magnitude2^63 and is admitted whenever its amount is not MIN.
The original raw rate bits, including NaN payload/sign, stay in the row.
Empty accepted output has no selected maximum and sum0. Native inactive words
and padding are not outputs. Excluded output activates no native row descriptor.

Requests describe the exact saturation operation (selected-balance subtraction,
accumulator0/1/2 addition, or summary subtraction-of-negated-payment), tagged
with the associated asset for value-level audit. Asset attribution is not an
extra native call parameter: native calls receive EDI0 and the relevant static
20-byte descriptor. The new API records these requests and does not claim that
the opaque native logger fulfilled them or preserved its required frame.

All returned success values correspond to a well-formed native representation
meeting every pointer/count/alias/frame/allocation and MXCSR premise in PROOF.
The caller's low32-tag2 exclusion and 104-byte active-field transfer give an
actual downstream use; the new API does not reconstruct its scheduling or
original vector layout. The credited surrounding rate producer and settlement
consumers are not dependencies of the new crate.

The API reads immutable supplied inputs and may build a private candidate
result before refusing. It returns no native error-state or failure request
trace. Native failure can leave earlier mutations and diagnostics in place;
no source-level refusal is evidence of native rollback. Allocation failure,
unwind/trap, malformed native trees, different floating controls and later
opaque helper effects remain outside the correspondence theorem.
