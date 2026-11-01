# Ordinary client batch and retained buffer state

This is a manual proof over the admitted node94 bytes, accompanied by exact
native exports and necessary structural checks. It is not executed target
behavior, an instruction evaluator, or an automatic semantic equivalence proof.
The active contract is the batch's value/error order and the buffer's persisted
state and ordered abstract enqueue attempts. Cryptographic recovery, block
preimages, the outer forward poll and channel delivery remain boundaries.

## Admission and premises

`scope.json` binds node94 SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes, and sixteen exact FDEs (10,566 bytes; 2,320 grouped rows).
`evidence.py` admits ELF64/x86-64, unique file-backed PT_LOAD spans, FDE/CIE
association, complete contiguous native byte partitions and matching GNU/LLVM
boundaries. The CIE/FDE bytes and every direct or RIP-relative call are retained.
RELATIVE calls require symbol index zero; imported copy/compare slots bind the
actual dynamic symbol. Register/dynamic calls remain visible and opaque.
LOCK prefixes split by LLVM are grouped. A non-NOP disguised behind an unreviewed
prefix is rejected. These facts establish the bodies read, not their semantics.

The correspondence concerns finite normal-return traces with ordinary x86-64 ABI
register/stack behavior. All item pointers are nonnull, initialized, live and
properly aligned as required by their loads; native Arc/refcount, vector and
channel invariants hold. Count products and pointer additions for 32-byte items,
40-byte transaction rows, 32-byte hash rows, certificates and byte slices neither
wrap nor exceed readable file-independent object spans / `isize::MAX`.
Output, scratch, immutable inputs, pending storage, history and channel spans do
not alias improperly. Imported `memcpy(dst,src,n)` copies exactly n bytes on
valid disjoint spans and writes no others; `memcmp` has ordinary unsigned-byte
lexicographic semantics. Pointers may already have escaped: lack of explicit
stores alone is **not** a no-clobber proof. All callee operations, logs, lazy getter,
allocations, destructors, locks and wakers preserve still-live inputs and caller
state outside their declared destinations, including through foreign/reentrant
aliases. This is an explicit frame premise. History remains stable while locked.

Allocation abort, malformed layouts, refcount overflow, panic/unwind/LSDA,
nontermination and concurrency that violates these premises are excluded. Calls
are conservatively allowed to return in CFG checks; no noreturn symbol inference
silently removes an edge. Safe-source capacity refusal and baseline fatal errors
are separate API outcomes, not native ordinary errors. Channel linearizability,
scheduler behavior, wake count, downstream delivery and outer reconnection are
not established here.

## P-batch: complete local gate order

Batch `0x4547690..0x4547ce4` receives out RDI, item pointer RSI, count RDX,
starting round RCX, history R8. Empty count takes `45476a7 -> 4547a1b` and writes
raw `0x8000000000000014`. Every ordinary local error ends at `4547a7b`.
Each item is 32 bytes: block Arc at +0, transaction-row Arc at +8, three raw u32
time words at +0x10/+0x14/+0x18. The signed block starts Arc+0x10.
Its QC round/hash are Arc+0x50/+0x58, block round +0x98, time +0xa0,
transaction hash vector pointer/count +0x18/+0x20. The optional proof's niche is
Arc+0x108: exactly `0x8000000000000000` means absent. Otherwise its child signed
block is at +0x108 and its QC at +0x200. This is a typed layout correspondence,
not admission of arbitrary tag values or a serialization format.

For each item, the following order follows all branch targets and shared joins:

1. `45476fe..4547712` accepts absent proof or index==count, else tag1a.
2. `4547718..454771f` compares QC round with the starting/previous block round,
   else tag15, actual QC round at out+8 and expected at out+0x10.
3. `4547725` skips the prior-hash test only on the first iteration. Otherwise
   two 16-byte `pcmpeqb` results are ANDed and the full 0xffff mask compared at
   `4547754`; tag16 stores actual QC hash at out+8 and previous digest at +0x28.
4. `4547764` passes Arc+0x10 to `454b700` at `4547773`. Only raw tag2a continues;
   `4547a9a..4547ae4` propagates the complete 80-byte result. We compare only
   the active typed error fields; copied padding is not initialized-value proof.
5. `4547794..45478d7` traverses every 40-byte tx row. Row hash occupies32 bytes;
   row+0x20 points to the byte Arc whose pointer/count are +0x18/+0x20. Each
   actual byte digest is checked before count or block-list checks. The first
   mismatch returns tag17 with the claimed row hash, not the computed digest.
6. `45478e0..4547970` then checks row count and every ordered 32-byte hash against
   the block vector. A count or positional mismatch returns tag18. Repeats are
   retained. There is no set comparison, sort, omission or early count shortcut.
7. `4547976..45479a3` checks all three u32 time words, in order, else tag19.
   Raw bits are compared; no chrono validity or conversion is claimed.
8. `45479a9` records the block round. `45479b0..45479d1` passes selector0 and
   the same complete signed-block pointer to `454c050`; its 32-byte output
   becomes the next iteration's expected hash. This call occurs even for the
   last block. No local rule requires successive block rounds to differ by one.

After the loop `4547a08` requires a last proof, else tag1b. With a proof:
`4547b6d` hashes the last block again; `4547b87` verifies the child;
`4547bac` verifies the proof QC. Either verifier failure is propagated before
link comparisons. `4547bc4..4547bf0` compares all32 child-QC-hash bytes at
Arc+0x150 with the last digest (tag1d). `4547c2e` hashes the child, and
`4547c3c..4547c68` compares all32 proof-QC-hash bytes at Arc+0x230 (tag1e).
On this mismatch, `4547c6a` calls the opaque lazy getter and `4547c8b` hashes the
child again before returning tag1e. The second digest is not used for the value
result, but remains observable at the digest boundary and is not removed.
`4547ca3..4547cb8` increments the saved last round and selects u64::MAX on wrap;
child round Arc+0x190 must equal that saturation, else tag1f. Success is raw
`0x800000000000002a`. Tags18/19/1a/1b/1d/1e/1f have no active local payload.

The local code does not separately compare proof-QC round or child-QC round to
the batch round; their existing verifier rules still apply. In particular the
saturating final comparison does not by itself make an otherwise invalid block
or certificate valid. First-parent hash is intentionally not checked.

## P-auth: actual dependency and complete signed time

The implementation composes the real baseline `verify_block` / `verify_qc`,
not caller-selected verifier results. Exact baseline source hashes and planned
paths are in `BASELINE-SOURCE-PLAN.json`. Their existing evidence is credited;
this packet does not independently re-prove their cryptographic internals.
`454b700` selects block-round stake data before proposer/QC/signature work.
At `454b7df` it retains the original full signed-block pointer; selector0 at
`454b7d6` and call `454b81b` hash that pointer, including its time at +0x90.
Signature input is +0xb0 and claimed proposer20 bytes at +0x9c/+0xac; membership
precedes recovery at `454b96a`. `47b01b0` and `4758d70` are fully exported
contexts for the already reconstructed admission operations.

Baseline `SignedBlock` omits the three u32 time words. Therefore the new wrapper
must retain them and the extended authenticator must have a required timed
block-signer method and a complete timed block-digest method. A private adapter
must route baseline signer requests through that method. A default that discards
time would not meet this contract. Block digest/recovery and proposer selection
remain actual external algorithms with ordinary-return/frame semantics; no
cryptographic result is proved by a fixture implementation. Digest calls must
be stable on equal complete values and may record calls without mutating inputs,
history or buffer. The mismatch-only lazy getter has no claimed value effect
under its frame premise; its timing/logging behavior is outside the safe API.

The inherited TC verifier explicitly uses stable input order where native
parallel child checks have unresolved competing-error precedence. Native
correspondence here consequently excludes competing failing TC children and
parallel cancellation races; a safe-source result there is the existing policy,
not a new target-derived prediction. The frozen fixture domain uses successful
TCs or at most one child / otherwise determined failing child, never competing
failures. Baseline fatal stake overflow / newer-hardfork panic paths are not
ordinary-return correspondence. Internal verifier call counts are not promoted
to a newly proved exact native trace; outer verifier/digest ordering is.

## P-hash: transaction bytes and conditional Keccak identity

`45477d9..4547846` zeroes the 200-byte state and offset; `454784e` sets rate136;
`454785a` stores delimiter1 and mode0. `4547864/4547868` pass the tx byte
pointer/count; `454786f` resolves through RELATIVE slot576e1d8 to full
`4f59a10..4f59e3a`. It XORs each complete136-byte chunk into the state and calls
P via slot5777790, then XORs the tail and records its length. Its vectorized
16-byte, scalar4-byte and final byte loops are all retained. This is ordinary
byte-stream absorption for nonwrapping input spans, including empty/multiple
blocks; no captured instruction is evaluated.

`4547880` copies0xe0 bytes through imported memcpy; `4547893` finalizes32 via
slot576e1e0 to `4f59e40..4f5a13d`. Mode0 selects `4f59eb5`, XORs delimiter1 at
remainder (`4f59ee7`), XORs0x80 at rate-1=135 (`4f59f0a`), calls P at
`4f59f14`, resets offset, then copies the first32 state bytes at `4f5a02b`.
When remainder135 the two XORs affect the same byte, giving0x81. Every complete
rate block gets P and there is always one final padded block. Output32<rate136
selects no additional squeeze permutation. The alternate pre-squeezed modes and
panic tails are bounded but outside this initialized caller path.

P is bound to address4f59480. Its identification with Keccak-f[1600] remains
conditional and credited to baseline `RE-005-action-signable-94` and its existing
MIT Rust Keccak provider. The independent mathematical expectation extracts only
the hash-pinned pure `keccak256` function and constants from
`tools/action_signable.py`; that module's imports and captured evaluators are
never imported or executed. This is independent source arithmetic, not a second
native observation, and all project evidence has one organization provenance.

## P-buffer: persisted state precedes verification and send

`4360000..43606aa` receives output RDI, state RSI and item RDX. QC round at
item.Arc+0x50 is compared with state+0x108 at `436001e`. Mismatch returns outer
raw tag2c with that QC round at out+8 and drops the item; state is unchanged.
Otherwise `4360035` stores the incoming block round into state+0x108 **before**
growth/append. `4360075..4360092` appends the complete32-byte item and publishes
the new length. Proof absence is tested only after these stores. Without proof,
length<=100 returns outer tag40; length>100 returns tag2a with the27-byte owned
text `Too many unconfirmed blocks`, retaining both pending and last_received.
A present proof bypasses this size gate.

`4360136..436016b` locks history and invokes the batch on all pending rows with
state+0x110 as starting round. Failure goes to `4360321`, formats the error,
copies80 bytes to output, releases the mutex at `43603e8` or helper `43603f8`,
and returns at `436055d`. There is no rollback or pending reset along this
complete ordinary path. The retained write inventory identifies explicit
first-operand writes; calls and implicit stack effects are separately premises.
State/item preservation across the log and unlock is explicitly required.

Success unlocks, copies last_received into state+0x110 at `4360198`, takes the
pending vector, then stores cap0/ptr8/len0 at `43601aa/43601b1/43601b9`. These
stores dominate the queue call `4360291`, even with all calls treated as returning.
Under the no-reentry premise, the later pending-length reread at `4360307` is0.
Each item is attempted in original order. A nonnull Arc domain excludes the
native null sentinel at `4360216`. Channel+0x1c0 bit0 is checked at `4360250`;
its closed edge `4360252 -> 4360403` precedes queue push. Otherwise an atomic
reservation adds2, and `4360271..4360291` passes the complete32-byte item.
On closure the current item is dropped at `436042d`, remaining items at
`4360544`, and outer tag35 returned. An already accepted prefix stays accepted;
confirmed stays advanced, pending stays empty. No automatic rollback occurs.

Full queue push `4b47b10..4b47d01` takes an atomic sequence at `4b47b21`, chooses
segment base sequence&~31 and slot sequence&31, follows/allocates0x420-byte
segments with compare/exchange, then at `4b47c94..4b47cab` copies both16-byte
halves into slot*32. Only afterwards `4b47caf` sets its ready bit and returns.
This proves the local normal-completion handoff under valid segment and lifetime
invariants. It does not prove global queue ownership safety, progress or delivery.
Growth `454ee00..454ee64` and realloc `454f420..454f50a` are retained; safe source
pre-admits representable sizes and reserves before semantic mutation when it
needs a recoverable capacity error. That extra refusal is outside native ordinary
correspondence. Drops (`4735b80`, `44c6e70`, two Arc contexts) are retained as
local cleanup requests; their transitive destructors keep frame premises.

## P-witness: a direct two-call counterexample to earlier prose

The old `RE-008-client-block-batch-94/README.md:70` and `error-tags.tsv:8`
say tag1a cannot be returned by the buffer. That inference overlooked retained
failed batches. Preserve the old packet and its historical evaluator fixtures;
they are not this packet's oracle. Initialize pending=[], last_received=confirmed0,
empty history root at history+8 and estimated_valid_until>=1. Take a well-formed
A with QC round0, block round1, and a present initialized proof. Appending A
advances last_received1. A is last, so the proof placement and QC-round gates pass.
`4547773` calls the block verifier, whose lookup at `454b7ac` enters full
`42c9930..42c9a21`. Empty root takes `42c993e -> 42c9a18`, zeroes EAX and returns
without a child call. `454b7b4 -> 454b90f` returns MissingValidatorSetRound(1),
raw tag28. No proposer, signature, QC, digest or hypothetical validity oracle is
used. Buffer returns it with A and last_received1 retained, confirmed0.

Now supply B with QC round1, block round2 and present proof. The outer gate
passes and pending becomes[A,B], last_received2. The first batch item A has
proof but is no longer last: `4547712 -> 4547a7c` returns tag1a before all auth
or hashes. Both items remain. This is a proven finite sequence of direct ordinary
calls under the premises, not observed execution of the captured node. An outer
poll may reset/reconnect after the first error; whole-poll reachability remains
unresolved. The caller's exclusion of empty-batch/tag14 and missing-last-proof/
tag1b is retained under noninterference; this witness does not refute it.
